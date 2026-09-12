package rpc

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/go-filesystems/nfs/xdr"
)

// Status is an ONC RPC accept_stat: the answer a procedure gives about
// whether it could be dispatched at all. It says nothing about whether the
// operation succeeded — NFS reports that inside the results, so a
// "file not found" is a [StatusSuccess] RPC carrying NFS3ERR_NOENT.
type Status uint32

// Accept statuses a procedure may return.
const (
	// StatusSuccess means the results have been encoded.
	StatusSuccess Status = Status(stSuccess)
	// StatusProcUnavail means the procedure number is not implemented.
	StatusProcUnavail Status = Status(stProcUnavail)
	// StatusGarbageArgs means the arguments did not decode.
	StatusGarbageArgs Status = Status(stGarbageArgs)
	// StatusSystemErr means the server failed for a reason the protocol
	// has no way to describe.
	StatusSystemErr Status = Status(stSystemErr)
)

// Call is one in-flight remote procedure call.
//
// Args and Res are valid only for the duration of the procedure: both alias
// per-connection buffers that the next call will reuse.
type Call struct {
	// XID is the client's transaction id, echoed in the reply.
	XID uint32
	// Prog, Vers and Proc identify the procedure.
	Prog, Vers, Proc uint32
	// Cred is the raw credential. It is unauthenticated; see [UnixCred].
	Cred Auth
	// Principal is who the client PROVED itself to be, or empty when the
	// flavour proves nothing — which is every flavour but RPCSEC_GSS.
	//
	// Empty and "root" are different answers. A procedure that treats an
	// unauthenticated call as anonymous is making a policy decision, and it
	// should make it deliberately rather than by reading Cred.UID.
	Principal string
	// Args decodes the procedure arguments.
	Args *xdr.Decoder
	// Res encodes the procedure results.
	Res *xdr.Encoder
	// Remote is the client's address, for export access checks.
	Remote net.Addr
	// TLS is the connection's TLS state, or nil when the call arrived in
	// the clear. A procedure that must not serve an unprotected caller has
	// to look: nothing else distinguishes the two.
	TLS *tls.ConnectionState
}

// Proc is a procedure implementation.
type Proc func(*Call) Status

// Program is one RPC program at one version.
type Program struct {
	// Prog is the program number (100003 for NFS, 100005 for MOUNT).
	Prog uint32
	// Vers is the program version.
	Vers uint32
	// Procs maps procedure numbers to implementations. A missing entry is
	// answered PROC_UNAVAIL, which is what a client needs to hear to fall
	// back rather than hang.
	Procs map[uint32]Proc
}

// maxRecordDefault caps one RPC record. NFSv3 WRITE is the only procedure
// whose request approaches it, and this server advertises wtmax well below,
// so a larger record is malformed or hostile. The cap is applied to the
// accumulated size of a multi-fragment record, not to each fragment, because
// otherwise a client could send unlimited 1-byte fragments.
const maxRecordDefault = 1 << 20

// lastFragment is the high bit of a record-marking header.
const lastFragment uint32 = 0x8000_0000

// ErrServerClosed is returned by Serve after Close.
var ErrServerClosed = errors.New("rpc: server closed")

// errRecordTooLarge reports a record over the server's ceiling.
var errRecordTooLarge = errors.New("rpc: record too large")

// Server dispatches RPC calls arriving on a TCP listener.
//
// Calls on one connection are handled one at a time, in arrival order.
// Clients pipeline aggressively — the Linux client will have a dozen RPCs
// outstanding on a single connection — so this serialises them. That is not
// a shortcut: a [github.com/go-filesystems/interface.Filesystem] is backed by
// one *os.File with one seek offset and is not documented as safe for
// concurrent use, so overlapping two READs would interleave seeks and return
// each other's bytes. Correct and ordered beats fast and wrong; a driver that
// later documents concurrency-safety can be given a parallel dispatcher
// without a protocol change.
type Server struct {
	// MaxRecord caps one RPC record in bytes. Zero means maxRecordDefault.
	MaxRecord int

	// TLS, when set, makes this server answer the AUTH_TLS probe (RFC 9289)
	// and upgrade the connection. Nil means the probe is answered the way
	// any unknown flavour is, which is what tells a client not to try.
	//
	// It does NOT make TLS required. A client that never probes is served
	// in the clear, and [Call.TLS] is how a procedure can tell the
	// difference — a server that treated the two alike would be offering a
	// guarantee it does not keep.
	//
	// Set it before Serve.
	TLS *tls.Config

	// Auth evaluates one further credential flavour — RPCSEC_GSS is the
	// reason it exists. Nil means AUTH_NULL and AUTH_UNIX and nothing else,
	// which is this server's behaviour when nobody asks for more.
	//
	// Set it before Serve: it is read without a lock on every call.
	Auth Authenticator

	mu       sync.Mutex
	programs map[uint64]*Program
	conns    map[net.Conn]struct{}
	ln       net.Listener
	closed   bool
	wg       sync.WaitGroup
}

// key packs a program/version pair.
func key(prog, vers uint32) uint64 { return uint64(prog)<<32 | uint64(vers) }

// Register adds a program. Registering the same program and version twice
// replaces the earlier one.
func (s *Server) Register(p *Program) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.programs == nil {
		s.programs = make(map[uint64]*Program)
	}
	s.programs[key(p.Prog, p.Vers)] = p
}

// lookup finds a program, and reports whether the program number exists at
// any version — the two answers a client needs to tell PROG_UNAVAIL from
// PROG_MISMATCH.
func (s *Server) lookup(prog, vers uint32) (p *Program, progExists bool, lo, hi uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.programs {
		if uint32(k>>32) != prog {
			continue
		}
		progExists = true
		if lo == 0 || v.Vers < lo {
			lo = v.Vers
		}
		if v.Vers > hi {
			hi = v.Vers
		}
	}
	return s.programs[key(prog, vers)], progExists, lo, hi
}

// Serve accepts connections until Close. It always returns a non-nil error.
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrServerClosed
	}
	s.ln = ln
	s.mu.Unlock()

	for {
		c, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return ErrServerClosed
			}
			return err
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			c.Close()
			return ErrServerClosed
		}
		if s.conns == nil {
			s.conns = make(map[net.Conn]struct{})
		}
		s.conns[c] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			s.serveConn(c)
		}()
	}
}

// Close stops the listener, drops every live connection and waits for the
// per-connection goroutines to finish.
//
// It drops connections rather than draining them because an NFS client's
// connection is idle-but-open almost all the time: waiting for it to close
// itself would mean waiting for the client to unmount.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	ln := s.ln
	conns := s.conns
	s.conns = nil
	s.mu.Unlock()

	var err error
	if ln != nil {
		err = ln.Close()
	}
	for c := range conns {
		c.Close()
	}
	s.wg.Wait()
	return err
}

// serveConn reads records off one connection until it fails or the server
// closes.
func (s *Server) serveConn(raw net.Conn) {
	// raw is what Close and the connection table know about, and it stays
	// that. c is what this loop reads and writes, and a STARTTLS upgrade
	// REPLACES it — closing or deleting the wrapper instead would leave the
	// entry in the table for a connection nobody can close.
	c := raw
	defer func() {
		raw.Close()
		s.mu.Lock()
		delete(s.conns, raw)
		s.mu.Unlock()
	}()

	var req, out []byte
	var state *tls.ConnectionState
	res := make([]byte, 0, 8192)
	for {
		var err error
		req, err = s.readRecord(c, req[:0])
		if err != nil {
			return
		}
		var startTLS bool
		res, startTLS, err = s.handle(req, res[:0], c.RemoteAddr(), state)
		if err != nil {
			// Nothing sensible can be replied to a message that is not
			// even a call, so the connection goes.
			return
		}
		if out, err = writeRecord(c, res, out); err != nil {
			return
		}
		if startTLS {
			// The reply saying STARTTLS has gone out; RFC 9289 §5.1 has the
			// client send its ClientHello on THIS connection next. Replacing
			// c means every later read and write goes through TLS, including
			// the record framing.
			upgraded, st, err := upgrade(c, s.TLS)
			if err != nil {
				return
			}
			c, state = upgraded, st
		}
	}
}

// readRecord reassembles one RPC record from its fragments, appending to dst.
func (s *Server) readRecord(r io.Reader, dst []byte) ([]byte, error) {
	limit := s.MaxRecord
	if limit <= 0 {
		limit = maxRecordDefault
	}
	var hdr [4]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return dst, err
		}
		h := binary.BigEndian.Uint32(hdr[:])
		n := int(h &^ lastFragment)
		if len(dst)+n > limit {
			return dst, errRecordTooLarge
		}
		start := len(dst)
		dst = append(dst, make([]byte, n)...)
		if _, err := io.ReadFull(r, dst[start:]); err != nil {
			return dst, err
		}
		if h&lastFragment != 0 {
			return dst, nil
		}
	}
}

// writeRecord frames a reply as a single last fragment.
//
// The header and the body go out in one Write. Sending them separately works,
// but a packet capture of a live mount shows it costing an extra segment per
// reply — the 4-byte header goes out alone, and every reply becomes two
// segments the client must reassemble. One buffer, one write.
func writeRecord(w io.Writer, body, scratch []byte) ([]byte, error) {
	scratch = binary.BigEndian.AppendUint32(scratch[:0], lastFragment|uint32(len(body)))
	scratch = append(scratch, body...)
	_, err := w.Write(scratch)
	return scratch, err
}

// handle turns one request record into one reply record. A non-nil error
// means no reply is possible and the connection should be dropped.
func (s *Server) handle(req, res []byte, remote net.Addr, state *tls.ConnectionState) ([]byte, bool, error) {
	d := xdr.NewDecoder(req)
	e := xdr.NewEncoder(res)
	h, err := decodeCall(d, len(req))
	if err != nil {
		if errors.Is(err, errBadRPCVersion) {
			// The xid was decoded before the version check failed, so the
			// client can be told which versions it should have used.
			encodeDenied(e, h.xid, rjRPCMismatch, rpcVersion, rpcVersion)
			return e.Bytes(), false, nil
		}
		return nil, false, err
	}

	// RFC 9289 §5.1: the probe is a NULL call that asks one question. It is
	// answered before the flavour switch below, because AUTH_TLS is not a
	// credential and has no business being evaluated as one.
	if isTLSProbe(h) {
		if s.TLS == nil {
			// Not refusing it loudly: a client reads the verifier, and one
			// that is not STARTTLS is exactly how RFC 9289 says "no".
			encodeDenied(e, h.xid, rjAuthError, 5, 0)
			return e.Bytes(), false, nil
		}
		encodeAccepted(e, h.xid, stSuccess, Auth{Flavor: AuthNull, Body: starttls})
		return e.Bytes(), true, nil
	}

	// Which flavours this server evaluates, and what it does with the rest.
	// AUTH_NULL and AUTH_UNIX prove nothing and are accepted as they arrive;
	// see [UnixCred] for why "accepted" is not "believed".
	verf, principal := authNone, ""
	var wrap func([]byte) []byte
	switch {
	case h.cred.Flavor == AuthNull || h.cred.Flavor == AuthUnix:
	case s.Auth != nil && h.cred.Flavor == s.Auth.Flavor():
		dec := s.Auth.Authenticate(&AuthCall{
			XID: h.xid, Prog: h.prog, Vers: h.vers, Proc: h.proc,
			Cred: h.cred, Verf: h.verf, Header: req[:h.credEnd],
			Args: d, Remote: remote,
		})
		if dec.Reject != 0 {
			encodeDenied(e, h.xid, rjAuthError, dec.Reject, 0)
			return e.Bytes(), false, nil
		}
		verf, principal, wrap = dec.Verf, dec.Principal, dec.WrapResults
		if dec.Args != nil {
			// The procedure reads what the authenticator unwrapped, not
			// what arrived: under sec=krb5i the arguments on the wire are
			// an envelope, and handing the procedure the envelope would
			// have it decode a length where it expects a file handle.
			d = dec.Args
		}
		if dec.Reply != nil {
			// Context establishment: the call reached a procedure number but
			// belongs to the flavour, not to the program. Dispatching it
			// would hand NULLPROC a token it has no idea about.
			encodeAccepted(e, h.xid, stSuccess, verf)
			dec.Reply(e)
			return e.Bytes(), false, nil
		}
	default:
		// AUTH_TOOWEAK (auth_stat 5): the client offered a flavour this
		// server cannot evaluate. Saying so lets it retry with AUTH_UNIX
		// instead of retransmitting forever.
		encodeDenied(e, h.xid, rjAuthError, 5, 0)
		return e.Bytes(), false, nil
	}

	prog, progExists, lo, hi := s.lookup(h.prog, h.vers)
	switch {
	case prog != nil:
	case progExists:
		encodeAccepted(e, h.xid, stProgMismatch, authNone)
		e.Uint32(lo)
		e.Uint32(hi)
		return e.Bytes(), false, nil
	default:
		encodeAccepted(e, h.xid, stProgUnavail, authNone)
		return e.Bytes(), false, nil
	}

	proc, ok := prog.Procs[h.proc]
	if !ok {
		encodeAccepted(e, h.xid, stProcUnavail, authNone)
		return e.Bytes(), false, nil
	}

	encodeAccepted(e, h.xid, stSuccess, verf)
	results := e.Len()
	st := proc(&Call{
		XID: h.xid, Prog: h.prog, Vers: h.vers, Proc: h.proc,
		Cred: h.cred, Principal: principal, Args: d, Res: e, Remote: remote,
		TLS: state,
	})
	if st != StatusSuccess {
		// Rewind past whatever the procedure had already written. The header
		// is fixed-size and identical for every accept_stat, so re-encoding
		// from zero is exact rather than a patch-up.
		e.Truncate(0)
		encodeAccepted(e, h.xid, uint32(st), verf)
		return e.Bytes(), false, nil
	}
	if wrap != nil {
		// Only a successful reply carries results to wrap. Wrapping an
		// empty body would produce an envelope around nothing, which is
		// not what any client unwraps.
		out := wrap(e.Bytes()[results:])
		e.Truncate(results)
		e.Fixed(out)
	}
	return e.Bytes(), false, nil
}
