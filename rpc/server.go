package rpc

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"runtime/debug"
	"slices"
	"sync"
	"time"

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
	// Principal is who the client PROVED itself to be, or empty when nothing
	// proved anything.
	//
	// Two things can set it. RPCSEC_GSS sets it per call, from the context
	// the client established. Otherwise — AUTH_NONE and AUTH_UNIX only — it
	// is the identity [Server.CertPrincipal] derived from the connection's
	// verified TLS client certificate, if one is configured and it answered.
	// An RPCSEC_GSS principal always wins over the certificate, which is what
	// draft-cel-nfsv4-rpc-tls-othername requires.
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
// whose request approaches it: 1 MiB of data (the wtmax the NFS layer
// advertises) plus its arguments and credentials, well under 2 MiB, so a
// larger record is malformed or hostile. The buffer grows as bytes arrive,
// so the cap is not an allocation a client can ask for by announcing it. The cap is applied to the
// accumulated size of a multi-fragment record, not to each fragment, because
// otherwise a client could send unlimited 1-byte fragments.
const maxRecordDefault = 2 << 20

// Defaults for the connection limits on [Server]. Each is generous for an
// NFS client and finite for anyone else.
const (
	// DefaultIdleTimeout is how long a connection may sit without delivering
	// a complete record. A Linux client closes its own idle transport after
	// five minutes and reconnects on demand, so a server that does the same
	// costs a well-behaved client nothing.
	DefaultIdleTimeout = 5 * time.Minute
	// DefaultHandshakeTimeout bounds the TLS handshake after STARTTLS.
	DefaultHandshakeTimeout = 30 * time.Second
	// DefaultMaxConns caps concurrent connections. A client uses one (the
	// Linux nconnect option at most 16), so this is room for hundreds of
	// clients while refusing the thousands of sockets a flood would open.
	DefaultMaxConns = 1024
)

// readChunk is the least a record buffer grows by at a time. The buffer never
// grows by what a fragment header CLAIMS, only by what has arrived: a header
// is four bytes anyone can send, and trusting it would let a client that
// sends nothing else make the server allocate a whole record.
const readChunk = 4096

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

	// CertPrincipal, when set, names the caller from the TLS client
	// certificate, for calls whose flavour proves nothing by itself
	// (AUTH_NONE and AUTH_UNIX). See [Call.Principal].
	//
	// It is called ONCE per connection, right after the handshake, with the
	// first chain crypto/tls VERIFIED — leaf first. A certificate that was
	// merely presented is never passed: with a [tls.Config] whose ClientAuth
	// does not verify (RequestClientCert, RequireAnyClientCert) there is no
	// verified chain, the function is not called, and the principal stays
	// empty. Returning ok=false, or an empty principal, also leaves it empty.
	//
	// The answer belongs to the connection it was computed on and to nothing
	// else: it lives in that connection's goroutine and dies with it.
	//
	// Set it before Serve.
	CertPrincipal func(chain []*x509.Certificate) (principal string, ok bool)

	// IdleTimeout closes a connection that has not delivered a complete
	// record for this long, and bounds how long writing one reply may block.
	// Zero means [DefaultIdleTimeout]; a negative value disables it.
	//
	// It is also what bounds a client that trickles a record one byte at a
	// time: the whole record must arrive within one IdleTimeout.
	//
	// Set it before Serve.
	IdleTimeout time.Duration

	// HandshakeTimeout bounds the TLS handshake that follows a STARTTLS
	// reply. Zero means [DefaultHandshakeTimeout]; a negative value disables
	// it. Without a bound, a client that is answered STARTTLS and then says
	// nothing holds its connection, and its goroutine, for ever.
	//
	// Set it before Serve.
	HandshakeTimeout time.Duration

	// MaxConns caps the connections served at once; one accepted past the
	// cap is closed immediately. Zero means [DefaultMaxConns]; a negative
	// value removes the cap.
	//
	// Set it before Serve.
	MaxConns int

	// ErrorLog receives what the server cannot report to a client — a
	// procedure that panicked, for one. Nil means the log package's
	// standard logger.
	//
	// Set it before Serve.
	ErrorLog *log.Logger

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
		if max := s.maxConns(); max > 0 && len(s.conns) >= max {
			// Refused by closing rather than by not accepting: a listener
			// that stops accepting leaves the flood queued in the kernel's
			// backlog, where it still delays every legitimate client.
			s.mu.Unlock()
			c.Close()
			continue
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
		// A panic outside a procedure — in an Authenticator, say — costs
		// this connection and nothing more. The one inside a procedure is
		// caught closer to it, in invoke, and answered.
		if r := recover(); r != nil {
			s.logf("rpc: panic serving %v: %v\n%s", raw.RemoteAddr(), r, debug.Stack())
		}
		raw.Close()
		s.mu.Lock()
		delete(s.conns, raw)
		s.mu.Unlock()
	}()

	var req []byte
	var state *tls.ConnectionState
	// peer is the identity the TLS client certificate carries. It is a local
	// of THIS goroutine on purpose: nothing another connection runs can read
	// or overwrite it, so a principal cannot leak from one client to another.
	var peer string
	res := make([]byte, 0, 8192)
	idle := timeoutOr(s.IdleTimeout, DefaultIdleTimeout)
	for {
		var err error
		if idle > 0 {
			// A deadline error is an ordinary read error: the loop returns
			// and the connection goes.
			_ = c.SetDeadline(time.Now().Add(idle))
		}
		req, err = s.readRecord(c, req[:0])
		if err != nil {
			return
		}
		var startTLS bool
		// The reply starts after room for its record mark: see writeRecord.
		res, startTLS, err = s.handle(req, res[:markLen], c.RemoteAddr(), state, peer)
		if err != nil {
			// Nothing sensible can be replied to a message that is not
			// even a call, so the connection goes.
			return
		}
		if idle > 0 {
			// Re-armed for the reply: the procedure's own time must not eat
			// into the time the client is given to read it.
			_ = c.SetWriteDeadline(time.Now().Add(idle))
		}
		if err = writeRecord(c, res); err != nil {
			return
		}
		if startTLS {
			// The reply saying STARTTLS has gone out; RFC 9289 §5.1 has the
			// client send its ClientHello on THIS connection next. Replacing
			// c means every later read and write goes through TLS, including
			// the record framing.
			upgraded, st, err := upgrade(c, s.TLS, timeoutOr(s.HandshakeTimeout, DefaultHandshakeTimeout))
			if err != nil {
				return
			}
			c, state = upgraded, st
			peer = s.certPrincipal(st)
		}
	}
}

// timeoutOr resolves a timeout field: zero means the default, a negative
// value means none (returned as zero).
func timeoutOr(d, def time.Duration) time.Duration {
	switch {
	case d == 0:
		return def
	case d < 0:
		return 0
	}
	return d
}

// maxConns resolves [Server.MaxConns]; zero or less from here means no cap.
func (s *Server) maxConns() int {
	switch {
	case s.MaxConns == 0:
		return DefaultMaxConns
	case s.MaxConns < 0:
		return 0
	}
	return s.MaxConns
}

// logf reports through [Server.ErrorLog].
func (s *Server) logf(format string, args ...any) {
	l := s.ErrorLog
	if l == nil {
		l = log.Default()
	}
	l.Output(2, fmt.Sprintf(format, args...))
}

// invoke runs one procedure, and turns a panic in it into SYSTEM_ERR.
//
// A procedure is code this package does not control — the NFS server's, and
// behind it a driver's — and a panic in it would otherwise unwind the
// connection goroutine and, unrecovered, kill the whole process: every
// client of every export, for one bad call. The caller rewinds whatever the
// procedure had encoded before it panicked, exactly as for any failure.
func (s *Server) invoke(p Proc, c *Call) (st Status) {
	defer func() {
		if r := recover(); r != nil {
			s.logf("rpc: panic in program %d version %d procedure %d from %v: %v\n%s",
				c.Prog, c.Vers, c.Proc, c.Remote, r, debug.Stack())
			st = StatusSystemErr
		}
	}()
	return p(c)
}

// certPrincipal asks [Server.CertPrincipal] who a freshly verified TLS peer is.
func (s *Server) certPrincipal(st *tls.ConnectionState) string {
	if s.CertPrincipal == nil || len(st.VerifiedChains) == 0 {
		return ""
	}
	p, ok := s.CertPrincipal(st.VerifiedChains[0])
	if !ok {
		return ""
	}
	return p
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
		// Read the fragment as it arrives, growing the buffer by at most what
		// has already been received (and at least readChunk). A reused
		// buffer with room enough reads the whole fragment in one go.
		for n > 0 {
			k := n
			if room := cap(dst) - len(dst); k > room {
				k = min(k, max(readChunk, len(dst)))
				dst = slices.Grow(dst, k)
			}
			start := len(dst)
			dst = dst[:start+k]
			if _, err := io.ReadFull(r, dst[start:]); err != nil {
				return dst[:start], err
			}
			n -= k
		}
		if h&lastFragment != 0 {
			return dst, nil
		}
	}
}

// markLen is the size of the record mark in front of every fragment.
const markLen = 4

// writeRecord frames a reply as a single last fragment. rec is the reply
// with markLen bytes of room in front of it, which the mark fills.
//
// The mark and the body go out in one Write. Sending them separately works,
// but a packet capture of a live mount shows it costing an extra segment per
// reply — the 4-byte header goes out alone, and every reply becomes two
// segments the client must reassemble. The room in front is what makes one
// Write possible without copying the body behind a header: for a READ, that
// body is up to a megabyte of file data.
func writeRecord(w io.Writer, rec []byte) error {
	binary.BigEndian.PutUint32(rec, lastFragment|uint32(len(rec)-markLen))
	_, err := w.Write(rec)
	return err
}

// handle turns one request record into one reply record, appended to what
// res already holds. A non-nil error means no reply is possible and the
// connection should be dropped.
//
// peer is the identity of the connection's TLS client certificate, or empty.
func (s *Server) handle(req, res []byte, remote net.Addr, state *tls.ConnectionState, peer string) ([]byte, bool, error) {
	d := xdr.NewDecoder(req)
	e := xdr.AppendEncoder(res)
	base := len(res)
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
		// draft-cel-nfsv4-rpc-tls-othername: an AUTH_NONE or AUTH_SYS
		// call on a connection whose certificate names someone is executed
		// AS that someone. The uid in the credential is still not believed.
		principal = peer
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
	st := s.invoke(proc, &Call{
		XID: h.xid, Prog: h.prog, Vers: h.vers, Proc: h.proc,
		Cred: h.cred, Principal: principal, Args: d, Res: e, Remote: remote,
		TLS: state,
	})
	if st != StatusSuccess {
		// Rewind past whatever the procedure had already written. The header
		// is fixed-size and identical for every accept_stat, so re-encoding
		// from the start is exact rather than a patch-up.
		e.Truncate(base)
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
