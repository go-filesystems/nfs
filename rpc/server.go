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
	"sync/atomic"
	"time"

	"github.com/go-filesystems/inflight"
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
	// Ranges says, for a procedure whose calls may run beside others, what
	// part of which file a call touches (a READ or a WRITE, to the NFS layer).
	// It is given a COPY of the decoder positioned at the procedure's
	// arguments, so reading them costs the procedure nothing, and reports
	// false for a call it cannot make sense of, which then runs alone and
	// fails in order. Two calls on one key whose ranges overlap, a write among
	// them, run in arrival order; every procedure with no entry runs alone,
	// after everything before it has been answered.
	Ranges map[uint32]func(args xdr.Decoder) (inflight.Span, bool)
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
	// DefaultMaxInFlight is how many calls one connection may have in progress
	// at once. The Linux client keeps a slot table per transport that grows to
	// 65536 entries at most and in practice a few dozen are busy.
	DefaultMaxInFlight = 32
	// DefaultMaxInFlightTotal is the ceiling across ALL connections: each call
	// in flight holds up to a record in (a WRITE, 1 MiB) and a reply out (a
	// READ, 1 MiB), so this bounds memory at about 256 MiB however many
	// connections there are.
	DefaultMaxInFlightTotal = 128
	// DefaultRecordTimeout bounds how long the rest of a record may take to
	// arrive once its first byte has: the call holds a slot and a token of the
	// server-wide budget meanwhile.
	DefaultRecordTimeout = 30 * time.Second
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
// Calls on one connection are decoded one at a time, in arrival order, and a
// procedure that declares what it touches ([Program.Ranges]) then runs beside
// the others, up to [Server.MaxInFlight] per connection and
// [Server.MaxInFlightTotal] across the server (both taken before the record is
// read). Replies leave as they are ready: an ONC RPC client matches a reply to
// its call by xid (RFC 5531), as the Linux client does with the dozens of calls
// it keeps outstanding on a transport. A call that declares nothing is a
// barrier: it waits for every earlier call to be answered and runs alone, which
// is what keeps a [github.com/go-filesystems/interface.Filesystem], whose
// calls are documented as safe beside each other only for ReadAt, correct.
// The mechanism is [github.com/go-filesystems/inflight]; MaxInFlight -1 is the
// one-call-at-a-time server of v0.10 and before.
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

	// MaxInFlight is how many calls one connection may have in progress at
	// once. Zero means [DefaultMaxInFlight]; a negative value means 1, the
	// one-call-at-a-time behaviour of v0.10 and before.
	//
	// Set it before Serve.
	MaxInFlight int

	// MaxInFlightTotal caps the calls in progress across every connection.
	// Zero or less means [DefaultMaxInFlightTotal]. A call takes its share
	// before its record is read and gives it back when its reply is written,
	// so a client that does not read its replies keeps its calls counted, as
	// it would keep a knfsd thread: close stalled connections (IdleTimeout).
	//
	// Set it before Serve.
	MaxInFlightTotal int

	// RecordTimeout bounds how long the rest of a record may take once its
	// first byte has arrived. Zero means [DefaultRecordTimeout]; a negative
	// value disables it.
	//
	// Set it before Serve.
	RecordTimeout time.Duration

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
	pool     *inflight.Pool // made by the first connection, from MaxInFlightTotal
}

// inflightPool returns the server-wide budget and range set, made on first use
// so that the fields above can be set any time before Serve.
func (s *Server) inflightPool() *inflight.Pool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pool == nil {
		n := s.MaxInFlightTotal
		if n <= 0 {
			n = DefaultMaxInFlightTotal
		}
		s.pool, _ = inflight.NewPool(n) // n is at least 1
	}
	return s.pool
}

// maxInFlight resolves [Server.MaxInFlight].
func (s *Server) maxInFlight() int {
	switch {
	case s.MaxInFlight == 0:
		return DefaultMaxInFlight
	case s.MaxInFlight < 0:
		return 1
	}
	return s.MaxInFlight
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
	var cn *inflight.Conn
	defer func() {
		// A panic outside a procedure — in an Authenticator, say — costs
		// this connection and nothing more. The one inside a procedure is
		// caught closer to it, in invoke, and answered.
		if r := recover(); r != nil {
			s.logf("rpc: panic serving %v: %v\n%s", raw.RemoteAddr(), r, debug.Stack())
		}
		if cn != nil {
			// Requests still in flight finish (or fail on the closing stream)
			// before the connection is forgotten.
			cn.Wait()
		}
		raw.Close()
		s.mu.Lock()
		delete(s.conns, raw)
		s.mu.Unlock()
	}()

	var state *tls.ConnectionState
	// peer is the identity the TLS client certificate carries. It is a local
	// of THIS goroutine on purpose: nothing another connection runs can read
	// or overwrite it, so a principal cannot leak from one client to another.
	var peer string
	idle := timeoutOr(s.IdleTimeout, DefaultIdleTimeout)
	record := timeoutOr(s.RecordTimeout, DefaultRecordTimeout)
	if idle > 0 && (record == 0 || idle < record) {
		// The whole record arrives within one IdleTimeout at the most, as it
		// always has.
		record = idle
	}
	w := &connWriter{c: c, raw: raw, idle: idle}
	// The error is impossible: the writer is not nil, the order is one of the
	// two, and the width is at least 1.
	cn, _ = s.inflightPool().NewConn(w, inflight.AnyOrder, s.maxInFlight())
	var active atomic.Int32 // calls handed to cn and not yet run
	pr := &prefixed{}
	for {
		if cn.Err() != nil {
			return
		}
		// Wait for the next record to begin BEFORE taking a slot and a token:
		// a connection with nothing to say holds nothing of the server's
		// budget. A timeout while calls are still being worked on is not an
		// idle connection (the client is waiting for them), so it is retried.
		first, err := awaitRecord(c, idle, &active)
		if err != nil {
			return
		}
		sl, err := cn.Begin()
		if err != nil {
			return
		}
		if record > 0 {
			// The slot and the token are held while the rest of the record
			// arrives, so the time that takes is bounded on its own, shorter
			// than the idle time: a client that trickles bytes must not be
			// able to hold the server-wide budget for minutes.
			_ = c.SetReadDeadline(time.Now().Add(record))
		}
		pr.reset(c, first)
		// small is what a slot keeps between calls. A call that needs more
		// borrows it (see borrow) and gives it back once it is done: a
		// connection doing nothing holds no large buffer, however large its
		// last call was.
		if sl.In == nil {
			sl.In = make([]byte, 0, smallBuffer)
		}
		req, err := s.readRecord(pr, sl.In[:0])
		if err != nil {
			cn.Abandon(sl)
			return
		}
		// The reply starts after room for its record mark: see writeRecord.
		res := borrow(markLen)
		if res == nil {
			if cap(sl.Out) < smallBuffer {
				sl.Out = make([]byte, 0, smallBuffer)
			}
			res = sl.Out[:0]
		}
		var later deferred
		reply, startTLS, err := s.handleUpTo(req, res[:markLen], c.RemoteAddr(), state, peer, &later)
		if err != nil {
			// Nothing sensible can be replied to a message that is not
			// even a call, so the connection goes.
			giveBack(req)
			cn.Abandon(sl)
			return
		}
		active.Add(1)
		switch {
		case later.run == nil:
			// Answered without a procedure (a refusal, a probe, a context
			// establishment): in order, alone.
			giveBack(req)
			cn.Barrier(sl, func(*inflight.Slot) ([]byte, error) {
				defer active.Add(-1)
				setMark(reply)
				return reply, nil
			})
		case later.ranged:
			cn.Go(sl, later.span, s.runner(later.run, req, &active))
		default:
			cn.Barrier(sl, s.runner(later.run, req, &active))
		}
		if startTLS {
			// The reply saying STARTTLS must be out before anything else
			// happens; RFC 9289 §5.1 has the client send its ClientHello on
			// THIS connection next. Replacing c means every later read and
			// write goes through TLS, including the record framing. Nothing is
			// in flight, so nothing reads w.c while it is replaced.
			cn.Wait()
			upgraded, st, err := upgrade(c, s.TLS, timeoutOr(s.HandshakeTimeout, DefaultHandshakeTimeout))
			if err != nil {
				return
			}
			c, state, w.c = upgraded, st, upgraded
			peer = s.certPrincipal(st)
		}
	}
}

// runner is the work of one call as inflight runs it: the procedure, then the
// record mark. A panic outside the procedure itself (invoke has answered that
// one) ends the connection and not the process.
func (s *Server) runner(run func() []byte, req []byte, active *atomic.Int32) inflight.Run {
	return func(*inflight.Slot) (out []byte, err error) {
		defer active.Add(-1)
		defer func() {
			if r := recover(); r != nil {
				s.logf("rpc: panic answering a call: %v\n%s", r, debug.Stack())
				out, err = nil, errPanic
			}
		}()
		out = run()
		giveBack(req)
		setMark(out)
		return out, nil
	}
}

var errPanic = errors.New("rpc: panic answering a call")

// connWriter writes one reply per Write, with its own deadline, and gives the
// reply's buffer back. A failed write closes the connection, which is what
// wakes the reader that is waiting for the next record.
type connWriter struct {
	c, raw net.Conn
	idle   time.Duration
}

func (w *connWriter) Write(p []byte) (int, error) {
	if w.idle > 0 {
		// Re-armed for each reply: the procedure's own time must not eat into
		// the time the client is given to read it.
		_ = w.c.SetWriteDeadline(time.Now().Add(w.idle))
	}
	n, err := w.c.Write(p)
	giveBack(p)
	if err != nil {
		w.raw.Close()
	}
	return n, err
}

// awaitRecord waits for the first byte of the next record, and returns it.
func awaitRecord(c net.Conn, idle time.Duration, active *atomic.Int32) (byte, error) {
	var b [1]byte
	for {
		if idle > 0 {
			// A deadline error is an ordinary read error: the loop returns
			// and the connection goes, unless calls are still in progress.
			_ = c.SetReadDeadline(time.Now().Add(idle))
		}
		n, err := c.Read(b[:])
		if n == 1 {
			return b[0], nil
		}
		var ne net.Error
		if err == nil || (errors.As(err, &ne) && ne.Timeout() && active.Load() > 0) {
			continue
		}
		return 0, err
	}
}

// prefixed is a reader that hands out one byte already taken from r first.
type prefixed struct {
	r    io.Reader
	b    byte
	have bool
}

func (p *prefixed) reset(r io.Reader, b byte) { p.r, p.b, p.have = r, b, true }

func (p *prefixed) Read(b []byte) (int, error) {
	if p.have && len(b) > 0 {
		b[0], p.have = p.b, false
		return 1, nil
	}
	return p.r.Read(b)
}

// setMark fills the record mark in front of a reply: see writeRecord.
func setMark(rec []byte) {
	binary.BigEndian.PutUint32(rec, lastFragment|uint32(len(rec)-markLen))
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
				// A buffer a finished call gave back, when one is big enough
				// for the whole fragment: memory that already exists, so not
				// an allocation the client asked for by announcing a size.
				if b := borrow(len(dst) + n); b != nil {
					dst = append(b, dst...)
				} else {
					k = min(k, max(readChunk, len(dst)))
					dst = slices.Grow(dst, k)
				}
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

// smallBuffer is what a connection keeps for itself: enough for every call
// but a READ or WRITE of real size.
const smallBuffer = 8 << 10

// buffers holds the buffers finished calls gave back, for the next call that
// needs one, on any connection. It has no New: borrow returns nil rather
// than allocate, so the growth of a record buffer still follows the bytes
// that arrive. The garbage collector empties it of what nobody borrows.
var buffers sync.Pool // of *[]byte

// borrow returns an empty buffer of at least n bytes of capacity that a
// finished call gave back, or nil.
func borrow(n int) []byte {
	p, _ := buffers.Get().(*[]byte)
	if p == nil {
		return nil
	}
	if cap(*p) < n {
		buffers.Put(p)
		return nil
	}
	return (*p)[:0]
}

// giveBack lends b to the next call, unless it is no larger than what a
// connection keeps for itself -- which is how a connection's own small
// buffer is never given away -- or larger than any call needs. The bytes in
// it are never read again: every user of a borrowed buffer appends from
// length zero.
func giveBack(b []byte) {
	if cap(b) <= smallBuffer || cap(b) > 2*maxRecordDefault {
		return
	}
	b = b[:0]
	buffers.Put(&b)
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
	return s.handleUpTo(req, res, remote, state, peer, nil)
}

// handleUpTo is handle, except that when later is not nil and the call reaches
// a procedure, it returns (nil, false, nil) with the procedure's work left in
// later instead of running it.
func (s *Server) handleUpTo(req, res []byte, remote net.Addr, state *tls.ConnectionState, peer string, later *deferred) ([]byte, bool, error) {
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
	if later != nil {
		// Everything above ran in the connection's reader, in arrival order:
		// decoding, authentication (an Authenticator keeps per-context state
		// that has to see calls in order) and lookup. What is left is the
		// procedure itself, which the caller may run beside others.
		if r := prog.Ranges[h.proc]; r != nil {
			later.span, later.ranged = r(*d)
		}
		later.run = func() []byte {
			out, _, _ := s.execute(proc, h, principal, d, e, remote, state, verf, wrap, base, results)
			return out
		}
		return nil, false, nil
	}
	return s.execute(proc, h, principal, d, e, remote, state, verf, wrap, base, results)
}

// deferred is what handle leaves for the caller when asked to stop short of
// running the procedure: the work, and what part of which file it touches.
type deferred struct {
	run    func() []byte
	span   inflight.Span
	ranged bool // span says what the call touches; false for a call that may touch anything
}

// execute runs the procedure and finishes the reply.
func (s *Server) execute(proc Proc, h callHeader, principal string, d *xdr.Decoder, e *xdr.Encoder,
	remote net.Addr, state *tls.ConnectionState, verf Auth, wrap func([]byte) []byte, base, results int) ([]byte, bool, error) {
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
