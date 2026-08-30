package rpc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/go-filesystems/nfs/xdr"
)

const testProg, testVers = 400000, 1

// newTestServer starts a server with one program on a loopback port.
func newTestServer(t *testing.T, procs map[uint32]Proc) (*Server, string) {
	t.Helper()
	s := &Server{}
	s.Register(&Program{Prog: testProg, Vers: testVers, Procs: procs})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	t.Cleanup(func() {
		s.Close()
		if err := <-done; !errors.Is(err, ErrServerClosed) {
			t.Errorf("Serve returned %v, want ErrServerClosed", err)
		}
	})
	return s, ln.Addr().String()
}

// callMsg builds an RPC call message.
func callMsg(xid, rpcvers, prog, vers, proc, credFlavor uint32, credBody, args []byte) []byte {
	e := xdr.NewEncoder(nil)
	e.Uint32(xid)
	e.Uint32(0) // CALL
	e.Uint32(rpcvers)
	e.Uint32(prog)
	e.Uint32(vers)
	e.Uint32(proc)
	e.Uint32(credFlavor)
	e.Opaque(credBody)
	e.Uint32(AuthNull)
	e.Opaque(nil)
	e.Fixed(args)
	return e.Bytes()
}

// exchange sends one record and reads one back.
func exchange(t *testing.T, addr string, msg []byte) []byte {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], lastFragment|uint32(len(msg)))
	if _, err := c.Write(append(hdr[:], msg...)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		t.Fatalf("read header: %v", err)
	}
	body := make([]byte, binary.BigEndian.Uint32(hdr[:])&^lastFragment)
	if _, err := io.ReadFull(c, body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	return body
}

// replyOf decodes the fixed part of an accepted or denied reply.
func replyOf(t *testing.T, body []byte) (replyStat, code uint32, rest *xdr.Decoder) {
	t.Helper()
	d := xdr.NewDecoder(body)
	mustU32(t, d) // xid
	if mt := mustU32(t, d); mt != msgReply {
		t.Fatalf("mtype = %d, want %d", mt, msgReply)
	}
	replyStat = mustU32(t, d)
	if replyStat == msgDenied {
		return replyStat, mustU32(t, d), d
	}
	mustU32(t, d) // verifier flavour
	if _, err := d.Opaque(); err != nil {
		t.Fatalf("verifier body: %v", err)
	}
	return replyStat, mustU32(t, d), d
}

func mustU32(t *testing.T, d *xdr.Decoder) uint32 {
	t.Helper()
	v, err := d.Uint32()
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return v
}

func TestDispatchSuccess(t *testing.T) {
	_, addr := newTestServer(t, map[uint32]Proc{
		1: func(c *Call) Status {
			n, err := c.Args.Uint32()
			if err != nil {
				return StatusGarbageArgs
			}
			if c.Remote == nil {
				t.Error("Call.Remote was nil")
			}
			c.Res.Uint32(n * 2)
			return StatusSuccess
		},
	})
	body := exchange(t, addr, callMsg(7, 2, testProg, testVers, 1, AuthNull, nil, []byte{0, 0, 0, 21}))
	st, code, rest := replyOf(t, body)
	if st != msgAccepted || code != stSuccess {
		t.Fatalf("reply = (%d, %d), want accepted/success", st, code)
	}
	if v := mustU32(t, rest); v != 42 {
		t.Fatalf("result = %d, want 42", v)
	}
}

func TestDispatchErrors(t *testing.T) {
	_, addr := newTestServer(t, map[uint32]Proc{
		1: func(c *Call) Status { return StatusSuccess },
		2: func(c *Call) Status {
			// Write something, then fail: the reply must be rewound, not
			// left with a half-built body the client would misparse.
			c.Res.Uint32(0xdeadbeef)
			return StatusGarbageArgs
		},
		3: func(c *Call) Status { return StatusSystemErr },
	})

	t.Run("unknown procedure", func(t *testing.T) {
		_, code, _ := replyOf(t, exchange(t, addr, callMsg(1, 2, testProg, testVers, 99, AuthNull, nil, nil)))
		if code != stProcUnavail {
			t.Fatalf("accept_stat = %d, want PROC_UNAVAIL", code)
		}
	})
	t.Run("unknown program", func(t *testing.T) {
		_, code, _ := replyOf(t, exchange(t, addr, callMsg(1, 2, 999999, 1, 1, AuthNull, nil, nil)))
		if code != stProgUnavail {
			t.Fatalf("accept_stat = %d, want PROG_UNAVAIL", code)
		}
	})
	t.Run("wrong version", func(t *testing.T) {
		_, code, rest := replyOf(t, exchange(t, addr, callMsg(1, 2, testProg, 99, 1, AuthNull, nil, nil)))
		if code != stProgMismatch {
			t.Fatalf("accept_stat = %d, want PROG_MISMATCH", code)
		}
		lo, hi := mustU32(t, rest), mustU32(t, rest)
		if lo != testVers || hi != testVers {
			t.Fatalf("version range = %d..%d, want %d..%d", lo, hi, testVers, testVers)
		}
	})
	t.Run("garbage args rewinds the reply", func(t *testing.T) {
		body := exchange(t, addr, callMsg(1, 2, testProg, testVers, 2, AuthNull, nil, nil))
		_, code, rest := replyOf(t, body)
		if code != stGarbageArgs {
			t.Fatalf("accept_stat = %d, want GARBAGE_ARGS", code)
		}
		if rest.Remaining() != 0 {
			t.Fatalf("%d bytes trailed a GARBAGE_ARGS reply; the rewind leaked results", rest.Remaining())
		}
	})
	t.Run("system error", func(t *testing.T) {
		_, code, _ := replyOf(t, exchange(t, addr, callMsg(1, 2, testProg, testVers, 3, AuthNull, nil, nil)))
		if code != stSystemErr {
			t.Fatalf("accept_stat = %d, want SYSTEM_ERR", code)
		}
	})
	t.Run("wrong RPC version", func(t *testing.T) {
		st, code, rest := replyOf(t, exchange(t, addr, callMsg(1, 3, testProg, testVers, 1, AuthNull, nil, nil)))
		if st != msgDenied || code != rjRPCMismatch {
			t.Fatalf("reply = (%d, %d), want denied/RPC_MISMATCH", st, code)
		}
		lo, hi := mustU32(t, rest), mustU32(t, rest)
		if lo != 2 || hi != 2 {
			t.Fatalf("RPC version range = %d..%d, want 2..2", lo, hi)
		}
	})
	t.Run("unsupported auth flavour", func(t *testing.T) {
		st, code, rest := replyOf(t, exchange(t, addr, callMsg(1, 2, testProg, testVers, 1, 6 /* RPCSEC_GSS */, nil, nil)))
		if st != msgDenied || code != rjAuthError {
			t.Fatalf("reply = (%d, %d), want denied/AUTH_ERROR", st, code)
		}
		if as := mustU32(t, rest); as != 5 {
			t.Fatalf("auth_stat = %d, want 5 (AUTH_TOOWEAK)", as)
		}
	})
}

// TestNotACallDropsTheConnection: a stray REPLY is something the server did
// not send and cannot answer, so the connection goes rather than the server
// inventing a response.
func TestNotACallDropsTheConnection(t *testing.T) {
	_, addr := newTestServer(t, map[uint32]Proc{1: func(*Call) Status { return StatusSuccess }})
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	e := xdr.NewEncoder(nil)
	e.Uint32(1)
	e.Uint32(msgReply)
	msg := e.Bytes()
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], lastFragment|uint32(len(msg)))
	c.Write(append(hdr[:], msg...))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, hdr[:]); err == nil {
		t.Fatal("the server answered a message that was not a call")
	}
}

func TestTruncatedHeaderDropsTheConnection(t *testing.T) {
	_, addr := newTestServer(t, map[uint32]Proc{1: func(*Call) Status { return StatusSuccess }})
	// Every 4-byte boundary of a well-formed call is a distinct field that
	// can run out: xid, mtype, rpcvers, prog, vers, proc, then both
	// opaque_auths. Truncating at each one covers them all rather than
	// guessing which are interesting.
	full := callMsg(1, 2, testProg, testVers, 1, AuthUnix, []byte{0, 0, 0, 0}, nil)
	var msgs [][]byte
	for n := 0; n < len(full); n += 4 {
		msgs = append(msgs, full[:n])
	}
	msgs = append(msgs, full[:7*4+2]) // mid-field, inside the credential body
	for _, msg := range msgs {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], lastFragment|uint32(len(msg)))
		c.Write(append(hdr[:], msg...))
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.ReadFull(c, hdr[:]); err == nil {
			t.Errorf("the server answered a %d-byte truncated call", len(msg))
		}
		c.Close()
	}
}

// TestFragmentedRecord: a client may split one record across fragments, and
// the reassembly is what makes a 128 KiB WRITE arrive intact.
func TestFragmentedRecord(t *testing.T) {
	_, addr := newTestServer(t, map[uint32]Proc{
		1: func(c *Call) Status {
			b, err := c.Args.Opaque()
			if err != nil {
				return StatusGarbageArgs
			}
			c.Res.Uint32(uint32(len(b)))
			return StatusSuccess
		},
	})
	payload := bytes.Repeat([]byte("x"), 400)
	e := xdr.NewEncoder(nil)
	e.Opaque(payload)
	msg := callMsg(1, 2, testProg, testVers, 1, AuthNull, nil, e.Bytes())

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	// Three fragments; only the last carries the terminator bit.
	cuts := []int{40, 120, len(msg)}
	prev := 0
	for i, cut := range cuts {
		var hdr [4]byte
		h := uint32(cut - prev)
		if i == len(cuts)-1 {
			h |= lastFragment
		}
		binary.BigEndian.PutUint32(hdr[:], h)
		if _, err := c.Write(append(hdr[:], msg[prev:cut]...)); err != nil {
			t.Fatalf("write fragment: %v", err)
		}
		prev = cut
	}
	var hdr [4]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		t.Fatalf("read header: %v", err)
	}
	body := make([]byte, binary.BigEndian.Uint32(hdr[:])&^lastFragment)
	io.ReadFull(c, body)
	_, code, rest := replyOf(t, body)
	if code != stSuccess {
		t.Fatalf("accept_stat = %d", code)
	}
	if n := mustU32(t, rest); n != uint32(len(payload)) {
		t.Fatalf("reassembled %d bytes, want %d", n, len(payload))
	}
}

// TestRecordTooLarge: an unbounded stream of small fragments must not let a
// client grow the server's buffer without limit.
func TestRecordTooLarge(t *testing.T) {
	s := &Server{MaxRecord: 64}
	s.Register(&Program{Prog: testProg, Vers: testVers, Procs: map[uint32]Proc{}})
	var buf bytes.Buffer
	for range 10 {
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], 16)
		buf.Write(hdr[:])
		buf.Write(make([]byte, 16))
	}
	if _, err := s.readRecord(&buf, nil); !errors.Is(err, errRecordTooLarge) {
		t.Fatalf("readRecord = %v, want errRecordTooLarge", err)
	}
}

func TestServeAfterClose(t *testing.T) {
	s := &Server{}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := s.Serve(nil); !errors.Is(err, ErrServerClosed) {
		t.Fatalf("Serve after Close = %v, want ErrServerClosed", err)
	}
}

// TestServeReturnsAcceptError covers a listener that fails for a reason other
// than the server closing.
func TestServeReturnsAcceptError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ln.Close()
	s := &Server{}
	if err := s.Serve(ln); err == nil || errors.Is(err, ErrServerClosed) {
		t.Fatalf("Serve on a dead listener = %v, want the accept error", err)
	}
}

// TestCloseRacesAccept covers the window where a connection is accepted after
// Close has been called: it must be dropped, not served.
func TestCloseRacesAccept(t *testing.T) {
	s := &Server{}
	s.Register(&Program{Prog: testProg, Vers: testVers, Procs: map[uint32]Proc{}})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	// A listener whose Accept hands back one connection, then blocks until
	// Close, is the deterministic way to sit in that window.
	fake := &gatedListener{Listener: ln, gate: make(chan struct{}), accepted: make(chan struct{}, 1)}
	done := make(chan error, 1)
	go func() { done <- s.Serve(fake) }()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	<-fake.accepted
	s.Close()
	close(fake.gate)
	if err := <-done; !errors.Is(err, ErrServerClosed) {
		t.Fatalf("Serve = %v, want ErrServerClosed", err)
	}
}

type gatedListener struct {
	net.Listener
	gate     chan struct{}
	accepted chan struct{}
	n        int
}

func (g *gatedListener) Accept() (net.Conn, error) {
	c, err := g.Listener.Accept()
	if err != nil {
		return nil, err
	}
	g.n++
	if g.n == 1 {
		g.accepted <- struct{}{}
		<-g.gate
	}
	return c, nil
}

func TestParseUnix(t *testing.T) {
	e := xdr.NewEncoder(nil)
	e.Uint32(99)
	e.String("host")
	e.Uint32(501)
	e.Uint32(20)
	e.Uint32(2)
	e.Uint32(12)
	e.Uint32(80)
	c, err := ParseUnix(Auth{Flavor: AuthUnix, Body: e.Bytes()})
	if err != nil {
		t.Fatalf("ParseUnix: %v", err)
	}
	if c.Stamp != 99 || c.Machine != "host" || c.UID != 501 || c.GID != 20 {
		t.Fatalf("ParseUnix = %+v", c)
	}
	if len(c.GIDs) != 2 || c.GIDs[0] != 12 || c.GIDs[1] != 80 {
		t.Fatalf("aux GIDs = %v", c.GIDs)
	}
}

func TestParseUnixRejects(t *testing.T) {
	full := func() []byte {
		e := xdr.NewEncoder(nil)
		e.Uint32(99)
		e.String("host")
		e.Uint32(501)
		e.Uint32(20)
		e.Uint32(1)
		e.Uint32(12)
		return e.Bytes()
	}()
	if _, err := ParseUnix(Auth{Flavor: AuthNull}); !errors.Is(err, ErrBadCred) {
		t.Fatalf("ParseUnix on AUTH_NULL = %v, want ErrBadCred", err)
	}
	// Every truncation point must be refused, not half-decoded.
	for n := 0; n < len(full); n += 4 {
		if _, err := ParseUnix(Auth{Flavor: AuthUnix, Body: full[:n]}); !errors.Is(err, ErrBadCred) {
			t.Errorf("ParseUnix on %d bytes = %v, want ErrBadCred", n, err)
		}
	}
	// An auxiliary group list longer than RFC 5531 allows.
	e := xdr.NewEncoder(nil)
	e.Uint32(0)
	e.String("h")
	e.Uint32(0)
	e.Uint32(0)
	e.Uint32(17)
	if _, err := ParseUnix(Auth{Flavor: AuthUnix, Body: e.Bytes()}); !errors.Is(err, ErrBadCred) {
		t.Fatalf("ParseUnix with 17 aux GIDs = %v, want ErrBadCred", err)
	}
	// A group count that is honest but whose entries are missing.
	e2 := xdr.NewEncoder(nil)
	e2.Uint32(0)
	e2.String("h")
	e2.Uint32(0)
	e2.Uint32(0)
	e2.Uint32(3)
	e2.Uint32(1)
	if _, err := ParseUnix(Auth{Flavor: AuthUnix, Body: e2.Bytes()}); !errors.Is(err, ErrBadCred) {
		t.Fatalf("ParseUnix with a truncated GID list = %v, want ErrBadCred", err)
	}
}

func TestRegisterReplaces(t *testing.T) {
	s := &Server{}
	s.Register(&Program{Prog: testProg, Vers: testVers, Procs: map[uint32]Proc{1: nil}})
	s.Register(&Program{Prog: testProg, Vers: testVers, Procs: map[uint32]Proc{2: nil}})
	p, exists, lo, hi := s.lookup(testProg, testVers)
	if p == nil || !exists || lo != testVers || hi != testVers {
		t.Fatalf("lookup = (%v, %v, %d, %d)", p, exists, lo, hi)
	}
	if _, ok := p.Procs[2]; !ok {
		t.Fatal("Register did not replace the earlier program")
	}
}

// TestWriteRecordError covers the reply path failing mid-write.
func TestWriteRecordError(t *testing.T) {
	if _, err := writeRecord(failWriter{}, []byte("x"), nil); err == nil {
		t.Fatal("writeRecord on a failing writer returned nil")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

// TestReadRecordTruncatedBody: a fragment header that promises more bytes
// than the peer sends must fail, not block forever on a short buffer.
func TestReadRecordTruncatedBody(t *testing.T) {
	var buf bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], lastFragment|64)
	buf.Write(hdr[:])
	buf.Write(make([]byte, 8))
	s := &Server{}
	if _, err := s.readRecord(&buf, nil); err == nil {
		t.Fatal("readRecord accepted a fragment shorter than its header claimed")
	}
}

// TestServeConnReplyWriteFailure: when the reply cannot be written the
// connection is dropped rather than the server spinning on a dead socket.
func TestServeConnReplyWriteFailure(t *testing.T) {
	s := &Server{}
	s.Register(&Program{Prog: testProg, Vers: testVers, Procs: map[uint32]Proc{
		1: func(*Call) Status { return StatusSuccess },
	}})
	msg := callMsg(1, 2, testProg, testVers, 1, AuthNull, nil, nil)
	var in bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], lastFragment|uint32(len(msg)))
	in.Write(hdr[:])
	in.Write(msg)
	// serveConn returning at all is the assertion: a writer that always
	// fails would otherwise loop.
	s.serveConn(&halfConn{r: &in})
}

// halfConn reads from r and fails every write.
type halfConn struct {
	net.Conn
	r io.Reader
}

func (h *halfConn) Read(p []byte) (int, error)  { return h.r.Read(p) }
func (h *halfConn) Write(p []byte) (int, error) { return 0, errors.New("write failed") }
func (h *halfConn) Close() error                { return nil }
func (h *halfConn) RemoteAddr() net.Addr        { return nil }
