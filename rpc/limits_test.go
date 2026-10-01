package rpc

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// limitServer starts a server with the given knobs and one procedure (1) that
// answers success, plus a procedure (2) that panics.
func limitServer(t *testing.T, configure func(*Server)) (*Server, string) {
	t.Helper()
	s := &Server{}
	if configure != nil {
		configure(s)
	}
	s.Register(&Program{Prog: testProg, Vers: testVers, Procs: map[uint32]Proc{
		1: func(c *Call) Status { c.Res.Uint32(42); return StatusSuccess },
		2: func(c *Call) Status {
			c.Res.Uint32(0xdead) // must be rewound, not sent
			var m map[string]int
			m["boom"]++ // a nil-map write: the kind of bug a driver ships
			return StatusSuccess
		},
	}})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	t.Cleanup(func() {
		s.Close()
		<-done
	})
	return s, ln.Addr().String()
}

// callOn sends one call on c and returns the reply record.
func callOn(t *testing.T, c net.Conn, xid, proc uint32) []byte {
	t.Helper()
	msg := callMsg(xid, 2, testProg, testVers, proc, AuthNull, nil, nil)
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

// waitClosed reports whether the server closes c within limit.
func waitClosed(t *testing.T, c net.Conn, limit time.Duration) bool {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(limit))
	var b [1]byte
	_, err := c.Read(b[:])
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	return err != nil
}

// TestAProcedurePanicIsAnsweredSystemErr: a panic in one procedure used to
// unwind the connection goroutine unrecovered and kill the whole process —
// the NFS WRITE crash of the v0.4.0 review reached exactly this. It must now
// cost that one call a SYSTEM_ERR, be logged, and leave the connection (and
// the server) serving.
func TestAProcedurePanicIsAnsweredSystemErr(t *testing.T) {
	var logged syncBuffer
	_, addr := limitServer(t, func(s *Server) { s.ErrorLog = log.New(&logged, "", 0) })
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))

	rs, code, rest := replyOf(t, callOn(t, c, 1, 2))
	if rs != msgAccepted || code != uint32(StatusSystemErr) {
		t.Fatalf("panicking procedure: reply_stat %d accept_stat %d, want SYSTEM_ERR", rs, code)
	}
	if rest.Remaining() != 0 {
		t.Fatalf("SYSTEM_ERR reply carries %d bytes of results the procedure wrote before panicking", rest.Remaining())
	}
	if !strings.Contains(logged.String(), "panic") || !strings.Contains(logged.String(), "assignment to entry in nil map") {
		t.Fatalf("the panic was not logged: %q", logged.String())
	}
	// Same connection, next call: still served.
	rs, code, rest = replyOf(t, callOn(t, c, 2, 1))
	if rs != msgAccepted || code != uint32(StatusSuccess) || mustU32(t, rest) != 42 {
		t.Fatalf("call after a panic: reply_stat %d accept_stat %d", rs, code)
	}
}

// TestAPanicOutsideAProcedureCostsOnlyTheConnection: an Authenticator is
// outside invoke's recover; its panic must drop the connection, not the
// process.
func TestAPanicOutsideAProcedureCostsOnlyTheConnection(t *testing.T) {
	var logged syncBuffer
	_, addr := limitServer(t, func(s *Server) {
		s.ErrorLog = log.New(&logged, "", 0)
		s.Auth = panicAuth{}
	})
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	msg := callMsg(1, 2, testProg, testVers, 1, 6, []byte{0, 0, 0, 0}, nil)
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], lastFragment|uint32(len(msg)))
	if _, err := c.Write(append(hdr[:], msg...)); err != nil {
		t.Fatal(err)
	}
	if !waitClosed(t, c, 5*time.Second) {
		t.Fatal("the connection outlived a panic in its authenticator")
	}
	if !strings.Contains(logged.String(), "panic serving") {
		t.Fatalf("the panic was not logged: %q", logged.String())
	}
	// The server is still up.
	body := exchange(t, addr, callMsg(9, 2, testProg, testVers, 1, AuthNull, nil, nil))
	if _, code, _ := replyOf(t, body); code != uint32(StatusSuccess) {
		t.Fatalf("server after a panic: accept_stat %d", code)
	}
}

// syncBuffer is a bytes.Buffer the server's goroutines may write while the
// test reads it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type panicAuth struct{}

func (panicAuth) Flavor() uint32                      { return 6 }
func (panicAuth) Authenticate(*AuthCall) AuthDecision { panic("authenticator bug") }

// TestAClaimedFragmentIsNotAllocatedBeforeItArrives is the v0.4.0 review's
// pre-authentication memory exhaustion: every connection that sent only a
// 4-byte header claiming ~1 MiB made the server allocate the whole fragment
// before a byte of it arrived. 200 such connections grew the live heap by
// 201 MiB. The buffer must now grow with what arrives.
func TestAClaimedFragmentIsNotAllocatedBeforeItArrives(t *testing.T) {
	_, addr := limitServer(t, nil)
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	const conns = 200
	var cs []net.Conn
	for range conns {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		cs = append(cs, c)
		var h [4]byte
		binary.BigEndian.PutUint32(h[:], (1<<20)-8) // not the last fragment
		if _, err := c.Write(h[:]); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		for _, c := range cs {
			c.Close()
		}
	}()
	time.Sleep(500 * time.Millisecond)
	runtime.GC()
	runtime.ReadMemStats(&m1)
	grew := (int64(m1.HeapAlloc) - int64(m0.HeapAlloc)) >> 20
	t.Logf("%d connections, 4 bytes sent each: live heap grew by %d MiB", conns, grew)
	// Each connection may hold readChunk (4 KiB) plus its goroutine's
	// bookkeeping; 200 of them is ~1 MiB. v0.4.0 grew by ~200 MiB.
	if grew > 32 {
		t.Fatalf("live heap grew by %d MiB for %d header-only connections", grew, conns)
	}
}

// TestReadRecordGrowsWithWhatArrives is the deterministic half of the test
// above: a header claiming 1 MiB followed by ten bytes must not leave a
// megabyte-capacity buffer behind.
func TestReadRecordGrowsWithWhatArrives(t *testing.T) {
	var in bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], lastFragment|(1<<20-8))
	in.Write(hdr[:])
	in.Write(make([]byte, 10))
	s := &Server{}
	dst, err := s.readRecord(&in, nil)
	if err == nil {
		t.Fatal("a truncated fragment was accepted")
	}
	if cap(dst) > 64<<10 {
		t.Fatalf("buffer capacity %d after 10 bytes of a 1 MiB claim", cap(dst))
	}

	// And a genuine large record still arrives whole, in pieces.
	want := bytes.Repeat([]byte("0123456789abcdef"), 40000) // 640000 bytes
	in.Reset()
	binary.BigEndian.PutUint32(hdr[:], 100000)
	in.Write(hdr[:])
	in.Write(want[:100000])
	binary.BigEndian.PutUint32(hdr[:], lastFragment|uint32(len(want)-100000))
	in.Write(hdr[:])
	in.Write(want[100000:])
	got, err := s.readRecord(&in, nil)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("large record: err %v, %d bytes, equal %v", err, len(got), bytes.Equal(got, want))
	}
}

// TestAnIdleConnectionIsClosed: v0.4.0 set no deadline at all, so a
// connection that said nothing held its goroutine for ever.
func TestAnIdleConnectionIsClosed(t *testing.T) {
	_, addr := limitServer(t, func(s *Server) { s.IdleTimeout = 200 * time.Millisecond })
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Active use first: the deadline is per record, not per connection.
	for i := range 3 {
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		callOn(t, c, uint32(i), 1)
		time.Sleep(100 * time.Millisecond)
	}
	if !waitClosed(t, c, 5*time.Second) {
		t.Fatal("an idle connection was still open after 25x its IdleTimeout")
	}
}

// TestAHalfSentRecordIsClosed: a record trickled — header, then silence —
// is bounded by the same deadline.
func TestAHalfSentRecordIsClosed(t *testing.T) {
	_, addr := limitServer(t, func(s *Server) { s.IdleTimeout = 200 * time.Millisecond })
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], lastFragment|100)
	if _, err := c.Write(append(h[:], 1, 2, 3)); err != nil {
		t.Fatal(err)
	}
	if !waitClosed(t, c, 5*time.Second) {
		t.Fatal("a half-sent record held its connection past IdleTimeout")
	}
}

// TestAStalledHandshakeIsDropped: after STARTTLS, a client that never sends
// its ClientHello must not hold the connection for ever.
func TestAStalledHandshakeIsDropped(t *testing.T) {
	cert, _ := selfSigned(t)
	_, addr := limitServer(t, func(s *Server) {
		s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
		s.IdleTimeout = -1 // isolate the handshake bound
		s.HandshakeTimeout = 200 * time.Millisecond
	})
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, _, ok := tlsProbe(t, c, Auth{Flavor: AuthTLS}); !ok {
		t.Fatal("the probe was denied")
	}
	if !waitClosed(t, c, 5*time.Second) {
		t.Fatal("a stalled handshake held its connection past HandshakeTimeout")
	}
}

// TestAHandshakeWithinTheBoundIsNotCutOff: the handshake deadline is lifted
// once it succeeds, so a TLS connection outlives it.
func TestAHandshakeWithinTheBoundIsNotCutOff(t *testing.T) {
	cert, pool := selfSigned(t)
	_, addr := limitServer(t, func(s *Server) {
		s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
		s.IdleTimeout = -1
		s.HandshakeTimeout = 300 * time.Millisecond
	})
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, _, ok := tlsProbe(t, c, Auth{Flavor: AuthTLS}); !ok {
		t.Fatal("the probe was denied")
	}
	tc := tls.Client(c, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(600 * time.Millisecond)
	_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
	if got := callOver(t, tc, testProg, testVers, 1); len(got) != 4 || got[3] != 42 {
		t.Fatalf("call after the handshake bound: %x", got)
	}
}

// TestConnectionsPastTheCapAreClosed: v0.4.0 accepted without limit.
func TestConnectionsPastTheCapAreClosed(t *testing.T) {
	_, addr := limitServer(t, func(s *Server) { s.MaxConns = 2 })
	var held []net.Conn
	for i := range 2 {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		callOn(t, c, uint32(i), 1) // registered and served
		held = append(held, c)
	}
	extra, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	if !waitClosed(t, extra, 5*time.Second) {
		t.Fatal("a connection past MaxConns was kept")
	}
	// The ones under the cap are untouched…
	_ = held[0].SetDeadline(time.Now().Add(5 * time.Second))
	callOn(t, held[0], 7, 1)
	// …and a slot freed is a slot reusable.
	held[1].Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(time.Second))
		msg := callMsg(8, 2, testProg, testVers, 1, AuthNull, nil, nil)
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], lastFragment|uint32(len(msg)))
		c.Write(append(hdr[:], msg...))
		_, err = io.ReadFull(c, hdr[:])
		c.Close()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a freed connection slot was never reusable")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestLimitDefaults(t *testing.T) {
	if got := timeoutOr(0, time.Minute); got != time.Minute {
		t.Errorf("zero timeout = %v, want the default", got)
	}
	if got := timeoutOr(-1, time.Minute); got != 0 {
		t.Errorf("negative timeout = %v, want none", got)
	}
	if got := timeoutOr(time.Second, time.Minute); got != time.Second {
		t.Errorf("explicit timeout = %v", got)
	}
	for _, tc := range []struct{ in, want int }{{0, DefaultMaxConns}, {-1, 0}, {3, 3}} {
		if got := (&Server{MaxConns: tc.in}).maxConns(); got != tc.want {
			t.Errorf("MaxConns %d resolves to %d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestANilErrorLogUsesTheStandardLogger: a panic is never reported nowhere.
func TestANilErrorLogUsesTheStandardLogger(t *testing.T) {
	var logged syncBuffer
	prev := log.Writer()
	log.SetOutput(&logged)
	defer log.SetOutput(prev)
	(&Server{}).logf("rpc: %s", "reported")
	if !strings.Contains(logged.String(), "rpc: reported") {
		t.Fatalf("standard logger got %q", logged.String())
	}
}
