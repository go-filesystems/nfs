package rpc

import (
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-filesystems/inflight"
	"github.com/go-filesystems/nfs/xdr"
)

// Concurrent dispatch: calls of one connection run beside each other, replies
// leave as they are ready and are matched by xid (RFC 5531), what is not
// declared to be a READ-like call runs alone, and the bounds hold.

// rangedServer starts a server whose procedures 1, 2 and 4 declare a range
// (read, read, write, of one key and one range each, as args say) and whose
// procedure 3 declares nothing.
func rangedServer(t *testing.T, s *Server, procs map[uint32]Proc, ranges map[uint32]func(xdr.Decoder) (inflight.Span, bool)) string {
	t.Helper()
	s.ErrorLog = log.New(io.Discard, "", 0)
	s.Register(&Program{Prog: testProg, Vers: testVers, Procs: procs, Ranges: ranges})
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
	return ln.Addr().String()
}

type rpcClient struct {
	t *testing.T
	c net.Conn
}

func dialRPC(t *testing.T, addr string) *rpcClient {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return &rpcClient{t: t, c: c}
}

func (c *rpcClient) send(xid, proc uint32, args []byte) {
	c.t.Helper()
	msg := callMsg(xid, 2, testProg, testVers, proc, AuthNull, nil, args)
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], lastFragment|uint32(len(msg)))
	if _, err := c.c.Write(append(hdr[:], msg...)); err != nil {
		c.t.Fatal(err)
	}
}

// recv reads one reply and returns its xid.
func (c *rpcClient) recv() uint32 {
	c.t.Helper()
	c.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var hdr [4]byte
	if _, err := io.ReadFull(c.c, hdr[:]); err != nil {
		c.t.Fatalf("read reply: %v", err)
	}
	body := make([]byte, binary.BigEndian.Uint32(hdr[:])&^lastFragment)
	if _, err := io.ReadFull(c.c, body); err != nil {
		c.t.Fatal(err)
	}
	return binary.BigEndian.Uint32(body)
}

// span decodes args as (key byte, off, len) and reports a read or a write.
func spanOf(write bool) func(xdr.Decoder) (inflight.Span, bool) {
	return func(a xdr.Decoder) (inflight.Span, bool) {
		k, err := a.Uint32()
		if err != nil {
			return inflight.Span{}, false
		}
		off, _ := a.Uint64()
		n, _ := a.Uint32()
		key := string(rune('a' + k))
		if write {
			return inflight.WriteRange(key, off, uint64(n)), true
		}
		return inflight.ReadRange(key, off, uint64(n)), true
	}
}

func spanArgs(key uint32, off uint64, n uint32) []byte {
	e := xdr.NewEncoder(nil)
	e.Uint32(key)
	e.Uint64(off)
	e.Uint32(n)
	return e.Bytes()
}

// gate is a procedure that reports it started and waits to be released.
type gate struct {
	started chan uint32
	release chan struct{}
}

func newGate() *gate { return &gate{started: make(chan uint32, 64), release: make(chan struct{})} }

func (g *gate) proc(c *Call) Status {
	g.started <- c.XID
	<-g.release
	return StatusSuccess
}

func waitStart(t *testing.T, g *gate) uint32 {
	t.Helper()
	select {
	case x := <-g.started:
		return x
	case <-time.After(5 * time.Second):
		t.Fatal("no procedure started")
	}
	return 0
}

func noStart(t *testing.T, g *gate, what string) {
	t.Helper()
	select {
	case x := <-g.started:
		t.Fatalf("%s: call %d started too early", what, x)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestRepliesLeaveAsReadyAndAreMatchedByXID(t *testing.T) {
	g := newGate()
	quick := func(*Call) Status { return StatusSuccess }
	addr := rangedServer(t, &Server{}, map[uint32]Proc{1: g.proc, 2: quick},
		map[uint32]func(xdr.Decoder) (inflight.Span, bool){1: spanOf(false), 2: spanOf(false)})
	c := dialRPC(t, addr)
	c.send(11, 1, spanArgs(0, 0, 8))
	if waitStart(t, g) != 11 {
		t.Fatal("wrong call started")
	}
	c.send(22, 2, spanArgs(0, 0, 8)) // behind a call still in the procedure
	if x := c.recv(); x != 22 {
		t.Fatalf("first reply is xid %d, want 22: the slow call must not hold it back", x)
	}
	close(g.release)
	if x := c.recv(); x != 11 {
		t.Fatalf("second reply is xid %d, want 11", x)
	}
}

func TestACallWithNoRangeRunsAloneAfterEverythingBeforeIt(t *testing.T) {
	g := newGate()
	var barrier atomic.Bool
	addr := rangedServer(t, &Server{}, map[uint32]Proc{
		1: g.proc,
		3: func(*Call) Status { barrier.Store(true); return StatusSuccess },
	}, map[uint32]func(xdr.Decoder) (inflight.Span, bool){1: spanOf(false)})
	c := dialRPC(t, addr)
	c.send(1, 1, spanArgs(0, 0, 8))
	waitStart(t, g)
	c.send(2, 3, nil)
	time.Sleep(100 * time.Millisecond)
	if barrier.Load() {
		t.Fatal("a call with no range ran beside a call in flight")
	}
	close(g.release)
	c.recv()
	c.recv()
	if !barrier.Load() {
		t.Fatal("the barrier never ran")
	}
}

func TestACallWhoseRangeDoesNotDecodeRunsAlone(t *testing.T) {
	g := newGate()
	var ran atomic.Bool
	addr := rangedServer(t, &Server{}, map[uint32]Proc{
		1: g.proc,
		2: func(*Call) Status { ran.Store(true); return StatusGarbageArgs },
	}, map[uint32]func(xdr.Decoder) (inflight.Span, bool){1: spanOf(false), 2: spanOf(false)})
	c := dialRPC(t, addr)
	c.send(1, 1, spanArgs(0, 0, 8))
	waitStart(t, g)
	c.send(2, 2, nil) // no arguments: the range cannot be read
	time.Sleep(100 * time.Millisecond)
	if ran.Load() {
		t.Fatal("a call whose range did not decode ran beside a call in flight")
	}
	close(g.release)
	c.recv()
	c.recv()
}

func TestOverlappingRangesWithAWriteKeepArrivalOrder(t *testing.T) {
	g := newGate()
	addr := rangedServer(t, &Server{}, map[uint32]Proc{1: g.proc, 4: g.proc},
		map[uint32]func(xdr.Decoder) (inflight.Span, bool){1: spanOf(false), 4: spanOf(true)})
	c := dialRPC(t, addr)
	c.send(1, 1, spanArgs(0, 0, 100)) // a read
	waitStart(t, g)
	c.send(2, 4, spanArgs(0, 50, 100)) // a write over part of it
	noStart(t, g, "an overlapping write")
	close(g.release)
	c.recv()
	c.recv()
}

func TestDisjointWritesRunTogether(t *testing.T) {
	g := newGate()
	addr := rangedServer(t, &Server{}, map[uint32]Proc{4: g.proc},
		map[uint32]func(xdr.Decoder) (inflight.Span, bool){4: spanOf(true)})
	c := dialRPC(t, addr)
	c.send(1, 4, spanArgs(0, 0, 100))
	c.send(2, 4, spanArgs(0, 100, 100))
	c.send(3, 4, spanArgs(1, 0, 100)) // another file
	for i := 0; i < 3; i++ {
		waitStart(t, g)
	}
	close(g.release)
	for i := 0; i < 3; i++ {
		c.recv()
	}
}

func TestPerConnectionBoundHoldsBeforeTheRecordIsRead(t *testing.T) {
	g := newGate()
	s := &Server{MaxInFlight: 2}
	addr := rangedServer(t, s, map[uint32]Proc{1: g.proc},
		map[uint32]func(xdr.Decoder) (inflight.Span, bool){1: spanOf(false)})
	c := dialRPC(t, addr)
	for x := uint32(1); x <= 3; x++ {
		c.send(x, 1, spanArgs(0, 0, 8))
	}
	waitStart(t, g)
	waitStart(t, g)
	noStart(t, g, "a third call with 2 in flight")
	g.release <- struct{}{} // let one finish
	if x := waitStart(t, g); x != 3 {
		t.Fatalf("started %d, want 3", x)
	}
	close(g.release)
	for i := 0; i < 3; i++ {
		c.recv()
	}
}

func TestServerWideBoundHoldsAcrossConnections(t *testing.T) {
	g := newGate()
	s := &Server{MaxInFlight: 8, MaxInFlightTotal: 2}
	addr := rangedServer(t, s, map[uint32]Proc{1: g.proc},
		map[uint32]func(xdr.Decoder) (inflight.Span, bool){1: spanOf(false)})
	a, b := dialRPC(t, addr), dialRPC(t, addr)
	a.send(1, 1, spanArgs(0, 0, 8))
	a.send(2, 1, spanArgs(0, 0, 8))
	waitStart(t, g)
	waitStart(t, g)
	b.send(3, 1, spanArgs(0, 0, 8))
	noStart(t, g, "a call of another connection with the budget spent")
	g.release <- struct{}{}
	if x := waitStart(t, g); x != 3 {
		t.Fatalf("started %d, want 3", x)
	}
	close(g.release)
}

func TestSlowCallIsNotAnIdleConnection(t *testing.T) {
	g := newGate()
	s := &Server{IdleTimeout: 150 * time.Millisecond}
	addr := rangedServer(t, s, map[uint32]Proc{1: g.proc},
		map[uint32]func(xdr.Decoder) (inflight.Span, bool){1: spanOf(false)})
	c := dialRPC(t, addr)
	c.send(1, 1, spanArgs(0, 0, 8))
	waitStart(t, g)
	time.Sleep(500 * time.Millisecond) // three idle periods, with a call in progress
	close(g.release)
	if x := c.recv(); x != 1 {
		t.Fatalf("reply xid %d", x)
	}
	// And now that nothing is in progress the connection IS idle.
	c.c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.c.Read(make([]byte, 1)); err == nil {
		t.Fatal("an idle connection was kept")
	}
}

func TestATrickledRecordIsCutOffByTheRecordTimeout(t *testing.T) {
	s := &Server{RecordTimeout: 150 * time.Millisecond}
	addr := rangedServer(t, s, map[uint32]Proc{1: func(*Call) Status { return StatusSuccess }}, nil)
	c := dialRPC(t, addr)
	c.c.Write([]byte{0x80, 0, 0, 40, 1}) // a record of 40 bytes, one of them sent
	c.c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.c.Read(make([]byte, 1)); err == nil {
		t.Fatal("a trickled record kept its slot and its token")
	}
}

func TestAPanicAnsweringACallEndsTheConnectionNotTheProcess(t *testing.T) {
	s := &Server{Auth: panicWrapAuth{}}
	addr := rangedServer(t, s, map[uint32]Proc{1: func(*Call) Status { return StatusSuccess }}, nil)
	c := dialRPC(t, addr)
	msg := callMsg(1, 2, testProg, testVers, 1, 6, nil, nil)
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], lastFragment|uint32(len(msg)))
	c.c.Write(append(hdr[:], msg...))
	c.c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c.c, hdr[:]); err == nil {
		t.Fatal("a reply came back from a call that panicked")
	}
	// The server is still there.
	c2 := dialRPC(t, addr)
	c2.send(2, 1, nil)
	c2.recv()
}

// pacedConn is fed its input by the test and fails every write.
type pacedConn struct {
	net.Conn
	in  chan []byte
	buf []byte
}

func (p *pacedConn) Read(b []byte) (int, error) {
	if len(p.buf) == 0 {
		d, ok := <-p.in
		if !ok {
			return 0, io.EOF
		}
		p.buf = d
	}
	n := copy(b, p.buf)
	p.buf = p.buf[n:]
	return n, nil
}
func (*pacedConn) Write([]byte) (int, error)        { return 0, io.ErrClosedPipe }
func (*pacedConn) Close() error                     { return nil }
func (*pacedConn) RemoteAddr() net.Addr             { return nil }
func (*pacedConn) SetReadDeadline(time.Time) error  { return nil }
func (*pacedConn) SetWriteDeadline(time.Time) error { return nil }

// A reply that fails to write while the connection waits for its next record
// ends the connection when that record begins, without reading it.
func TestFailureWhileIdleEndsTheConnectionAtTheNextRecord(t *testing.T) {
	g := newGate()
	s := &Server{IdleTimeout: -1, ErrorLog: log.New(io.Discard, "", 0)}
	s.Register(&Program{Prog: testProg, Vers: testVers, Procs: map[uint32]Proc{1: g.proc},
		Ranges: map[uint32]func(xdr.Decoder) (inflight.Span, bool){1: spanOf(false)}})
	pc := &pacedConn{in: make(chan []byte, 2)}
	msg := callMsg(1, 2, testProg, testVers, 1, AuthNull, nil, spanArgs(0, 0, 8))
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], lastFragment|uint32(len(msg)))
	pc.in <- append(hdr[:], msg...)
	done := make(chan struct{})
	go func() { s.serveConn(pc); close(done) }()
	waitStart(t, g)
	close(g.release)
	time.Sleep(100 * time.Millisecond) // the reply's write fails; the reader is waiting
	pc.in <- []byte{0x80}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the connection outlived a failed reply")
	}
}

type panicWrapAuth struct{}

func (panicWrapAuth) Flavor() uint32 { return 6 }
func (panicWrapAuth) Authenticate(*AuthCall) AuthDecision {
	return AuthDecision{WrapResults: func([]byte) []byte { panic("wrap") }}
}

func TestMaxInFlightResolution(t *testing.T) {
	for _, tc := range []struct{ in, want int }{{0, DefaultMaxInFlight}, {-1, 1}, {5, 5}} {
		if got := (&Server{MaxInFlight: tc.in}).maxInFlight(); got != tc.want {
			t.Errorf("MaxInFlight %d -> %d, want %d", tc.in, got, tc.want)
		}
	}
	// The pool is made once, whatever the setting (the bound itself is
	// exercised by TestServerWideBoundHoldsAcrossConnections).
	for _, n := range []int{0, -4, 3} {
		s := &Server{MaxInFlightTotal: n}
		if p := s.inflightPool(); p == nil || p != s.inflightPool() {
			t.Errorf("MaxInFlightTotal %d: pool %v", n, p)
		}
	}
}

// A connection whose Read returns (0, nil) once is read again, not closed.
type zeroThenData struct {
	net.Conn
	calls int
}

func (z *zeroThenData) Read(p []byte) (int, error) {
	z.calls++
	if z.calls == 1 {
		return 0, nil
	}
	p[0] = 7
	return 1, nil
}
func (z *zeroThenData) SetReadDeadline(time.Time) error { return nil }

func TestAwaitRecordRetriesAnEmptyRead(t *testing.T) {
	var active atomic.Int32
	b, err := awaitRecord(&zeroThenData{}, time.Second, &active)
	if err != nil || b != 7 {
		t.Fatalf("awaitRecord = %d, %v", b, err)
	}
	// Any other error is the connection's end.
	if _, err := awaitRecord(&errConn{}, time.Second, &active); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("awaitRecord = %v", err)
	}
}

type errConn struct{ net.Conn }

func (*errConn) Read([]byte) (int, error)        { return 0, io.ErrClosedPipe }
func (*errConn) SetReadDeadline(time.Time) error { return nil }

func TestPrefixedReaderHandsOutItsByteFirst(t *testing.T) {
	var p prefixed
	p.reset(io.LimitReader(zeroReader{}, 3), 9)
	if n, err := p.Read(nil); n != 0 || err != nil {
		t.Fatalf("Read(nil) = %d, %v", n, err)
	}
	buf := make([]byte, 4)
	if n, _ := p.Read(buf); n != 1 || buf[0] != 9 {
		t.Fatalf("first Read = %d %v", n, buf)
	}
	if n, _ := p.Read(buf); n != 3 {
		t.Fatalf("second Read = %d", n)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { return len(p), nil }
