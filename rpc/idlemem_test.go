// Copyright (c) 2026, go-filesystems
// SPDX-License-Identifier: BSD-3-Clause

package rpc

import (
	"encoding/binary"
	"io"
	"net"
	"runtime"
	"testing"
	"time"
)

// A connection between calls holds no large buffer. A record may be 2 MiB
// and a reply 1 MiB, so a connection that kept what its largest call needed
// would cost 3 MiB for as long as it stays open, doing nothing -- times
// DefaultMaxConns, before anybody has to authenticate.
func TestAnIdleConnectionHoldsNoLargeBuffer(t *testing.T) {
	const conns = 24
	reply := make([]byte, 1<<20)
	_, addr := newTestServer(t, map[uint32]Proc{1: func(c *Call) Status {
		c.Res.Opaque(reply)
		return StatusSuccess
	}})
	msg := callMsg(1, rpcVersion, testProg, testVers, 1, AuthNull, nil, make([]byte, 3<<19))

	heap := func() uint64 {
		var m runtime.MemStats
		for range 3 {
			runtime.GC() // three: sync.Pool keeps a victim generation
		}
		runtime.ReadMemStats(&m)
		return m.HeapAlloc
	}
	before := heap()
	var open []net.Conn
	defer func() {
		for _, c := range open {
			c.Close()
		}
	}()
	for range conns {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		open = append(open, c)
		c.SetDeadline(time.Now().Add(10 * time.Second))
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], lastFragment|uint32(len(msg)))
		if _, err := c.Write(append(hdr[:], msg...)); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := io.CopyN(io.Discard, c, int64(binary.BigEndian.Uint32(hdr[:])&^lastFragment)); err != nil {
			t.Fatal(err)
		}
	}
	retained := int64(heap()) - int64(before)
	if retained > 8<<20 {
		t.Fatalf("%d idle connections retain %d MiB after one large call each; want under 8", conns, retained>>20)
	}
	t.Logf("%d idle connections retain %d KiB", conns, retained>>10)
}

// What is lent and what is not: a connection's own small buffer never, an
// oversized one never, anything between once, to one borrower.
func TestGiveBackAndBorrow(t *testing.T) {
	for borrow(1) != nil { // empty the pool other tests filled
	}
	giveBack(make([]byte, 0, smallBuffer))
	giveBack(make([]byte, 0, 2*maxRecordDefault+1))
	if b := borrow(1); b != nil {
		t.Fatalf("borrowed a %d-byte buffer nobody should have lent", cap(b))
	}
	giveBack(make([]byte, 5, 64<<10))
	if b := borrow(128 << 10); b != nil {
		t.Fatalf("borrow(128 KiB) returned %d bytes of capacity", cap(b))
	}
	// sync.Pool may drop what it is given -- under the race detector it does
	// so on purpose -- so the lending is asked a few times.
	var b []byte
	for range 100 {
		if b = borrow(32 << 10); b != nil {
			break
		}
		giveBack(make([]byte, 5, 64<<10))
	}
	if b == nil || len(b) != 0 || cap(b) < 64<<10 {
		t.Fatalf("borrow(32 KiB) = len %d cap %d, want a lent buffer, empty", len(b), cap(b))
	}
}
