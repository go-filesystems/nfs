package nfs_test

// AUDIT 2026-11-22 reproducer (untracked). READDIR / READDIRPLUS take
// Server.fsmu exclusively and THEN resolve the handle (readdirCommon -> fhArg).
// For an authentic handle the handle table does not know yet (a handle minted
// by an earlier Server sharing the key: the documented SetHandleKey restart
// case), fhArg calls rediscover, which takes fsmu.Lock() again. sync.RWMutex is
// not re-entrant: the goroutine deadlocks holding the exclusive lock, and every
// later filesystem call of every client blocks for ever.

import (
	"net"
	"testing"
	"time"

	"github.com/go-filesystems/nfs"
	"github.com/go-filesystems/nfs/xdr"
)

// auditServe is serve() without the Close-and-wait cleanup: on a deadlocked
// server Close never returns, and the test must report, not hang.
func auditServe(t *testing.T, key []byte) string {
	t.Helper()
	s, err := nfs.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Export("/", fixture()); err != nil {
		t.Fatal(err)
	}
	if err := s.SetHandleKey(key); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(ln)
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

func TestAuditReaddirOnRediscoveredHandleDeadlocksServer(t *testing.T) {
	key, err := nfs.NewHandleKey()
	if err != nil {
		t.Fatal(err)
	}
	// Server A: the client mounts and keeps the root handle.
	a := dial(t, auditServe(t, key))
	root := a.mount("/")

	// Server B: the "restarted" server, same key, same export. The client does
	// not MNT again (a hard mount never does); its first call is READDIR.
	addrB := auditServe(t, key)
	b := dial(t, addrB)
	b.conn.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan nfs.Status, 1)
	go func() {
		defer func() { recover() }()
		st, _ := b.nfsCall(16, func(e *xdr.Encoder) {
			e.Opaque(root)
			e.Uint64(0)
			e.Fixed(make([]byte, 8))
			e.Uint32(4096)
		})
		done <- st
	}()
	select {
	case st := <-done:
		t.Logf("READDIR answered status %d: not deadlocked", st)
		return
	case <-time.After(3 * time.Second):
	}

	// The lock is now held for ever: a second, unrelated client cannot even
	// GETATTR a handle it gets from a fresh MNT.
	c2, err := net.Dial("tcp", addrB)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	w2 := dial(t, addrB)
	root2 := w2.mount("/") // MNT does not take fsmu: still answered
	w2.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := make(chan struct{}, 1)
	go func() {
		defer func() { recover() }()
		w2.nfsCall(1, func(e *xdr.Encoder) { e.Opaque(root2) })
		got <- struct{}{}
	}()
	select {
	case <-got:
		t.Fatal("READDIR hung for 3s but a second client's GETATTR was answered: per-connection hang only")
	case <-time.After(4 * time.Second):
		t.Fatal("DEADLOCK: READDIR on an authentic-but-unknown handle never answered, and a second client's GETATTR is blocked server-wide (fsmu held for ever)")
	}
}
