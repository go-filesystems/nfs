package nfs_test

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/go-filesystems/nfs"
)

// keyedServer serves fs at "/" (plus, optionally, other exports first) under
// key, and returns a client on it. A nil key keeps the server's own.
func keyedServer(t *testing.T, key []byte, fs *memFS, extra ...string) *wire {
	t.Helper()
	addr := serve(t, func(s *nfs.Server) {
		// Exports added BEFORE the key, and others before "/": neither the
		// order of SetHandleKey nor the order of exports may change a handle.
		for _, p := range extra {
			if err := s.Export(p, newMemFS()); err != nil {
				t.Fatalf("Export %s: %v", p, err)
			}
		}
		if err := s.Export("/", fs, nfs.ReadWrite()); err != nil {
			t.Fatalf("Export: %v", err)
		}
		if key != nil {
			if err := s.SetHandleKey(key); err != nil {
				t.Fatalf("SetHandleKey: %v", err)
			}
		}
	})
	return dial(t, addr)
}

// TestAHandleOutlivesItsServerUnderASharedKey is the API fileshare needs: it
// rebuilds its nfs.Server on every configuration change, and up to v0.4.0
// each one drew a fresh handle key, so every handle a client held became
// NFS3ERR_BADHANDLE (EIO on every open file). With the key carried over, a
// handle minted by server A must work on server B — which has never been
// asked about that path — and must not work under any other key.
func TestAHandleOutlivesItsServerUnderASharedKey(t *testing.T) {
	key, err := nfs.NewHandleKey()
	if err != nil {
		t.Fatal(err)
	}
	fs := fixture()

	a := keyedServer(t, key, fs)
	rootA := a.mount("/")
	dir, st := a.lookup(rootA, "dir")
	if st != nfs.StatusOK {
		t.Fatalf("LOOKUP dir: %v", st)
	}
	file, st := a.lookup(dir, "nested.bin")
	if st != nfs.StatusOK {
		t.Fatalf("LOOKUP nested.bin: %v", st)
	}
	want := a.readAll(file, 1<<16)

	// B: same key, same export path and filesystem, but another export
	// added before it. Nothing has been looked up on B.
	b := keyedServer(t, key, fs, "/other")
	if got := b.readAll(file, 1<<16); !bytes.Equal(got, want) {
		t.Fatalf("server B read %d bytes through A's handle, want the %d A read", len(got), len(want))
	}
	if n, st := b.write(file, 0, []byte("B")); st != nfs.StatusOK || n != 1 {
		t.Fatalf("WRITE on B through A's handle = (%d, %v)", n, st)
	}
	if rootB := b.mount("/"); !bytes.Equal(rootB, rootA) {
		t.Fatal("the same key and export path gave two different root handles")
	}

	// C: another key. A's handle is not authentic there.
	other, _ := nfs.NewHandleKey()
	c := keyedServer(t, other, fs)
	if _, _, st := c.read(file, 0, 16); st != nfs.StatusBadHandle {
		t.Fatalf("READ through A's handle under another key = %v, want BADHANDLE", st)
	}
	// D: no key given, which is v0.4.0's behaviour — also not valid.
	d := keyedServer(t, nil, fs)
	if _, _, st := d.read(file, 0, 16); st != nfs.StatusBadHandle {
		t.Fatalf("READ through A's handle on a server with its own key = %v, want BADHANDLE", st)
	}
}

// TestAHandleForAPathThatIsGoneIsStale: the shared key must not resurrect a
// deleted file, nor alias its handle onto anything else.
func TestAHandleForAPathThatIsGoneIsStale(t *testing.T) {
	key, _ := nfs.NewHandleKey()
	fs := fixture()
	a := keyedServer(t, key, fs)
	dir, _ := a.lookup(a.mount("/"), "dir")
	file, st := a.lookup(dir, "nested.bin")
	if st != nfs.StatusOK {
		t.Fatalf("LOOKUP: %v", st)
	}
	if err := fs.DeleteFile("/dir/nested.bin"); err != nil {
		t.Fatal(err)
	}
	b := keyedServer(t, key, fs)
	if _, _, st := b.read(file, 0, 16); st != nfs.StatusStale {
		t.Fatalf("READ through a handle for a deleted path on B = %v, want STALE", st)
	}
	// Still stale on a second try, which is inside the walk interval: the
	// answer comes from the table, not from another walk.
	if _, _, st := b.read(file, 0, 16); st != nfs.StatusStale {
		t.Fatalf("second READ = %v, want STALE", st)
	}
}

func TestSetHandleKeyRefusals(t *testing.T) {
	s, err := nfs.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetHandleKey(make([]byte, nfs.HandleKeySize-1)); !errors.Is(err, nfs.ErrHandleKey) {
		t.Fatalf("SetHandleKey with a 31-byte key = %v, want ErrHandleKey", err)
	}
	if err := s.Export("/", newMemFS()); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	defer func() { s.Close(); <-done }()
	// Serve marks the server started before it accepts; wait for that by
	// connecting once.
	if c, err := net.Dial("tcp", ln.Addr().String()); err == nil {
		c.Close()
	}
	key, _ := nfs.NewHandleKey()
	if err := s.SetHandleKey(key); !errors.Is(err, nfs.ErrServing) {
		t.Fatalf("SetHandleKey while serving = %v, want ErrServing", err)
	}
}

func TestNewHandleKey(t *testing.T) {
	a, err := nfs.NewHandleKey()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := nfs.NewHandleKey()
	if len(a) != nfs.HandleKeySize || bytes.Equal(a, b) {
		t.Fatalf("NewHandleKey: %d bytes, two draws equal: %v", len(a), bytes.Equal(a, b))
	}
}

// TestConnLimitsAreApplied: the nfs-level knob reaches the RPC server.
func TestConnLimitsAreApplied(t *testing.T) {
	addr := serve(t, func(s *nfs.Server) {
		if err := s.Export("/", newMemFS()); err != nil {
			t.Fatal(err)
		}
		if err := s.SetConnLimits(nfs.ConnLimits{IdleTimeout: 150 * time.Millisecond, MaxConns: 1}); err != nil {
			t.Fatal(err)
		}
		if err := s.SetErrorLog(nil); err != nil {
			t.Fatal(err)
		}
	})
	w := dial(t, addr)
	w.mount("/") // the one connection the cap allows is served
	extra, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	_ = extra.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := extra.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("a connection past MaxConns 1 was kept (%v)", err)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
