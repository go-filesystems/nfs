package nfs_test

// Findings of the security audit of 2026-11-05 (v0.8.1), written as tests that
// trace what the server asks of the driver.

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/go-filesystems/nfs"
	"github.com/go-filesystems/nfs/xdr"
)

// countFS counts what the server reads from a driver that has no OpenFile.
type countFS struct {
	*memFS
	calls atomic.Int64
	bytes atomic.Int64
}

func (c *countFS) ReadFile(path string) ([]byte, error) {
	b, err := c.memFS.ReadFile(path)
	c.calls.Add(1)
	c.bytes.Add(int64(len(b)))
	return b, err
}

// An NFS READ of a few bytes must not load a file that is larger than the
// server allows to be loaded whole: a driver with no OpenFile is read through
// ReadFile, which materialises the entire file for every READ request.
func TestReadOfAHugeFileWithoutOpenFileIsRefused(t *testing.T) {
	big := make([]byte, 80<<20) // above the default bound (64 MiB)
	c := &countFS{memFS: fixture().add("/big.bin", 0o100644, big, 99)}
	addr := serve(t, func(s *nfs.Server) { s.Export("/", c) })
	w := dial(t, addr)
	root := w.mount("/")
	fh, st := w.lookup(root, "big.bin")
	if st != nfs.StatusOK {
		t.Fatalf("LOOKUP: %v", st)
	}
	if _, _, st := w.read(fh, 0, 4); st == nfs.StatusOK {
		t.Errorf("a 4-byte READ of an 80 MiB file succeeded by loading it whole (%d bytes read from the driver): refuse, or read a range", c.bytes.Load())
	}
	if n := c.bytes.Load(); n > 1<<20 {
		t.Errorf("the server loaded %d bytes from the driver to answer a 4-byte READ", n)
	}
}

// The bound is configurable, and a file under it is still served (whole, as
// documented).
func TestMaxFallbackReadIsConfigurable(t *testing.T) {
	c := &countFS{memFS: fixture().add("/four.bin", 0o100644, make([]byte, 4096), 98)}
	addr := serve(t, func(s *nfs.Server) { s.Export("/", c, nfs.WithMaxFallbackRead(1024)) })
	w := dial(t, addr)
	root := w.mount("/")
	fh, _ := w.lookup(root, "four.bin")
	if _, _, st := w.read(fh, 0, 8); st == nfs.StatusOK {
		t.Error("a 4 KiB file over a 1 KiB bound was loaded whole")
	}
	hello, _ := w.lookup(root, "hello.txt")
	data, _, st := w.read(hello, 0, 5)
	if st != nfs.StatusOK || len(data) != 5 {
		t.Errorf("a file under the bound: %q %v", data, st)
	}
	if c.calls.Load() != 1 {
		t.Errorf("ReadFile calls = %d, want 1 (the small file)", c.calls.Load())
	}
	// A bound of zero is the default, a negative one lifts it.
	c2 := &countFS{memFS: fixture().add("/four.bin", 0o100644, make([]byte, 4096), 98)}
	addr2 := serve(t, func(s *nfs.Server) { s.Export("/", c2, nfs.WithMaxFallbackRead(-1)) })
	w2 := dial(t, addr2)
	fh2, _ := w2.lookup(w2.mount("/"), "four.bin")
	if _, _, st := w2.read(fh2, 0, 8); st != nfs.StatusOK {
		t.Errorf("an unbounded fallback refused a READ: %v", st)
	}
}

// ownFS records Chown calls; ownerFS also tells the server the current owner.
type ownFS struct {
	*capFS
	mu    sync.Mutex
	calls [][2]uint32
}

func (o *ownFS) Chown(path string, uid, gid uint32) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls = append(o.calls, [2]uint32{uid, gid})
	return nil
}

func (o *ownFS) got() [][2]uint32 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([][2]uint32(nil), o.calls...)
}

type ownerFS struct{ *ownFS }

func (o ownerFS) Owner(path string) (uint32, uint32, error) { return 5, 7, nil }

// sattrUID sets only the uid; sattrGID only the gid.
func sattrOwner(uid, gid *uint32) func(*xdr.Encoder) {
	return func(e *xdr.Encoder) {
		e.Bool(false) // mode
		e.Bool(uid != nil)
		if uid != nil {
			e.Uint32(*uid)
		}
		e.Bool(gid != nil)
		if gid != nil {
			e.Uint32(*gid)
		}
		e.Bool(false) // size
		e.Uint32(0)
		e.Uint32(0)
	}
}

// SETATTR of the uid alone must not set the gid to 0 (RFC 1813 3.3.2: a field
// that is not set is not changed). The Chown capability takes both values, so
// the server either knows the other one (OwnerReader) or refuses.
func TestSetAttrUIDAloneLeavesTheGIDAlone(t *testing.T) {
	uid, gid := uint32(1000), uint32(2000)
	for _, tc := range []struct {
		name string
		set  func(*xdr.Encoder)
	}{{"uid only", sattrOwner(&uid, nil)}, {"gid only", sattrOwner(nil, &gid)}} {
		t.Run("no owner reader: "+tc.name, func(t *testing.T) {
			o := &ownFS{capFS: &capFS{memFS: fixture()}}
			addr := serve(t, func(s *nfs.Server) { s.Export("/", o, nfs.ReadWrite()) })
			w := dial(t, addr)
			fh, _ := w.lookup(w.mount("/"), "hello.txt")
			st, _ := w.nfsCall(2, func(e *xdr.Encoder) { e.Opaque(fh); tc.set(e); e.Bool(false) })
			if len(o.got()) > 0 {
				t.Errorf("Chown%v called for a partial change: the unset field is now 0", o.got())
			}
			if st != nfs.StatusNotSupp {
				t.Errorf("SETATTR of one owner field with no way to read the other = %v, want NOTSUPP", st)
			}
		})
	}
	t.Run("owner reader", func(t *testing.T) {
		o := &ownFS{capFS: &capFS{memFS: fixture()}}
		addr := serve(t, func(s *nfs.Server) { s.Export("/", ownerFS{o}, nfs.ReadWrite()) })
		w := dial(t, addr)
		fh, _ := w.lookup(w.mount("/"), "hello.txt")
		if st, _ := w.nfsCall(2, func(e *xdr.Encoder) { e.Opaque(fh); sattrOwner(&uid, nil)(e); e.Bool(false) }); st != nfs.StatusOK {
			t.Fatalf("SETATTR uid: %v", st)
		}
		if st, _ := w.nfsCall(2, func(e *xdr.Encoder) { e.Opaque(fh); sattrOwner(nil, &gid)(e); e.Bool(false) }); st != nfs.StatusOK {
			t.Fatalf("SETATTR gid: %v", st)
		}
		if got := o.got(); len(got) != 2 || got[0] != [2]uint32{1000, 7} || got[1] != [2]uint32{5, 2000} {
			t.Errorf("Chown calls = %v, want [{1000 7} {5 2000}]", got)
		}
	})
	t.Run("both", func(t *testing.T) {
		o := &ownFS{capFS: &capFS{memFS: fixture()}}
		addr := serve(t, func(s *nfs.Server) { s.Export("/", o, nfs.ReadWrite()) })
		w := dial(t, addr)
		fh, _ := w.lookup(w.mount("/"), "hello.txt")
		if st, _ := w.nfsCall(2, func(e *xdr.Encoder) { e.Opaque(fh); sattrOwner(&uid, &gid)(e); e.Bool(false) }); st != nfs.StatusOK {
			t.Fatalf("SETATTR: %v", st)
		}
		if got := o.got(); len(got) != 1 || got[0] != [2]uint32{1000, 2000} {
			t.Errorf("Chown calls = %v", got)
		}
	})
}
