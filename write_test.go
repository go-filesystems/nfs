package nfs_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/go-filesystems/nfs"
	"github.com/go-filesystems/nfs/xdr"
)

// sattrNone encodes an sattr3 with nothing set.
func sattrNone(e *xdr.Encoder) {
	for range 4 {
		e.Bool(false)
	}
	e.Uint32(0) // atime: DONT_CHANGE
	e.Uint32(0) // mtime: DONT_CHANGE
}

// sattrMode encodes an sattr3 setting only the mode.
func sattrMode(mode uint32) func(*xdr.Encoder) {
	return func(e *xdr.Encoder) {
		e.Bool(true)
		e.Uint32(mode)
		e.Bool(false)
		e.Bool(false)
		e.Bool(false)
		e.Uint32(0)
		e.Uint32(0)
	}
}

// sattrSize encodes an sattr3 setting only the size.
func sattrSize(size uint64) func(*xdr.Encoder) {
	return func(e *xdr.Encoder) {
		e.Bool(false)
		e.Bool(false)
		e.Bool(false)
		e.Bool(true)
		e.Uint64(size)
		e.Uint32(0)
		e.Uint32(0)
	}
}

// sattrAll sets every field, including client-supplied times.
func sattrAll(e *xdr.Encoder) {
	e.Bool(true)
	e.Uint32(0o600)
	e.Bool(true)
	e.Uint32(501)
	e.Bool(true)
	e.Uint32(20)
	e.Bool(false)
	e.Uint32(2) // atime SET_TO_CLIENT_TIME
	e.Uint32(1000)
	e.Uint32(0)
	e.Uint32(1) // mtime SET_TO_SERVER_TIME
}

func TestCreateWriteReadRemove(t *testing.T) {
	m := fixture()
	addr := serve(t, func(s *nfs.Server) { s.Export("/", m, nfs.ReadWrite()) })
	w := dial(t, addr)
	root := w.mount("/")

	// CREATE (guarded)
	st, d := w.nfsCall(8, func(e *xdr.Encoder) {
		e.Opaque(root)
		e.String("new.txt")
		e.Uint32(1) // GUARDED
		sattrMode(0o640)(e)
	})
	if st != nfs.StatusOK {
		t.Fatalf("CREATE: %v", st)
	}
	if w.mustU32(d) != 1 {
		t.Fatal("CREATE returned no file handle")
	}
	fh, err := d.Opaque()
	if err != nil {
		t.Fatalf("CREATE handle: %v", err)
	}

	// A second guarded CREATE must refuse rather than clobber.
	st, _ = w.nfsCall(8, func(e *xdr.Encoder) {
		e.Opaque(root)
		e.String("new.txt")
		e.Uint32(1)
		sattrMode(0o640)(e)
	})
	if st != nfs.StatusExist {
		t.Fatalf("guarded CREATE over an existing file = %v, want EXIST", st)
	}
	// UNCHECKED overwrites.
	st, _ = w.nfsCall(8, func(e *xdr.Encoder) {
		e.Opaque(root)
		e.String("new.txt")
		e.Uint32(0)
		sattrNone(e)
	})
	if st != nfs.StatusOK {
		t.Fatalf("unchecked CREATE over an existing file = %v", st)
	}
	// EXCLUSIVE degrades to guarded: it still refuses to clobber.
	st, _ = w.nfsCall(8, func(e *xdr.Encoder) {
		e.Opaque(root)
		e.String("new.txt")
		e.Uint32(2)
		e.Fixed(make([]byte, 8))
	})
	if st != nfs.StatusExist {
		t.Fatalf("exclusive CREATE over an existing file = %v, want EXIST", st)
	}

	// WRITE, then read back through the driver and through NFS.
	payload := []byte("written over nfs")
	st, d = w.nfsCall(7, func(e *xdr.Encoder) {
		e.Opaque(fh)
		e.Uint64(0)
		e.Uint32(uint32(len(payload)))
		e.Uint32(2) // FILE_SYNC
		e.Opaque(payload)
	})
	if st != nfs.StatusOK {
		t.Fatalf("WRITE: %v", st)
	}
	w.skipWcc(d)
	if n := w.mustU32(d); n != uint32(len(payload)) {
		t.Fatalf("WRITE count = %d, want %d", n, len(payload))
	}
	if committed := w.mustU32(d); committed != 2 {
		t.Fatalf("WRITE committed = %d, want 2 (FILE_SYNC)", committed)
	}
	verf, err := d.Fixed(8)
	if err != nil {
		t.Fatalf("WRITE verf: %v", err)
	}

	direct, err := m.ReadFile("/new.txt")
	if err != nil {
		t.Fatalf("driver ReadFile: %v", err)
	}
	if !bytes.Equal(direct, payload) {
		t.Fatalf("driver sees %q after WRITE, want %q", direct, payload)
	}
	got, _, st := w.read(fh, 0, 4096)
	if st != nfs.StatusOK || !bytes.Equal(got, payload) {
		t.Fatalf("READ after WRITE = (%q, %v)", got, st)
	}

	// A WRITE past the end grows the file with a zero gap.
	st, _ = w.nfsCall(7, func(e *xdr.Encoder) {
		e.Opaque(fh)
		e.Uint64(20)
		e.Uint32(2)
		e.Uint32(2)
		e.Opaque([]byte("XY"))
	})
	if st != nfs.StatusOK {
		t.Fatalf("WRITE past the end: %v", st)
	}
	grown, _ := m.ReadFile("/new.txt")
	if len(grown) != 22 || grown[20] != 'X' || grown[16] != 0 {
		t.Fatalf("after a sparse WRITE the file is %q", grown)
	}

	// COMMIT: the verifier must match the one WRITE reported, or a client
	// concludes the server restarted and its data is lost.
	st, d = w.nfsCall(21, func(e *xdr.Encoder) {
		e.Opaque(fh)
		e.Uint64(0)
		e.Uint32(0)
	})
	if st != nfs.StatusOK {
		t.Fatalf("COMMIT: %v", st)
	}
	w.skipWcc(d)
	cverf, _ := d.Fixed(8)
	if !bytes.Equal(verf, cverf) {
		t.Fatalf("COMMIT verifier %x differs from WRITE's %x", cverf, verf)
	}

	// REMOVE
	st, _ = w.nfsCall(12, func(e *xdr.Encoder) {
		e.Opaque(root)
		e.String("new.txt")
	})
	if st != nfs.StatusOK {
		t.Fatalf("REMOVE: %v", st)
	}
	if _, st := w.lookup(root, "new.txt"); st != nfs.StatusNoEnt {
		t.Fatalf("LOOKUP after REMOVE = %v, want NOENT", st)
	}
}

func TestMkdirRmdirRename(t *testing.T) {
	m := fixture()
	addr := serve(t, func(s *nfs.Server) { s.Export("/", m, nfs.ReadWrite()) })
	w := dial(t, addr)
	root := w.mount("/")

	st, _ := w.nfsCall(9, func(e *xdr.Encoder) {
		e.Opaque(root)
		e.String("newdir")
		sattrMode(0o750)(e)
	})
	if st != nfs.StatusOK {
		t.Fatalf("MKDIR: %v", st)
	}
	st, _ = w.nfsCall(9, func(e *xdr.Encoder) {
		e.Opaque(root)
		e.String("newdir")
		sattrNone(e)
	})
	if st != nfs.StatusExist {
		t.Fatalf("MKDIR over an existing name = %v, want EXIST", st)
	}

	// RMDIR must refuse a non-empty directory even though several drivers'
	// DeleteDir would happily delete it recursively.
	st, _ = w.nfsCall(13, func(e *xdr.Encoder) {
		e.Opaque(root)
		e.String("dir")
	})
	if st != nfs.StatusNotEmpty {
		t.Fatalf("RMDIR on a non-empty directory = %v, want NOTEMPTY", st)
	}
	if _, err := m.Stat("/dir/nested.bin"); err != nil {
		t.Fatal("RMDIR deleted the directory's contents anyway")
	}
	st, _ = w.nfsCall(13, func(e *xdr.Encoder) {
		e.Opaque(root)
		e.String("newdir")
	})
	if st != nfs.StatusOK {
		t.Fatalf("RMDIR on an empty directory: %v", st)
	}

	// RMDIR on a file and REMOVE on a directory must each be refused.
	st, _ = w.nfsCall(13, func(e *xdr.Encoder) {
		e.Opaque(root)
		e.String("hello.txt")
	})
	if st != nfs.StatusNotDir {
		t.Fatalf("RMDIR on a file = %v, want NOTDIR", st)
	}
	st, _ = w.nfsCall(12, func(e *xdr.Encoder) {
		e.Opaque(root)
		e.String("dir")
	})
	if st != nfs.StatusIsDir {
		t.Fatalf("REMOVE on a directory = %v, want ISDIR", st)
	}
	st, _ = w.nfsCall(12, func(e *xdr.Encoder) {
		e.Opaque(root)
		e.String("gone")
	})
	if st != nfs.StatusNoEnt {
		t.Fatalf("REMOVE on a missing name = %v, want NOENT", st)
	}

	// RENAME
	st, d := w.nfsCall(14, func(e *xdr.Encoder) {
		e.Opaque(root)
		e.String("hello.txt")
		e.Opaque(root)
		e.String("moved.txt")
	})
	if st != nfs.StatusOK {
		t.Fatalf("RENAME: %v", st)
	}
	w.skipWcc(d)
	w.skipWcc(d)
	if _, st := w.lookup(root, "moved.txt"); st != nfs.StatusOK {
		t.Fatalf("LOOKUP after RENAME = %v", st)
	}
	st, _ = w.nfsCall(14, func(e *xdr.Encoder) {
		e.Opaque(root)
		e.String("missing")
		e.Opaque(root)
		e.String("x")
	})
	if st != nfs.StatusNoEnt {
		t.Fatalf("RENAME of a missing source = %v, want NOENT", st)
	}
}

func TestSetAttr(t *testing.T) {
	base := fixture()
	cap := &capFS{memFS: base}
	addr := serve(t, func(s *nfs.Server) { s.Export("/", cap, nfs.ReadWrite()) })
	w := dial(t, addr)
	root := w.mount("/")
	fh, _ := w.lookup(root, "hello.txt")

	// Truncate to 4 bytes through SETATTR, the path `> file` takes.
	st, d := w.nfsCall(2, func(e *xdr.Encoder) {
		e.Opaque(fh)
		sattrSize(4)(e)
		e.Bool(false)
	})
	if st != nfs.StatusOK {
		t.Fatalf("SETATTR size: %v", st)
	}
	w.skipWcc(d)
	data, _ := base.ReadFile("/hello.txt")
	if string(data) != "hell" {
		t.Fatalf("after SETATTR size=4 the driver holds %q", data)
	}

	// Mode, owner and both timestamps at once.
	st, _ = w.nfsCall(2, func(e *xdr.Encoder) {
		e.Opaque(fh)
		sattrAll(e)
		e.Bool(false)
	})
	if st != nfs.StatusOK {
		t.Fatalf("SETATTR all: %v", st)
	}
	stat, _ := base.Stat("/hello.txt")
	if stat.Mode()&0o7777 != 0o600 {
		t.Fatalf("mode after SETATTR = %#o, want 0600", stat.Mode()&0o7777)
	}

	// A guard that does not match must refuse: it is the protocol's
	// compare-and-set, and honouring it wrongly is a lost update.
	st, _ = w.nfsCall(2, func(e *xdr.Encoder) {
		e.Opaque(fh)
		sattrMode(0o644)(e)
		e.Bool(true)
		e.Uint32(1) // a ctime that cannot be the current one
		e.Uint32(0)
	})
	if st != nfs.StatusNotSync {
		t.Fatalf("SETATTR with a stale guard = %v, want NOT_SYNC", st)
	}
	// A guard that matches goes through.
	st, d = w.nfsCall(1, func(e *xdr.Encoder) { e.Opaque(fh) })
	if st != nfs.StatusOK {
		t.Fatalf("GETATTR: %v", st)
	}
	for range 11 {
		w.mustU32(d)
	}
	var ctime uint32
	for range 3 {
		ctime = w.mustU32(d)
		w.mustU32(d)
	}
	st, _ = w.nfsCall(2, func(e *xdr.Encoder) {
		e.Opaque(fh)
		sattrMode(0o644)(e)
		e.Bool(true)
		e.Uint32(ctime)
		e.Uint32(0)
	})
	if st != nfs.StatusOK {
		t.Fatalf("SETATTR with a matching guard = %v", st)
	}
}

// TestSetAttrSizeWithoutTruncater: silently ignoring a truncate would let a
// client believe a file is empty when it is not.
func TestSetAttrSizeWithoutTruncater(t *testing.T) {
	addr := serve(t, func(s *nfs.Server) { s.Export("/", fixture(), nfs.ReadWrite()) })
	w := dial(t, addr)
	root := w.mount("/")
	fh, _ := w.lookup(root, "hello.txt")
	st, _ := w.nfsCall(2, func(e *xdr.Encoder) {
		e.Opaque(fh)
		sattrSize(0)(e)
		e.Bool(false)
	})
	if st != nfs.StatusNotSupp {
		t.Fatalf("SETATTR size on a driver with no Truncate = %v, want NOTSUPP", st)
	}
}

func TestSymlinkAndReadlink(t *testing.T) {
	base := fixture()
	base.add("/alink", 0o120777, nil, 12)
	base.nodes["/alink"].link = "/hello.txt"
	cap := &capFS{memFS: base}
	addr := serve(t, func(s *nfs.Server) { s.Export("/", cap, nfs.ReadWrite()) })
	w := dial(t, addr)
	root := w.mount("/")

	fh, st := w.lookup(root, "alink")
	if st != nfs.StatusOK {
		t.Fatalf("LOOKUP alink: %v", st)
	}
	st, d := w.nfsCall(5, func(e *xdr.Encoder) { e.Opaque(fh) })
	if st != nfs.StatusOK {
		t.Fatalf("READLINK: %v", st)
	}
	w.skipPostOp(d)
	target, err := d.String()
	if err != nil {
		t.Fatalf("READLINK target: %v", err)
	}
	if target != "/hello.txt" {
		t.Fatalf("READLINK = %q, want /hello.txt", target)
	}

	// READLINK on a regular file is INVAL, as readlink(2) gives.
	reg, _ := w.lookup(root, "hello.txt")
	st, _ = w.nfsCall(5, func(e *xdr.Encoder) { e.Opaque(reg) })
	if st != nfs.StatusInval {
		t.Fatalf("READLINK on a regular file = %v, want INVAL", st)
	}

	// SYMLINK
	st, _ = w.nfsCall(10, func(e *xdr.Encoder) {
		e.Opaque(root)
		e.String("newlink")
		sattrNone(e)
		e.String("/dir")
	})
	if st != nfs.StatusOK {
		t.Fatalf("SYMLINK: %v", st)
	}
	if got, err := cap.ReadLink("/newlink"); err != nil || got != "/dir" {
		t.Fatalf("driver ReadLink after SYMLINK = (%q, %v)", got, err)
	}
}

func TestSymlinkAndLinkUnsupported(t *testing.T) {
	addr := serve(t, func(s *nfs.Server) { s.Export("/", fixture(), nfs.ReadWrite()) })
	w := dial(t, addr)
	root := w.mount("/")
	st, _ := w.nfsCall(10, func(e *xdr.Encoder) {
		e.Opaque(root)
		e.String("l")
		sattrNone(e)
		e.String("/x")
	})
	if st != nfs.StatusNotSupp {
		t.Fatalf("SYMLINK on a driver without Symlinker = %v, want NOTSUPP", st)
	}
	fh, _ := w.lookup(root, "hello.txt")
	st, _ = w.nfsCall(15, func(e *xdr.Encoder) {
		e.Opaque(fh)
		e.Opaque(root)
		e.String("hard")
	})
	if st != nfs.StatusNotSupp {
		t.Fatalf("LINK on a driver without HardLinker = %v, want NOTSUPP", st)
	}
}

func TestLink(t *testing.T) {
	cap := &capFS{memFS: fixture()}
	addr := serve(t, func(s *nfs.Server) { s.Export("/", cap, nfs.ReadWrite()) })
	w := dial(t, addr)
	root := w.mount("/")
	fh, _ := w.lookup(root, "hello.txt")
	st, _ := w.nfsCall(15, func(e *xdr.Encoder) {
		e.Opaque(fh)
		e.Opaque(root)
		e.String("hard.txt")
	})
	if st != nfs.StatusOK {
		t.Fatalf("LINK: %v", st)
	}
	if _, err := cap.Stat("/hard.txt"); err != nil {
		t.Fatalf("driver Stat after LINK: %v", err)
	}
	// PATHCONF must advertise the capability it actually has.
	st, d := w.nfsCall(20, func(e *xdr.Encoder) { e.Opaque(root) })
	if st != nfs.StatusOK {
		t.Fatalf("PATHCONF: %v", st)
	}
	w.skipPostOp(d)
	if linkmax := w.mustU32(d); linkmax != 32000 {
		t.Fatalf("PATHCONF linkmax = %d, want 32000 on a HardLinker", linkmax)
	}
	// FSINFO must set FSF3_LINK.
	st, d = w.nfsCall(19, func(e *xdr.Encoder) { e.Opaque(root) })
	if st != nfs.StatusOK {
		t.Fatalf("FSINFO: %v", st)
	}
	w.skipPostOp(d)
	for range 7 {
		w.mustU32(d)
	}
	w.mustU64(d)
	w.mustU32(d)
	w.mustU32(d)
	if props := w.mustU32(d); props&1 == 0 {
		t.Fatalf("FSINFO properties = %#x, want FSF3_LINK set", props)
	}
}

// TestMknodIsRefused: a device node has no representation in the contract, so
// answering NOTSUPP is better than silently making a regular file.
func TestMknodIsRefused(t *testing.T) {
	addr := serve(t, func(s *nfs.Server) { s.Export("/", fixture(), nfs.ReadWrite()) })
	w := dial(t, addr)
	root := w.mount("/")
	st, _ := w.nfsCall(11, func(e *xdr.Encoder) {
		e.Opaque(root)
		e.String("dev")
		e.Uint32(3)
	})
	if st != nfs.StatusNotSupp {
		t.Fatalf("MKNOD = %v, want NOTSUPP", st)
	}
}

// TestReadOnlyRefusesEveryMutation is the property a read-only export exists
// for: no procedure may reach the driver's write side.
func TestReadOnlyRefusesEveryMutation(t *testing.T) {
	m := fixture()
	addr := serve(t, func(s *nfs.Server) { s.Export("/", m, nfs.WithCapacity(1, 1)) })
	w := dial(t, addr)
	root := w.mount("/")
	fh, _ := w.lookup(root, "hello.txt")

	for _, tc := range []struct {
		name string
		proc uint32
		args func(*xdr.Encoder)
	}{
		{"SETATTR", 2, func(e *xdr.Encoder) { e.Opaque(fh); sattrMode(0o777)(e); e.Bool(false) }},
		{"WRITE", 7, func(e *xdr.Encoder) {
			e.Opaque(fh)
			e.Uint64(0)
			e.Uint32(1)
			e.Uint32(2)
			e.Opaque([]byte("x"))
		}},
		{"CREATE", 8, func(e *xdr.Encoder) { e.Opaque(root); e.String("z"); e.Uint32(0); sattrNone(e) }},
		{"MKDIR", 9, func(e *xdr.Encoder) { e.Opaque(root); e.String("z"); sattrNone(e) }},
		{"SYMLINK", 10, func(e *xdr.Encoder) { e.Opaque(root); e.String("z"); sattrNone(e); e.String("/t") }},
		{"REMOVE", 12, func(e *xdr.Encoder) { e.Opaque(root); e.String("hello.txt") }},
		{"RMDIR", 13, func(e *xdr.Encoder) { e.Opaque(root); e.String("dir") }},
		{"RENAME", 14, func(e *xdr.Encoder) { e.Opaque(root); e.String("hello.txt"); e.Opaque(root); e.String("z") }},
		{"LINK", 15, func(e *xdr.Encoder) { e.Opaque(fh); e.Opaque(root); e.String("z") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, _ := w.nfsCall(tc.proc, tc.args)
			if st != nfs.StatusROFS {
				t.Fatalf("%s on a read-only export = %v, want ROFS", tc.name, st)
			}
		})
	}
	if _, err := m.ReadFile("/hello.txt"); err != nil {
		t.Fatalf("the image changed under a read-only export: %v", err)
	}
	if data, _ := m.ReadFile("/hello.txt"); string(data) != "hello, nfs\n" {
		t.Fatal("a read-only export let a write through")
	}
}

// TestWriteTooLarge: a client that ignores wtmax must be refused, not obeyed.
func TestWriteTooLarge(t *testing.T) {
	addr := serve(t, func(s *nfs.Server) { s.Export("/", fixture(), nfs.ReadWrite()) })
	w := dial(t, addr)
	root := w.mount("/")
	fh, _ := w.lookup(root, "hello.txt")
	big := bytes.Repeat([]byte("x"), 1<<17+1)
	st, _ := w.nfsCall(7, func(e *xdr.Encoder) {
		e.Opaque(fh)
		e.Uint64(0)
		e.Uint32(uint32(len(big)))
		e.Uint32(2)
		e.Opaque(big)
	})
	if st != nfs.StatusInval {
		t.Fatalf("WRITE above wtmax = %v, want INVAL", st)
	}
}

func TestWriteOnDirectory(t *testing.T) {
	addr := serve(t, func(s *nfs.Server) { s.Export("/", fixture(), nfs.ReadWrite()) })
	w := dial(t, addr)
	root := w.mount("/")
	st, _ := w.nfsCall(7, func(e *xdr.Encoder) {
		e.Opaque(root)
		e.Uint64(0)
		e.Uint32(1)
		e.Uint32(2)
		e.Opaque([]byte("x"))
	})
	if st != nfs.StatusIsDir {
		t.Fatalf("WRITE on a directory = %v, want ISDIR", st)
	}
}

var errDriver = errors.New("memfs: injected driver failure")

// TestDriverFailuresBecomeStatuses walks the error branch of every procedure
// that calls into the driver.
func TestDriverFailuresBecomeStatuses(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  string
		proc uint32
		args func(root, fh []byte) func(*xdr.Encoder)
		want nfs.Status
	}{
		{"WRITE read-back fails", "ReadFile:/hello.txt", 7, func(root, fh []byte) func(*xdr.Encoder) {
			return func(e *xdr.Encoder) {
				e.Opaque(fh)
				e.Uint64(0)
				e.Uint32(1)
				e.Uint32(2)
				e.Opaque([]byte("x"))
			}
		}, nfs.StatusIO},
		{"WRITE write-back fails", "WriteFile:/hello.txt", 7, func(root, fh []byte) func(*xdr.Encoder) {
			return func(e *xdr.Encoder) {
				e.Opaque(fh)
				e.Uint64(0)
				e.Uint32(1)
				e.Uint32(2)
				e.Opaque([]byte("x"))
			}
		}, nfs.StatusIO},
		{"CREATE fails", "WriteFile:/z", 8, func(root, fh []byte) func(*xdr.Encoder) {
			return func(e *xdr.Encoder) { e.Opaque(root); e.String("z"); e.Uint32(0); sattrNone(e) }
		}, nfs.StatusIO},
		{"MKDIR fails", "MkDir:/z", 9, func(root, fh []byte) func(*xdr.Encoder) {
			return func(e *xdr.Encoder) { e.Opaque(root); e.String("z"); sattrNone(e) }
		}, nfs.StatusIO},
		{"REMOVE fails", "DeleteFile:/hello.txt", 12, func(root, fh []byte) func(*xdr.Encoder) {
			return func(e *xdr.Encoder) { e.Opaque(root); e.String("hello.txt") }
		}, nfs.StatusIO},
		{"RMDIR fails", "DeleteDir:/empty-dir", 13, func(root, fh []byte) func(*xdr.Encoder) {
			return func(e *xdr.Encoder) { e.Opaque(root); e.String("empty-dir") }
		}, nfs.StatusIO},
		{"RMDIR listing fails", "ListDir:/empty-dir", 13, func(root, fh []byte) func(*xdr.Encoder) {
			return func(e *xdr.Encoder) { e.Opaque(root); e.String("empty-dir") }
		}, nfs.StatusNotDir},
		{"RENAME fails", "Rename:/hello.txt", 14, func(root, fh []byte) func(*xdr.Encoder) {
			return func(e *xdr.Encoder) { e.Opaque(root); e.String("hello.txt"); e.Opaque(root); e.String("z") }
		}, nfs.StatusIO},
		{"READ fails", "ReadFile:/hello.txt", 6, func(root, fh []byte) func(*xdr.Encoder) {
			return func(e *xdr.Encoder) { e.Opaque(fh); e.Uint64(0); e.Uint32(16) }
		}, nfs.StatusIO},
		{"READDIR listing fails", "ListDir:/", 16, func(root, fh []byte) func(*xdr.Encoder) {
			return func(e *xdr.Encoder) {
				e.Opaque(root)
				e.Uint64(0)
				e.Fixed(make([]byte, 8))
				e.Uint32(4096)
			}
		}, nfs.StatusNotDir},
		{"READDIRPLUS listing fails", "ListDir:/", 17, func(root, fh []byte) func(*xdr.Encoder) {
			return func(e *xdr.Encoder) {
				e.Opaque(root)
				e.Uint64(0)
				e.Fixed(make([]byte, 8))
				e.Uint32(512)
				e.Uint32(4096)
			}
		}, nfs.StatusNotDir},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := fixture()
			m.add("/empty-dir", 0o040755, nil, 20)
			addr := serve(t, func(s *nfs.Server) { s.Export("/", m, nfs.ReadWrite()) })
			w := dial(t, addr)
			root := w.mount("/")
			fh, _ := w.lookup(root, "hello.txt")
			m.failWith(tc.key, errDriver)
			if st, _ := w.nfsCall(tc.proc, tc.args(root, fh)); st != tc.want {
				t.Fatalf("%s = %v, want %v", tc.name, st, tc.want)
			}
		})
	}
}

// TestCapabilityFailures covers the optional interfaces failing.
func TestCapabilityFailures(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*capFS)
		proc  uint32
		args  func(root, fh []byte) func(*xdr.Encoder)
		want  nfs.Status
	}{
		{"Truncate fails", func(c *capFS) { c.truncErr = errDriver }, 2,
			func(root, fh []byte) func(*xdr.Encoder) {
				return func(e *xdr.Encoder) { e.Opaque(fh); sattrSize(1)(e); e.Bool(false) }
			}, nfs.StatusIO},
		{"Chmod fails", func(c *capFS) { c.chmodErr = errDriver }, 2,
			func(root, fh []byte) func(*xdr.Encoder) {
				return func(e *xdr.Encoder) { e.Opaque(fh); sattrMode(0o600)(e); e.Bool(false) }
			}, nfs.StatusIO},
		{"Chown fails", func(c *capFS) { c.chownErr = errDriver }, 2,
			func(root, fh []byte) func(*xdr.Encoder) {
				return func(e *xdr.Encoder) {
					e.Opaque(fh)
					e.Bool(false)
					e.Bool(true)
					e.Uint32(1)
					e.Bool(false)
					e.Bool(false)
					e.Uint32(0)
					e.Uint32(0)
					e.Bool(false)
				}
			}, nfs.StatusIO},
		{"Chtimes fails", func(c *capFS) { c.timesErr = errDriver }, 2,
			func(root, fh []byte) func(*xdr.Encoder) {
				return func(e *xdr.Encoder) {
					e.Opaque(fh)
					e.Bool(false)
					e.Bool(false)
					e.Bool(false)
					e.Bool(false)
					e.Uint32(1)
					e.Uint32(1)
					e.Bool(false)
				}
			}, nfs.StatusIO},
		{"Symlink fails", func(c *capFS) { c.symErr = errDriver }, 10,
			func(root, fh []byte) func(*xdr.Encoder) {
				return func(e *xdr.Encoder) { e.Opaque(root); e.String("l"); sattrNone(e); e.String("/t") }
			}, nfs.StatusIO},
		{"Link fails", func(c *capFS) { c.linkErr = errDriver }, 15,
			func(root, fh []byte) func(*xdr.Encoder) {
				return func(e *xdr.Encoder) { e.Opaque(fh); e.Opaque(root); e.String("h") }
			}, nfs.StatusIO},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &capFS{memFS: fixture()}
			tc.setup(c)
			addr := serve(t, func(s *nfs.Server) { s.Export("/", c, nfs.ReadWrite()) })
			w := dial(t, addr)
			root := w.mount("/")
			fh, _ := w.lookup(root, "hello.txt")
			if st, _ := w.nfsCall(tc.proc, tc.args(root, fh)); st != tc.want {
				t.Fatalf("%s = %v, want %v", tc.name, st, tc.want)
			}
		})
	}
}
