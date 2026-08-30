package nfs_test

import (
	"bytes"
	"testing"

	"github.com/go-filesystems/nfs"
	"github.com/go-filesystems/nfs/xdr"
)

// fixture builds a small tree: /hello.txt, /dir/, /dir/nested.bin, /link.
func fixture() *memFS {
	m := newMemFS()
	m.add("/hello.txt", 0o100644, []byte("hello, nfs\n"), 7)
	m.add("/dir", 0o040755, nil, 8)
	m.add("/dir/nested.bin", 0o100600, bytes.Repeat([]byte("ab"), 5000), 9)
	m.add("/empty", 0o100644, nil, 0)
	return m
}

func TestMountAndRead(t *testing.T) {
	m := fixture()
	addr := serve(t, func(s *nfs.Server) {
		if err := s.Export("/", m, nfs.WithCapacity(1<<20, 1<<19)); err != nil {
			t.Fatalf("Export: %v", err)
		}
	})
	w := dial(t, addr)

	root := w.mount("/")
	if len(root) != 60 {
		t.Fatalf("root handle length = %d, want 60", len(root))
	}

	fh, st := w.lookup(root, "hello.txt")
	if st != nfs.StatusOK {
		t.Fatalf("LOOKUP hello.txt: %v", st)
	}
	data, eof, st := w.read(fh, 0, 4096)
	if st != nfs.StatusOK {
		t.Fatalf("READ: %v", st)
	}
	if got, want := string(data), "hello, nfs\n"; got != want {
		t.Fatalf("READ = %q, want %q", got, want)
	}
	if !eof {
		t.Fatal("READ did not report eof at end of a short file")
	}

	// A short read from the middle, and the byte-for-byte comparison with
	// what the driver itself returns.
	direct, err := m.ReadFile("/dir/nested.bin")
	if err != nil {
		t.Fatalf("driver ReadFile: %v", err)
	}
	dirFH, st := w.lookup(root, "dir")
	if st != nfs.StatusOK {
		t.Fatalf("LOOKUP dir: %v", st)
	}
	nestedFH, st := w.lookup(dirFH, "nested.bin")
	if st != nfs.StatusOK {
		t.Fatalf("LOOKUP nested.bin: %v", st)
	}
	var got []byte
	off := uint64(0)
	for {
		chunk, eof, st := w.read(nestedFH, off, 1024)
		if st != nfs.StatusOK {
			t.Fatalf("READ at %d: %v", off, st)
		}
		got = append(got, chunk...)
		off += uint64(len(chunk))
		if eof {
			break
		}
	}
	if !bytes.Equal(got, direct) {
		t.Fatalf("NFS read %d bytes, driver returned %d, contents differ", len(got), len(direct))
	}

	// Reading past the end is eof with no data, not an error.
	chunk, eof, st := w.read(fh, 1_000_000, 16)
	if st != nfs.StatusOK || len(chunk) != 0 || !eof {
		t.Fatalf("READ past end = (%d bytes, eof=%v, %v)", len(chunk), eof, st)
	}
}

func TestLookupDotAndDotDot(t *testing.T) {
	addr := serve(t, func(s *nfs.Server) { s.Export("/", fixture()) })
	w := dial(t, addr)
	root := w.mount("/")
	dirFH, _ := w.lookup(root, "dir")

	self, st := w.lookup(dirFH, ".")
	if st != nfs.StatusOK || !bytes.Equal(self, dirFH) {
		t.Fatalf(`LOOKUP "." = (%x, %v), want the same handle`, self, st)
	}
	up, st := w.lookup(dirFH, "..")
	if st != nfs.StatusOK || !bytes.Equal(up, root) {
		t.Fatalf(`LOOKUP ".." = (%x, %v), want the root handle`, up, st)
	}
	// ".." at the root is clamped: nothing above an export is nameable.
	up, st = w.lookup(root, "..")
	if st != nfs.StatusOK || !bytes.Equal(up, root) {
		t.Fatalf(`LOOKUP ".." at root = (%x, %v), want the root handle`, up, st)
	}
}

func TestLookupErrors(t *testing.T) {
	addr := serve(t, func(s *nfs.Server) { s.Export("/", fixture()) })
	w := dial(t, addr)
	root := w.mount("/")

	for _, tc := range []struct {
		name string
		arg  string
		want nfs.Status
	}{
		{"missing", "nope", nfs.StatusNoEnt},
		{"empty", "", nfs.StatusInval},
		{"slash", "a/b", nfs.StatusInval},
		{"nul", "a\x00b", nfs.StatusInval},
		{"too long", string(bytes.Repeat([]byte("x"), 256)), nfs.StatusNameTooLong},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, st := w.lookup(root, tc.arg); st != tc.want {
				t.Fatalf("LOOKUP %q = %v, want %v", tc.arg, st, tc.want)
			}
		})
	}
}

func TestReaddirAndPlus(t *testing.T) {
	addr := serve(t, func(s *nfs.Server) { s.Export("/", fixture()) })
	w := dial(t, addr)
	root := w.mount("/")

	ents, st := w.readdir(root, 4096)
	if st != nfs.StatusOK {
		t.Fatalf("READDIR: %v", st)
	}
	want := []string{".", "..", "dir", "empty", "hello.txt"}
	var names []string
	for _, e := range ents {
		names = append(names, e.name)
	}
	if len(names) != len(want) {
		t.Fatalf("READDIR names = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("READDIR names = %v, want %v", names, want)
		}
	}

	// The driver's own "." and ".." must not be echoed a second time.
	seen := map[string]int{}
	for _, n := range names {
		seen[n]++
		if seen[n] > 1 {
			t.Fatalf("READDIR emitted %q twice", n)
		}
	}

	// Empty files report inode 0 through the driver; the server must still
	// give them a unique fileid, or clients alias them together.
	plus, st := w.readdirPlus(root, 8192)
	if st != nfs.StatusOK {
		t.Fatalf("READDIRPLUS: %v", st)
	}
	ids := map[uint64]string{}
	for _, e := range plus {
		if e.name == "." || e.name == ".." {
			continue
		}
		if prev, dup := ids[e.fileid]; dup {
			t.Fatalf("fileid %d shared by %q and %q", e.fileid, prev, e.name)
		}
		ids[e.fileid] = e.name
		if !e.hasFH {
			t.Fatalf("READDIRPLUS entry %q carried no handle", e.name)
		}
	}
	// Every handle from READDIRPLUS must be usable without a LOOKUP.
	for _, e := range plus {
		if e.name != "hello.txt" {
			continue
		}
		data, _, st := w.read(e.fh, 0, 64)
		if st != nfs.StatusOK || string(data) != "hello, nfs\n" {
			t.Fatalf("READ via READDIRPLUS handle = (%q, %v)", data, st)
		}
	}
}

// TestReaddirPaginates forces multiple round trips by shrinking the byte
// budget, which is the path a client takes on any directory of real size.
func TestReaddirPaginates(t *testing.T) {
	m := newMemFS()
	for i := range 40 {
		m.add("/f"+string(rune('a'+i%26))+string(rune('a'+i/26)), 0o100644, []byte{byte(i)}, uint64(100+i))
	}
	addr := serve(t, func(s *nfs.Server) { s.Export("/", m) })
	w := dial(t, addr)
	root := w.mount("/")

	ents, st := w.readdir(root, 200)
	if st != nfs.StatusOK {
		t.Fatalf("READDIR: %v", st)
	}
	if len(ents) != 42 {
		t.Fatalf("READDIR returned %d entries across pages, want 42", len(ents))
	}
	plus, st := w.readdirPlus(root, 600)
	if st != nfs.StatusOK {
		t.Fatalf("READDIRPLUS: %v", st)
	}
	if len(plus) != 42 {
		t.Fatalf("READDIRPLUS returned %d entries across pages, want 42", len(plus))
	}
}

func TestBadCookie(t *testing.T) {
	addr := serve(t, func(s *nfs.Server) { s.Export("/", fixture()) })
	w := dial(t, addr)
	root := w.mount("/")

	// A cookie past the end of the listing.
	st, _ := w.nfsCall(16, func(e *xdr.Encoder) {
		e.Opaque(root)
		e.Uint64(9999)
		e.Fixed(make([]byte, 8))
		e.Uint32(4096)
	})
	if st != nfs.StatusBadCookie {
		t.Fatalf("READDIR with an out-of-range cookie = %v, want BAD_COOKIE", st)
	}
	// A stale verifier on a resumed call.
	st, _ = w.nfsCall(16, func(e *xdr.Encoder) {
		e.Opaque(root)
		e.Uint64(2)
		e.Fixed([]byte("BADVERF!"))
		e.Uint32(4096)
	})
	if st != nfs.StatusBadCookie {
		t.Fatalf("READDIR with a stale verifier = %v, want BAD_COOKIE", st)
	}
}

func TestAccessAndInfoProcedures(t *testing.T) {
	addr := serve(t, func(s *nfs.Server) {
		s.Export("/", fixture(), nfs.WithCapacity(4096, 2048))
	})
	w := dial(t, addr)
	root := w.mount("/")

	// ACCESS on a read-only export must not offer MODIFY/EXTEND/DELETE.
	st, d := w.nfsCall(4, func(e *xdr.Encoder) {
		e.Opaque(root)
		e.Uint32(0x3f)
	})
	if st != nfs.StatusOK {
		t.Fatalf("ACCESS: %v", st)
	}
	w.skipPostOp(d)
	if got := w.mustU32(d); got != 0x23 {
		t.Fatalf("ACCESS on a read-only export = %#x, want %#x", got, 0x23)
	}

	st, d = w.nfsCall(19, func(e *xdr.Encoder) { e.Opaque(root) })
	if st != nfs.StatusOK {
		t.Fatalf("FSINFO: %v", st)
	}
	w.skipPostOp(d)
	if rtmax := w.mustU32(d); rtmax != 1<<17 {
		t.Fatalf("FSINFO rtmax = %d, want %d", rtmax, 1<<17)
	}

	st, d = w.nfsCall(18, func(e *xdr.Encoder) { e.Opaque(root) })
	if st != nfs.StatusOK {
		t.Fatalf("FSSTAT: %v", st)
	}
	w.skipPostOp(d)
	if tbytes := w.mustU64(d); tbytes != 4096 {
		t.Fatalf("FSSTAT tbytes = %d, want 4096 (WithCapacity)", tbytes)
	}

	st, d = w.nfsCall(20, func(e *xdr.Encoder) { e.Opaque(root) })
	if st != nfs.StatusOK {
		t.Fatalf("PATHCONF: %v", st)
	}
	w.skipPostOp(d)
	w.mustU32(d) // linkmax
	if nameMax := w.mustU32(d); nameMax != 255 {
		t.Fatalf("PATHCONF name_max = %d, want 255", nameMax)
	}

	// NULL must succeed with an empty body.
	w.call(nfs.ProgramNFS, nfs.VersionNFS, 0, nil)
	w.call(nfs.ProgramMount, nfs.VersionMount, 0, nil)
}

func TestGetAttrShape(t *testing.T) {
	addr := serve(t, func(s *nfs.Server) { s.Export("/", fixture()) })
	w := dial(t, addr)
	root := w.mount("/")
	fh, _ := w.lookup(root, "hello.txt")

	st, d := w.nfsCall(1, func(e *xdr.Encoder) { e.Opaque(fh) })
	if st != nfs.StatusOK {
		t.Fatalf("GETATTR: %v", st)
	}
	a := fattrView{}
	a.ftype = w.mustU32(d)
	a.mode = w.mustU32(d)
	a.nlink = w.mustU32(d)
	w.mustU32(d)
	w.mustU32(d)
	a.size = w.mustU64(d)
	if a.ftype != 1 {
		t.Fatalf("ftype = %d, want 1 (NF3REG)", a.ftype)
	}
	if a.size != 11 {
		t.Fatalf("size = %d, want 11", a.size)
	}
	// Read-only export: the write bits must be cleared so a client's own
	// permission check agrees with the ROFS it would otherwise discover late.
	if a.mode&0o222 != 0 {
		t.Fatalf("mode = %#o, want no write bits on a read-only export", a.mode)
	}
	if a.nlink != 1 {
		t.Fatalf("nlink = %d, want 1 (find's leaf optimisation must stay off)", a.nlink)
	}

	// A directory reports NF3DIR.
	st, d = w.nfsCall(1, func(e *xdr.Encoder) { e.Opaque(root) })
	if st != nfs.StatusOK {
		t.Fatalf("GETATTR root: %v", st)
	}
	if ftype := w.mustU32(d); ftype != 2 {
		t.Fatalf("root ftype = %d, want 2 (NF3DIR)", ftype)
	}
}

func TestReadOnDirectoryIsISDIR(t *testing.T) {
	addr := serve(t, func(s *nfs.Server) { s.Export("/", fixture()) })
	w := dial(t, addr)
	root := w.mount("/")
	if _, _, st := w.read(root, 0, 16); st != nfs.StatusIsDir {
		t.Fatalf("READ on a directory = %v, want ISDIR", st)
	}
}
