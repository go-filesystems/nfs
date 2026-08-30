package nfs_test

import (
	"bytes"
	"testing"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/nfs"
	"github.com/go-filesystems/nfs/xdr"
)

// procArgs describes one NFS procedure's argument list as a sequence of
// encoders, so a test can truncate it after any prefix.
type procArgs struct {
	name  string
	proc  uint32
	parts []func(e *xdr.Encoder, root, fh []byte)
}

func fhPart(useRoot bool) func(*xdr.Encoder, []byte, []byte) {
	return func(e *xdr.Encoder, root, fh []byte) {
		if useRoot {
			e.Opaque(root)
			return
		}
		e.Opaque(fh)
	}
}

func namePart(n string) func(*xdr.Encoder, []byte, []byte) {
	return func(e *xdr.Encoder, root, fh []byte) { e.String(n) }
}

func u32Part(v uint32) func(*xdr.Encoder, []byte, []byte) {
	return func(e *xdr.Encoder, root, fh []byte) { e.Uint32(v) }
}

func u64Part(v uint64) func(*xdr.Encoder, []byte, []byte) {
	return func(e *xdr.Encoder, root, fh []byte) { e.Uint64(v) }
}

func fixedPart(n int) func(*xdr.Encoder, []byte, []byte) {
	return func(e *xdr.Encoder, root, fh []byte) { e.Fixed(make([]byte, n)) }
}

func opaquePart(b []byte) func(*xdr.Encoder, []byte, []byte) {
	return func(e *xdr.Encoder, root, fh []byte) { e.Opaque(b) }
}

func sattrPart() func(*xdr.Encoder, []byte, []byte) {
	return func(e *xdr.Encoder, root, fh []byte) { sattrNone(e) }
}

// allProcs is every NFSv3 procedure that takes arguments, described part by
// part.
var allProcs = []procArgs{
	{"GETATTR", 1, []func(*xdr.Encoder, []byte, []byte){fhPart(false)}},
	{"SETATTR", 2, []func(*xdr.Encoder, []byte, []byte){fhPart(false), sattrPart(), u32Part(0)}},
	{"LOOKUP", 3, []func(*xdr.Encoder, []byte, []byte){fhPart(true), namePart("hello.txt")}},
	{"ACCESS", 4, []func(*xdr.Encoder, []byte, []byte){fhPart(false), u32Part(0x3f)}},
	{"READLINK", 5, []func(*xdr.Encoder, []byte, []byte){fhPart(false)}},
	{"READ", 6, []func(*xdr.Encoder, []byte, []byte){fhPart(false), u64Part(0), u32Part(16)}},
	{"WRITE", 7, []func(*xdr.Encoder, []byte, []byte){fhPart(false), u64Part(0), u32Part(1), u32Part(2), opaquePart([]byte("x"))}},
	{"CREATE", 8, []func(*xdr.Encoder, []byte, []byte){fhPart(true), namePart("z"), u32Part(0), sattrPart()}},
	{"MKDIR", 9, []func(*xdr.Encoder, []byte, []byte){fhPart(true), namePart("z"), sattrPart()}},
	{"SYMLINK", 10, []func(*xdr.Encoder, []byte, []byte){fhPart(true), namePart("z"), sattrPart(), namePart("/t")}},
	{"MKNOD", 11, []func(*xdr.Encoder, []byte, []byte){fhPart(true), namePart("z")}},
	{"REMOVE", 12, []func(*xdr.Encoder, []byte, []byte){fhPart(true), namePart("hello.txt")}},
	{"RMDIR", 13, []func(*xdr.Encoder, []byte, []byte){fhPart(true), namePart("dir")}},
	{"RENAME", 14, []func(*xdr.Encoder, []byte, []byte){fhPart(true), namePart("hello.txt"), fhPart(true), namePart("z")}},
	{"LINK", 15, []func(*xdr.Encoder, []byte, []byte){fhPart(false), fhPart(true), namePart("z")}},
	{"READDIR", 16, []func(*xdr.Encoder, []byte, []byte){fhPart(true), u64Part(0), fixedPart(8), u32Part(4096)}},
	{"READDIRPLUS", 17, []func(*xdr.Encoder, []byte, []byte){fhPart(true), u64Part(0), fixedPart(8), u32Part(512), u32Part(4096)}},
	{"FSSTAT", 18, []func(*xdr.Encoder, []byte, []byte){fhPart(true)}},
	{"FSINFO", 19, []func(*xdr.Encoder, []byte, []byte){fhPart(true)}},
	{"PATHCONF", 20, []func(*xdr.Encoder, []byte, []byte){fhPart(true)}},
	{"COMMIT", 21, []func(*xdr.Encoder, []byte, []byte){fhPart(false), u64Part(0), u32Part(0)}},
}

// TestTruncatedArgumentsAreGarbageArgs: every procedure must refuse a short
// argument list at the RPC level rather than decoding whatever follows. A
// server that guesses here hands the client a reply for a request it did not
// make.
func TestTruncatedArgumentsAreGarbageArgs(t *testing.T) {
	addr := serve(t, func(s *nfs.Server) { s.Export("/", fixture(), nfs.ReadWrite()) })
	w := dial(t, addr)
	root := w.mount("/")
	fh, _ := w.lookup(root, "hello.txt")

	for _, p := range allProcs {
		for cut := range len(p.parts) {
			e := xdr.NewEncoder(nil)
			for _, part := range p.parts[:cut] {
				part(e, root, fh)
			}
			r := w.callBytes(nfs.ProgramNFS, nfs.VersionNFS, p.proc, e.Bytes())
			if r.acceptStat != 4 {
				t.Errorf("%s truncated after %d parts: accept_stat = %d, want GARBAGE_ARGS", p.name, cut, r.acceptStat)
			}
		}
	}
}

// TestForgedHandleIsRefused: the server dereferences whatever 64 bytes
// arrive, so a handle it did not mint must fail rather than index a table.
func TestForgedHandleIsRefused(t *testing.T) {
	addr := serve(t, func(s *nfs.Server) { s.Export("/", fixture(), nfs.ReadWrite()) })
	w := dial(t, addr)
	root := w.mount("/")
	fh, _ := w.lookup(root, "hello.txt")
	forged := bytes.Repeat([]byte{0xa5}, 60)

	for _, p := range allProcs {
		e := xdr.NewEncoder(nil)
		e.Opaque(forged)
		for _, part := range p.parts[1:] {
			part(e, forged, forged)
		}
		r := w.callBytes(nfs.ProgramNFS, nfs.VersionNFS, p.proc, e.Bytes())
		if r.acceptStat != 0 {
			t.Errorf("%s with a forged handle: accept_stat = %d, want an NFS-level error", p.name, r.acceptStat)
			continue
		}
		st, err := r.body.Uint32()
		if err != nil {
			t.Errorf("%s: %v", p.name, err)
			continue
		}
		if nfs.Status(st) != nfs.StatusBadHandle {
			t.Errorf("%s with a forged handle = %v, want BADHANDLE", p.name, nfs.Status(st))
		}
	}
	_ = fh
}

// TestSecondForgedHandle covers the procedures that decode two handles: the
// second must be validated as strictly as the first.
func TestSecondForgedHandle(t *testing.T) {
	addr := serve(t, func(s *nfs.Server) { s.Export("/", fixture(), nfs.ReadWrite()) })
	w := dial(t, addr)
	root := w.mount("/")
	fh, _ := w.lookup(root, "hello.txt")
	forged := bytes.Repeat([]byte{0x5a}, 60)

	st, _ := w.nfsCall(14, func(e *xdr.Encoder) {
		e.Opaque(root)
		e.String("hello.txt")
		e.Opaque(forged)
		e.String("z")
	})
	if st != nfs.StatusBadHandle {
		t.Fatalf("RENAME with a forged target handle = %v, want BADHANDLE", st)
	}
	st, _ = w.nfsCall(15, func(e *xdr.Encoder) {
		e.Opaque(fh)
		e.Opaque(forged)
		e.String("z")
	})
	if st != nfs.StatusBadHandle {
		t.Fatalf("LINK with a forged directory handle = %v, want BADHANDLE", st)
	}
}

// TestBadNameInEveryDirOp: the single component is the only untrusted name
// that enters the path space, so every procedure that takes one must reject
// a slash the same way.
func TestBadNameInEveryDirOp(t *testing.T) {
	addr := serve(t, func(s *nfs.Server) { s.Export("/", fixture(), nfs.ReadWrite()) })
	w := dial(t, addr)
	root := w.mount("/")
	for _, p := range []procArgs{
		allProcs[7], allProcs[8], allProcs[9], allProcs[10],
		allProcs[11], allProcs[12], allProcs[13], allProcs[14],
	} {
		e := xdr.NewEncoder(nil)
		for i, part := range p.parts {
			slashHere := i == 1
			if p.proc == 15 {
				slashHere = i == 2
			}
			if slashHere || (p.proc == 14 && i == 3) {
				e.String("a/b")
				continue
			}
			part(e, root, root)
		}
		r := w.callBytes(nfs.ProgramNFS, nfs.VersionNFS, p.proc, e.Bytes())
		if r.acceptStat != 0 {
			t.Errorf("%s with a slashed name: accept_stat = %d", p.name, r.acceptStat)
			continue
		}
		st, _ := r.body.Uint32()
		if nfs.Status(st) != nfs.StatusInval {
			t.Errorf("%s with a slashed name = %v, want INVAL", p.name, nfs.Status(st))
		}
	}
}

// TestCrossExportOperations: NFSv3 has no cross-filesystem rename or link.
func TestCrossExportOperations(t *testing.T) {
	a, b := fixture(), fixture()
	addr := serve(t, func(s *nfs.Server) {
		s.Export("/a", a, nfs.ReadWrite())
		s.Export("/b", b, nfs.ReadWrite())
	})
	w := dial(t, addr)
	rootA := w.mount("/a")
	rootB := w.mount("/b")
	if bytes.Equal(rootA, rootB) {
		t.Fatal("two exports minted the same root handle")
	}
	st, _ := w.nfsCall(14, func(e *xdr.Encoder) {
		e.Opaque(rootA)
		e.String("hello.txt")
		e.Opaque(rootB)
		e.String("z")
	})
	if st != nfs.StatusXDev {
		t.Fatalf("cross-export RENAME = %v, want XDEV", st)
	}
	fhA, _ := w.lookup(rootA, "hello.txt")
	st, _ = w.nfsCall(15, func(e *xdr.Encoder) {
		e.Opaque(fhA)
		e.Opaque(rootB)
		e.String("z")
	})
	if st != nfs.StatusXDev {
		t.Fatalf("cross-export LINK = %v, want XDEV", st)
	}
}

// TestMutationsOnANonDirectoryParent covers the NOTDIR branch shared by every
// creating procedure.
func TestMutationsOnANonDirectoryParent(t *testing.T) {
	addr := serve(t, func(s *nfs.Server) { s.Export("/", fixture(), nfs.ReadWrite()) })
	w := dial(t, addr)
	root := w.mount("/")
	fh, _ := w.lookup(root, "hello.txt")
	for _, tc := range []struct {
		name string
		proc uint32
		args func(*xdr.Encoder)
	}{
		{"CREATE", 8, func(e *xdr.Encoder) { e.Opaque(fh); e.String("z"); e.Uint32(0); sattrNone(e) }},
		{"MKDIR", 9, func(e *xdr.Encoder) { e.Opaque(fh); e.String("z"); sattrNone(e) }},
		{"SYMLINK", 10, func(e *xdr.Encoder) { e.Opaque(fh); e.String("z"); sattrNone(e); e.String("/t") }},
		{"REMOVE", 12, func(e *xdr.Encoder) { e.Opaque(fh); e.String("z") }},
		{"RENAME", 14, func(e *xdr.Encoder) { e.Opaque(fh); e.String("z"); e.Opaque(root); e.String("y") }},
		{"LINK", 15, func(e *xdr.Encoder) { e.Opaque(fh); e.Opaque(fh); e.String("z") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if st, _ := w.nfsCall(tc.proc, tc.args); st != nfs.StatusNotDir {
				t.Fatalf("%s under a regular file = %v, want NOTDIR", tc.name, st)
			}
		})
	}
}

// TestOperationsOnAMissingParent covers the branch where the directory handle
// resolves but the path behind it has since disappeared.
func TestOperationsOnAMissingParent(t *testing.T) {
	m := fixture()
	addr := serve(t, func(s *nfs.Server) { s.Export("/", m, nfs.ReadWrite()) })
	w := dial(t, addr)
	root := w.mount("/")
	dirFH, _ := w.lookup(root, "dir")
	delete(m.nodes, "/dir")
	delete(m.nodes, "/dir/nested.bin")

	for _, tc := range []struct {
		name string
		proc uint32
		args func(*xdr.Encoder)
		want nfs.Status
	}{
		{"GETATTR", 1, func(e *xdr.Encoder) { e.Opaque(dirFH) }, nfs.StatusNoEnt},
		{"SETATTR", 2, func(e *xdr.Encoder) { e.Opaque(dirFH); sattrNone(e); e.Bool(false) }, nfs.StatusNoEnt},
		{"ACCESS", 4, func(e *xdr.Encoder) { e.Opaque(dirFH); e.Uint32(0x3f) }, nfs.StatusNoEnt},
		{"READ", 6, func(e *xdr.Encoder) { e.Opaque(dirFH); e.Uint64(0); e.Uint32(1) }, nfs.StatusNoEnt},
		{"WRITE", 7, func(e *xdr.Encoder) {
			e.Opaque(dirFH)
			e.Uint64(0)
			e.Uint32(1)
			e.Uint32(2)
			e.Opaque([]byte("x"))
		}, nfs.StatusNoEnt},
		{"CREATE", 8, func(e *xdr.Encoder) { e.Opaque(dirFH); e.String("z"); e.Uint32(0); sattrNone(e) }, nfs.StatusNoEnt},
		{"MKNOD", 11, func(e *xdr.Encoder) { e.Opaque(dirFH); e.String("z") }, nfs.StatusNotSupp},
		{"READDIR", 16, func(e *xdr.Encoder) {
			e.Opaque(dirFH)
			e.Uint64(0)
			e.Fixed(make([]byte, 8))
			e.Uint32(4096)
		}, nfs.StatusNoEnt},
		{"COMMIT", 21, func(e *xdr.Encoder) { e.Opaque(dirFH); e.Uint64(0); e.Uint32(0) }, nfs.StatusNoEnt},
		{"LOOKUP", 3, func(e *xdr.Encoder) { e.Opaque(dirFH); e.String("nested.bin") }, nfs.StatusNoEnt},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if st, _ := w.nfsCall(tc.proc, tc.args); st != tc.want {
				t.Fatalf("%s on a vanished directory = %v, want %v", tc.name, st, tc.want)
			}
		})
	}
}

// TestReaddirPlusOnAVanishedEntry covers the branch where a listed name has
// no attributes: the entry is still emitted, with the optional fields absent,
// rather than the whole listing failing.
func TestReaddirPlusOnAVanishedEntry(t *testing.T) {
	m := fixture()
	m.failWith("Stat:/hello.txt", errDriver)
	addr := serve(t, func(s *nfs.Server) { s.Export("/", m) })
	w := dial(t, addr)
	root := w.mount("/")

	ents, st := w.readdirPlus(root, 8192)
	if st != nfs.StatusOK {
		t.Fatalf("READDIRPLUS: %v", st)
	}
	var found bool
	for _, e := range ents {
		if e.name != "hello.txt" {
			continue
		}
		found = true
		if e.hasFH {
			t.Fatal("READDIRPLUS attached a handle to an entry it could not stat")
		}
	}
	if !found {
		t.Fatal("READDIRPLUS dropped an entry it could not stat")
	}
	// READDIR takes the same branch for its fileid.
	if _, st := w.readdir(root, 4096); st != nfs.StatusOK {
		t.Fatalf("READDIR: %v", st)
	}
}

// TestMountProcedures covers the MOUNTv3 program.
func TestMountProcedures(t *testing.T) {
	addr := serve(t, func(s *nfs.Server) {
		s.Export("/", fixture())
		s.Export("/second", fixture())
	})
	w := dial(t, addr)

	t.Run("MNT of an unknown export", func(t *testing.T) {
		d := w.call(nfs.ProgramMount, nfs.VersionMount, 1, func(e *xdr.Encoder) { e.String("/nope") })
		if st := w.mustU32(d); st != 2 {
			t.Fatalf("MNT /nope = %d, want MNT3ERR_NOENT", st)
		}
	})
	t.Run("MNT normalises the path", func(t *testing.T) {
		// A client that asks for "//second/" must reach the same export.
		d := w.call(nfs.ProgramMount, nfs.VersionMount, 1, func(e *xdr.Encoder) { e.String("//second/") })
		if st := w.mustU32(d); st != 0 {
			t.Fatalf("MNT //second/ = %d, want OK", st)
		}
		if _, err := d.Opaque(); err != nil {
			t.Fatalf("MNT handle: %v", err)
		}
		n := w.mustU32(d)
		if n != 2 {
			t.Fatalf("MNT advertised %d auth flavours, want 2", n)
		}
	})
	t.Run("MNT with a garbage argument", func(t *testing.T) {
		r := w.callBytes(nfs.ProgramMount, nfs.VersionMount, 1, nil)
		if r.acceptStat != 4 {
			t.Fatalf("MNT with no argument: accept_stat = %d, want GARBAGE_ARGS", r.acceptStat)
		}
	})
	t.Run("DUMP is empty", func(t *testing.T) {
		d := w.call(nfs.ProgramMount, nfs.VersionMount, 2, nil)
		if v := w.mustU32(d); v != 0 {
			t.Fatalf("DUMP list head = %d, want 0 (empty)", v)
		}
	})
	t.Run("UMNT", func(t *testing.T) {
		w.call(nfs.ProgramMount, nfs.VersionMount, 3, func(e *xdr.Encoder) { e.String("/") })
		r := w.callBytes(nfs.ProgramMount, nfs.VersionMount, 3, nil)
		if r.acceptStat != 4 {
			t.Fatalf("UMNT with no argument: accept_stat = %d, want GARBAGE_ARGS", r.acceptStat)
		}
	})
	t.Run("UMNTALL", func(t *testing.T) {
		w.call(nfs.ProgramMount, nfs.VersionMount, 4, nil)
	})
	t.Run("EXPORT lists every export", func(t *testing.T) {
		d := w.call(nfs.ProgramMount, nfs.VersionMount, 5, nil)
		seen := map[string]bool{}
		for w.mustU32(d) == 1 {
			name, err := d.String()
			if err != nil {
				t.Fatalf("export name: %v", err)
			}
			seen[name] = true
			if w.mustU32(d) != 0 {
				t.Fatal("EXPORT advertised a host restriction that is not enforced")
			}
		}
		if !seen["/"] || !seen["/second"] {
			t.Fatalf("EXPORT listed %v, want / and /second", seen)
		}
	})
	t.Run("an unknown MOUNT procedure", func(t *testing.T) {
		r := w.callBytes(nfs.ProgramMount, nfs.VersionMount, 42, nil)
		if r.acceptStat != 3 {
			t.Fatalf("accept_stat = %d, want PROC_UNAVAIL", r.acceptStat)
		}
	})
}

// TestRandomAccessOpener drives the Opener path rather than the whole-file
// fallback, and checks the two produce identical bytes.
func TestRandomAccessOpener(t *testing.T) {
	base := fixture()
	o := &openFS{memFS: base}
	addr := serve(t, func(s *nfs.Server) { s.Export("/", o) })
	w := dial(t, addr)
	root := w.mount("/")
	dirFH, _ := w.lookup(root, "dir")
	fh, _ := w.lookup(dirFH, "nested.bin")

	direct, _ := base.ReadFile("/dir/nested.bin")
	var got []byte
	off := uint64(0)
	for {
		chunk, eof, st := w.read(fh, off, 997) // deliberately not a power of two
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
		t.Fatal("the Opener path returned different bytes from ReadFile")
	}
	// Past the end through the Opener.
	chunk, eof, st := w.read(fh, 1<<20, 16)
	if st != nfs.StatusOK || len(chunk) != 0 || !eof {
		t.Fatalf("READ past the end through the Opener = (%d, %v, %v)", len(chunk), eof, st)
	}
}

func TestOpenerFailures(t *testing.T) {
	t.Run("OpenFile returns an error", func(t *testing.T) {
		o := &openFS{memFS: fixture(), openErr: errDriver}
		addr := serve(t, func(s *nfs.Server) { s.Export("/", o) })
		w := dial(t, addr)
		root := w.mount("/")
		fh, _ := w.lookup(root, "hello.txt")
		if _, _, st := w.read(fh, 0, 16); st != nfs.StatusIO {
			t.Fatalf("READ through a failing Opener = %v, want IO", st)
		}
	})
	t.Run("OpenFile returns a nil File", func(t *testing.T) {
		o := &openFS{memFS: fixture(), nilFile: true}
		addr := serve(t, func(s *nfs.Server) { s.Export("/", o) })
		w := dial(t, addr)
		root := w.mount("/")
		fh, _ := w.lookup(root, "hello.txt")
		if _, _, st := w.read(fh, 0, 16); st != nfs.StatusIO {
			t.Fatalf("READ through an Opener returning nil = %v, want IO", st)
		}
	})
	t.Run("ReadAt fails", func(t *testing.T) {
		e := &errOpenFS{memFS: fixture(), err: errDriver}
		addr := serve(t, func(s *nfs.Server) { s.Export("/", e) })
		w := dial(t, addr)
		root := w.mount("/")
		fh, _ := w.lookup(root, "hello.txt")
		if _, _, st := w.read(fh, 0, 8); st != nfs.StatusIO {
			t.Fatalf("READ with a failing ReadAt = %v, want IO", st)
		}
	})
}

// TestNonInterfaceOpenersFallBack: a driver with a method NAMED OpenFile that
// is not filesystem.Opener must be read through ReadFile, not called.
//
// The first case is the one that documents the rule. foreignOpener has the
// right name, the right arity, the right semantics and a result type that is
// structurally identical to filesystem.File — and it is a different named
// type, so Go does not consider the interface satisfied. Its OpenFile serves
// bytes that are deliberately NOT the file's, so if the server ever matched by
// structure again this test would fail on content rather than on a nil check.
func TestNonInterfaceOpenersFallBack(t *testing.T) {
	for _, tc := range []struct {
		name string
		fs   filesystem.Filesystem
	}{
		{"a structurally identical but distinct File type", &foreignOpener{memFS: fixture()}},
		{"extra argument", &badOpener{memFS: fixture()}},
		{"wrong result type", &wrongResultOpener{memFS: fixture()}},
		{"argument is not a path", &notStringOpener{memFS: fixture()}},
		{"wrong arity", &oneResultOpener{memFS: fixture()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := serve(t, func(s *nfs.Server) {
				if err := s.Export("/", tc.fs); err != nil {
					t.Fatalf("Export: %v", err)
				}
			})
			w := dial(t, addr)
			root := w.mount("/")
			fh, _ := w.lookup(root, "hello.txt")
			data, _, st := w.read(fh, 0, 64)
			if st != nfs.StatusOK || string(data) != "hello, nfs\n" {
				t.Fatalf("READ = (%q, %v), want the ReadFile fallback to have served it", data, st)
			}
		})
	}
}

// TestUnknownNFSProcedure: a procedure this server does not implement must
// say so, or a client retries forever instead of falling back.
func TestUnknownNFSProcedure(t *testing.T) {
	addr := serve(t, func(s *nfs.Server) { s.Export("/", fixture()) })
	w := dial(t, addr)
	r := w.callBytes(nfs.ProgramNFS, nfs.VersionNFS, 99, nil)
	if r.acceptStat != 3 {
		t.Fatalf("accept_stat = %d, want PROC_UNAVAIL", r.acceptStat)
	}
}

// TestSattrDecodeTruncations walks every optional field of sattr3, since each
// "set" flag adds a value the decoder must then find.
func TestSattrDecodeTruncations(t *testing.T) {
	addr := serve(t, func(s *nfs.Server) { s.Export("/", fixture(), nfs.ReadWrite()) })
	w := dial(t, addr)
	root := w.mount("/")
	fh, _ := w.lookup(root, "hello.txt")

	full := func() []byte {
		e := xdr.NewEncoder(nil)
		e.Opaque(fh)
		sattrAll(e)
		e.Bool(true)
		e.Uint32(0)
		e.Uint32(0)
		return e.Bytes()
	}()
	for n := len(full) - 4; n > len(fh)+4; n -= 4 {
		r := w.callBytes(nfs.ProgramNFS, nfs.VersionNFS, 2, full[:n])
		if r.acceptStat != 4 {
			t.Fatalf("SETATTR truncated to %d bytes: accept_stat = %d, want GARBAGE_ARGS", n, r.acceptStat)
		}
	}
}

// TestCreateModeIsRejected covers the createmode3 discriminant.
func TestCreateModeIsRejected(t *testing.T) {
	addr := serve(t, func(s *nfs.Server) { s.Export("/", fixture(), nfs.ReadWrite()) })
	w := dial(t, addr)
	root := w.mount("/")
	r := w.callBytes(nfs.ProgramNFS, nfs.VersionNFS, 8, func() []byte {
		e := xdr.NewEncoder(nil)
		e.Opaque(root)
		e.String("z")
		e.Uint32(9) // not a createmode3
		return e.Bytes()
	}())
	if r.acceptStat != 4 {
		t.Fatalf("CREATE with an unknown createmode: accept_stat = %d, want GARBAGE_ARGS", r.acceptStat)
	}
	// An EXCLUSIVE create whose verifier is truncated.
	r = w.callBytes(nfs.ProgramNFS, nfs.VersionNFS, 8, func() []byte {
		e := xdr.NewEncoder(nil)
		e.Opaque(root)
		e.String("z")
		e.Uint32(2)
		return e.Bytes()
	}())
	if r.acceptStat != 4 {
		t.Fatalf("EXCLUSIVE CREATE with no verifier: accept_stat = %d, want GARBAGE_ARGS", r.acceptStat)
	}
}

// TestClientIgnoringAdvertisedLimits: a client is free to ask for more than
// FSINFO offered, and the server must clamp rather than obey.
func TestClientIgnoringAdvertisedLimits(t *testing.T) {
	m := fixture()
	addr := serve(t, func(s *nfs.Server) { s.Export("/", m, nfs.ReadWrite()) })
	w := dial(t, addr)
	root := w.mount("/")
	dirFH, _ := w.lookup(root, "dir")
	fh, _ := w.lookup(dirFH, "nested.bin")

	// READ above rtmax.
	data, _, st := w.read(fh, 0, 1<<20)
	if st != nfs.StatusOK {
		t.Fatalf("READ above rtmax: %v", st)
	}
	if len(data) > 1<<17 {
		t.Fatalf("READ returned %d bytes, above the advertised rtmax", len(data))
	}

	// READDIR above dtpref.
	if _, st := w.readdir(root, 1<<20); st != nfs.StatusOK {
		t.Fatalf("READDIR above dtpref: %v", st)
	}
	// READDIRPLUS above dtpref, and with maxcount zero.
	if _, st := w.readdirPlus(root, 1<<20); st != nfs.StatusOK {
		t.Fatalf("READDIRPLUS above dtpref: %v", st)
	}
	st, _ = w.nfsCall(17, func(e *xdr.Encoder) {
		e.Opaque(root)
		e.Uint64(0)
		e.Fixed(make([]byte, 8))
		e.Uint32(0)
		e.Uint32(0)
	})
	if st != nfs.StatusOK {
		t.Fatalf("READDIRPLUS with maxcount 0 = %v", st)
	}
}

// TestAccessOnAWritableExport is the other half of the read-only case: a
// client must be told it may modify, or it refuses operations up front.
func TestAccessOnAWritableExport(t *testing.T) {
	addr := serve(t, func(s *nfs.Server) { s.Export("/", fixture(), nfs.ReadWrite()) })
	w := dial(t, addr)
	root := w.mount("/")
	st, d := w.nfsCall(4, func(e *xdr.Encoder) {
		e.Opaque(root)
		e.Uint32(0x3f)
	})
	if st != nfs.StatusOK {
		t.Fatalf("ACCESS: %v", st)
	}
	w.skipPostOp(d)
	if got := w.mustU32(d); got != 0x3f {
		t.Fatalf("ACCESS on a writable export = %#x, want %#x", got, 0x3f)
	}
}

// TestSetAttrIgnoresWhatTheDriverCannotDo: mode, owner and times on a driver
// with no MetadataSetter are dropped, and the reply carries the real
// attributes so the client sees the truth immediately.
func TestSetAttrIgnoresWhatTheDriverCannotDo(t *testing.T) {
	m := fixture()
	addr := serve(t, func(s *nfs.Server) { s.Export("/", m, nfs.ReadWrite()) })
	w := dial(t, addr)
	root := w.mount("/")
	fh, _ := w.lookup(root, "hello.txt")
	st, d := w.nfsCall(2, func(e *xdr.Encoder) {
		e.Opaque(fh)
		sattrMode(0o600)(e)
		e.Bool(false)
	})
	if st != nfs.StatusOK {
		t.Fatalf("SETATTR mode on a driver with no MetadataSetter = %v, want OK", st)
	}
	w.skipWcc(d)
	stat, _ := m.Stat("/hello.txt")
	if stat.Mode()&0o7777 != 0o644 {
		t.Fatalf("mode changed to %#o on a driver that cannot chmod", stat.Mode()&0o7777)
	}
}

// TestSetAttrClientTimes covers the SET_TO_CLIENT_TIME arm of both timestamps.
func TestSetAttrClientTimes(t *testing.T) {
	c := &capFS{memFS: fixture()}
	addr := serve(t, func(s *nfs.Server) { s.Export("/", c, nfs.ReadWrite()) })
	w := dial(t, addr)
	root := w.mount("/")
	fh, _ := w.lookup(root, "hello.txt")
	st, _ := w.nfsCall(2, func(e *xdr.Encoder) {
		e.Opaque(fh)
		e.Bool(false)
		e.Bool(false)
		e.Bool(false)
		e.Bool(false)
		e.Uint32(2) // atime SET_TO_CLIENT_TIME
		e.Uint32(111)
		e.Uint32(0)
		e.Uint32(2) // mtime SET_TO_CLIENT_TIME
		e.Uint32(222)
		e.Uint32(0)
		e.Bool(false)
	})
	if st != nfs.StatusOK {
		t.Fatalf("SETATTR with client times = %v", st)
	}
	if c.nodes["/hello.txt"].mtime != 222 {
		t.Fatalf("mtime = %d, want the client's 222", c.nodes["/hello.txt"].mtime)
	}
}

// TestSattrSizeAndTimeTruncations walks the optional fields the earlier
// truncation test does not set.
func TestSattrSizeAndTimeTruncations(t *testing.T) {
	addr := serve(t, func(s *nfs.Server) { s.Export("/", fixture(), nfs.ReadWrite()) })
	w := dial(t, addr)
	root := w.mount("/")
	fh, _ := w.lookup(root, "hello.txt")

	// size set, then both timestamps SET_TO_CLIENT_TIME.
	e := xdr.NewEncoder(nil)
	e.Opaque(fh)
	e.Bool(false)
	e.Bool(false)
	e.Bool(false)
	e.Bool(true)
	e.Uint64(9)
	e.Uint32(2)
	e.Uint32(1)
	e.Uint32(0)
	e.Uint32(2)
	e.Uint32(2)
	e.Uint32(0)
	e.Bool(false)
	full := e.Bytes()
	for n := len(full) - 4; n > len(fh)+4+16; n -= 4 {
		r := w.callBytes(nfs.ProgramNFS, nfs.VersionNFS, 2, full[:n])
		if r.acceptStat != 4 {
			t.Fatalf("SETATTR truncated to %d bytes: accept_stat = %d, want GARBAGE_ARGS", n, r.acceptStat)
		}
	}
}
