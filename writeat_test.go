package nfs_test

import (
	"bytes"
	"strings"
	"testing"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/nfs"
	"github.com/go-filesystems/nfs/xdr"
)

// write performs WRITE and returns the count the server acknowledged.
func (w *wire) write(fh []byte, off uint64, data []byte) (uint32, nfs.Status) {
	w.t.Helper()
	st, d := w.nfsCall(7, func(e *xdr.Encoder) {
		e.Opaque(fh)
		e.Uint64(off)
		e.Uint32(uint32(len(data)))
		e.Uint32(2) // FILE_SYNC
		e.Opaque(data)
	})
	if st != nfs.StatusOK {
		return 0, st
	}
	w.skipWcc(d)
	n := w.mustU32(d)
	if committed := w.mustU32(d); committed != 2 {
		w.t.Fatalf("WRITE committed = %d, want 2 (FILE_SYNC)", committed)
	}
	if _, err := d.Fixed(8); err != nil {
		w.t.Fatalf("WRITE verf: %v", err)
	}
	return n, st
}

// readAll drains a file through READ, which is the only way this test suite
// is allowed to look at a file: through the wire, not through the driver's
// Go API. A positional write that landed in the right place on disk but that
// the server then describes wrongly is still a broken mount.
func (w *wire) readAll(fh []byte, size int) []byte {
	w.t.Helper()
	var got []byte
	off := uint64(0)
	for {
		chunk, eof, st := w.read(fh, off, 997) // deliberately not a power of two
		if st != nfs.StatusOK {
			w.t.Fatalf("READ at %d: %v", off, st)
		}
		got = append(got, chunk...)
		off += uint64(len(chunk))
		if eof || len(got) > size+1<<16 {
			break
		}
	}
	return got
}

// writeCase is one (offset, length) shape. The set below is chosen to cover
// every way a positional write can go wrong that a whole-file rewrite cannot:
// a partial overwrite, a write that ends exactly at the old end, one that
// extends, one that starts past the end and therefore leaves a HOLE which must
// read back as zeros, and one that replaces everything.
type writeCase struct {
	name string
	off  uint64
	n    int
}

var writeCases = []writeCase{
	{"at the start", 0, 64},
	{"inside, aligned to nothing in particular", 997, 300},
	{"ending exactly at the old end", 9900, 100},
	{"the last byte", 9999, 1},
	{"extending past the end", 9990, 100},
	{"starting exactly at the end", 10000, 128},
	{"leaving a hole, which must read as zeros", 12000, 64},
	{"a hole far past the end", 40000, 16},
	{"replacing the whole file", 0, 10000},
	{"empty write", 500, 0},
}

// TestPositionalWriteMatchesReadModifyWrite is the verification this whole
// change exists for.
//
// For each shape, the SAME WRITE is issued twice over the wire: once to a
// server whose driver implements filesystem.WritableFile, and once to a server
// whose driver does not and which therefore takes the ReadFile+splice+
// WriteFile fallback. The two files must end up byte-for-byte identical, and
// must read back identically through READ.
//
// The fallback is the oracle on purpose. It is the code that was there before,
// it is obviously correct because it manipulates a whole []byte in memory, and
// it is what every client saw. A positional write that disagrees with it is a
// regression by definition, whatever the specification says.
func TestPositionalWriteMatchesReadModifyWrite(t *testing.T) {
	for _, tc := range writeCases {
		t.Run(tc.name, func(t *testing.T) {
			payload := make([]byte, tc.n)
			for i := range payload {
				payload[i] = byte('A' + i%26)
			}

			fast := &openFS{memFS: fixture(), writable: true}
			slow := fixture()

			fastFH, fastW := exportAndLookup(t, fast, "/dir/nested.bin")
			slowFH, slowW := exportAndLookup(t, slow, "/dir/nested.bin")

			if n, st := fastW.write(fastFH, tc.off, payload); st != nfs.StatusOK || int(n) != tc.n {
				t.Fatalf("positional WRITE = (%d, %v), want (%d, OK)", n, st, tc.n)
			}
			if n, st := slowW.write(slowFH, tc.off, payload); st != nfs.StatusOK || int(n) != tc.n {
				t.Fatalf("fallback WRITE = (%d, %v), want (%d, OK)", n, st, tc.n)
			}

			// The driver's own view: the two images must be identical.
			fastBytes, err := fast.memFS.ReadFile("/dir/nested.bin")
			if err != nil {
				t.Fatalf("driver ReadFile after the positional write: %v", err)
			}
			slowBytes, err := slow.ReadFile("/dir/nested.bin")
			if err != nil {
				t.Fatalf("driver ReadFile after the fallback write: %v", err)
			}
			if !bytes.Equal(fastBytes, slowBytes) {
				t.Fatalf("positional write produced %d bytes, read-modify-write produced %d; first difference at %d",
					len(fastBytes), len(slowBytes), firstDiff(fastBytes, slowBytes))
			}

			// ...and the server's view of them, through READ, must agree too:
			// a right file described wrongly is still a broken mount.
			fastRead := fastW.readAll(fastFH, len(fastBytes))
			slowRead := slowW.readAll(slowFH, len(slowBytes))
			if !bytes.Equal(fastRead, slowRead) {
				t.Fatalf("READ disagrees between the two paths at byte %d", firstDiff(fastRead, slowRead))
			}
			if !bytes.Equal(fastRead, fastBytes) {
				t.Fatalf("READ over the positional path disagrees with the driver at byte %d",
					firstDiff(fastRead, fastBytes))
			}

			// A hole must be zeros, not whatever the allocator had. Checked
			// explicitly rather than inferred from the two paths agreeing,
			// because they could agree on the wrong thing.
			if tc.off > 10000 {
				if hole := fastBytes[10000:tc.off]; !bytes.Equal(hole, make([]byte, len(hole))) {
					t.Fatalf("the hole at [10000,%d) is not zero-filled", tc.off)
				}
			}

			// The positional path must not have rewritten the whole file:
			// that is the entire point, and counting WriteFile calls is the
			// only way to prove it did not silently fall back.
			if fast.wholeFileWrites != 0 {
				t.Fatalf("the positional path called WriteFile %d times; it must call none", fast.wholeFileWrites)
			}
			if tc.n > 0 {
				if fast.lastWriteOff != int64(tc.off) || fast.lastWriteLen != tc.n {
					t.Fatalf("driver saw WriteAt(len=%d, off=%d), client sent (len=%d, off=%d)",
						fast.lastWriteLen, fast.lastWriteOff, tc.n, tc.off)
				}
			}
		})
	}
}

// TestSequentialWriteIsPositional is the shape a real client produces: a file
// written from offset 0 in fixed-size blocks. It is the case the 90 kB/s
// measurement came from, so it is the case pinned here.
func TestSequentialWriteIsPositional(t *testing.T) {
	const block, blocks = 8192, 16
	want := make([]byte, block*blocks)
	for i := range want {
		want[i] = byte(i * 7)
	}

	fs := &openFS{memFS: newMemFS().add("/big.bin", 0o100644, nil, 11), writable: true}
	fh, w := exportAndLookup(t, fs, "/big.bin")

	for i := range blocks {
		off := uint64(i * block)
		if n, st := w.write(fh, off, want[off:off+block]); st != nfs.StatusOK || n != block {
			t.Fatalf("WRITE block %d = (%d, %v)", i, n, st)
		}
		// Size must follow every block, or a client reading its own writes
		// back sees a short file.
		got, err := fs.memFS.ReadFile("/big.bin")
		if err != nil {
			t.Fatalf("ReadFile after block %d: %v", i, err)
		}
		if len(got) != int(off)+block {
			t.Fatalf("after block %d the file is %d bytes, want %d", i, len(got), int(off)+block)
		}
	}
	if got := w.readAll(fh, len(want)); !bytes.Equal(got, want) {
		t.Fatalf("the assembled file differs at byte %d", firstDiff(got, want))
	}
	if fs.wholeFileWrites != 0 {
		t.Fatalf("WriteFile was called %d times for a sequential positional write", fs.wholeFileWrites)
	}
}

// TestOpenableButNotWritableFallsBack covers the case ext4 actually produces:
// a driver with an Opener whose File is read-only for this particular inode.
// The server must fall back for that file rather than refuse the write.
func TestOpenableButNotWritableFallsBack(t *testing.T) {
	fs := &openFS{memFS: fixture()} // writable is false: a plain File
	fh, w := exportAndLookup(t, fs, "/hello.txt")
	payload := []byte("PATCH")
	if n, st := w.write(fh, 7, payload); st != nfs.StatusOK || int(n) != len(payload) {
		t.Fatalf("WRITE through a read-only File = (%d, %v)", n, st)
	}
	got, err := fs.memFS.ReadFile("/hello.txt")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if want := []byte("hello, PATCH"); !bytes.Equal(got, want) {
		t.Fatalf("file = %q, want %q", got, want)
	}
	if fs.wholeFileWrites != 1 {
		t.Fatalf("WriteFile called %d times, want exactly 1 (the fallback)", fs.wholeFileWrites)
	}
}

// TestPositionalWriteFailures walks every error the positional path can
// return, in the order the path performs them.
func TestPositionalWriteFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		mk   func() *openFS
	}{
		{"OpenFile fails", func() *openFS {
			return &openFS{memFS: fixture(), writable: true, openErr: errDriver}
		}},
		{"OpenFile returns a nil File", func() *openFS {
			return &openFS{memFS: fixture(), writable: true, nilFile: true}
		}},
		{"WriteAt fails", func() *openFS {
			return &openFS{memFS: fixture(), writable: true, writeErr: errDriver}
		}},
		{"Sync fails", func() *openFS {
			return &openFS{memFS: fixture(), writable: true, syncErr: errDriver}
		}},
		{"Close fails after a successful write", func() *openFS {
			return &openFS{memFS: fixture(), writable: true, closeErr: errDriver}
		}},
		{"Close fails on a File that is not writable", func() *openFS {
			return &openFS{memFS: fixture(), closeErr: errDriver}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := tc.mk()
			fh, w := exportAndLookup(t, fs, "/hello.txt")
			if _, st := w.write(fh, 0, []byte("x")); st != nfs.StatusIO {
				t.Fatalf("WRITE = %v, want IO", st)
			}
		})
	}
}

// TestWriteOffsetOverflowIsRefused: off is a uint64 off the wire and every
// driver offset is an int64, so a client can name an offset no driver can
// express. It must be refused, not truncated into a negative offset somewhere
// inside the volume, and not turned into a make() of absurd size by the
// fallback either — so both paths are checked.
func TestWriteOffsetOverflowIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		fs   filesystem.Filesystem
	}{
		{"positional", &openFS{memFS: fixture(), writable: true}},
		{"fallback", fixture()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fh, w := exportAndLookup(t, tc.fs, "/hello.txt")
			if _, st := w.write(fh, ^uint64(0)-4, []byte("hello")); st != nfs.StatusInval {
				t.Fatalf("WRITE at an offset no int64 can hold = %v, want INVAL", st)
			}
			if got, err := tc.fs.ReadFile("/hello.txt"); err != nil || string(got) != "hello, nfs\n" {
				t.Fatalf("the refused write changed the file: %q, %v", got, err)
			}
		})
	}
}

// exportAndLookup exports fsys read-write and returns a handle on path.
func exportAndLookup(t *testing.T, fsys filesystem.Filesystem, path string) ([]byte, *wire) {
	t.Helper()
	addr := serve(t, func(s *nfs.Server) {
		if err := s.Export("/", fsys, nfs.ReadWrite()); err != nil {
			t.Fatalf("Export: %v", err)
		}
	})
	w := dial(t, addr)
	fh := w.mount("/")
	for _, comp := range strings.Split(strings.Trim(path, "/"), "/") {
		var st nfs.Status
		fh, st = w.lookup(fh, comp)
		if st != nfs.StatusOK {
			t.Fatalf("LOOKUP %q in %q: %v", comp, path, st)
		}
	}
	return fh, w
}

// firstDiff reports the index of the first differing byte, or the length of
// the shorter slice when one is a prefix of the other. A failure message that
// names the offset is the difference between a five-minute diagnosis and an
// afternoon of printf.
func firstDiff(a, b []byte) int {
	n := min(len(a), len(b))
	for i := range n {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}
