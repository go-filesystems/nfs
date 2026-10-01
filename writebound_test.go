package nfs_test

import (
	"bytes"
	"testing"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/nfs"
)

// The v0.4.0 review's HIGH finding: the read-modify-write fallback allocated
// off+len(data) bytes, and procWrite only bounded off by MaxInt64-len. One
// WRITE at 2^62 from any client allowed to write panicked in makeslice and
// killed the server — every client, every export. Offsets around 2^36..2^40
// asked for an allocation that took the process down the other way.
//
// Reachable wherever the fallback is taken: a driver with no positional write
// at all (the memFS fixture), or one that opens the file but hands back a
// read-only File — what osfs does for a 0444 file.

func TestAWriteFarPastTheEndIsRefusedNotAllocated(t *testing.T) {
	for _, tc := range []struct {
		name string
		off  uint64
	}{
		{"2^62, the makeslice panic", 1 << 62},
		{"2^40, the out-of-memory", 1 << 40},
		{"just past the growth bound", 10000 + 64*(1<<17) + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, fx := range []struct {
				name string
				fs   func() filesystem.Filesystem
			}{
				{"no positional write", func() filesystem.Filesystem { return fixture() }},
				{"opens read-only", func() filesystem.Filesystem { return &openFS{memFS: fixture()} }},
			} {
				t.Run(fx.name, func(t *testing.T) {
					fh, w := exportAndLookup(t, fx.fs(), "/dir/nested.bin")
					before := w.readAll(fh, 1<<16)
					if _, st := w.write(fh, tc.off, []byte("x")); st != nfs.StatusFBig {
						t.Fatalf("WRITE at %d = %v, want NFS3ERR_FBIG", tc.off, st)
					}
					// The server is alive, and the file is as it was.
					if after := w.readAll(fh, 1<<16); !bytes.Equal(after, before) {
						t.Fatalf("a refused WRITE changed the file: %d bytes, was %d", len(after), len(before))
					}
				})
			}
		})
	}
}

// TestAWriteWithinTheGrowthBoundStillExtends: the bound must not refuse the
// hole-leaving writes a client really sends.
func TestAWriteWithinTheGrowthBoundStillExtends(t *testing.T) {
	fh, w := exportAndLookup(t, fixture(), "/dir/nested.bin")
	before := w.readAll(fh, 1<<16)
	off := uint64(len(before)) + 3<<17 // three wsize of hole
	if n, st := w.write(fh, off, []byte("tail")); st != nfs.StatusOK || n != 4 {
		t.Fatalf("WRITE three wsize past the end = (%d, %v), want (4, OK)", n, st)
	}
	after := w.readAll(fh, int(off)+4)
	if uint64(len(after)) != off+4 || string(after[off:]) != "tail" {
		t.Fatalf("file is %d bytes after the write, want %d ending in tail", len(after), off+4)
	}
	if !bytes.Equal(after[:len(before)], before) || bytes.ContainsFunc(after[len(before):off], func(r rune) bool { return r != 0 }) {
		t.Fatal("the extended file does not read as the old bytes, a hole of zeros, then the new ones")
	}
}
