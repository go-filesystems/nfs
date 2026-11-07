package nfs_test

import (
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/nfs"
	"github.com/go-filesystems/nfs/xdr"
)

// guardFS is a driver that counts the calls inside it, so that a test can
// prove what the server's lock keeps apart. Read-only path calls and ReadAt may
// overlap (the export asserts it with WithConcurrentPathOps); a call that
// changes anything must find none of them running, and none may start while it
// runs. A violation is recorded, not raced into: the race detector judges the
// data, these counters judge the schedule.
type guardFS struct {
	*openFS
	readers  atomic.Int32 // Stat/ReadAt/ReadFile calls inside the driver now
	mutating atomic.Int32 // changing calls inside the driver now
	bad      atomic.Int32 // overlaps seen
	slow     time.Duration
}

func (g *guardFS) enterRead() func() {
	if g.mutating.Load() != 0 {
		g.bad.Add(1)
	}
	g.readers.Add(1)
	return func() {
		g.readers.Add(-1)
		if g.mutating.Load() != 0 {
			g.bad.Add(1)
		}
	}
}

func (g *guardFS) enterMutation() func() {
	if g.readers.Load() != 0 || g.mutating.Add(1) != 1 {
		g.bad.Add(1)
	}
	if g.readers.Load() != 0 {
		g.bad.Add(1)
	}
	time.Sleep(g.slow)
	return func() { g.mutating.Add(-1) }
}

func (g *guardFS) Stat(p string) (filesystem.Stat, error) {
	defer g.enterRead()()
	return g.openFS.Stat(p)
}

func (g *guardFS) ReadFile(p string) ([]byte, error) {
	defer g.enterRead()()
	return g.openFS.ReadFile(p)
}

func (g *guardFS) WriteFile(p string, d []byte, perm os.FileMode) error {
	defer g.enterMutation()()
	return g.openFS.WriteFile(p, d, perm)
}

func (g *guardFS) DeleteFile(p string) error {
	defer g.enterMutation()()
	return g.openFS.DeleteFile(p)
}

func (g *guardFS) Truncate(p string, size int64) error {
	defer g.enterMutation()()
	g.mu.Lock()
	defer g.mu.Unlock()
	n, err := g.node(p)
	if err != nil {
		return err
	}
	if size < 0 {
		return errors.New("negative size")
	}
	grown := make([]byte, size)
	copy(grown, n.data)
	n.data = grown
	return nil
}

func (g *guardFS) Chmod(p string, perm os.FileMode) error {
	defer g.enterMutation()()
	g.mu.Lock()
	defer g.mu.Unlock()
	n, err := g.node(p)
	if err != nil {
		return err
	}
	n.mode = n.mode&^0o7777 | uint16(perm&0o7777)
	return nil
}

func (g *guardFS) OpenFile(p string) (filesystem.File, error) {
	defer g.enterRead()()
	f, err := g.openFS.OpenFile(p)
	if err != nil {
		return nil, err
	}
	return &guardFile{File: f, g: g}, nil
}

// guardFile counts ReadAt (shared with the lock) and WriteAt (a mutation of
// the bytes, but one the interface lets overlap ReadAt on other ranges, so it
// is only counted, not judged).
type guardFile struct {
	filesystem.File
	g *guardFS
}

func (f *guardFile) ReadAt(p []byte, off int64) (int, error) {
	defer f.g.enterRead()()
	time.Sleep(f.g.slow)
	return f.File.ReadAt(p, off)
}

func (f *guardFile) WriteAt(p []byte, off int64) (int, error) {
	return f.File.(filesystem.WritableFile).WriteAt(p, off)
}

func (f *guardFile) Truncate(n int64) error { return f.File.(filesystem.WritableFile).Truncate(n) }
func (f *guardFile) Sync() error            { return f.File.(filesystem.WritableFile).Sync() }

// A READ on an export with WithConcurrentPathOps holds the lock once, shared:
// READs overlap each other, and never overlap WRITE (path fallback), SETATTR
// (size, mode), CREATE or REMOVE of the same files. The race detector judges
// the bytes, guardFS the schedule.
func TestSharedReadNeverOverlapsAMutation(t *testing.T) {
	g := &guardFS{openFS: &openFS{memFS: fixture(), writable: true}, slow: 200 * time.Microsecond}
	addr := serve(t, func(s *nfs.Server) {
		if err := s.Export("/", g, nfs.ReadWrite(), nfs.WithConcurrentPathOps()); err != nil {
			t.Fatal(err)
		}
	})
	root := dial(t, addr).mount("/")
	var stop atomic.Bool
	var wg sync.WaitGroup
	var reads atomic.Int64
	for c := 0; c < 4; c++ {
		wg.Add(1)
		go func(c int) {
			defer wg.Done()
			w := dial(t, addr)
			dir, _ := w.lookup(root, "dir")
			fh, _ := w.lookup(dir, "nested.bin")
			for !stop.Load() {
				data, _, st := w.read(fh, uint64(c*100), 512)
				reads.Add(1)
				if st != nfs.StatusOK {
					t.Errorf("READ = %v", st)
					return
				}
				for _, b := range data {
					if b != 'a' && b != 'b' && b != 'z' && b != 0 {
						t.Errorf("READ returned a torn byte %q", b)
						return
					}
				}
				// A file that comes and goes: any answer but a torn one is fine.
				if tfh, st := w.lookup(root, "tmp.bin"); st == nfs.StatusOK {
					if d, _, st := w.read(tfh, 0, 64); st == nfs.StatusOK {
						for _, b := range d {
							if b != 't' && b != 0 {
								t.Errorf("tmp.bin READ returned a torn byte %q", b)
								return
							}
						}
					}
				}
			}
		}(c)
	}
	w := dial(t, addr)
	dir, _ := w.lookup(root, "dir")
	fh, _ := w.lookup(dir, "nested.bin")
	for i := 0; i < 25; i++ {
		// positional WRITE (shared lock, its range kept apart from READs)
		if st, _ := w.nfsCall(7, func(e *xdr.Encoder) {
			e.Opaque(fh)
			e.Uint64(uint64(i * 8))
			e.Uint32(8)
			e.Uint32(0)
			e.Opaque([]byte("zzzzzzzz"))
		}); st != nfs.StatusOK {
			t.Errorf("WRITE = %v", st)
		}
		// SETATTR size and mode (exclusive)
		sizes := []uint64{4000, 10000}
		if st, _ := w.nfsCall(2, func(e *xdr.Encoder) {
			e.Opaque(fh)
			sattrSize(sizes[i%2])(e)
			e.Bool(false)
		}); st != nfs.StatusOK {
			t.Errorf("SETATTR size = %v", st)
		}
		if st, _ := w.nfsCall(2, func(e *xdr.Encoder) {
			e.Opaque(fh)
			sattrMode(0o600)(e)
			e.Bool(false)
		}); st != nfs.StatusOK {
			t.Errorf("SETATTR mode = %v", st)
		}
		// CREATE, WRITE, REMOVE (exclusive, exclusive, exclusive)
		st, d := w.nfsCall(8, func(e *xdr.Encoder) {
			e.Opaque(root)
			e.String("tmp.bin")
			e.Uint32(0)
			sattrNone(e)
		})
		if st != nfs.StatusOK {
			t.Errorf("CREATE = %v", st)
			continue
		}
		if w.mustU32(d) == 1 {
			if tfh, err := d.Opaque(); err == nil {
				w.nfsCall(7, func(e *xdr.Encoder) {
					e.Opaque(tfh)
					e.Uint64(0)
					e.Uint32(8)
					e.Uint32(0)
					e.Opaque([]byte("tttttttt"))
				})
			}
		}
		if st, _ := w.nfsCall(12, func(e *xdr.Encoder) {
			e.Opaque(root)
			e.String("tmp.bin")
		}); st != nfs.StatusOK {
			t.Errorf("REMOVE = %v", st)
		}
	}
	stop.Store(true)
	wg.Wait()
	if n := g.bad.Load(); n != 0 {
		t.Fatalf("%d overlaps of a READ with a mutating driver call", n)
	}
	if reads.Load() == 0 {
		t.Fatal("no READ ran")
	}
}

// Two READs of one connection are in the driver together when the export says
// path calls may overlap: the point of the shared lock, proved by a driver that
// waits for a second caller inside ReadAt.
func TestSharedReadsOverlapInTheDriver(t *testing.T) {
	g := &guardFS{openFS: &openFS{memFS: fixture()}}
	var inside atomic.Int32
	var overlapped atomic.Bool
	hook := &overlapFS{guardFS: g, inside: &inside, overlapped: &overlapped}
	addr := serve(t, func(s *nfs.Server) {
		if err := s.Export("/", hook, nfs.WithConcurrentPathOps()); err != nil {
			t.Fatal(err)
		}
	})
	root := dial(t, addr).mount("/")
	var wg sync.WaitGroup
	for c := 0; c < 4; c++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := dial(t, addr)
			dir, _ := w.lookup(root, "dir")
			fh, _ := w.lookup(dir, "nested.bin")
			for i := 0; i < 10; i++ {
				if _, _, st := w.read(fh, 0, 256); st != nfs.StatusOK {
					t.Errorf("READ = %v", st)
				}
			}
		}()
	}
	wg.Wait()
	if !overlapped.Load() {
		t.Fatal("no two READs were ever inside the driver together")
	}
}

type overlapFS struct {
	*guardFS
	inside     *atomic.Int32
	overlapped *atomic.Bool
}

func (o *overlapFS) OpenFile(p string) (filesystem.File, error) {
	f, err := o.guardFS.OpenFile(p)
	if err != nil {
		return nil, err
	}
	return &overlapFile{File: f, o: o}, nil
}

type overlapFile struct {
	filesystem.File
	o *overlapFS
}

func (f *overlapFile) ReadAt(p []byte, off int64) (int, error) {
	if f.o.inside.Add(1) > 1 {
		f.o.overlapped.Store(true)
	}
	time.Sleep(time.Millisecond)
	defer f.o.inside.Add(-1)
	return f.File.ReadAt(p, off)
}
