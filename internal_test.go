package nfs

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"testing"
	"time"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/nfs/rpc"
	"github.com/go-filesystems/nfs/xdr"
)

func TestCleanPath(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"/", "/"},
		{"", "/"},
		{"//a//b/", "/a/b"},
		{"/a/./b", "/a/b"},
		{"/a/../b", "/b"},
		{"/../../etc", "/etc"},
		{"a/b", "/a/b"},
		{"/a/b/..", "/a"},
	} {
		if got := cleanPath(tc.in); got != tc.want {
			t.Errorf("cleanPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParentOf(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"/", "/"},
		{"/a", "/"},
		{"/a/b", "/a"},
		{"noslash", "/"},
	} {
		if got := parentOf(tc.in); got != tc.want {
			t.Errorf("parentOf(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestJoinNameLongPath(t *testing.T) {
	// A legal component appended to an already-enormous directory must be
	// refused rather than extending the path space without bound.
	dir := "/" + string(make([]byte, maxPath))
	for i := 1; i < len(dir); i++ {
		dir = dir[:i] + "x" + dir[i+1:]
	}
	if _, st := joinName(dir, "x"); st != StatusNameTooLong {
		t.Fatalf("joinName on an over-long path = %v, want NAMETOOLONG", st)
	}
}

func TestFtypeOf(t *testing.T) {
	for _, tc := range []struct {
		mode uint16
		want uint32
	}{
		{sIFREG | 0o644, ftypeReg},
		{sIFDIR | 0o755, ftypeDir},
		{sIFLNK | 0o777, ftypeLnk},
		{sIFBLK, ftypeBlk},
		{sIFCHR, ftypeChr},
		{sIFSOCK, ftypeSock},
		{sIFIFO, ftypeFifo},
		{0o644, ftypeReg}, // no type bits at all
	} {
		if got := ftypeOf(tc.mode); got != tc.want {
			t.Errorf("ftypeOf(%#o) = %d, want %d", tc.mode, got, tc.want)
		}
	}
}

func TestStatusFor(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want Status
	}{
		{"nil", nil, StatusOK},
		{"not exist", fs.ErrNotExist, StatusNoEnt},
		{"exist", fs.ErrExist, StatusExist},
		{"permission", fs.ErrPermission, StatusAccess},
		{"invalid", fs.ErrInvalid, StatusInval},
		{"shrink", filesystem.ErrShrinkUnsupported, StatusNotSupp},
		{"handle full", errHandleFull, StatusServerFault},
		{"text not found", errors.New(`fat32: "/x" not found`), StatusNoEnt},
		{"text no such", errors.New("no such file"), StatusNoEnt},
		{"text does not exist", errors.New("it does not exist"), StatusNoEnt},
		{"text not a dir", errors.New("iso9660: not a directory"), StatusNotDir},
		{"text is a dir", errors.New("is a directory"), StatusIsDir},
		{"text not regular", errors.New("not a regular file"), StatusInval},
		{"text not symlink", errors.New("not a symbolic link"), StatusInval},
		{"text not empty", errors.New("directory not empty"), StatusNotEmpty},
		{"text read-only", errors.New("iso9660: filesystem is read-only"), StatusROFS},
		{"text exists", errors.New("path already exists"), StatusExist},
		{"text no space", errors.New("no space left"), StatusNoSpc},
		{"text too many", errors.New("too many links"), StatusMLink},
		{"unknown", errors.New("boom"), StatusIO},
	} {
		if got := statusFor(tc.err, StatusIO); got != tc.want {
			t.Errorf("%s: statusFor = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// --- handle store ----------------------------------------------------------

func TestHandleStoreRoundTrip(t *testing.T) {
	s, err := newHandleStore()
	if err != nil {
		t.Fatalf("newHandleStore: %v", err)
	}
	h1, err := s.Handle(1, "/a")
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if len(h1) != handleSize {
		t.Fatalf("handle length = %d, want %d", len(h1), handleSize)
	}
	h2, _ := s.Handle(1, "/a")
	if string(h1) != string(h2) {
		t.Fatal("the same path minted two different handles")
	}
	h3, _ := s.Handle(2, "/a")
	if string(h1) == string(h3) {
		t.Fatal("the same path in two exports minted the same handle")
	}
	k, stale, ok := s.Resolve(h1)
	if !ok || stale || k.export != 1 || k.path != "/a" {
		t.Fatalf("Resolve = (%+v, stale=%v, ok=%v)", k, stale, ok)
	}

	// A handle must not disclose the path it names.
	if idx := indexOf(h1, []byte("/a")); idx >= 0 {
		t.Fatalf("handle bytes contain the path at offset %d", idx)
	}
}

func indexOf(hay, needle []byte) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if string(hay[i:i+len(needle)]) == string(needle) {
			return i
		}
	}
	return -1
}

func TestHandleStoreRejects(t *testing.T) {
	s, _ := newHandleStore()
	good, _ := s.Handle(1, "/a")

	t.Run("wrong length", func(t *testing.T) {
		if _, _, ok := s.Resolve(good[:handleSize-1]); ok {
			t.Fatal("a short handle resolved")
		}
	})
	t.Run("wrong magic", func(t *testing.T) {
		bad := append([]byte(nil), good...)
		bad[0] ^= 0xff
		if _, _, ok := s.Resolve(bad); ok {
			t.Fatal("a handle with a wrong magic resolved")
		}
	})
	t.Run("forged", func(t *testing.T) {
		// Flip a slot bit and keep the rest: this is the attack the MAC
		// exists to stop — walking slots to reach an unexported path.
		bad := append([]byte(nil), good...)
		bad[27] ^= 0x01
		if _, _, ok := s.Resolve(bad); ok {
			t.Fatal("a forged handle resolved")
		}
	})
	t.Run("previous epoch", func(t *testing.T) {
		other := &handleStore{key: s.key, epoch: s.epoch + 1, max: maxHandles, byPath: map[handleKey]uint64{}}
		old, _ := other.Handle(1, "/a")
		_, stale, ok := s.Resolve(old)
		if ok {
			t.Fatal("a handle from another epoch resolved")
		}
		if !stale {
			t.Fatal("a handle from another epoch was not reported stale")
		}
	})
	t.Run("slot past the table", func(t *testing.T) {
		// Mint with a store that has the same key but more slots, so the MAC
		// verifies and only the bounds check can reject it.
		wide := &handleStore{key: s.key, epoch: s.epoch, max: maxHandles, byPath: map[handleKey]uint64{}}
		for i := range 5 {
			wide.Handle(1, string(rune('a'+i)))
		}
		far, _ := wide.Handle(1, "/far")
		if _, stale, ok := s.Resolve(far); ok || !stale {
			t.Fatalf("an out-of-range slot resolved (stale=%v, ok=%v)", stale, ok)
		}
	})
}

func TestHandleStoreFull(t *testing.T) {
	s, _ := newHandleStore()
	s.max = 2
	if _, err := s.Handle(1, "/a"); err != nil {
		t.Fatalf("first Handle: %v", err)
	}
	if _, err := s.Handle(1, "/b"); err != nil {
		t.Fatalf("second Handle: %v", err)
	}
	if _, err := s.Handle(1, "/c"); !errors.Is(err, errHandleFull) {
		t.Fatalf("third Handle error = %v, want errHandleFull", err)
	}
	// An already-known path still resolves once the table is full: the
	// server degrades for new paths, it does not break existing mounts.
	if _, err := s.Handle(1, "/a"); err != nil {
		t.Fatalf("known path after overflow: %v", err)
	}
	if _, err := s.slotOf(1, "/c"); !errors.Is(err, errHandleFull) {
		t.Fatalf("slotOf after overflow = %v, want errHandleFull", err)
	}
}

func TestNewHandleStoreCSPRNGFailure(t *testing.T) {
	orig := randRead
	t.Cleanup(func() { randRead = orig })

	boom := errors.New("no entropy")
	randRead = func(b []byte) (int, error) { return 0, boom }
	if _, err := newHandleStore(); !errors.Is(err, boom) {
		t.Fatalf("newHandleStore with a dead CSPRNG = %v, want %v", err, boom)
	}
	// The second read must be checked too, or the epoch would be zero on a
	// partially-failing CSPRNG.
	calls := 0
	randRead = func(b []byte) (int, error) {
		calls++
		if calls == 1 {
			return len(b), nil
		}
		return 0, boom
	}
	if _, err := newHandleStore(); !errors.Is(err, boom) {
		t.Fatalf("newHandleStore with a failing epoch read = %v, want %v", err, boom)
	}
	randRead = orig
	if _, err := New(); err != nil {
		t.Fatalf("New after restoring the CSPRNG: %v", err)
	}
	randRead = func(b []byte) (int, error) { return 0, boom }
	if _, err := New(); !errors.Is(err, boom) {
		t.Fatalf("New with a dead CSPRNG = %v, want it to refuse", err)
	}
}

// --- the Opener probe ------------------------------------------------------

type probeFile interface {
	io.ReaderAt
	io.Closer
	Size() int64
}

type nopFS struct{}

func (nopFS) Close() error                                  { return nil }
func (nopFS) ReadFile(string) ([]byte, error)               { return nil, nil }
func (nopFS) ListDir(string) ([]filesystem.DirEntry, error) { return nil, nil }
func (nopFS) Stat(string) (filesystem.Stat, error) {
	return filesystem.NewStat(sIFDIR|0o755, 0, 3), nil
}
func (nopFS) WriteFile(string, []byte, os.FileMode) error { return nil }
func (nopFS) ReadLink(string) (string, error)             { return "", nil }
func (nopFS) MkDir(string, os.FileMode) error             { return nil }
func (nopFS) DeleteFile(string) error                     { return nil }
func (nopFS) DeleteDir(string) error                      { return nil }
func (nopFS) Rename(string, string) error                 { return nil }

// probeNamed returns a *named interface distinct from filesystem.File* with
// the very same method set. Go compares method sets by type identity, so this
// is NOT filesystem.Opener, and the probe must say so.
type probeNamed struct{ nopFS }

func (probeNamed) OpenFile(p string) (probeFile, error) { return nil, nil }

// probeNative is the real thing: OpenFile returning filesystem.File.
type probeNative struct{ nopFS }

func (probeNative) OpenFile(p string) (File, error) { return nil, nil }

type probeNilFile struct{ nopFS }

func (probeNilFile) OpenFile(p string) (File, error) { return nil, nil }

type probeArity struct{ nopFS }

func (probeArity) OpenFile(p string) probeFile { return nil }

type probeExtraArg struct{ nopFS }

func (probeExtraArg) OpenFile(p string, n int) (probeFile, error) { return nil, nil }

type probeNotString struct{ nopFS }

func (probeNotString) OpenFile(n int) (probeFile, error) { return nil, nil }

type probeWrongResult struct{ nopFS }

func (probeWrongResult) OpenFile(p string) (int, error) { return 0, nil }

type probeNotError struct{ nopFS }

func (probeNotError) OpenFile(p string) (probeFile, int) { return nil, 0 }

type probeErr struct{ nopFS }

var errProbe = errors.New("probe: open failed")

func (probeErr) OpenFile(p string) (File, error) { return nil, errProbe }

func TestOpenerFor(t *testing.T) {
	t.Run("declared with the interface module's File", func(t *testing.T) {
		if openerFor(probeNative{}) == nil {
			t.Fatal("the probe missed a real filesystem.Opener")
		}
	})
	// Every case below has a method named OpenFile and is still not the
	// capability. The first is the one worth stating out loud: identical
	// shape, identical semantics, different named type. Accepting it would
	// mean matching by structure again, which is what the reflection probe
	// this replaced had to do because the interface module had no tagged
	// release carrying Opener.
	for _, tc := range []struct {
		name string
		fs   any
	}{
		{"a structurally identical but distinct File type", probeNamed{}},
		{"no OpenFile at all", nopFS{}},
		{"wrong arity", probeArity{}},
		{"extra argument", probeExtraArg{}},
		{"argument is not a path", probeNotString{}},
		{"result does not satisfy File", probeWrongResult{}},
		{"second result is not an error", probeNotError{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if openerFor(tc.fs) != nil {
				t.Fatal("the probe accepted something that is not filesystem.Opener")
			}
		})
	}
	t.Run("open error is propagated", func(t *testing.T) {
		e := &export{open: openerFor(probeErr{})}
		if _, err := e.openFile("/x"); !errors.Is(err, errProbe) {
			t.Fatalf("open error = %v, want %v", err, errProbe)
		}
	})
	t.Run("a nil File with no error is refused, not dereferenced", func(t *testing.T) {
		e := &export{open: openerFor(probeNilFile{})}
		if _, err := e.openFile("/x"); !errors.Is(err, errNilFile) {
			t.Fatalf("open error = %v, want errNilFile", err)
		}
	})
}

// --- timestamps ------------------------------------------------------------

type timedStat struct {
	filesystem.Stat
	when int64
}

func (t timedStat) ModTime() int64 { return t.when }

type timedFS struct{ nopFS }

func (timedFS) Stat(string) (filesystem.Stat, error) {
	return timedStat{Stat: filesystem.NewStat(sIFREG|0o644, 3, 9), when: 1234567890}, nil
}

func TestAttrUsesDriverModTime(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Export("/", timedFS{}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	a, st := s.attrFor(s.byID[1], "/f")
	if st != StatusOK {
		t.Fatalf("attrFor: %v", st)
	}
	if a.mtime != 1234567890 || a.atime != 1234567890 || a.ctime != 1234567890 {
		t.Fatalf("timestamps = %d/%d/%d, want the driver's ModTime", a.atime, a.mtime, a.ctime)
	}
	_ = time.Now
}

// TestAttrSyntheticFileIDOverflow covers the branch where a zero inode needs a
// synthetic fileid but the handle table is full.
func TestAttrSyntheticFileIDOverflow(t *testing.T) {
	s, _ := New()
	if err := s.Export("/", zeroInodeFS{}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	s.handles.max = 0
	if _, st := s.attrFor(s.byID[1], "/f"); st != StatusServerFault {
		t.Fatalf("attrFor with a full handle table = %v, want SERVERFAULT", st)
	}
}

type zeroInodeFS struct{ nopFS }

func (zeroInodeFS) Stat(string) (filesystem.Stat, error) {
	return filesystem.NewStat(sIFREG|0o644, 0, 0), nil
}

func TestExportValidation(t *testing.T) {
	s, _ := New()
	for _, bad := range []string{"", "relative", "/a/", "/a/../b", "//a"} {
		if err := s.Export(bad, nopFS{}); !errors.Is(err, ErrExportPath) {
			t.Errorf("Export(%q) = %v, want ErrExportPath", bad, err)
		}
	}
	if err := s.Export("/ok", nopFS{}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if err := s.Export("/ok", nopFS{}); !errors.Is(err, ErrExportExists) {
		t.Fatalf("duplicate Export = %v, want ErrExportExists", err)
	}
}

func TestServeWithoutExports(t *testing.T) {
	s, _ := New()
	if err := s.Serve(nil); !errors.Is(err, ErrNoExports) {
		t.Fatalf("Serve with no exports = %v, want ErrNoExports", err)
	}
	if err := s.ListenAndServe("127.0.0.1:0"); !errors.Is(err, ErrNoExports) {
		t.Fatalf("ListenAndServe with no exports = %v, want ErrNoExports", err)
	}
	if err := s.ListenAndServe("256.256.256.256:99999"); err == nil {
		t.Fatal("ListenAndServe on an unusable address returned nil")
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestListenAndServeRuns covers the success path through the convenience
// wrapper, which otherwise only ever fails in tests.
func TestListenAndServeRuns(t *testing.T) {
	s, _ := New()
	if err := s.Export("/", nopFS{}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- s.ListenAndServe("127.0.0.1:0") }()
	// Close races the listen; retry until the server is up enough to close.
	for range 100 {
		if err := s.Close(); err == nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	<-done
}

func TestExportByIDMissing(t *testing.T) {
	s, _ := New()
	if e := s.exportByID(99); e != nil {
		t.Fatal("exportByID returned an export for an unknown id")
	}
}

// --- procedures driven directly ---------------------------------------------
//
// A few branches cannot be reached from the wire because they depend on
// server state a client cannot create: a handle minted before a restart, an
// export that has gone away, a full handle table. Calling the procedure with
// a hand-built rpc.Call reaches them without pretending they are unreachable.

// invoke runs one procedure and returns its RPC status and reply decoder.
func invoke(p rpc.Proc, args []byte) (rpc.Status, *xdr.Decoder) {
	res := xdr.NewEncoder(nil)
	st := p(&rpc.Call{Args: xdr.NewDecoder(args), Res: res})
	return st, xdr.NewDecoder(res.Bytes())
}

// fhArgs encodes a single file handle as a procedure argument list.
func fhArgs(h []byte) []byte {
	e := xdr.NewEncoder(nil)
	e.Opaque(h)
	return e.Bytes()
}

func newTestServer(t *testing.T) (*Server, []byte) {
	t.Helper()
	s, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Export("/", nopFS{}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	h, err := s.handles.Handle(1, "/")
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	return s, h
}

// TestStaleHandleAfterRestart: a handle minted by a previous process must be
// reported stale so the client re-walks from the mount root, never silently
// resolved to whatever now sits in that slot.
func TestStaleHandleAfterRestart(t *testing.T) {
	s, h := newTestServer(t)
	s.handles.epoch++ // exactly what a restart looks like to a client
	st, d := invoke(s.procGetAttr, fhArgs(h))
	if st != rpc.StatusSuccess {
		t.Fatalf("GETATTR: rpc status %v", st)
	}
	got, err := d.Uint32()
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if Status(got) != StatusStale {
		t.Fatalf("GETATTR with a previous-epoch handle = %v, want STALE", Status(got))
	}
}

// TestHandleForAVanishedExport covers a handle that authenticates but whose
// export is no longer registered.
func TestHandleForAVanishedExport(t *testing.T) {
	s, h := newTestServer(t)
	s.mu.Lock()
	delete(s.byID, 1)
	s.mu.Unlock()
	_, d := invoke(s.procGetAttr, fhArgs(h))
	got, _ := d.Uint32()
	if Status(got) != StatusStale {
		t.Fatalf("GETATTR for a vanished export = %v, want STALE", Status(got))
	}
}

// TestHandleTableFullDegradesGracefully: once the table is full the server
// must answer, not evict a handle a client is still using.
func TestHandleTableFullDegradesGracefully(t *testing.T) {
	t.Run("MNT", func(t *testing.T) {
		// A fresh server: the root handle must not already be in the table,
		// or MNT would find it rather than try to mint it.
		s, err := New()
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if err := s.Export("/", nopFS{}); err != nil {
			t.Fatalf("Export: %v", err)
		}
		s.handles.max = 0
		e := xdr.NewEncoder(nil)
		e.String("/")
		_, d := invoke(s.procMnt, e.Bytes())
		if got, _ := d.Uint32(); got != mountErrInval {
			t.Fatalf("MNT with a full handle table = %d, want MNT3ERR_INVAL", got)
		}
	})
	t.Run("LOOKUP", func(t *testing.T) {
		s, h := newTestServer(t)
		s.handles.max = 1
		e := xdr.NewEncoder(nil)
		e.Opaque(h)
		e.String("x")
		_, d := invoke(s.procLookup, e.Bytes())
		got, _ := d.Uint32()
		if Status(got) != StatusServerFault {
			t.Fatalf("LOOKUP with a full handle table = %v, want SERVERFAULT", Status(got))
		}
	})
	t.Run("CREATE", func(t *testing.T) {
		s, h := newTestServer(t)
		s.byID[1].ro = false
		s.handles.max = 1
		e := xdr.NewEncoder(nil)
		e.Opaque(h)
		e.String("x")
		e.Uint32(0) // UNCHECKED
		for range 4 {
			e.Bool(false)
		}
		e.Uint32(0)
		e.Uint32(0)
		_, d := invoke(s.procCreate, e.Bytes())
		got, _ := d.Uint32()
		if Status(got) != StatusOK {
			t.Fatalf("CREATE with a full handle table = %v, want OK with no handle", Status(got))
		}
		if hasFH, _ := d.Uint32(); hasFH != 0 {
			t.Fatal("CREATE returned a handle it could not mint")
		}
	})
}

// TestNilStatIsAServerFault: a driver that returns (nil, nil) from Stat would
// otherwise take a nil dereference in a connection goroutine with no recover,
// killing every mount the process holds.
func TestNilStatIsAServerFault(t *testing.T) {
	s, _ := New()
	if err := s.Export("/", nilStatFS{}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if _, st := s.attrFor(s.byID[1], "/"); st != StatusServerFault {
		t.Fatalf("attrFor on a nil Stat = %v, want SERVERFAULT", st)
	}
}

type nilStatFS struct{ nopFS }

func (nilStatFS) Stat(string) (filesystem.Stat, error) { return nil, nil }

func TestExportRejectsANilFilesystem(t *testing.T) {
	s, _ := New()
	if err := s.Export("/", nil); !errors.Is(err, ErrNilFilesystem) {
		t.Fatalf("Export(nil) = %v, want ErrNilFilesystem", err)
	}
}
