package nfs

import (
	"bytes"
	"errors"
	"log"
	"net"
	"testing"

	filesystem "github.com/go-filesystems/interface"
)

// treeFS is a directory tree for walking: dirs maps a directory to its entry
// names; a path not in dirs is a file. A directory in broken fails ListDir.
type treeFS struct {
	nopFS
	dirs   map[string][]string
	broken map[string]bool
}

func (f treeFS) ListDir(p string) ([]filesystem.DirEntry, error) {
	if f.broken[p] {
		return nil, errors.New("medium error")
	}
	var out []filesystem.DirEntry
	for _, n := range f.dirs[p] {
		out = append(out, filesystem.NewDirEntry(1, n, 0))
	}
	return out, nil
}

func (f treeFS) Stat(p string) (filesystem.Stat, error) {
	if _, ok := f.dirs[p]; ok {
		return filesystem.NewStat(sIFDIR|0o755, 0, 2), nil
	}
	return filesystem.NewStat(sIFREG|0o644, 1, 3), nil
}

// twinOf returns a fresh server on the same key exporting the same fs at "/",
// and the handle the first server would mint for path.
func twinOf(t *testing.T, fs filesystem.Filesystem, path string) (*Server, *export, pathID) {
	t.Helper()
	key, _ := NewHandleKey()
	a, _ := New()
	a.Export("/", fs)
	a.SetHandleKey(key)
	h, err := a.handles.Handle(a.byPath["/"].id, path)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := New()
	b.Export("/", fs)
	b.SetHandleKey(key)
	return b, b.byPath["/"], handleID(h)
}

func TestRediscoverBranches(t *testing.T) {
	tree := treeFS{
		dirs: map[string][]string{
			"/":       {"a", "bad", "slash/name", "."},
			"/a":      {"deep"},
			"/a/deep": {"leaf"},
			"/bad":    {"never"},
		},
		broken: map[string]bool{"/bad": true},
	}

	t.Run("finds a nested path past a broken directory and a bad name", func(t *testing.T) {
		b, e, id := twinOf(t, tree, "/a/deep/leaf")
		if p, ok := b.rediscover(e, id); !ok || p != "/a/deep/leaf" {
			t.Fatalf("rediscover = (%q, %v)", p, ok)
		}
	})
	t.Run("the root", func(t *testing.T) {
		b, e, id := twinOf(t, tree, "/")
		if p, ok := b.rediscover(e, id); !ok || p != "/" {
			t.Fatalf("rediscover = (%q, %v)", p, ok)
		}
	})
	t.Run("already learned while waiting", func(t *testing.T) {
		b, e, id := twinOf(t, tree, "/a")
		b.handles.learn(e.id, "/a")
		e.lastWalk = e.lastWalk.AddDate(100, 0, 0) // a walk would be refused
		if p, ok := b.rediscover(e, id); !ok || p != "/a" {
			t.Fatalf("rediscover = (%q, %v)", p, ok)
		}
	})
	t.Run("walk interval", func(t *testing.T) {
		b, e, id := twinOf(t, tree, "/missing")
		if _, ok := b.rediscover(e, id); ok {
			t.Fatal("found a path that does not exist")
		}
		// Create it now: inside the interval, no second walk finds it.
		tree.dirs["/"] = append(tree.dirs["/"], "missing")
		defer func() { tree.dirs["/"] = tree.dirs["/"][:len(tree.dirs["/"])-1] }()
		if _, ok := b.rediscover(e, id); ok {
			t.Fatal("a second walk ran inside rediscoverInterval")
		}
	})
	t.Run("table full before the root", func(t *testing.T) {
		b, e, id := twinOf(t, tree, "/a")
		b.handles.max = 0
		if _, ok := b.rediscover(e, id); ok {
			t.Fatal("rediscover with a full table found something")
		}
	})
	t.Run("table full mid-walk keeps what it found", func(t *testing.T) {
		b, e, id := twinOf(t, tree, "/a")
		b.handles.max = 2 // "/" and "/a", then full
		if p, ok := b.rediscover(e, id); !ok || p != "/a" {
			t.Fatalf("rediscover = (%q, %v)", p, ok)
		}
	})
}

func TestExportIDCollisionIsRefused(t *testing.T) {
	s, _ := New()
	s.byID[s.handles.exportID("/x")] = &export{}
	if err := s.Export("/x", nopFS{}); !errors.Is(err, ErrExportExists) {
		t.Fatalf("Export over a colliding id = %v, want ErrExportExists", err)
	}
}

func TestConnSettersRefuseWhileServing(t *testing.T) {
	s, _ := New()
	s.Export("/", nopFS{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	defer func() { s.Close(); <-done }()
	if c, err := net.Dial("tcp", ln.Addr().String()); err == nil {
		c.Close()
	}
	if err := s.SetConnLimits(ConnLimits{}); !errors.Is(err, ErrServing) {
		t.Fatalf("SetConnLimits while serving = %v", err)
	}
	if err := s.SetErrorLog(log.New(&bytes.Buffer{}, "", 0)); !errors.Is(err, ErrServing) {
		t.Fatalf("SetErrorLog while serving = %v", err)
	}
}
