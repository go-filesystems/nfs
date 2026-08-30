package nfs_test

import (
	"errors"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	filesystem "github.com/go-filesystems/interface"
)

// memFS is an in-memory filesystem.Filesystem used to drive the server
// without pulling a concrete driver into this module's dependency graph —
// the same separation detect keeps between its core and its fat32 adapter.
type memFS struct {
	mu    sync.Mutex
	nodes map[string]*memNode
	// fail injects an error for the named operation on the named path,
	// which is how the error branches of every procedure are reached.
	fail map[string]error
	// caps selects which optional interfaces this instance satisfies; see
	// newMemFS.
	closed bool
}

type memNode struct {
	mode  uint16
	data  []byte
	link  string
	inode uint64
	mtime int64
}

func newMemFS() *memFS {
	return &memFS{
		nodes: map[string]*memNode{"/": {mode: 0o040755, inode: 1}},
		fail:  map[string]error{},
	}
}

// add inserts a node, creating nothing implicitly: a test that forgets the
// parent directory should see the same NOTDIR a real driver would give.
func (m *memFS) add(path string, mode uint16, data []byte, inode uint64) *memFS {
	m.nodes[path] = &memNode{mode: mode, data: data, inode: inode}
	return m
}

func (m *memFS) failWith(key string, err error) *memFS { m.fail[key] = err; return m }

func (m *memFS) check(op, path string) error { return m.fail[op+":"+path] }

func (m *memFS) Close() error {
	m.closed = true
	return m.fail["Close:"]
}

func (m *memFS) node(path string) (*memNode, error) {
	n, ok := m.nodes[path]
	if !ok {
		return nil, errors.New("memfs: " + path + " not found")
	}
	return n, nil
}

func (m *memFS) Stat(path string) (filesystem.Stat, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check("Stat", path); err != nil {
		return nil, err
	}
	n, err := m.node(path)
	if err != nil {
		return nil, err
	}
	return memStat{mode: n.mode, size: uint64(len(n.data)), inode: n.inode}, nil
}

type memStat struct {
	mode  uint16
	size  uint64
	inode uint64
}

func (s memStat) Mode() uint16  { return s.mode }
func (s memStat) Size() uint64  { return s.size }
func (s memStat) Inode() uint64 { return s.inode }

func (m *memFS) ReadFile(path string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check("ReadFile", path); err != nil {
		return nil, err
	}
	n, err := m.node(path)
	if err != nil {
		return nil, err
	}
	if n.mode&0o170000 == 0o040000 {
		return nil, errors.New("memfs: is a directory")
	}
	out := make([]byte, len(n.data))
	copy(out, n.data)
	return out, nil
}

func (m *memFS) ListDir(path string) ([]filesystem.DirEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check("ListDir", path); err != nil {
		return nil, err
	}
	n, err := m.node(path)
	if err != nil {
		return nil, err
	}
	if n.mode&0o170000 != 0o040000 {
		return nil, errors.New("memfs: not a directory")
	}
	prefix := path
	if prefix != "/" {
		prefix += "/"
	}
	var names []string
	for p := range m.nodes {
		if p == path || !strings.HasPrefix(p, prefix) {
			continue
		}
		rest := p[len(prefix):]
		if strings.Contains(rest, "/") {
			continue
		}
		names = append(names, rest)
	}
	sort.Strings(names)
	// A real FAT directory carries "." and ".." on disk; emitting them here
	// keeps the server's filtering honest.
	out := []filesystem.DirEntry{
		filesystem.NewDirEntry(0, ".", 0),
		filesystem.NewDirEntry(0, "..", 0),
	}
	for _, name := range names {
		out = append(out, filesystem.NewDirEntry(m.nodes[prefix+name].inode, name, 0))
	}
	return out, nil
}

func (m *memFS) WriteFile(path string, data []byte, perm os.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check("WriteFile", path); err != nil {
		return err
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	if n, ok := m.nodes[path]; ok {
		n.data = cp
		return nil
	}
	m.nodes[path] = &memNode{mode: 0o100000 | uint16(perm&0o7777), data: cp, inode: uint64(len(m.nodes) + 1)}
	return nil
}

func (m *memFS) ReadLink(path string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check("ReadLink", path); err != nil {
		return "", err
	}
	n, err := m.node(path)
	if err != nil {
		return "", err
	}
	if n.mode&0o170000 != 0o120000 {
		return "", errors.New("memfs: not a symbolic link")
	}
	return n.link, nil
}

func (m *memFS) MkDir(path string, perm os.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check("MkDir", path); err != nil {
		return err
	}
	m.nodes[path] = &memNode{mode: 0o040000 | uint16(perm&0o7777), inode: uint64(len(m.nodes) + 1)}
	return nil
}

func (m *memFS) DeleteFile(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check("DeleteFile", path); err != nil {
		return err
	}
	delete(m.nodes, path)
	return nil
}

func (m *memFS) DeleteDir(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check("DeleteDir", path); err != nil {
		return err
	}
	delete(m.nodes, path)
	return nil
}

func (m *memFS) Rename(oldPath, newPath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check("Rename", oldPath); err != nil {
		return err
	}
	n, err := m.node(oldPath)
	if err != nil {
		return err
	}
	delete(m.nodes, oldPath)
	m.nodes[newPath] = n
	return nil
}

// --- optional capabilities -------------------------------------------------

// capFS adds every optional capability. It is a distinct type so that a test
// can also exercise a driver that has none.
type capFS struct {
	*memFS
	// linkErr, symErr and so on inject failures into the optional calls.
	linkErr, symErr, truncErr, chmodErr, chownErr, timesErr error
}

func (c *capFS) Symlink(target, linkPath string) error {
	if c.symErr != nil {
		return c.symErr
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nodes[linkPath] = &memNode{mode: 0o120777, link: target, inode: uint64(len(c.nodes) + 1)}
	return nil
}

func (c *capFS) Link(oldPath, newPath string) error {
	if c.linkErr != nil {
		return c.linkErr
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	n, err := c.node(oldPath)
	if err != nil {
		return err
	}
	c.nodes[newPath] = n
	return nil
}

func (c *capFS) Truncate(path string, newSize int64) error {
	if c.truncErr != nil {
		return c.truncErr
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	n, err := c.node(path)
	if err != nil {
		return err
	}
	if int(newSize) <= len(n.data) {
		n.data = n.data[:newSize]
		return nil
	}
	grown := make([]byte, newSize)
	copy(grown, n.data)
	n.data = grown
	return nil
}

func (c *capFS) Chmod(path string, perm os.FileMode) error {
	if c.chmodErr != nil {
		return c.chmodErr
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	n, err := c.node(path)
	if err != nil {
		return err
	}
	n.mode = n.mode&0o170000 | uint16(perm&0o7777)
	return nil
}

func (c *capFS) Chown(path string, uid, gid uint32) error { return c.chownErr }

func (c *capFS) Chtimes(path string, atime, mtime time.Time) error {
	if c.timesErr != nil {
		return c.timesErr
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	n, err := c.node(path)
	if err != nil {
		return err
	}
	n.mtime = mtime.Unix()
	return nil
}

// --- the Opener capability, declared the way interface declares it ---------

// openerFile mirrors github.com/go-filesystems/interface.File: a *distinct*
// named interface with the same method set. A driver's OpenFile returns this
// type, not the server's own File, which is exactly the situation the
// server's reflection probe exists to handle — a plain type assertion here
// would fail.
type openerFile interface {
	io.ReaderAt
	io.Closer
	Size() int64
}

// openFS is a memFS that implements the optional random-access capability.
type openFS struct {
	*memFS
	openErr error
	// nilFile makes OpenFile return (nil, nil), the driver bug the server
	// has to survive rather than panic on.
	nilFile bool
}

func (o *openFS) OpenFile(path string) (openerFile, error) {
	if o.openErr != nil {
		return nil, o.openErr
	}
	if o.nilFile {
		return nil, nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	n, err := o.node(path)
	if err != nil {
		return nil, err
	}
	return &memFile{data: n.data}, nil
}

type memFile struct {
	data    []byte
	readErr error
	closed  bool
}

func (f *memFile) Size() int64 { return int64(len(f.data)) }
func (f *memFile) Close() error {
	f.closed = true
	return nil
}

func (f *memFile) ReadAt(p []byte, off int64) (int, error) {
	if f.readErr != nil {
		return 0, f.readErr
	}
	if off >= int64(len(f.data)) {
		return 0, io.EOF
	}
	n := copy(p, f.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// badOpener has an OpenFile with the wrong shape, so the probe must reject it
// and fall back to ReadFile rather than call it.
type badOpener struct{ *memFS }

func (b *badOpener) OpenFile(path string, extra int) (openerFile, error) { return nil, nil }

// wrongResultOpener returns a type that does not satisfy File.
type wrongResultOpener struct{ *memFS }

func (w *wrongResultOpener) OpenFile(path string) (int, error) { return 0, nil }

// notStringOpener takes something other than a path.
type notStringOpener struct{ *memFS }

func (n *notStringOpener) OpenFile(i int) (openerFile, error) { return nil, nil }

// oneResultOpener has the wrong arity.
type oneResultOpener struct{ *memFS }

func (o *oneResultOpener) OpenFile(path string) openerFile { return nil }

// errFile is an OpenFile result whose ReadAt fails.
type errOpenFS struct {
	*memFS
	err error
}

func (e *errOpenFS) OpenFile(path string) (openerFile, error) {
	return &memFile{data: make([]byte, 16), readErr: e.err}, nil
}
