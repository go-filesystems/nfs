package nfs

import (
	"errors"
	"io/fs"
	"net"
	"strings"
	"sync"
	"time"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/nfs/rpc"
)

// Errors returned by [Server.Export].
var (
	// ErrExportPath reports an export path that is not a clean absolute
	// path.
	ErrExportPath = errors.New("nfs: export path must be a clean absolute path")
	// ErrExportExists reports a second export on the same path.
	ErrExportExists = errors.New("nfs: export path already in use")
	// ErrNilFilesystem reports Export called with no filesystem. It is
	// caught here because the alternative is a nil dereference on the first
	// client request — long after the mistake, in a connection goroutine,
	// with no recover.
	ErrNilFilesystem = errors.New("nfs: nil filesystem")
	// ErrNoExports reports Serve called with nothing exported. Starting
	// such a server would accept mounts it can only answer with errors.
	ErrNoExports = errors.New("nfs: no exports")
)

// export is one exported filesystem.
type export struct {
	id   uint64
	path string
	fs   filesystem.Filesystem
	// open is the driver's random-access reader, or nil when it has none.
	open func(string) (File, error)
	ro   bool
	// total and avail feed FSSTAT. Zero means "unknown"; see [WithCapacity].
	total, avail uint64
}

// Server is an NFSv3 and MOUNTv3 server.
//
// The zero value is not usable; call [New].
type Server struct {
	handles *handleStore
	// start is the timestamp reported for every file's atime/mtime/ctime
	// until a driver can report real ones. See [attrFor].
	start uint32

	// fsmu serialises *all* access to every exported filesystem.
	//
	// A go-filesystems driver wraps a single *os.File and is not documented
	// as safe for concurrent use; two overlapping READs would interleave
	// seeks and hand each caller the other's bytes. NFS clients pipeline
	// heavily, so this is not a theoretical race — it is the first thing a
	// parallel `ls -lR` would hit.
	fsmu sync.Mutex

	mu      sync.Mutex
	byPath  map[string]*export
	byID    map[uint64]*export
	nextID  uint64
	rpcsrv  *rpc.Server
	started bool
}

// ExportOption configures one export.
type ExportOption func(*export)

// ReadWrite makes an export writable. Exports are read-only by default:
// most of what this module is pointed at is a forensic or build artefact,
// and an accidental write to one is unrecoverable.
func ReadWrite() ExportOption { return func(e *export) { e.ro = false } }

// WithCapacity sets the total and available byte counts reported by FSSTAT
// (what `df` prints).
//
// It exists because [github.com/go-filesystems/interface.Filesystem] has no
// statfs operation, so this module genuinely cannot know. Rather than invent
// a plausible number — which would make `df` confidently wrong, and would
// make a client refuse a write it could actually have done — an export with
// no capacity set reports zeros, and the caller who does know (it opened the
// image, so it knows its size) can say so.
func WithCapacity(total, avail uint64) ExportOption {
	return func(e *export) { e.total, e.avail = total, avail }
}

// New returns a Server with no exports.
//
// It returns an error only if the system CSPRNG is unavailable, which would
// make file handles forgeable; see handle.go.
func New() (*Server, error) {
	h, err := newHandleStore()
	if err != nil {
		return nil, err
	}
	s := &Server{
		handles: h,
		start:   uint32(time.Now().Unix()),
		byPath:  make(map[string]*export),
		byID:    make(map[uint64]*export),
		rpcsrv:  &rpc.Server{},
	}
	s.rpcsrv.Register(s.nfsProgram())
	s.rpcsrv.Register(s.mountProgram())
	return s, nil
}

// Export publishes fsys at the given export path, which is what a client
// names in `host:/path`. Use "/" for a single-filesystem server.
func (s *Server) Export(path string, fsys filesystem.Filesystem, opts ...ExportOption) error {
	if path == "" || path[0] != '/' || path != cleanPath(path) {
		return ErrExportPath
	}
	if fsys == nil {
		return ErrNilFilesystem
	}
	e := &export{path: path, fs: fsys, open: openerFor(fsys), ro: true}
	for _, o := range opts {
		o(e)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.byPath[path]; dup {
		return ErrExportExists
	}
	s.nextID++
	e.id = s.nextID
	s.byPath[path] = e
	s.byID[e.id] = e
	return nil
}

// exportByPath looks up an export by the path a client mounted.
func (s *Server) exportByPath(p string) *export {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byPath[p]
}

// exportByID looks up the export a file handle names.
func (s *Server) exportByID(id uint64) *export {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byID[id]
}

// exportList returns every export, for MOUNTPROC3_EXPORT.
func (s *Server) exportList() []*export {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*export, 0, len(s.byPath))
	for _, e := range s.byPath {
		out = append(out, e)
	}
	return out
}

// Serve accepts connections on ln until [Server.Close], answering both the
// NFS and MOUNT programs on the same port. It always returns a non-nil error.
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	n := len(s.byPath)
	s.started = true
	s.mu.Unlock()
	if n == 0 {
		return ErrNoExports
	}
	return s.rpcsrv.Serve(ln)
}

// ListenAndServe listens on addr and serves. Bind to loopback unless you
// have read the security note in the package documentation.
func (s *Server) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

// Close stops the server and drops every client connection. It does not
// close the exported filesystems: this module did not open them, and the
// caller may still want them.
func (s *Server) Close() error { return s.rpcsrv.Close() }

// ---------------------------------------------------------------------------
// Path handling
// ---------------------------------------------------------------------------

// cleanPath normalises an absolute path: exactly one leading slash, no
// duplicate slashes, no "." or ".." components, no trailing slash except at
// the root.
//
// It is written out rather than delegated to path.Clean because a relative
// input must not be silently rooted, and because ".." must be clamped at the
// root rather than escaping it — path.Clean leaves a leading ".." in place.
func cleanPath(p string) string {
	var out []string
	for _, part := range strings.Split(p, "/") {
		switch part {
		case "", ".":
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, part)
		}
	}
	return "/" + strings.Join(out, "/")
}

// parentOf returns the containing directory, clamped at the root. Clamping is
// the containment guarantee: no sequence of ".." lookups can name anything
// above the export.
func parentOf(p string) string {
	i := strings.LastIndexByte(p, '/')
	if i <= 0 {
		return "/"
	}
	return p[:i]
}

// joinName resolves one directory-plus-component pair from the wire.
//
// NFSv3 never sends a path: it sends a directory handle and a single
// component, which is what keeps a server from having to trust client-side
// path parsing. The component is validated here — this is the only place
// untrusted names enter the path space.
func joinName(dir, name string) (string, Status) {
	switch name {
	case "":
		return "", StatusInval
	case ".":
		return dir, StatusOK
	case "..":
		return parentOf(dir), StatusOK
	}
	if len(name) > nameMax {
		return "", StatusNameTooLong
	}
	// A slash would let one component name a path, and a NUL would let the
	// visible name differ from the name a C caller downstream sees.
	if strings.ContainsAny(name, "/\x00") {
		return "", StatusInval
	}
	full := name
	if dir == "/" {
		full = "/" + name
	} else {
		full = dir + "/" + name
	}
	if len(full) > maxPath {
		return "", StatusNameTooLong
	}
	return full, StatusOK
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

// substringStatus maps a fragment of a driver's error text to an nfsstat3.
//
// This is a wart, and it is worth being explicit about whose wart it is:
// [github.com/go-filesystems/interface] defines no error taxonomy, so drivers
// report "not found" however they like — iso9660 has typed sentinels that do
// not wrap [io/fs.ErrNotExist], fat32 uses bare fmt.Errorf. A protocol server
// must turn those into distinct wire codes, because a client behaves very
// differently on ENOENT than on EIO.
//
// The mitigation is that this table is a *last* resort. Sentinels are tried
// first, and every procedure that can afford to establishes existence and
// type with an explicit Stat rather than inferring them from an error string.
// The real fix belongs upstream: sentinel errors in the interface module that
// every driver wraps.
var substringStatus = []struct {
	frag   string
	status Status
}{
	{"not found", StatusNoEnt},
	{"no such", StatusNoEnt},
	{"does not exist", StatusNoEnt},
	{"not a directory", StatusNotDir},
	{"is a directory", StatusIsDir},
	{"not a regular file", StatusInval},
	{"not a symbolic link", StatusInval},
	{"not empty", StatusNotEmpty},
	{"read-only", StatusROFS},
	{"already exists", StatusExist},
	{"no space", StatusNoSpc},
	{"too many", StatusMLink},
}

// statusFor maps a driver error to an nfsstat3, using fallback when nothing
// matches.
func statusFor(err error, fallback Status) Status {
	if err == nil {
		return StatusOK
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return StatusNoEnt
	case errors.Is(err, fs.ErrExist):
		return StatusExist
	case errors.Is(err, fs.ErrPermission):
		return StatusAccess
	case errors.Is(err, fs.ErrInvalid):
		return StatusInval
	case errors.Is(err, filesystem.ErrShrinkUnsupported):
		return StatusNotSupp
	case errors.Is(err, errHandleFull):
		return StatusServerFault
	}
	low := strings.ToLower(err.Error())
	for _, m := range substringStatus {
		if strings.Contains(low, m.frag) {
			return m.status
		}
	}
	return fallback
}
