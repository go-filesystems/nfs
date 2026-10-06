package nfs

import (
	"crypto/tls"
	"errors"
	"io/fs"
	"log"
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
	// ErrServing reports a change to a server that is already running. It is
	// refused rather than applied: a client that mounted a moment earlier
	// would be on the old configuration with no way to tell.
	ErrServing = errors.New("nfs: server is already serving")
)

// export is one exported filesystem.
type export struct {
	id   uint64
	path string
	fs   filesystem.Filesystem
	// open is the driver's random-access capability, or nil when it has none.
	// It serves READ at an offset, and — when the File it returns is also a
	// WritableFile — WRITE at an offset too.
	open Opener
	ro   bool
	// total and avail feed FSSTAT. Zero means "unknown"; see [WithCapacity].
	total, avail uint64
	// capacity, when set, is asked at every FSSTAT instead; see
	// [WithCapacityFunc].
	capacity func() (total, avail uint64)
	// allow, when set, decides per CALLER what this export permits. See
	// [AllowCall] and [AllowPrincipal].
	allow func(c *rpc.Call) (read, write bool)
	// requireTLS refuses calls that did not arrive over TLS. See [RequireTLS].
	requireTLS bool
	// lastWalk is when [Server.rediscover] last walked this export. It is
	// guarded by [Server.fsmu], which every walk holds.
	lastWalk time.Time
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
	return func(e *export) { e.total, e.avail, e.capacity = total, avail, nil }
}

// WithCapacityFunc makes FSSTAT ask f for the total and available byte
// counts at every call, instead of reporting the fixed ones [WithCapacity]
// sets. It is for an export whose size or free space changes while it is
// served -- a directory of the host, a quota that is resized -- where a
// number taken once at Export goes stale with the first write.
//
// f runs on the RPC's goroutine, outside the server's lock, once per FSSTAT:
// it must be safe for concurrent use and must not block, because a client's
// `df` waits for it. A caller whose numbers are slow to obtain keeps the last
// ones it has and refreshes them elsewhere. Zero means "unknown", as for
// [WithCapacity]. Of the two options, the one given last wins; a nil f
// is the same as never giving this one.
func WithCapacityFunc(f func() (total, avail uint64)) ExportOption {
	return func(e *export) { e.capacity = f }
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
	e.id = s.handles.exportID(path)
	if _, dup := s.byID[e.id]; dup {
		// Two export paths whose keyed 64-bit hashes collide. Not a thing
		// that happens, and refused rather than aliased if it ever does.
		return ErrExportExists
	}
	s.byPath[path] = e
	s.byID[e.id] = e
	return nil
}

// SetHandleKey makes this server mint and accept file handles under key
// instead of a key of its own, drawn at [New].
//
// It is what lets a client's handles outlive the Server that minted them. A
// program that replaces its Server — on a configuration change, or across a
// restart — and gives the new one the same key and the same export paths
// keeps every handle its clients hold working: the new Server finds the path
// a handle names even if nobody has looked it up there yet (see handle.go).
// Without it every handle is NFS3ERR_BADHANDLE to the next Server, which a
// Linux client reports as EIO on every file it has open.
//
// key must hold at least [HandleKeySize] bytes ([ErrHandleKey] otherwise);
// [NewHandleKey] draws one. It is copied. Keep it secret: it authenticates
// every handle, so whoever holds it can name any file of any export without a
// LOOKUP. The export gates ([RequireTLS], [AllowCall], [ReadWrite]) are still
// judged on every call.
//
// An export path is what ties a handle to an export, so the same path must
// publish the same filesystem on both Servers; a handle for a path that is
// gone is answered NFS3ERR_STALE.
//
// Call it before Serve ([ErrServing] after). Exports already added are
// re-keyed; handles minted before the call are no longer valid.
func (s *Server) SetHandleKey(key []byte) error {
	if len(key) < HandleKeySize {
		return ErrHandleKey
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return ErrServing
	}
	s.handles = newHandleStoreWith(key, s.handles.epoch)
	s.byID = make(map[uint64]*export, len(s.byPath))
	for _, e := range s.byPath {
		e.id = s.handles.exportID(e.path)
		s.byID[e.id] = e
	}
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
	case errors.Is(err, errQuota):
		return StatusDQuot
	case errors.Is(err, errNoSpace):
		return StatusNoSpc
	}
	low := strings.ToLower(err.Error())
	for _, m := range substringStatus {
		if strings.Contains(low, m.frag) {
			return m.status
		}
	}
	return fallback
}

// SetAuthenticator makes this server accept one further credential flavour,
// which in practice means Kerberos: see
// [github.com/go-filesystems/nfs/rpcgss].
//
// Without it the server accepts AUTH_NULL and AUTH_UNIX, where a client
// asserts a uid and nothing can disagree. With it, calls carrying that
// flavour are authenticated, and [github.com/go-filesystems/nfs/rpc.Call]
// carries who the caller proved itself to be.
//
// It does NOT stop AUTH_UNIX from being accepted as well. An export that must
// refuse everything but Kerberos is a policy this module does not yet
// express, and saying so is better than implying a guarantee: a mount that
// silently fell back to AUTH_UNIX would look exactly like one that did not.
//
// Call it before Serve.
func (s *Server) SetAuthenticator(a rpc.Authenticator) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return ErrServing
	}
	s.rpcsrv.Auth = a
	return nil
}

// authFlavor is the extra credential flavour this server accepts, if any.
// MOUNT has to announce it; see procMnt.
func (s *Server) authFlavor() (uint32, bool) {
	if s.rpcsrv.Auth == nil {
		return 0, false
	}
	return s.rpcsrv.Auth.Flavor(), true
}

// SetTLS makes this server answer the AUTH_TLS probe of RFC 9289 and upgrade
// the connection, which is what a Linux client mounting with xprtsec=tls
// expects.
//
// It does NOT make TLS required — [RequireTLS] does that, per export. And by
// itself it authenticates the MACHINE rather than the person: a certificate
// says which host is talking, not who. [Server.SetCertificatePrincipal] is
// the exception, for certificates that name a user. None of this is a
// substitute for sec=krb5 on a shared client, and the two compose — a
// Kerberos mount over TLS gets both.
//
// The server offers the ALPN protocol "sunrpc" (RFC 9289 §5.2) unless cfg
// names protocols of its own.
//
// Call it before Serve.
func (s *Server) SetTLS(cfg *tls.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return ErrServing
	}
	s.rpcsrv.TLS = cfg
	return nil
}

// ConnLimits bounds what one client connection may hold. The zero value of
// each field means the default; a negative value means no bound.
type ConnLimits struct {
	// IdleTimeout closes a connection that has not delivered a complete RPC
	// record for this long. Default [rpc.DefaultIdleTimeout] (5 min): a
	// Linux client drops its own idle connection after five minutes and
	// reconnects on demand, so this costs a real client nothing.
	IdleTimeout time.Duration
	// HandshakeTimeout bounds the TLS handshake after STARTTLS. Default
	// [rpc.DefaultHandshakeTimeout] (30 s).
	HandshakeTimeout time.Duration
	// MaxConns caps concurrent connections; one past the cap is closed as
	// soon as it is accepted. Default [rpc.DefaultMaxConns] (1024).
	MaxConns int
}

// SetConnLimits replaces the connection limits. Every server has them —
// the defaults apply without this call — because the connection is where a
// client that has not yet proved anything can spend the server's memory and
// goroutines.
//
// Call it before Serve.
func (s *Server) SetConnLimits(l ConnLimits) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return ErrServing
	}
	s.rpcsrv.IdleTimeout = l.IdleTimeout
	s.rpcsrv.HandshakeTimeout = l.HandshakeTimeout
	s.rpcsrv.MaxConns = l.MaxConns
	return nil
}

// SetErrorLog sets where the server reports what it cannot tell a client —
// a procedure that panicked, answered SYSTEM_ERR, for one. Nil means the log
// package's standard logger.
//
// Call it before Serve.
func (s *Server) SetErrorLog(l *log.Logger) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return ErrServing
	}
	s.rpcsrv.ErrorLog = l
	return nil
}

// AllowPrincipal restricts an export to the callers a predicate accepts.
//
// It is the option that makes a restricted share servable over NFS at all.
// Without an authenticator or a certificate principal (see
// [Server.SetCertificatePrincipal]) the principal is always empty, so a predicate that
// refuses the empty string refuses everybody — which is the correct answer,
// and the reason this is safe to set unconditionally: a server that forgot to
// configure Kerberos serves nothing rather than serving everything.
//
// The predicate is called on EVERY operation, not once at mount. NFSv3 is
// stateless: there is no session to attach a decision to, a file handle is a
// bearer token that outlives any mount, and a client that keeps one across a
// change of policy would otherwise keep the access it had.
//
// It must be safe for concurrent use, and it should be cheap: it is on the
// path of every read.
//
// It is [AllowCall] reading only [rpc.Call.Principal].
func AllowPrincipal(allow func(principal string) (read, write bool)) ExportOption {
	return AllowCall(func(c *rpc.Call) (bool, bool) { return allow(c.Principal) })
}

// mayWrite reports whether this caller may change this export.
//
// Two gates, and they are not the same question: ro is a property of the
// EXPORT ("this image is served read-only"), and the predicate is a property
// of the CALLER ("this person may read but not write"). A share can be
// writable and still refuse a particular person.
func (s *Server) mayWrite(c *rpc.Call, e *export) bool {
	if e.ro {
		return false
	}
	_, w := e.permits(c)
	return w
}
