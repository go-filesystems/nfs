// Package demo serves a FAT32 image over NFSv3 so it can be mounted with the
// operating system's own client.
//
// It lives in its own module, mirroring detect/fat32reg, so that the core nfs
// module never acquires a dependency on a concrete driver — a driver's
// `replace github.com/go-filesystems/interface => ../interface` does not
// survive transitive importing, which is exactly the breakage that split
// exists to avoid.
//
// It is also this repository's real-mount harness: what proves the server is
// not merely self-consistent is a kernel NFS client reading bytes back out of
// a genuine on-disk image.
package demo

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"

	"crypto/tls"
	"crypto/x509"

	"github.com/go-authn/krb5"
	fat32 "github.com/go-filesystems/fat32"
	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/nfs"
	"github.com/go-filesystems/nfs/rpcgss"
)

// newServer is [nfs.New], indirected so the two failure paths in Setup that
// cannot happen in production — a dead CSPRNG, and an export path that is
// already taken on a server this function just created — are still reachable
// from a test. An error path that has never been executed is an error path
// that has never been shown to clean up after itself, and both of these must
// close the driver they already opened.
var newServer = nfs.New

// Setup opens the image, exports it and returns a server bound to addr,
// without accepting anything yet. Splitting it out of [Main] is what makes
// the whole program reachable from a test: a caller can take the real
// listener's address before a single connection arrives.
//
// The returned server owns nothing but the export; the caller closes both it
// and the listener.
func Setup(image, addr string, readWrite bool, out io.Writer) (*nfs.Server, net.Listener, error) {
	return SetupOpts(image, addr, readWrite, false, out)
}

// wholeFileOnly hides a driver's OpenFile, and therefore its
// filesystem.Opener and filesystem.WritableFile capabilities, from the server.
//
// # Why a demo has a switch for making itself slow
//
// The value of a positional write is a NUMBER, and a number needs a baseline
// measured the same way. Comparing this repository's HEAD against a checkout
// of an older commit would compare two builds on two machines at two times,
// which measures the machines as much as the code. Wrapping the same driver,
// in the same process, on the same image, and taking the capability away is
// the only A/B where the single difference is the thing being measured.
//
// Struct embedding is what makes it exact: every Filesystem method is promoted
// unchanged, so the driver underneath is untouched — only the optional
// interfaces, which are matched on the outer type, disappear. The server then
// takes the ReadFile+splice+WriteFile path it takes for any driver without
// them, which is the code that was there before WritableFile existed.
type wholeFileOnly struct{ filesystem.Filesystem }

// SetupOpts is [Setup] with the measurement switch. Pass noPositional to serve
// the image as if the driver had no Opener/WritableFile capability at all; see
// [wholeFileOnly].
func SetupOpts(image, addr string, readWrite, noPositional bool, out io.Writer, opts ...Option) (*nfs.Server, net.Listener, error) {
	fi, err := os.Stat(image)
	if err != nil {
		return nil, nil, err
	}
	fsys, err := fat32.Open(image, -1)
	if err != nil {
		return nil, nil, err
	}
	srv, err := newServer()
	if err != nil {
		fsys.Close()
		return nil, nil, err
	}
	// The image's size is the one capacity figure that is actually known
	// here; the Filesystem contract has no statfs, so without this `df`
	// would report zero. Free space is genuinely unknown, hence 0.
	var exported filesystem.Filesystem = fsys
	if noPositional {
		exported = wholeFileOnly{fsys}
		fmt.Fprintln(out, "positional read/write DISABLED: serving through ReadFile/WriteFile only")
	}
	exportOpts := []nfs.ExportOption{nfs.WithCapacity(uint64(fi.Size()), 0)}
	if readWrite {
		exportOpts = append(exportOpts, nfs.ReadWrite())
	}
	var set settings
	for _, o := range opts {
		o(&set)
	}
	if set.requireTLS {
		exportOpts = append(exportOpts, nfs.RequireTLS())
		fmt.Fprintln(out, "TLS REQUIRED: calls in the clear are refused NFS3ERR_ACCES (MNT and NULL excepted)")
	}
	if len(set.allow) > 0 {
		allow := set.allow
		exportOpts = append(exportOpts, nfs.AllowPrincipal(func(p string) (bool, bool) {
			ok := slices.Contains(allow, p)
			return ok, ok
		}))
		fmt.Fprintf(out, "export restricted to %s\n", strings.Join(allow, ", "))
	}
	if err := applyAuth(srv, set, out); err != nil {
		fsys.Close()
		return nil, nil, err
	}
	if err := srv.Export("/", exported, exportOpts...); err != nil {
		fsys.Close()
		return nil, nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fsys.Close()
		return nil, nil, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	fmt.Fprintf(out, "serving %s on %s\n", image, ln.Addr())
	fmt.Fprintf(out, "  macOS: sudo mount -t nfs -o vers=3,tcp,port=%d,mountport=%d,noresvport 127.0.0.1:/ /Volumes/img\n", port, port)
	fmt.Fprintf(out, "  Linux: sudo mount -t nfs -o vers=3,tcp,port=%d,mountport=%d,nolock 127.0.0.1:/ /mnt/img\n", port, port)
	return srv, ln, nil
}

// Main parses args and serves until the listener fails. It returns a process
// exit status.
func Main(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("fat32demo", flag.ContinueOnError)
	fs.SetOutput(errOut)
	image := fs.String("image", "", "path to a FAT32 image")
	addr := fs.String("addr", "127.0.0.1:12049", "listen address")
	rw := fs.Bool("rw", false, "export read-write (default read-only)")
	noPositional := fs.Bool("no-positional", false,
		"hide the driver's Opener/WritableFile capabilities, forcing whole-file reads and writes (for A/B measurement)")
	keytab := fs.String("keytab", "",
		"accept sec=krb5 mounts using the service principals in this keytab (sec=sys stays accepted too)")
	certFile := fs.String("tls-cert", "", "accept xprtsec=tls mounts with this certificate (plain TCP stays accepted too)")
	keyFile := fs.String("tls-key", "", "the private key for -tls-cert")
	clientCA := fs.String("tls-client-ca", "", "verify client certificates against this CA and name the caller from their FreeBSD otherName (needs -tls-cert)")
	requireTLS := fs.Bool("require-tls", false, "refuse NFS calls that did not arrive over TLS (needs -tls-cert)")
	allow := fs.String("allow", "", "comma-separated principals the export is restricted to (read and write)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	var opts []Option
	if *keytab != "" {
		opts = append(opts, Keytab(*keytab))
	}
	if *certFile != "" {
		opts = append(opts, TLS(*certFile, *keyFile))
	}
	if *clientCA != "" {
		opts = append(opts, ClientCA(*clientCA))
	}
	if *requireTLS {
		opts = append(opts, RequireTLS())
	}
	if *allow != "" {
		opts = append(opts, Allow(strings.Split(*allow, ",")...))
	}
	srv, ln, err := SetupOpts(*image, *addr, *rw, *noPositional, out, opts...)
	if err != nil {
		fmt.Fprintln(errOut, "fat32demo:", err)
		return 1
	}
	defer srv.Close()
	fmt.Fprintln(errOut, "fat32demo:", srv.Serve(ln))
	return 1
}

// Option configures the served server beyond the positional arguments.
//
// It is variadic rather than a sixth parameter so that callers written before
// there was anything to configure keep compiling.
type Option func(*settings)

type settings struct {
	keytab, certFile, keyFile, clientCA string
	requireTLS                          bool
	allow                               []string
}

// ClientCA makes the server verify client certificates against the CA in
// path and name each TLS caller from the FreeBSD identity otherName its
// certificate carries (see [nfs.OtherNamePrincipal]). It needs [TLS].
func ClientCA(path string) Option { return func(s *settings) { s.clientCA = path } }

// RequireTLS refuses NFS calls that did not arrive over TLS. It needs [TLS].
func RequireTLS() Option { return func(s *settings) { s.requireTLS = true } }

// Allow restricts the export to the named principals, for reading and
// writing alike.
func Allow(principals ...string) Option {
	return func(s *settings) { s.allow = append(s.allow, principals...) }
}

// errNeedsTLS reports an option that only means something over TLS.
var errNeedsTLS = errors.New("-tls-client-ca and -require-tls need -tls-cert")

// Keytab makes the server accept sec=krb5 mounts, using the service
// principals in the keytab at path.
//
// It does NOT make Kerberos mandatory: AUTH_UNIX stays acceptable alongside,
// which is what nfs.Server.SetAuthenticator documents. A demo that implied
// otherwise would be the most misleading thing in this repository.
func Keytab(path string) Option { return func(s *settings) { s.keytab = path } }

// applyAuth is called from SetupOpts once the server exists.
func applyAuth(srv *nfs.Server, s settings, out io.Writer) error {
	if err := applyTLS(srv, s, out); err != nil {
		return err
	}
	if s.keytab == "" {
		return nil
	}
	a, err := krb5.Load(s.keytab)
	if err != nil {
		return err
	}
	// Announced only on success, and after the fact: SetAuthenticator refuses
	// a server that is already serving, and a line saying Kerberos is on
	// would then be the last thing an operator read before it was not.
	err = srv.SetAuthenticator(rpcgss.New(a))
	if err == nil {
		fmt.Fprintf(out, "sec=krb5 accepted (keytab %s); sec=sys still accepted\n", s.keytab)
	}
	return err
}

// TLS makes the server answer the AUTH_TLS probe of RFC 9289, which is what a
// Linux client mounting with xprtsec=tls expects.
//
// Like [Keytab] it adds a possibility rather than a requirement: a client that
// never probes is still served in the clear. And a certificate says which HOST
// is talking, not who — it is not a substitute for sec=krb5, it composes with
// it.
func TLS(certFile, keyFile string) Option {
	return func(s *settings) { s.certFile, s.keyFile = certFile, keyFile }
}

// applyTLS is called from SetupOpts once the server exists.
// otherName names a verified TLS caller by its FreeBSD identity otherName.
func otherName(chain []*x509.Certificate) (string, bool) {
	p, err := nfs.OtherNamePrincipal(chain[0])
	return p, err == nil
}

func applyTLS(srv *nfs.Server, s settings, out io.Writer) error {
	if s.certFile == "" {
		if s.clientCA != "" || s.requireTLS {
			return errNeedsTLS
		}
		return nil
	}
	cert, err := tls.LoadX509KeyPair(s.certFile, s.keyFile)
	if err != nil {
		return err
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	var named error
	if s.clientCA != "" {
		pem, err := os.ReadFile(s.clientCA)
		if err != nil {
			return err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return fmt.Errorf("%s: no certificate in it", s.clientCA)
		}
		cfg.ClientAuth, cfg.ClientCAs = tls.VerifyClientCertIfGiven, pool
		named = srv.SetCertificatePrincipal(otherName)
	}
	// Both setters fail for one reason only, a server already serving, and
	// either failing must stop the server rather than leave TLS half on.
	err = errors.Join(named, srv.SetTLS(cfg))
	if err != nil {
		return err
	}
	if s.clientCA != "" {
		fmt.Fprintf(out, "client certificates verified against %s; callers named by their otherName\n", s.clientCA)
	}
	fmt.Fprintf(out, "xprtsec=tls accepted (certificate %s); plain TCP still accepted\n", s.certFile)
	return nil
}
