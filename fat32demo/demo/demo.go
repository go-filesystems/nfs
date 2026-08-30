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
	"flag"
	"fmt"
	"io"
	"net"
	"os"

	fat32 "github.com/go-filesystems/fat32"
	"github.com/go-filesystems/nfs"
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
	opts := []nfs.ExportOption{nfs.WithCapacity(uint64(fi.Size()), 0)}
	if readWrite {
		opts = append(opts, nfs.ReadWrite())
	}
	if err := srv.Export("/", fsys, opts...); err != nil {
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
	if err := fs.Parse(args); err != nil {
		return 2
	}
	srv, ln, err := Setup(*image, *addr, *rw, out)
	if err != nil {
		fmt.Fprintln(errOut, "fat32demo:", err)
		return 1
	}
	defer srv.Close()
	fmt.Fprintln(errOut, "fat32demo:", srv.Serve(ln))
	return 1
}
