// Package nfs implements a read/write NFS version 3 server (RFC 1813) that
// exports any [github.com/go-filesystems/interface.Filesystem].
//
// It turns every go-filesystems driver — ext4, xfs, btrfs, zfs, ntfs, fat32,
// exfat, hfsplus, apfs, iso9660, squashfs, ufs, ffs, uefi, oci — into
// something you can `mount` and browse with ordinary tools, on macOS, Linux
// and Windows, from one pure-Go binary.
//
// # Why NFS and not FUSE or FSKit
//
// This is the whole design decision, so it is worth stating plainly.
//
// Mounting an arbitrary filesystem natively on macOS means FSKit: an app
// extension carrying the com.apple.developer.fskit.fsmodule entitlement,
// which requires a provisioning profile issued by Apple. That is a
// distribution wall, not a programming problem — no amount of correct code
// gets past it, and the result would only ever mount on macOS anyway. FUSE
// means a kernel extension (or macFUSE's system extension), which is a second
// wall plus a per-OS C ABI.
//
// NFS is already in every one of those kernels as a *client*. macOS mounts
// it, Linux mounts it, Windows mounts it. So the mountable surface is a
// network protocol, the server is ordinary portable Go, and there is no
// kext, no entitlement, no cgo and no OS-specific code anywhere in this
// module. That preserves exactly the property go-filesystems exists for:
// independence from the host operating system.
//
// The cost is honest and worth naming: a loopback TCP round trip per
// operation instead of a syscall, and NFSv3's stateless model (no open file
// descriptors, no byte-range locks, no notifications).
//
// # Serving one
//
//	fs, err := fat32.Open("disk.img", -1)
//	if err != nil {
//		return err
//	}
//	defer fs.Close()
//
//	srv := nfs.New()
//	if err := srv.Export("/", fs); err != nil {
//		return err
//	}
//	ln, err := net.Listen("tcp", "127.0.0.1:12049")
//	if err != nil {
//		return err
//	}
//	defer srv.Close()
//	go srv.Serve(ln)
//
// Both the MOUNT and NFS programs are served on that single port, so no
// rpcbind (and therefore no privileged port 111, and therefore no root on the
// server side) is involved. Clients are pointed at it directly:
//
//	# macOS
//	sudo mount -t nfs -o vers=3,tcp,port=12049,mountport=12049,noresvport \
//	    127.0.0.1:/ /Volumes/img
//
//	# Linux
//	sudo mount -t nfs -o vers=3,tcp,port=12049,mountport=12049,nolock \
//	    127.0.0.1:/ /mnt/img
//
// Mounting still needs root on the *client* side; that is the OS's rule about
// who may alter the namespace, and nothing here can or should change it.
//
// # Security posture
//
// AUTH_UNIX credentials are claims, not proofs: a client says "uid 501" and
// the wire cannot disagree. This server therefore does not use them for
// access decisions at all. Access is controlled by two things you choose:
// which address the listener is bound to (bind to loopback unless you mean
// otherwise), and whether an export is read-only. Do not put this on a
// public interface expecting the uid fields to protect anything.
package nfs
