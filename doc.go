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
//
// Two things do prove who is calling: RPCSEC_GSS (sec=krb5, krb5i, krb5p; see
// [Server.SetAuthenticator]) and, over RPC-with-TLS, a client certificate
// that names a user (see below). Either one fills
// [github.com/go-filesystems/nfs/rpc.Call.Principal], which [AllowPrincipal]
// and [AllowCall] judge on every operation.
//
// # RPC-with-TLS and who the caller is
//
// [Server.SetTLS] answers the AUTH_TLS probe of RFC 9289 and upgrades the
// connection; [RequireTLS] makes an export refuse every NFS procedure that did
// not arrive that way.
//
// RFC 9289 itself says a server "cannot utilize the remote TLS peer identity
// to authenticate RPC users": a certificate names a peer, and the server
// cannot know whether that peer is one person or a machine shared by many.
// draft-cel-nfsv4-rpc-tls-othername-04 (an individual draft, September 2026)
// lifts that for certificates that SAY they name a user: an identity otherName
// in the SubjectAltName makes the server execute every AUTH_NONE and AUTH_SYS
// call on that TLS session as that identity, RPCSEC_GSS calls being
// unaffected, and a certificate with more than one such otherName MUST be
// rejected. Its OIDs are still unassigned at IANA ([OIDNFSv4Principal]).
// FreeBSD shipped the idea first under a private OID: rpc.tlsservd(8) -u
// (--certuser) maps the otherName 1.3.6.1.4.1.2238.1.1.1, a UTF8String
// "user@domain", to a user, and exports(5) -tlscertuser makes an export
// require one. [OtherNamePrincipal] reads that encoding
// ([OIDFreeBSDCertUser]) and [Server.SetCertificatePrincipal] applies it.
//
// ⛔ What that identity is worth depends on the CLIENT. On Linux the client
// certificate belongs to a MOUNT, not to a user: the kernel hands the
// handshake to tlshd with the certificate and key named on the mount line
// (keyring serials) or in tlshd.conf, and every user of that machine who
// touches the mount acts as the certificate's identity. That is sound on a
// single-user machine. On a shared one it is not, and the answer there is
// still Kerberos, which authenticates each user separately.
package nfs
