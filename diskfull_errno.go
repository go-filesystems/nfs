//go:build !plan9

package nfs

import "syscall"

// The two errnos a filesystem returns when a write cannot be stored for want
// of room, read by errno rather than by the words around them. RFC 1813 §2.6
// gives each its own status, and Linux's knfsd (fs/nfsd/vfs.c, nfserrno)
// sends exactly that: EDQUOT is NFS3ERR_DQUOT, ENOSPC is NFS3ERR_NOSPC.
var (
	errQuota   error = syscall.EDQUOT
	errNoSpace error = syscall.ENOSPC
)
