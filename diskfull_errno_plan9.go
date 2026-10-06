package nfs

import "errors"

// Plan 9's syscall has no errno numbers: its errors are strings. These two
// are never returned by anything, so nothing matches them, and a driver's
// "no space" still reaches NFS3ERR_NOSPC through the text fallback.
var (
	errQuota   = errors.New("nfs: no errno EDQUOT on plan9")
	errNoSpace = errors.New("nfs: no errno ENOSPC on plan9")
)
