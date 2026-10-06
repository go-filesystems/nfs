//go:build !plan9

package nfs_test

import (
	"fmt"
	"os"
	"syscall"
	"testing"

	"github.com/go-filesystems/nfs"
)

// TestAFullFilesystemAnswersWithTheStatusRFC1813Names: a WRITE that the
// driver refuses because the disk is full, or because the user's quota is,
// must say which, on the wire.
//
// The expected numbers are written out from RFC 1813 §2.6, not taken from this
// package's constants, so a constant that drifted would be caught too:
//
//	NFS3ERR_NOSPC = 28  "No space left on device."
//	NFS3ERR_DQUOT = 69  "Resource (quota) hard limit exceeded."
//
// Linux's knfsd does the same (fs/nfsd/vfs.c, nfserrno: -ENOSPC ->
// nfserr_nospc, -EDQUOT -> nfserr_dquot). Before this test, EDQUOT fell
// through to the caller's fallback and a client over quota read NFS3ERR_IO,
// which tells the user the disk is failing.
func TestAFullFilesystemAnswersWithTheStatusRFC1813Names(t *testing.T) {
	const (
		nfs3errNoSpc = 28 // RFC 1813 §2.6
		nfs3errDQuot = 69 // RFC 1813 §2.6
	)
	for _, tc := range []struct {
		name string
		err  error
		want nfs.Status
	}{
		{"ENOSPC as os returns it", &os.PathError{Op: "write", Path: "/dir/nested.bin", Err: syscall.ENOSPC}, nfs3errNoSpc},
		{"EDQUOT as os returns it", &os.PathError{Op: "write", Path: "/dir/nested.bin", Err: syscall.EDQUOT}, nfs3errDQuot},
		// A driver that wraps the errno with words of its own must still be
		// read by the errno, not by whether its text happens to match.
		{"ENOSPC wrapped in other words", fmt.Errorf("store refused the block: %w", syscall.ENOSPC), nfs3errNoSpc},
		{"EDQUOT wrapped in other words", fmt.Errorf("store refused the block: %w", syscall.EDQUOT), nfs3errDQuot},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := fixture().failWith("WriteFile:/dir/nested.bin", tc.err)
			fh, w := exportAndLookup(t, m, "/dir/nested.bin")
			if _, st := w.write(fh, 0, []byte("x")); st != tc.want {
				t.Fatalf("WRITE refused with %v answered nfsstat3 %d (%v), want %d", tc.err, uint32(st), st, uint32(tc.want))
			}
		})
	}
}
