package nfs_test

import (
	"errors"
	"testing"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/nfs"
	"github.com/go-filesystems/nfs/xdr"
)

// syncFS is a driver with no positional files (the embedded interface hides
// the memFS's) and a filesystem-level Sync, as (*hfsplus.Volume) is.
type syncFS struct {
	filesystem.Filesystem
	syncs int
	err   error
}

func (s *syncFS) Sync() error { s.syncs++; return s.err }

// For such a driver an UNSTABLE WRITE is answered UNSTABLE and not synced, a
// WRITE that asks for stability is synced before it is answered FILE_SYNC, and
// COMMIT syncs. A failed Sync is NFS3ERR_IO, never a success the client trusts.
func TestWriteAndCommitSyncAVolumeSyncer(t *testing.T) {
	fs := &syncFS{Filesystem: fixture()}
	addr := serve(t, func(s *nfs.Server) { s.Export("/", fs, nfs.ReadWrite()) })
	w := dial(t, addr)
	root := w.mount("/")
	st, d := w.nfsCall(8, func(e *xdr.Encoder) {
		e.Opaque(root)
		e.String("v.txt")
		e.Uint32(0)
		sattrNone(e)
	})
	if st != nfs.StatusOK || w.mustU32(d) != 1 {
		t.Fatalf("CREATE: %v", st)
	}
	fh, _ := d.Opaque()

	write := func(stable uint32) (nfs.Status, uint32) {
		st, d := w.nfsCall(7, func(e *xdr.Encoder) {
			e.Opaque(fh)
			e.Uint64(0)
			e.Uint32(3)
			e.Uint32(stable)
			e.Opaque([]byte("abc"))
		})
		if st != nfs.StatusOK {
			return st, 0
		}
		w.skipWcc(d)
		w.mustU32(d) // count
		return st, w.mustU32(d)
	}
	commit := func() nfs.Status {
		st, _ := w.nfsCall(21, func(e *xdr.Encoder) {
			e.Opaque(fh)
			e.Uint64(0)
			e.Uint32(0)
		})
		return st
	}

	if st, how := write(0); st != nfs.StatusOK || how != 0 || fs.syncs != 0 {
		t.Fatalf("UNSTABLE WRITE: status %v committed %d syncs %d, want OK, 0, 0", st, how, fs.syncs)
	}
	if st := commit(); st != nfs.StatusOK || fs.syncs != 1 {
		t.Fatalf("COMMIT: status %v syncs %d, want OK and 1", st, fs.syncs)
	}
	if st, how := write(2); st != nfs.StatusOK || how != 2 || fs.syncs != 2 {
		t.Fatalf("FILE_SYNC WRITE: status %v committed %d syncs %d, want OK, 2, 2", st, how, fs.syncs)
	}

	fs.err = errors.New("disk gone")
	if st := commit(); st != nfs.StatusIO {
		t.Errorf("COMMIT with a failing Sync = %v, want IO", st)
	}
	if st, _ := write(2); st != nfs.StatusIO {
		t.Errorf("FILE_SYNC WRITE with a failing Sync = %v, want IO", st)
	}
}
