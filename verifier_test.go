package nfs_test

import (
	"bytes"
	"testing"

	"github.com/go-filesystems/nfs"
	"github.com/go-filesystems/nfs/xdr"
)

// writeVerifier makes a WRITE on a server of its own and returns the verifier
// the WRITE and the COMMIT that follows both carry.
func writeVerifier(t *testing.T) (write, commit []byte) {
	t.Helper()
	m := fixture()
	addr := serve(t, func(s *nfs.Server) { s.Export("/", m, nfs.ReadWrite()) })
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
	st, d = w.nfsCall(7, func(e *xdr.Encoder) {
		e.Opaque(fh)
		e.Uint64(0)
		e.Uint32(1)
		e.Uint32(0) // UNSTABLE
		e.Opaque([]byte("x"))
	})
	if st != nfs.StatusOK {
		t.Fatalf("WRITE: %v", st)
	}
	w.skipWcc(d)
	w.mustU32(d) // count
	w.mustU32(d) // committed
	write, _ = d.Fixed(8)
	st, d = w.nfsCall(21, func(e *xdr.Encoder) {
		e.Opaque(fh)
		e.Uint64(0)
		e.Uint32(0)
	})
	if st != nfs.StatusOK {
		t.Fatalf("COMMIT: %v", st)
	}
	w.skipWcc(d)
	commit, _ = d.Fixed(8)
	return write, commit
}

// A client compares the verifier across calls to learn whether the server
// restarted, and so whether unstable writes it has not committed are lost
// (RFC 1813 3.3.7, 3.3.21). Two servers, a restart or the new generation a
// reload starts, must therefore answer different verifiers, while one server
// answers the same on WRITE and COMMIT. A constant verifier would let a client
// trust uncommitted data across a restart.
func TestTwoServersAnswerDifferentWriteVerifiers(t *testing.T) {
	w1, c1 := writeVerifier(t)
	w2, c2 := writeVerifier(t)
	if !bytes.Equal(w1, c1) || !bytes.Equal(w2, c2) {
		t.Fatalf("WRITE and COMMIT disagree on one server: %x/%x and %x/%x", w1, c1, w2, c2)
	}
	if bytes.Equal(w1, w2) {
		t.Fatalf("two servers answered the same verifier %x", w1)
	}
}
