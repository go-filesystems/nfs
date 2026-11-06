package nfs_test

import (
	"encoding/binary"
	"io"
	"sync"
	"testing"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/nfs"
	"github.com/go-filesystems/nfs/xdr"
)

// sendCall writes one RPC call without waiting for its reply.
func (w *wire) sendCall(proc uint32, args []byte) uint32 {
	w.t.Helper()
	w.xid++
	e := xdr.NewEncoder(nil)
	e.Uint32(w.xid)
	e.Uint32(0)
	e.Uint32(2)
	e.Uint32(nfs.ProgramNFS)
	e.Uint32(nfs.VersionNFS)
	e.Uint32(proc)
	e.Uint32(w.credFlavor)
	e.Opaque(w.credBody)
	e.Uint32(0)
	e.Opaque(nil)
	e.Fixed(args)
	msg := e.Bytes()
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 0x8000_0000|uint32(len(msg)))
	if _, err := w.conn.Write(append(hdr[:], msg...)); err != nil {
		w.t.Fatalf("write: %v", err)
	}
	return w.xid
}

// recvReply reads one reply record, whichever call it answers.
func (w *wire) recvReply() (xid uint32, body *xdr.Decoder) {
	w.t.Helper()
	var rh [4]byte
	if _, err := io.ReadFull(w.conn, rh[:]); err != nil {
		w.t.Fatalf("read header: %v", err)
	}
	buf := make([]byte, binary.BigEndian.Uint32(rh[:])&^0x8000_0000)
	if _, err := io.ReadFull(w.conn, buf); err != nil {
		w.t.Fatalf("read body: %v", err)
	}
	d := xdr.NewDecoder(buf)
	xid = w.mustU32(d)
	w.mustU32(d) // REPLY
	w.mustU32(d) // MSG_ACCEPTED
	w.mustU32(d) // verifier flavour
	if _, err := d.Opaque(); err != nil {
		w.t.Fatalf("verifier: %v", err)
	}
	if st := w.mustU32(d); st != 0 {
		w.t.Fatalf("accept_stat %d", st)
	}
	return xid, d
}

// Pipelined READs on one connection, answered together and matched by xid
// (RFC 5531), return exactly the bytes asked for, on a driver that reads by
// range (so the ReadAt of each runs under the shared lock) and on one that
// does not (whole-file reads, under the exclusive one).
func TestPipelinedReadsAreMatchedByXID(t *testing.T) {
	for _, tc := range []struct {
		name string
		fsys func() filesystem.Filesystem
		opts []nfs.ExportOption
	}{
		{"ranged driver, shared ReadAt", func() filesystem.Filesystem { return &openFS{memFS: fixture()} }, []nfs.ExportOption{nfs.WithConcurrentReads()}},
		{"ranged driver, exclusive", func() filesystem.Filesystem { return &openFS{memFS: fixture()} }, nil},
		{"whole-file driver", func() filesystem.Filesystem { return fixture() }, []nfs.ExportOption{nfs.WithConcurrentReads()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want, _ := fixture().ReadFile("/dir/nested.bin")
			addr := serve(t, func(s *nfs.Server) {
				if err := s.Export("/", tc.fsys(), tc.opts...); err != nil {
					t.Fatal(err)
				}
			})
			w := dial(t, addr)
			root := w.mount("/")
			dir, _ := w.lookup(root, "dir")
			fh, st := w.lookup(dir, "nested.bin")
			if st != nfs.StatusOK {
				t.Fatalf("LOOKUP: %v", st)
			}
			const n, chunk = 24, 400
			offs := map[uint32]uint64{}
			for i := 0; i < n; i++ {
				e := xdr.NewEncoder(nil)
				e.Opaque(fh)
				e.Uint64(uint64(i * chunk))
				e.Uint32(chunk)
				offs[w.sendCall(6, e.Bytes())] = uint64(i * chunk)
			}
			for range n {
				xid, d := w.recvReply()
				off, ok := offs[xid]
				if !ok {
					t.Fatalf("a reply for xid %d, which was never sent", xid)
				}
				delete(offs, xid)
				if st := nfs.Status(w.mustU32(d)); st != nfs.StatusOK {
					t.Fatalf("READ at %d: %v", off, st)
				}
				w.skipPostOp(d)
				w.mustU32(d) // count
				w.mustU32(d) // eof
				data, err := d.Opaque()
				if err != nil {
					t.Fatal(err)
				}
				if string(data) != string(want[off:off+chunk]) {
					t.Fatalf("READ at %d returned the wrong bytes", off)
				}
			}
		})
	}
}

// Several connections reading the same file at once, with WRITEs among them:
// the exclusive operations never overlap a ReadAt (the race detector is the
// judge) and every READ returns a whole, consistent block.
func TestConnectionsReadWhileAnotherWrites(t *testing.T) {
	fsys := &openFS{memFS: fixture(), writable: true}
	addr := serve(t, func(s *nfs.Server) {
		if err := s.Export("/", fsys, nfs.ReadWrite(), nfs.WithConcurrentReads()); err != nil {
			t.Fatal(err)
		}
	})
	root := dial(t, addr).mount("/")
	var wg sync.WaitGroup
	for c := 0; c < 4; c++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := dial(t, addr)
			dir, _ := w.lookup(root, "dir")
			fh, _ := w.lookup(dir, "nested.bin")
			for i := 0; i < 20; i++ {
				data, _, st := w.read(fh, 0, 512)
				if st != nfs.StatusOK || len(data) != 512 {
					t.Errorf("READ = %d bytes, %v", len(data), st)
					return
				}
				for _, b := range data {
					if b != 'a' && b != 'b' && b != 'z' {
						t.Errorf("READ returned a torn byte %q", b)
						return
					}
				}
			}
		}()
	}
	w := dial(t, addr)
	dir, _ := w.lookup(root, "dir")
	fh, _ := w.lookup(dir, "nested.bin")
	for i := 0; i < 20; i++ {
		e := xdr.NewEncoder(nil)
		e.Opaque(fh)
		e.Uint64(uint64(i * 8))
		e.Uint32(8)
		e.Uint32(0)
		e.Opaque([]byte("zzzzzzzz"))
		w.sendCall(7, e.Bytes())
		w.recvReply()
	}
	wg.Wait()
}
