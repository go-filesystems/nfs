package nfs_test

import (
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/go-filesystems/nfs"
	"github.com/go-filesystems/nfs/xdr"
)

// wire is a minimal NFSv3 client speaking the real protocol over TCP.
//
// The server is verified through the wire, not through its Go API. That is
// the only way to prove the thing a `mount` will actually exercise: an
// in-process call cannot catch a wrong XDR alignment, a missing
// discriminant, or a reply whose fields are in the wrong order — and those
// are exactly the defects that make a real mount fail.
type wire struct {
	t    *testing.T
	conn net.Conn
	xid  uint32
	// cred selects the credential flavour; AUTH_UNIX by default.
	credFlavor uint32
	credBody   []byte
}

const (
	replyAccepted = 0
	replyDenied   = 1
)

// reply carries a decoded RPC reply.
type reply struct {
	replyStat  uint32
	acceptStat uint32
	rejectStat uint32
	// mismatchLo/Hi are the version range on RPC_MISMATCH or PROG_MISMATCH.
	mismatchLo, mismatchHi uint32
	authStat               uint32
	body                   *xdr.Decoder
}

func dial(t *testing.T, addr string) *wire {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	w := &wire{t: t, conn: c, credFlavor: 1}
	// A plausible AUTH_UNIX body: stamp, machine, uid, gid, empty gid list.
	e := xdr.NewEncoder(nil)
	e.Uint32(42)
	e.String("test")
	e.Uint32(501)
	e.Uint32(20)
	e.Uint32(0)
	w.credBody = append([]byte(nil), e.Bytes()...)
	return w
}

// raw sends an already-encoded RPC message body and returns the raw reply.
func (w *wire) raw(msg []byte) []byte {
	w.t.Helper()
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 0x8000_0000|uint32(len(msg)))
	if _, err := w.conn.Write(append(hdr[:], msg...)); err != nil {
		w.t.Fatalf("write: %v", err)
	}
	var rh [4]byte
	if _, err := io.ReadFull(w.conn, rh[:]); err != nil {
		w.t.Fatalf("read header: %v", err)
	}
	n := binary.BigEndian.Uint32(rh[:]) &^ 0x8000_0000
	buf := make([]byte, n)
	if _, err := io.ReadFull(w.conn, buf); err != nil {
		w.t.Fatalf("read body: %v", err)
	}
	return buf
}

// callBytes performs one RPC and returns the decoded reply.
func (w *wire) callBytes(prog, vers, proc uint32, args []byte) reply {
	w.t.Helper()
	w.xid++
	e := xdr.NewEncoder(nil)
	e.Uint32(w.xid)
	e.Uint32(0) // CALL
	e.Uint32(2) // RPC version
	e.Uint32(prog)
	e.Uint32(vers)
	e.Uint32(proc)
	e.Uint32(w.credFlavor)
	e.Opaque(w.credBody)
	e.Uint32(0) // verifier: AUTH_NULL
	e.Opaque(nil)
	e.Fixed(args)
	d := xdr.NewDecoder(w.raw(e.Bytes()))

	var r reply
	xid := w.mustU32(d)
	if xid != w.xid {
		w.t.Fatalf("reply xid = %d, want %d", xid, w.xid)
	}
	if mt := w.mustU32(d); mt != 1 {
		w.t.Fatalf("reply mtype = %d, want 1", mt)
	}
	r.replyStat = w.mustU32(d)
	if r.replyStat == replyDenied {
		r.rejectStat = w.mustU32(d)
		if r.rejectStat == 0 {
			r.mismatchLo, r.mismatchHi = w.mustU32(d), w.mustU32(d)
		} else {
			r.authStat = w.mustU32(d)
		}
		return r
	}
	w.mustU32(d) // verifier flavour
	if _, err := d.Opaque(); err != nil {
		w.t.Fatalf("verifier body: %v", err)
	}
	r.acceptStat = w.mustU32(d)
	if r.acceptStat == 2 { // PROG_MISMATCH
		r.mismatchLo, r.mismatchHi = w.mustU32(d), w.mustU32(d)
	}
	r.body = d
	return r
}

func (w *wire) mustU32(d *xdr.Decoder) uint32 {
	w.t.Helper()
	v, err := d.Uint32()
	if err != nil {
		w.t.Fatalf("decode uint32: %v", err)
	}
	return v
}

// call encodes args through fn and requires an accepted, successful RPC.
func (w *wire) call(prog, vers, proc uint32, fn func(*xdr.Encoder)) *xdr.Decoder {
	w.t.Helper()
	e := xdr.NewEncoder(nil)
	if fn != nil {
		fn(e)
	}
	r := w.callBytes(prog, vers, proc, e.Bytes())
	if r.replyStat != replyAccepted || r.acceptStat != 0 {
		w.t.Fatalf("prog %d proc %d: reply_stat=%d accept_stat=%d", prog, proc, r.replyStat, r.acceptStat)
	}
	return r.body
}

// nfsCall issues an NFSv3 procedure and returns its nfsstat3 plus the rest.
func (w *wire) nfsCall(proc uint32, fn func(*xdr.Encoder)) (nfs.Status, *xdr.Decoder) {
	w.t.Helper()
	d := w.call(nfs.ProgramNFS, nfs.VersionNFS, proc, fn)
	return nfs.Status(w.mustU32(d)), d
}

// mount performs MOUNTPROC3_MNT and returns the root handle.
func (w *wire) mount(path string) []byte {
	w.t.Helper()
	d := w.call(nfs.ProgramMount, nfs.VersionMount, 1, func(e *xdr.Encoder) { e.String(path) })
	if st := w.mustU32(d); st != 0 {
		w.t.Fatalf("MNT %q: status %d", path, st)
	}
	fh, err := d.Opaque()
	if err != nil {
		w.t.Fatalf("MNT handle: %v", err)
	}
	return fh
}

// lookup performs LOOKUP and returns the object handle.
func (w *wire) lookup(dir []byte, name string) ([]byte, nfs.Status) {
	w.t.Helper()
	st, d := w.nfsCall(3, func(e *xdr.Encoder) {
		e.Opaque(dir)
		e.String(name)
	})
	if st != nfs.StatusOK {
		return nil, st
	}
	fh, err := d.Opaque()
	if err != nil {
		w.t.Fatalf("LOOKUP handle: %v", err)
	}
	return fh, st
}

// read performs READ and returns the data and the eof flag.
func (w *wire) read(fh []byte, off uint64, count uint32) ([]byte, bool, nfs.Status) {
	w.t.Helper()
	st, d := w.nfsCall(6, func(e *xdr.Encoder) {
		e.Opaque(fh)
		e.Uint64(off)
		e.Uint32(count)
	})
	if st != nfs.StatusOK {
		return nil, false, st
	}
	w.skipPostOp(d)
	w.mustU32(d) // count, redundant with the opaque length
	eofRaw := w.mustU32(d)
	data, err := d.Opaque()
	if err != nil {
		w.t.Fatalf("READ data: %v", err)
	}
	return data, eofRaw == 1, st
}

// skipPostOp consumes a post_op_attr and reports whether it was present.
func (w *wire) skipPostOp(d *xdr.Decoder) (fattrView, bool) {
	w.t.Helper()
	if w.mustU32(d) == 0 {
		return fattrView{}, false
	}
	var a fattrView
	a.ftype = w.mustU32(d)
	a.mode = w.mustU32(d)
	a.nlink = w.mustU32(d)
	w.mustU32(d) // uid
	w.mustU32(d) // gid
	a.size = w.mustU64(d)
	a.used = w.mustU64(d)
	w.mustU32(d) // rdev major
	w.mustU32(d) // rdev minor
	a.fsid = w.mustU64(d)
	a.fileid = w.mustU64(d)
	for range 3 {
		w.mustU32(d)
		w.mustU32(d)
	}
	return a, true
}

// skipWcc consumes a wcc_data.
func (w *wire) skipWcc(d *xdr.Decoder) {
	w.t.Helper()
	if w.mustU32(d) == 1 {
		w.mustU64(d)
		for range 2 {
			w.mustU32(d)
			w.mustU32(d)
		}
	}
	w.skipPostOp(d)
}

func (w *wire) mustU64(d *xdr.Decoder) uint64 {
	w.t.Helper()
	v, err := d.Uint64()
	if err != nil {
		w.t.Fatalf("decode uint64: %v", err)
	}
	return v
}

type fattrView struct {
	ftype, mode, nlink uint32
	size, used         uint64
	fsid, fileid       uint64
}

// dirEntry is one READDIR/READDIRPLUS entry as seen by the client.
type dirEntry struct {
	fileid uint64
	name   string
	cookie uint64
	attr   fattrView
	hasFH  bool
	fh     []byte
}

// readdir walks READDIR to completion, following cookies exactly as a client
// kernel does — which is what proves the cookie and verifier handling.
func (w *wire) readdir(fh []byte, count uint32) ([]dirEntry, nfs.Status) {
	w.t.Helper()
	var out []dirEntry
	var cookie uint64
	var verf [8]byte
	for {
		st, d := w.nfsCall(16, func(e *xdr.Encoder) {
			e.Opaque(fh)
			e.Uint64(cookie)
			e.Fixed(verf[:])
			e.Uint32(count)
		})
		if st != nfs.StatusOK {
			return out, st
		}
		w.skipPostOp(d)
		v, err := d.Fixed(8)
		if err != nil {
			w.t.Fatalf("cookieverf: %v", err)
		}
		copy(verf[:], v)
		n := 0
		for w.mustU32(d) == 1 {
			var ent dirEntry
			ent.fileid = w.mustU64(d)
			if ent.name, err = d.String(); err != nil {
				w.t.Fatalf("entry name: %v", err)
			}
			ent.cookie = w.mustU64(d)
			out = append(out, ent)
			cookie = ent.cookie
			n++
		}
		if w.mustU32(d) == 1 {
			return out, st
		}
		if n == 0 {
			w.t.Fatal("READDIR made no progress and did not report eof")
		}
	}
}

// readdirPlus is readdir with attributes and handles.
func (w *wire) readdirPlus(fh []byte, maxcount uint32) ([]dirEntry, nfs.Status) {
	w.t.Helper()
	var out []dirEntry
	var cookie uint64
	var verf [8]byte
	for {
		st, d := w.nfsCall(17, func(e *xdr.Encoder) {
			e.Opaque(fh)
			e.Uint64(cookie)
			e.Fixed(verf[:])
			e.Uint32(maxcount / 8)
			e.Uint32(maxcount)
		})
		if st != nfs.StatusOK {
			return out, st
		}
		w.skipPostOp(d)
		v, err := d.Fixed(8)
		if err != nil {
			w.t.Fatalf("cookieverf: %v", err)
		}
		copy(verf[:], v)
		n := 0
		for w.mustU32(d) == 1 {
			var ent dirEntry
			ent.fileid = w.mustU64(d)
			if ent.name, err = d.String(); err != nil {
				w.t.Fatalf("entry name: %v", err)
			}
			ent.cookie = w.mustU64(d)
			ent.attr, _ = w.skipPostOp(d)
			if w.mustU32(d) == 1 {
				ent.hasFH = true
				if ent.fh, err = d.Opaque(); err != nil {
					w.t.Fatalf("entry handle: %v", err)
				}
			}
			out = append(out, ent)
			cookie = ent.cookie
			n++
		}
		if w.mustU32(d) == 1 {
			return out, st
		}
		if n == 0 {
			w.t.Fatal("READDIRPLUS made no progress and did not report eof")
		}
	}
}

// serve starts a server on a loopback port and returns its address.
func serve(t *testing.T, setup func(*nfs.Server)) string {
	t.Helper()
	s, err := nfs.New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	setup(s)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	t.Cleanup(func() {
		s.Close()
		<-done
	})
	return ln.Addr().String()
}
