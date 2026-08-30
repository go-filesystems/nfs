package nfs

import (
	"math"
	"os"
	"time"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/nfs/rpc"
	"github.com/go-filesystems/nfs/xdr"
)

// writeVerf is the write verifier returned by WRITE and COMMIT.
//
// A client compares it across calls to learn whether the server restarted and
// therefore whether unstable writes it had not yet committed are lost. This
// server only ever answers FILE_SYNC — a driver's WriteFile has already
// reached the backing image before the reply is built — so nothing is ever at
// risk, but the field must still change across restarts to stay truthful. It
// is derived from the handle store's epoch, which is exactly "this process
// instance".
func (s *Server) writeVerf() []byte {
	var b [8]byte
	for i := range 8 {
		b[i] = byte(s.handles.epoch >> (56 - 8*i))
	}
	return b[:]
}

// sattr is a decoded sattr3 (RFC 1813 §2.5): every field optional.
type sattr struct {
	modeSet bool
	mode    uint32
	uidSet  bool
	uid     uint32
	gidSet  bool
	gid     uint32
	sizeSet bool
	size    uint64
	// atimeHow and mtimeHow are time_how: 0 DONT_CHANGE, 1 SET_TO_SERVER_TIME,
	// 2 SET_TO_CLIENT_TIME.
	atimeHow, mtimeHow uint32
	atime, mtime       uint32
}

// decodeSattr reads an sattr3.
func decodeSattr(d *xdr.Decoder) (sattr, error) {
	var a sattr
	var err error
	if a.modeSet, err = d.Bool(); err != nil {
		return a, err
	}
	if a.modeSet {
		if a.mode, err = d.Uint32(); err != nil {
			return a, err
		}
	}
	if a.uidSet, err = d.Bool(); err != nil {
		return a, err
	}
	if a.uidSet {
		if a.uid, err = d.Uint32(); err != nil {
			return a, err
		}
	}
	if a.gidSet, err = d.Bool(); err != nil {
		return a, err
	}
	if a.gidSet {
		if a.gid, err = d.Uint32(); err != nil {
			return a, err
		}
	}
	if a.sizeSet, err = d.Bool(); err != nil {
		return a, err
	}
	if a.sizeSet {
		if a.size, err = d.Uint64(); err != nil {
			return a, err
		}
	}
	if a.atimeHow, err = d.Uint32(); err != nil {
		return a, err
	}
	if a.atimeHow == 2 {
		if a.atime, err = d.Uint32(); err != nil {
			return a, err
		}
		if _, err = d.Uint32(); err != nil {
			return a, err
		}
	}
	if a.mtimeHow, err = d.Uint32(); err != nil {
		return a, err
	}
	if a.mtimeHow == 2 {
		if a.mtime, err = d.Uint32(); err != nil {
			return a, err
		}
		if _, err = d.Uint32(); err != nil {
			return a, err
		}
	}
	return a, nil
}

// perm turns an optional sattr3 mode into an os.FileMode for the driver
// calls that take one, defaulting to 0644 for files.
func (a sattr) perm(def os.FileMode) os.FileMode {
	if !a.modeSet {
		return def
	}
	return os.FileMode(a.mode & 0o7777)
}

// applySattr applies what the driver can actually do.
//
// Attributes the driver cannot set are ignored rather than refused, with one
// exception: size. Silently ignoring a truncate would let a client believe a
// file is empty when it is not, which is data loss in the direction that
// matters; ignoring an unsettable mode or timestamp merely means the client's
// next GETATTR shows the old value, which it can see for itself.
//
// The caller must hold [Server.fsmu].
func (s *Server) applySattr(e *export, path string, a sattr) Status {
	if a.sizeSet {
		t, ok := e.fs.(filesystem.Truncater)
		if !ok {
			return StatusNotSupp
		}
		if err := t.Truncate(path, int64(a.size)); err != nil {
			return statusFor(err, StatusIO)
		}
	}
	m, ok := e.fs.(filesystem.MetadataSetter)
	if !ok {
		return StatusOK
	}
	if a.modeSet {
		if err := m.Chmod(path, os.FileMode(a.mode&0o7777)); err != nil {
			return statusFor(err, StatusIO)
		}
	}
	if a.uidSet || a.gidSet {
		if err := m.Chown(path, a.uid, a.gid); err != nil {
			return statusFor(err, StatusIO)
		}
	}
	if a.atimeHow != 0 || a.mtimeHow != 0 {
		now := time.Now()
		at, mt := now, now
		if a.atimeHow == 2 {
			at = time.Unix(int64(a.atime), 0)
		}
		if a.mtimeHow == 2 {
			mt = time.Unix(int64(a.mtime), 0)
		}
		if err := m.Chtimes(path, at, mt); err != nil {
			return statusFor(err, StatusIO)
		}
	}
	return StatusOK
}

// wccFail encodes a failed mutating reply: status plus a wcc_data whose
// "before" is absent.
func wccFail(res *xdr.Encoder, st Status, after fattr, afterSt Status) {
	res.Uint32(uint32(st))
	encodeWcc(res, fattr{}, false, after, afterSt)
}

// SETATTR (RFC 1813 §3.2).
func (s *Server) procSetAttr(c *rpc.Call) rpc.Status {
	e, path, st, garbage := s.fhArg(c.Args)
	if garbage {
		return rpc.StatusGarbageArgs
	}
	a, err := decodeSattr(c.Args)
	if err != nil {
		return rpc.StatusGarbageArgs
	}
	guard, err := c.Args.Bool()
	if err != nil {
		return rpc.StatusGarbageArgs
	}
	var guardCtime uint32
	if guard {
		if guardCtime, err = c.Args.Uint32(); err != nil {
			return rpc.StatusGarbageArgs
		}
		if _, err = c.Args.Uint32(); err != nil {
			return rpc.StatusGarbageArgs
		}
	}
	if st != StatusOK {
		wccFail(c.Res, st, fattr{}, st)
		return rpc.StatusSuccess
	}
	s.fsmu.Lock()
	defer s.fsmu.Unlock()
	before, beforeSt := s.attrFor(e, path)
	if beforeSt != StatusOK {
		wccFail(c.Res, beforeSt, fattr{}, beforeSt)
		return rpc.StatusSuccess
	}
	if e.ro {
		wccFail(c.Res, StatusROFS, before, StatusOK)
		return rpc.StatusSuccess
	}
	// The guard is the protocol's compare-and-set: apply only if nothing has
	// changed the object since the client last looked.
	if guard && guardCtime != before.ctime {
		wccFail(c.Res, StatusNotSync, before, StatusOK)
		return rpc.StatusSuccess
	}
	st = s.applySattr(e, path, a)
	after, afterSt := s.attrFor(e, path)
	c.Res.Uint32(uint32(st))
	encodeWcc(c.Res, before, true, after, afterSt)
	return rpc.StatusSuccess
}

// WRITE (RFC 1813 §3.7).
//
// # Positional when the driver can, read-modify-write when it cannot
//
// A WRITE names an offset. Whether this server can honour it as an offset
// depends entirely on the driver:
//
//   - The driver implements [github.com/go-filesystems/interface.Opener] and
//     the [github.com/go-filesystems/interface.File] it returns is also a
//     [github.com/go-filesystems/interface.WritableFile]: the bytes go where
//     the client put them, and the cost is the bytes themselves.
//   - Otherwise [github.com/go-filesystems/interface.Filesystem] offers only
//     WriteFile, which replaces a WHOLE file. The request then costs
//     O(filesize): read everything, splice, write everything back. A client
//     streaming a file in wtpref-sized blocks pays that per block, so the
//     transfer is quadratic in the file's size.
//
// The second path is not a theoretical cost. Against a FAT32 image with no
// positional write, a 2 MiB sequential dd in 64 KiB blocks over a real Linux
// kernel NFS mount took 23 s — 90 kB/s — and a soft,timeo=50 mount gave up
// with EIO partway through, because one WRITE round-trip exceeded the
// client's timeout. It is kept because it is the only thing a read-only-ish
// driver can do, and because a correct slow answer beats NFS3ERR_NOTSUPP; it
// is not kept because it is acceptable.
func (s *Server) procWrite(c *rpc.Call) rpc.Status {
	e, path, st, garbage := s.fhArg(c.Args)
	if garbage {
		return rpc.StatusGarbageArgs
	}
	off, err := c.Args.Uint64()
	if err != nil {
		return rpc.StatusGarbageArgs
	}
	if _, err = c.Args.Uint32(); err != nil { // count, redundant with len(data)
		return rpc.StatusGarbageArgs
	}
	if _, err = c.Args.Uint32(); err != nil { // stable
		return rpc.StatusGarbageArgs
	}
	data, err := c.Args.Opaque()
	if err != nil {
		return rpc.StatusGarbageArgs
	}
	if st != StatusOK {
		wccFail(c.Res, st, fattr{}, st)
		return rpc.StatusSuccess
	}
	if len(data) > writeMax {
		wccFail(c.Res, StatusInval, fattr{}, StatusNoEnt)
		return rpc.StatusSuccess
	}
	// off is a uint64 off the wire and len(data) is bounded by writeMax, but
	// the sum still has to be expressible as the int64 every driver offset
	// is, or the positional path would hand a negative offset to a WriteAt.
	// Refusing here also spares the fallback a make() of absurd size.
	if off > math.MaxInt64-uint64(len(data)) {
		wccFail(c.Res, StatusInval, fattr{}, StatusNoEnt)
		return rpc.StatusSuccess
	}
	s.fsmu.Lock()
	defer s.fsmu.Unlock()
	before, beforeSt := s.attrFor(e, path)
	if beforeSt != StatusOK {
		wccFail(c.Res, beforeSt, fattr{}, beforeSt)
		return rpc.StatusSuccess
	}
	if e.ro {
		wccFail(c.Res, StatusROFS, before, StatusOK)
		return rpc.StatusSuccess
	}
	if before.ftype == ftypeDir {
		wccFail(c.Res, StatusIsDir, before, StatusOK)
		return rpc.StatusSuccess
	}
	if st := s.writeAt(e, path, off, data, os.FileMode(before.mode)); st != StatusOK {
		wccFail(c.Res, st, before, StatusOK)
		return rpc.StatusSuccess
	}
	after, afterSt := s.attrFor(e, path)
	c.Res.Uint32(uint32(StatusOK))
	encodeWcc(c.Res, before, true, after, afterSt)
	c.Res.Uint32(uint32(len(data)))
	c.Res.Uint32(writeFileSync)
	c.Res.Fixed(s.writeVerf())
	return rpc.StatusSuccess
}

// writeAt lands data at off, positionally when the driver allows it.
//
// The probe is on the FILE, not on the driver, and that distinction is the
// reason this is a separate function rather than a branch inside procWrite:
// a driver may open one file writably and hand back a plain, read-only File
// for another — ext4 does exactly that for an inode whose body is inline or
// mapped by the old block map rather than by extents. Falling back per file
// keeps those files working at the slow-but-correct speed while every other
// file on the same volume gets the fast path.
//
// Failure of the positional path is reported, never retried through the
// fallback. A WriteAt that failed halfway has already changed the file, and
// re-splicing the same request over the result would write the client's bytes
// twice or paper over a real medium error; the client's own retry, which
// carries the same offset and the same bytes, is the correct recovery.
//
// The caller must hold [Server.fsmu].
func (s *Server) writeAt(e *export, path string, off uint64, data []byte, perm os.FileMode) Status {
	if e.open != nil {
		f, err := e.openFile(path)
		if err != nil {
			return statusFor(err, StatusIO)
		}
		if w, ok := f.(WritableFile); ok {
			// Close's error matters here in a way it does not on the read
			// path: it is a driver's last chance to report that a write it
			// buffered could not be flushed, and swallowing it would let the
			// server answer FILE_SYNC for bytes that never landed.
			if _, err := w.WriteAt(data, int64(off)); err != nil {
				f.Close()
				return statusFor(err, StatusIO)
			}
			// Sync before Close, so the FILE_SYNC this server always answers
			// with is a claim the driver has actually been asked to honour.
			// NFSv3 §3.21 lets a server promise stability only if it can.
			if err := w.Sync(); err != nil {
				f.Close()
				return statusFor(err, StatusIO)
			}
			if err := f.Close(); err != nil {
				return statusFor(err, StatusIO)
			}
			return StatusOK
		}
		// Openable but not writable: fall through to read-modify-write, and
		// release the handle first so the driver is not asked to serve a
		// WriteFile on a path it still has open.
		if err := f.Close(); err != nil {
			return statusFor(err, StatusIO)
		}
	}
	cur, err := e.fs.ReadFile(path)
	if err != nil {
		return statusFor(err, StatusIO)
	}
	end := off + uint64(len(data))
	if end > uint64(len(cur)) {
		grown := make([]byte, end)
		copy(grown, cur)
		cur = grown
	}
	copy(cur[off:], data)
	if err := e.fs.WriteFile(path, cur, perm); err != nil {
		return statusFor(err, StatusIO)
	}
	return StatusOK
}

// createReply encodes the shared tail of CREATE, MKDIR and SYMLINK.
func (s *Server) createReply(c *rpc.Call, e *export, dir, full string, before fattr, beforeOK bool) {
	obj, objSt := s.attrFor(e, full)
	dirAfter, dirAfterSt := s.attrFor(e, dir)
	h, err := s.handles.Handle(e.id, full)
	c.Res.Uint32(uint32(StatusOK))
	if err != nil {
		c.Res.Bool(false)
	} else {
		c.Res.Bool(true)
		c.Res.Opaque(h)
	}
	encodePostOp(c.Res, obj, objSt)
	encodeWcc(c.Res, before, beforeOK, dirAfter, dirAfterSt)
}

// mutablePrologue performs the checks every creating procedure shares.
//
// The caller must hold [Server.fsmu].
func (s *Server) mutablePrologue(e *export, dir string) (before fattr, st Status) {
	before, st = s.attrFor(e, dir)
	if st != StatusOK {
		return fattr{}, st
	}
	if e.ro {
		return before, StatusROFS
	}
	if before.ftype != ftypeDir {
		return before, StatusNotDir
	}
	return before, StatusOK
}

// CREATE (RFC 1813 §3.8).
func (s *Server) procCreate(c *rpc.Call) rpc.Status {
	e, dir, full, st, garbage := s.dirOpArg(c.Args)
	if garbage {
		return rpc.StatusGarbageArgs
	}
	how, err := c.Args.Uint32()
	if err != nil {
		return rpc.StatusGarbageArgs
	}
	var attrs sattr
	switch how {
	case createUnchecked, createGuarded:
		if attrs, err = decodeSattr(c.Args); err != nil {
			return rpc.StatusGarbageArgs
		}
	case createExclusive:
		// The 8-byte verifier is meant to be stored with the file so a
		// retransmitted EXCLUSIVE create is recognised as a duplicate. No
		// driver has anywhere to put it, so exclusive create degrades to
		// guarded — which is safe (it still refuses to clobber) and merely
		// loses idempotence across a retransmit.
		if _, err = c.Args.Fixed(8); err != nil {
			return rpc.StatusGarbageArgs
		}
		how = createGuarded
	default:
		return rpc.StatusGarbageArgs
	}
	if st != StatusOK {
		wccFail(c.Res, st, fattr{}, st)
		return rpc.StatusSuccess
	}
	s.fsmu.Lock()
	defer s.fsmu.Unlock()
	before, st := s.mutablePrologue(e, dir)
	if st != StatusOK {
		wccFail(c.Res, st, before, StatusOK)
		return rpc.StatusSuccess
	}
	if _, err := e.fs.Stat(full); err == nil {
		if how == createGuarded {
			wccFail(c.Res, StatusExist, before, StatusOK)
			return rpc.StatusSuccess
		}
	}
	if err := e.fs.WriteFile(full, nil, attrs.perm(0o644)); err != nil {
		wccFail(c.Res, statusFor(err, StatusIO), before, StatusOK)
		return rpc.StatusSuccess
	}
	s.createReply(c, e, dir, full, before, true)
	return rpc.StatusSuccess
}

// MKDIR (RFC 1813 §3.9).
func (s *Server) procMkdir(c *rpc.Call) rpc.Status {
	e, dir, full, st, garbage := s.dirOpArg(c.Args)
	if garbage {
		return rpc.StatusGarbageArgs
	}
	attrs, err := decodeSattr(c.Args)
	if err != nil {
		return rpc.StatusGarbageArgs
	}
	if st != StatusOK {
		wccFail(c.Res, st, fattr{}, st)
		return rpc.StatusSuccess
	}
	s.fsmu.Lock()
	defer s.fsmu.Unlock()
	before, st := s.mutablePrologue(e, dir)
	if st != StatusOK {
		wccFail(c.Res, st, before, StatusOK)
		return rpc.StatusSuccess
	}
	if _, err := e.fs.Stat(full); err == nil {
		wccFail(c.Res, StatusExist, before, StatusOK)
		return rpc.StatusSuccess
	}
	if err := e.fs.MkDir(full, attrs.perm(0o755)); err != nil {
		wccFail(c.Res, statusFor(err, StatusIO), before, StatusOK)
		return rpc.StatusSuccess
	}
	s.createReply(c, e, dir, full, before, true)
	return rpc.StatusSuccess
}

// SYMLINK (RFC 1813 §3.10).
func (s *Server) procSymlink(c *rpc.Call) rpc.Status {
	e, dir, full, st, garbage := s.dirOpArg(c.Args)
	if garbage {
		return rpc.StatusGarbageArgs
	}
	if _, err := decodeSattr(c.Args); err != nil {
		return rpc.StatusGarbageArgs
	}
	target, err := c.Args.String()
	if err != nil {
		return rpc.StatusGarbageArgs
	}
	if st != StatusOK {
		wccFail(c.Res, st, fattr{}, st)
		return rpc.StatusSuccess
	}
	s.fsmu.Lock()
	defer s.fsmu.Unlock()
	before, st := s.mutablePrologue(e, dir)
	if st != StatusOK {
		wccFail(c.Res, st, before, StatusOK)
		return rpc.StatusSuccess
	}
	sym, ok := e.fs.(filesystem.Symlinker)
	if !ok {
		wccFail(c.Res, StatusNotSupp, before, StatusOK)
		return rpc.StatusSuccess
	}
	if err := sym.Symlink(target, full); err != nil {
		wccFail(c.Res, statusFor(err, StatusIO), before, StatusOK)
		return rpc.StatusSuccess
	}
	s.createReply(c, e, dir, full, before, true)
	return rpc.StatusSuccess
}

// MKNOD (RFC 1813 §3.11).
//
// Device, socket and FIFO nodes have no representation in the Filesystem
// contract, so this is a truthful NFS3ERR_NOTSUPP rather than a silent
// regular file — which is what a client would otherwise have to discover by
// reading back something that is not a device.
func (s *Server) procMknod(c *rpc.Call) rpc.Status {
	e, dir, _, st, garbage := s.dirOpArg(c.Args)
	if garbage {
		return rpc.StatusGarbageArgs
	}
	if st != StatusOK {
		wccFail(c.Res, st, fattr{}, st)
		return rpc.StatusSuccess
	}
	s.fsmu.Lock()
	before, beforeSt := s.attrFor(e, dir)
	s.fsmu.Unlock()
	wccFail(c.Res, StatusNotSupp, before, beforeSt)
	return rpc.StatusSuccess
}

// removeCommon backs REMOVE and RMDIR, which differ only in which driver call
// they make and which type they insist on.
func (s *Server) removeCommon(c *rpc.Call, wantDir bool) rpc.Status {
	e, dir, full, st, garbage := s.dirOpArg(c.Args)
	if garbage {
		return rpc.StatusGarbageArgs
	}
	if st != StatusOK {
		wccFail(c.Res, st, fattr{}, st)
		return rpc.StatusSuccess
	}
	s.fsmu.Lock()
	defer s.fsmu.Unlock()
	before, st := s.mutablePrologue(e, dir)
	if st != StatusOK {
		wccFail(c.Res, st, before, StatusOK)
		return rpc.StatusSuccess
	}
	target, targetSt := s.attrFor(e, full)
	if targetSt != StatusOK {
		wccFail(c.Res, targetSt, before, StatusOK)
		return rpc.StatusSuccess
	}
	isDir := target.ftype == ftypeDir
	if wantDir && !isDir {
		wccFail(c.Res, StatusNotDir, before, StatusOK)
		return rpc.StatusSuccess
	}
	if !wantDir && isDir {
		wccFail(c.Res, StatusIsDir, before, StatusOK)
		return rpc.StatusSuccess
	}
	var err error
	if wantDir {
		// RMDIR must refuse a non-empty directory. Several drivers'
		// DeleteDir remove the contents recursively, which would turn one
		// rmdir into a silent recursive delete, so emptiness is checked
		// here rather than trusted to the driver.
		names, listSt := s.listDir(e, full)
		if listSt != StatusOK {
			wccFail(c.Res, listSt, before, StatusOK)
			return rpc.StatusSuccess
		}
		if len(names) > 0 {
			wccFail(c.Res, StatusNotEmpty, before, StatusOK)
			return rpc.StatusSuccess
		}
		err = e.fs.DeleteDir(full)
	} else {
		err = e.fs.DeleteFile(full)
	}
	if err != nil {
		wccFail(c.Res, statusFor(err, StatusIO), before, StatusOK)
		return rpc.StatusSuccess
	}
	after, afterSt := s.attrFor(e, dir)
	c.Res.Uint32(uint32(StatusOK))
	encodeWcc(c.Res, before, true, after, afterSt)
	return rpc.StatusSuccess
}

// REMOVE (RFC 1813 §3.12).
func (s *Server) procRemove(c *rpc.Call) rpc.Status { return s.removeCommon(c, false) }

// RMDIR (RFC 1813 §3.13).
func (s *Server) procRmdir(c *rpc.Call) rpc.Status { return s.removeCommon(c, true) }

// RENAME (RFC 1813 §3.14).
func (s *Server) procRename(c *rpc.Call) rpc.Status {
	fromE, fromDir, fromFull, st, garbage := s.dirOpArg(c.Args)
	if garbage {
		return rpc.StatusGarbageArgs
	}
	toE, toDir, toFull, st2, garbage := s.dirOpArg(c.Args)
	if garbage {
		return rpc.StatusGarbageArgs
	}
	if st != StatusOK || st2 != StatusOK {
		bad := st
		if bad == StatusOK {
			bad = st2
		}
		c.Res.Uint32(uint32(bad))
		encodeWcc(c.Res, fattr{}, false, fattr{}, bad)
		encodeWcc(c.Res, fattr{}, false, fattr{}, bad)
		return rpc.StatusSuccess
	}
	renameFail := func(st Status, a, b fattr, aSt, bSt Status) rpc.Status {
		c.Res.Uint32(uint32(st))
		encodeWcc(c.Res, fattr{}, false, a, aSt)
		encodeWcc(c.Res, fattr{}, false, b, bSt)
		return rpc.StatusSuccess
	}
	if fromE != toE {
		// NFSv3 has no cross-filesystem rename; XDEV is what a client
		// expects and what makes `mv` fall back to copy-and-delete.
		return renameFail(StatusXDev, fattr{}, fattr{}, StatusNoEnt, StatusNoEnt)
	}
	s.fsmu.Lock()
	defer s.fsmu.Unlock()
	fromBefore, st := s.mutablePrologue(fromE, fromDir)
	if st != StatusOK {
		return renameFail(st, fromBefore, fattr{}, StatusOK, StatusNoEnt)
	}
	toBefore, toBeforeSt := s.attrFor(toE, toDir)
	if err := fromE.fs.Rename(fromFull, toFull); err != nil {
		return renameFail(statusFor(err, StatusIO), fromBefore, toBefore, StatusOK, toBeforeSt)
	}
	fromAfter, fromAfterSt := s.attrFor(fromE, fromDir)
	toAfter, toAfterSt := s.attrFor(toE, toDir)
	c.Res.Uint32(uint32(StatusOK))
	encodeWcc(c.Res, fromBefore, true, fromAfter, fromAfterSt)
	encodeWcc(c.Res, toBefore, toBeforeSt == StatusOK, toAfter, toAfterSt)
	return rpc.StatusSuccess
}

// LINK (RFC 1813 §3.15).
func (s *Server) procLink(c *rpc.Call) rpc.Status {
	e, path, st, garbage := s.fhArg(c.Args)
	if garbage {
		return rpc.StatusGarbageArgs
	}
	linkE, linkDir, linkFull, st2, garbage := s.dirOpArg(c.Args)
	if garbage {
		return rpc.StatusGarbageArgs
	}
	if st != StatusOK || st2 != StatusOK {
		bad := st
		if bad == StatusOK {
			bad = st2
		}
		c.Res.Uint32(uint32(bad))
		c.Res.Bool(false)
		encodeWcc(c.Res, fattr{}, false, fattr{}, bad)
		return rpc.StatusSuccess
	}
	s.fsmu.Lock()
	defer s.fsmu.Unlock()
	obj, objSt := s.attrFor(e, path)
	before, st := s.mutablePrologue(linkE, linkDir)
	linkFailure := func(st Status) rpc.Status {
		c.Res.Uint32(uint32(st))
		encodePostOp(c.Res, obj, objSt)
		encodeWcc(c.Res, fattr{}, false, before, StatusOK)
		return rpc.StatusSuccess
	}
	if st != StatusOK {
		return linkFailure(st)
	}
	if e != linkE {
		return linkFailure(StatusXDev)
	}
	hl, ok := e.fs.(filesystem.HardLinker)
	if !ok {
		return linkFailure(StatusNotSupp)
	}
	if err := hl.Link(path, linkFull); err != nil {
		return linkFailure(statusFor(err, StatusIO))
	}
	obj, objSt = s.attrFor(e, path)
	after, afterSt := s.attrFor(linkE, linkDir)
	c.Res.Uint32(uint32(StatusOK))
	encodePostOp(c.Res, obj, objSt)
	encodeWcc(c.Res, before, true, after, afterSt)
	return rpc.StatusSuccess
}

// COMMIT (RFC 1813 §3.21).
//
// Every WRITE this server accepts is already FILE_SYNC by the time it is
// acknowledged, so COMMIT has nothing to flush and answers OK. It is still
// implemented rather than left PROC_UNAVAIL: a client that cannot commit will
// keep retrying and never consider a file durable.
func (s *Server) procCommit(c *rpc.Call) rpc.Status {
	e, path, st, garbage := s.fhArg(c.Args)
	if garbage {
		return rpc.StatusGarbageArgs
	}
	if _, err := c.Args.Uint64(); err != nil {
		return rpc.StatusGarbageArgs
	}
	if _, err := c.Args.Uint32(); err != nil {
		return rpc.StatusGarbageArgs
	}
	if st != StatusOK {
		wccFail(c.Res, st, fattr{}, st)
		return rpc.StatusSuccess
	}
	s.fsmu.Lock()
	a, aSt := s.attrFor(e, path)
	s.fsmu.Unlock()
	if aSt != StatusOK {
		wccFail(c.Res, aSt, fattr{}, aSt)
		return rpc.StatusSuccess
	}
	c.Res.Uint32(uint32(StatusOK))
	encodeWcc(c.Res, a, true, a, StatusOK)
	c.Res.Fixed(s.writeVerf())
	return rpc.StatusSuccess
}
