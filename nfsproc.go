package nfs

import (
	"encoding/binary"
	"errors"
	"hash/fnv"
	"io"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/nfs/rpc"
	"github.com/go-filesystems/nfs/xdr"
)

// Transfer sizes advertised by FSINFO and enforced by READ/WRITE.
//
// They are held under the RPC layer's 1 MiB record ceiling with room to
// spare, so a client that honours FSINFO can never build a request the
// server will refuse to read — which would otherwise show up as a mount that
// works until the first large file.
const (
	readMax  = 1 << 17 // 128 KiB
	writeMax = 1 << 17
	dirPref  = 1 << 15 // 32 KiB, the preferred READDIR reply size
)

// nfsProgram builds the NFSv3 program table.
func (s *Server) nfsProgram() *rpc.Program {
	return &rpc.Program{
		Prog: ProgramNFS,
		Vers: VersionNFS,
		Procs: map[uint32]rpc.Proc{
			procNull:        func(*rpc.Call) rpc.Status { return rpc.StatusSuccess },
			procGetAttr:     s.procGetAttr,
			procSetAttr:     s.procSetAttr,
			procLookup:      s.procLookup,
			procAccess:      s.procAccess,
			procReadlink:    s.procReadlink,
			procRead:        s.procRead,
			procWrite:       s.procWrite,
			procCreate:      s.procCreate,
			procMkdir:       s.procMkdir,
			procSymlink:     s.procSymlink,
			procMknod:       s.procMknod,
			procRemove:      s.procRemove,
			procRmdir:       s.procRmdir,
			procRename:      s.procRename,
			procLink:        s.procLink,
			procReaddir:     s.procReaddir,
			procReaddirPlus: s.procReaddirPlus,
			procFsstat:      s.procFsstat,
			procFsinfo:      s.procFsinfo,
			procPathconf:    s.procPathconf,
			procCommit:      s.procCommit,
		},
	}
}

// fhArg decodes a leading fhandle3 and resolves it.
//
// garbage reports an argument that did not decode, which is an RPC-level
// failure; st reports a handle that decoded but does not name anything,
// which is an ordinary NFS error inside a successful RPC.
func (s *Server) fhArg(d *xdr.Decoder) (e *export, path string, st Status, garbage bool) {
	h, err := d.Opaque()
	if err != nil {
		return nil, "", StatusOK, true
	}
	k, stale, ok := s.handles.Resolve(h)
	if !ok {
		if stale {
			return nil, "", StatusStale, false
		}
		return nil, "", StatusBadHandle, false
	}
	e = s.exportByID(k.export)
	if e == nil {
		// The handle authenticated but its export is gone. Only reachable
		// if exports could be removed; answered as stale because that is
		// what a client can act on.
		return nil, "", StatusStale, false
	}
	return e, k.path, StatusOK, false
}

// dirOpArg decodes a diropargs3 (directory handle plus one component).
func (s *Server) dirOpArg(d *xdr.Decoder) (e *export, dir, full string, st Status, garbage bool) {
	e, dir, fhSt, garbage := s.fhArg(d)
	if garbage {
		return nil, "", "", StatusOK, true
	}
	// The name is decoded even when the handle was rejected. NFSv3 arguments
	// are positional with no length framing, so returning early here would
	// leave the decoder pointing at the name while the procedure reads its
	// *next* argument — and a caller sending a stale handle would get
	// GARBAGE_ARGS instead of the NFS3ERR_STALE that tells it to re-LOOKUP.
	name, err := d.String()
	if err != nil {
		return nil, "", "", StatusOK, true
	}
	if fhSt != StatusOK {
		return nil, "", "", fhSt, false
	}
	full, st = joinName(dir, name)
	if st != StatusOK {
		return nil, "", "", st, false
	}
	return e, dir, full, StatusOK, false
}

// GETATTR (RFC 1813 §3.1).
func (s *Server) procGetAttr(c *rpc.Call) rpc.Status {
	e, path, st, garbage := s.fhArg(c.Args)
	if garbage {
		return rpc.StatusGarbageArgs
	}
	if st != StatusOK {
		c.Res.Uint32(uint32(st))
		return rpc.StatusSuccess
	}
	s.fsmu.Lock()
	a, st := s.attrFor(e, path)
	s.fsmu.Unlock()
	c.Res.Uint32(uint32(st))
	if st == StatusOK {
		a.encode(c.Res)
	}
	return rpc.StatusSuccess
}

// LOOKUP (RFC 1813 §3.3).
func (s *Server) procLookup(c *rpc.Call) rpc.Status {
	e, dir, full, st, garbage := s.dirOpArg(c.Args)
	if garbage {
		return rpc.StatusGarbageArgs
	}
	if st != StatusOK {
		c.Res.Uint32(uint32(st))
		c.Res.Bool(false)
		return rpc.StatusSuccess
	}
	s.fsmu.Lock()
	objAttr, objSt := s.attrFor(e, full)
	dirAttr, dirSt := s.attrFor(e, dir)
	s.fsmu.Unlock()
	if objSt != StatusOK {
		c.Res.Uint32(uint32(objSt))
		encodePostOp(c.Res, dirAttr, dirSt)
		return rpc.StatusSuccess
	}
	h, err := s.handles.Handle(e.id, full)
	if err != nil {
		c.Res.Uint32(uint32(StatusServerFault))
		encodePostOp(c.Res, dirAttr, dirSt)
		return rpc.StatusSuccess
	}
	c.Res.Uint32(uint32(StatusOK))
	c.Res.Opaque(h)
	encodePostOp(c.Res, objAttr, objSt)
	encodePostOp(c.Res, dirAttr, dirSt)
	return rpc.StatusSuccess
}

// ACCESS (RFC 1813 §3.4).
//
// The answer is derived from the export's read-only flag and the object's
// type, never from the caller's AUTH_UNIX uid — which is an unverified claim
// (see the package security note). A client uses this to pre-empt operations
// it would otherwise attempt and have refused; answering it honestly is what
// keeps `cp` from failing halfway rather than up front.
func (s *Server) procAccess(c *rpc.Call) rpc.Status {
	e, path, st, garbage := s.fhArg(c.Args)
	if garbage {
		return rpc.StatusGarbageArgs
	}
	want, err := c.Args.Uint32()
	if err != nil {
		return rpc.StatusGarbageArgs
	}
	if st != StatusOK {
		c.Res.Uint32(uint32(st))
		c.Res.Bool(false)
		return rpc.StatusSuccess
	}
	s.fsmu.Lock()
	a, st := s.attrFor(e, path)
	s.fsmu.Unlock()
	if st != StatusOK {
		c.Res.Uint32(uint32(st))
		c.Res.Bool(false)
		return rpc.StatusSuccess
	}
	allowed := access3Read | access3Lookup | access3Execute
	if !e.ro {
		allowed |= access3Modify | access3Extend | access3Delete
	}
	c.Res.Uint32(uint32(StatusOK))
	encodePostOp(c.Res, a, StatusOK)
	c.Res.Uint32(want & allowed)
	return rpc.StatusSuccess
}

// READLINK (RFC 1813 §3.5).
func (s *Server) procReadlink(c *rpc.Call) rpc.Status {
	e, path, st, garbage := s.fhArg(c.Args)
	if garbage {
		return rpc.StatusGarbageArgs
	}
	if st != StatusOK {
		c.Res.Uint32(uint32(st))
		c.Res.Bool(false)
		return rpc.StatusSuccess
	}
	s.fsmu.Lock()
	a, aSt := s.attrFor(e, path)
	target, err := e.fs.ReadLink(path)
	s.fsmu.Unlock()
	if err != nil {
		// A driver with no symlinks reports its own error here; INVAL is
		// what POSIX readlink(2) gives for a non-symlink.
		c.Res.Uint32(uint32(statusFor(err, StatusInval)))
		encodePostOp(c.Res, a, aSt)
		return rpc.StatusSuccess
	}
	c.Res.Uint32(uint32(StatusOK))
	encodePostOp(c.Res, a, aSt)
	// The target is the raw stored string. It is NOT resolved or validated
	// here: resolution is the client kernel's job and doing it server-side
	// would change what the client sees relative to a local mount.
	c.Res.String(target)
	return rpc.StatusSuccess
}

// READ (RFC 1813 §3.6).
func (s *Server) procRead(c *rpc.Call) rpc.Status {
	e, path, st, garbage := s.fhArg(c.Args)
	if garbage {
		return rpc.StatusGarbageArgs
	}
	off, err := c.Args.Uint64()
	if err != nil {
		return rpc.StatusGarbageArgs
	}
	count, err := c.Args.Uint32()
	if err != nil {
		return rpc.StatusGarbageArgs
	}
	if st != StatusOK {
		c.Res.Uint32(uint32(st))
		c.Res.Bool(false)
		return rpc.StatusSuccess
	}
	if count > readMax {
		count = readMax
	}
	s.fsmu.Lock()
	a, aSt := s.attrFor(e, path)
	var data []byte
	var eof bool
	if aSt != StatusOK {
		st = aSt
	} else if a.ftype == ftypeDir {
		st = StatusIsDir
	} else {
		data, eof, st = s.readAt(e, path, off, int(count))
	}
	s.fsmu.Unlock()
	if st != StatusOK {
		c.Res.Uint32(uint32(st))
		encodePostOp(c.Res, a, aSt)
		return rpc.StatusSuccess
	}
	c.Res.Uint32(uint32(StatusOK))
	encodePostOp(c.Res, a, aSt)
	c.Res.Uint32(uint32(len(data)))
	c.Res.Bool(eof)
	c.Res.Opaque(data)
	return rpc.StatusSuccess
}

// readAt reads one range, using the driver's random-access reader when it has
// one.
//
// # The fallback, and what it costs
//
// A driver that does not implement the optional Opener capability is read
// through ReadFile, which materialises the *entire file* in memory for every
// READ request. A client streaming a 4 GiB image in 128 KiB reads therefore
// causes 32768 full-file reads — quadratic time and a 4 GiB allocation each
// time. This is correct but only usable for small files; the fix is for the
// driver to implement OpenFile, not for this module to cache, because a cache
// would have to guess when the underlying image changed.
//
// The caller must hold [Server.fsmu].
func (s *Server) readAt(e *export, path string, off uint64, count int) ([]byte, bool, Status) {
	if e.open != nil {
		f, err := e.openFile(path)
		if err != nil {
			return nil, false, statusFor(err, StatusIO)
		}
		defer f.Close()
		size := f.Size()
		if off >= uint64(size) {
			return nil, true, StatusOK
		}
		if remaining := uint64(size) - off; uint64(count) > remaining {
			count = int(remaining)
		}
		buf := make([]byte, count)
		n, err := f.ReadAt(buf, int64(off))
		// io.ReaderAt is allowed to return io.EOF together with a full read.
		if err != nil && !(errors.Is(err, io.EOF) && n == len(buf)) {
			return nil, false, statusFor(err, StatusIO)
		}
		return buf[:n], off+uint64(n) >= uint64(size), StatusOK
	}

	data, err := e.fs.ReadFile(path)
	if err != nil {
		return nil, false, statusFor(err, StatusIO)
	}
	if off >= uint64(len(data)) {
		return nil, true, StatusOK
	}
	end := off + uint64(count)
	if end > uint64(len(data)) {
		end = uint64(len(data))
	}
	return data[off:end], end >= uint64(len(data)), StatusOK
}

// listDir enumerates a directory's entry names.
//
// "." and ".." are stripped: FAT and several other formats store them as real
// on-disk entries, so passing the driver's list straight through would emit
// them twice — once from the format and once from the synthetic pair every
// NFS READDIR must produce.
//
// The caller must hold [Server.fsmu].
func (s *Server) listDir(e *export, path string) ([]string, Status) {
	ents, err := e.fs.ListDir(path)
	if err != nil {
		return nil, statusFor(err, StatusNotDir)
	}
	names := make([]string, 0, len(ents))
	for _, ent := range ents {
		n := ent.Name()
		if n == "." || n == ".." || n == "" {
			continue
		}
		names = append(names, n)
	}
	return names, StatusOK
}

// cookieVerf hashes a directory's entry names.
//
// NFSv3 cookies are opaque indices into a listing the server does not keep,
// so a client resuming a READDIR must be told if the listing changed under
// it. The verifier is that signal: a changed directory produces a different
// hash, and the resumed call is answered NFS3ERR_BAD_COOKIE — a re-listing —
// instead of silently skipping or repeating entries.
func cookieVerf(names []string) uint64 {
	h := fnv.New64a()
	for _, n := range names {
		h.Write([]byte(n))
		h.Write([]byte{0})
	}
	return h.Sum64()
}

// readdirCommon decodes the arguments shared by READDIR and READDIRPLUS and
// produces the entry list to resume from.
func (s *Server) readdirCommon(d *xdr.Decoder) (e *export, path string, names []string, start int, st Status, garbage bool) {
	e, path, st, garbage = s.fhArg(d)
	if garbage {
		return nil, "", nil, 0, StatusOK, true
	}
	cookie, err := d.Uint64()
	if err != nil {
		return nil, "", nil, 0, StatusOK, true
	}
	verfBytes, err := d.Fixed(8)
	if err != nil {
		return nil, "", nil, 0, StatusOK, true
	}
	if st != StatusOK {
		return e, path, nil, 0, st, false
	}
	names, st = s.listDir(e, path)
	if st != StatusOK {
		return e, path, nil, 0, st, false
	}
	// Entries 0 and 1 are the synthetic "." and ".."; cookies are
	// one-based so that cookie 0 unambiguously means "from the start".
	total := len(names) + 2
	if cookie > uint64(total) {
		return e, path, nil, 0, StatusBadCookie, false
	}
	if cookie != 0 {
		var want [8]byte
		binary.BigEndian.PutUint64(want[:], cookieVerf(names))
		if string(verfBytes) != string(want[:]) {
			return e, path, nil, 0, StatusBadCookie, false
		}
	}
	return e, path, names, int(cookie), StatusOK, false
}

// entryName maps a listing index to its name; 0 and 1 are the synthetic pair.
func entryName(names []string, i int) string {
	switch i {
	case 0:
		return "."
	case 1:
		return ".."
	default:
		return names[i-2]
	}
}

// entryPath maps a listing index to a full path inside the export.
func entryPath(dir string, names []string, i int) string {
	switch i {
	case 0:
		return dir
	case 1:
		return parentOf(dir)
	default:
		p, _ := joinName(dir, names[i-2])
		return p
	}
}

// READDIR (RFC 1813 §3.16).
func (s *Server) procReaddir(c *rpc.Call) rpc.Status {
	s.fsmu.Lock()
	e, path, names, start, st, garbage := s.readdirCommon(c.Args)
	if garbage {
		s.fsmu.Unlock()
		return rpc.StatusGarbageArgs
	}
	count, err := c.Args.Uint32()
	if err != nil {
		s.fsmu.Unlock()
		return rpc.StatusGarbageArgs
	}
	var dirAttr fattr
	dirSt := st
	if st == StatusOK {
		dirAttr, dirSt = s.attrFor(e, path)
	}
	type item struct {
		fileid uint64
		name   string
		cookie uint64
	}
	var items []item
	eof := true
	if st == StatusOK {
		budget := int(count)
		if budget > dirPref {
			budget = dirPref
		}
		// 88 bytes covers the reply header, dir attributes and the trailing
		// eof flag; each entry costs 24 bytes plus its padded name.
		used := 88
		for i := start; i < len(names)+2; i++ {
			name := entryName(names, i)
			cost := 24 + (len(name)+3)/4*4
			if used+cost > budget && len(items) > 0 {
				eof = false
				break
			}
			used += cost
			a, aSt := s.attrFor(e, entryPath(path, names, i))
			id := uint64(i + 1)
			if aSt == StatusOK {
				id = a.fileid
			}
			items = append(items, item{fileid: id, name: name, cookie: uint64(i + 1)})
		}
	}
	verf := cookieVerf(names)
	s.fsmu.Unlock()

	c.Res.Uint32(uint32(st))
	if st != StatusOK {
		encodePostOp(c.Res, dirAttr, dirSt)
		return rpc.StatusSuccess
	}
	encodePostOp(c.Res, dirAttr, dirSt)
	var vb [8]byte
	binary.BigEndian.PutUint64(vb[:], verf)
	c.Res.Fixed(vb[:])
	for _, it := range items {
		c.Res.Bool(true)
		c.Res.Uint64(it.fileid)
		c.Res.String(it.name)
		c.Res.Uint64(it.cookie)
	}
	c.Res.Bool(false)
	c.Res.Bool(eof)
	return rpc.StatusSuccess
}

// READDIRPLUS (RFC 1813 §3.17).
//
// It is the same walk as READDIR with attributes and a file handle attached
// to every entry, which is what turns `ls -l` from one round trip per file
// into one for the whole directory.
func (s *Server) procReaddirPlus(c *rpc.Call) rpc.Status {
	s.fsmu.Lock()
	e, path, names, start, st, garbage := s.readdirCommon(c.Args)
	if garbage {
		s.fsmu.Unlock()
		return rpc.StatusGarbageArgs
	}
	dircount, err := c.Args.Uint32()
	if err != nil {
		s.fsmu.Unlock()
		return rpc.StatusGarbageArgs
	}
	maxcount, err := c.Args.Uint32()
	if err != nil {
		s.fsmu.Unlock()
		return rpc.StatusGarbageArgs
	}
	_ = dircount
	var dirAttr fattr
	dirSt := st
	if st == StatusOK {
		dirAttr, dirSt = s.attrFor(e, path)
	}
	type item struct {
		name   string
		cookie uint64
		attr   fattr
		attrSt Status
		fh     []byte
	}
	var items []item
	eof := true
	if st == StatusOK {
		budget := int(maxcount)
		if budget <= 0 || budget > dirPref {
			budget = dirPref
		}
		// A plus entry adds ~88 bytes of attributes and a 64-byte handle to
		// READDIR's 24; 200 is the conservative constant that keeps the
		// reply inside maxcount without encoding it twice to find out.
		used := 128
		for i := start; i < len(names)+2; i++ {
			name := entryName(names, i)
			cost := 200 + (len(name)+3)/4*4
			if used+cost > budget && len(items) > 0 {
				eof = false
				break
			}
			used += cost
			full := entryPath(path, names, i)
			a, aSt := s.attrFor(e, full)
			var fh []byte
			if aSt == StatusOK {
				if h, err := s.handles.Handle(e.id, full); err == nil {
					fh = h
				}
			}
			items = append(items, item{
				name: name, cookie: uint64(i + 1),
				attr: a, attrSt: aSt, fh: fh,
			})
		}
	}
	verf := cookieVerf(names)
	s.fsmu.Unlock()

	c.Res.Uint32(uint32(st))
	encodePostOp(c.Res, dirAttr, dirSt)
	if st != StatusOK {
		return rpc.StatusSuccess
	}
	var vb [8]byte
	binary.BigEndian.PutUint64(vb[:], verf)
	c.Res.Fixed(vb[:])
	for _, it := range items {
		c.Res.Bool(true)
		id := it.cookie
		if it.attrSt == StatusOK {
			id = it.attr.fileid
		}
		c.Res.Uint64(id)
		c.Res.String(it.name)
		c.Res.Uint64(it.cookie)
		encodePostOp(c.Res, it.attr, it.attrSt)
		// post_op_fh3. Omitting it is legal and costs the client one LOOKUP,
		// which is why a handle-table overflow degrades rather than fails.
		if it.fh != nil {
			c.Res.Bool(true)
			c.Res.Opaque(it.fh)
		} else {
			c.Res.Bool(false)
		}
	}
	c.Res.Bool(false)
	c.Res.Bool(eof)
	return rpc.StatusSuccess
}

// FSSTAT (RFC 1813 §3.18).
func (s *Server) procFsstat(c *rpc.Call) rpc.Status {
	e, path, st, garbage := s.fhArg(c.Args)
	if garbage {
		return rpc.StatusGarbageArgs
	}
	if st != StatusOK {
		c.Res.Uint32(uint32(st))
		c.Res.Bool(false)
		return rpc.StatusSuccess
	}
	s.fsmu.Lock()
	a, aSt := s.attrFor(e, path)
	s.fsmu.Unlock()
	c.Res.Uint32(uint32(StatusOK))
	encodePostOp(c.Res, a, aSt)
	// tbytes / fbytes / abytes. Zero means "unknown" here — see
	// [WithCapacity] for why nothing is invented.
	c.Res.Uint64(e.total)
	c.Res.Uint64(e.avail)
	c.Res.Uint64(e.avail)
	// tfiles / ffiles / afiles: no driver exposes an inode count.
	c.Res.Uint64(0)
	c.Res.Uint64(0)
	c.Res.Uint64(0)
	// invarsec: 0 means "make no assumption about how long this stays
	// valid", which is the only truthful answer for a mutable image.
	c.Res.Uint32(0)
	return rpc.StatusSuccess
}

// FSINFO (RFC 1813 §3.19).
func (s *Server) procFsinfo(c *rpc.Call) rpc.Status {
	e, path, st, garbage := s.fhArg(c.Args)
	if garbage {
		return rpc.StatusGarbageArgs
	}
	if st != StatusOK {
		c.Res.Uint32(uint32(st))
		c.Res.Bool(false)
		return rpc.StatusSuccess
	}
	s.fsmu.Lock()
	a, aSt := s.attrFor(e, path)
	s.fsmu.Unlock()
	c.Res.Uint32(uint32(StatusOK))
	encodePostOp(c.Res, a, aSt)
	c.Res.Uint32(readMax)  // rtmax
	c.Res.Uint32(readMax)  // rtpref
	c.Res.Uint32(512)      // rtmult
	c.Res.Uint32(writeMax) // wtmax
	c.Res.Uint32(writeMax) // wtpref
	c.Res.Uint32(512)      // wtmult
	c.Res.Uint32(dirPref)  // dtpref
	c.Res.Uint64(1<<63 - 1)
	// time_delta 1s: the timestamps this server reports have one-second
	// resolution, so claiming better would invite a client to expect an
	// mtime change it will never observe.
	c.Res.Uint32(1)
	c.Res.Uint32(0)
	props := fsf3Symlink | fsf3Homogeneous | fsf3CanSetTime
	if _, ok := e.fs.(filesystem.HardLinker); ok {
		props |= fsf3Link
	}
	c.Res.Uint32(props)
	return rpc.StatusSuccess
}

// PATHCONF (RFC 1813 §3.20).
func (s *Server) procPathconf(c *rpc.Call) rpc.Status {
	e, path, st, garbage := s.fhArg(c.Args)
	if garbage {
		return rpc.StatusGarbageArgs
	}
	if st != StatusOK {
		c.Res.Uint32(uint32(st))
		c.Res.Bool(false)
		return rpc.StatusSuccess
	}
	s.fsmu.Lock()
	a, aSt := s.attrFor(e, path)
	s.fsmu.Unlock()
	c.Res.Uint32(uint32(StatusOK))
	encodePostOp(c.Res, a, aSt)
	linkmax := uint32(1)
	if _, ok := e.fs.(filesystem.HardLinker); ok {
		linkmax = 32000
	}
	c.Res.Uint32(linkmax)
	c.Res.Uint32(nameMax)
	c.Res.Bool(true)  // no_trunc: an over-long name is refused, not silently cut
	c.Res.Bool(true)  // chown_restricted
	c.Res.Bool(false) // case_insensitive: unknowable through the interface
	c.Res.Bool(true)  // case_preserving
	return rpc.StatusSuccess
}
