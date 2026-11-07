package nfs

import (
	"math"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/nfs/xdr"
)

// fattr is a decoded NFSv3 fattr3 (RFC 1813 §2.5).
type fattr struct {
	ftype  uint32
	mode   uint32
	nlink  uint32
	uid    uint32
	gid    uint32
	size   uint64
	used   uint64
	fsid   uint64
	fileid uint64
	atime  uint32
	mtime  uint32
	ctime  uint32
	// The nanoseconds of each, nfstime3's second field. Zero where the
	// filesystem keeps whole seconds.
	atimeNs, mtimeNs, ctimeNs uint32
}

// ftypeOf maps the POSIX type bits of a driver's mode to an ftype3.
//
// A mode with no type bits at all (a driver that reports permissions only)
// is treated as a regular file: that is the only guess that cannot make a
// client try to enumerate a non-directory.
func ftypeOf(mode uint16) uint32 {
	switch mode & sIFMT {
	case sIFDIR:
		return ftypeDir
	case sIFLNK:
		return ftypeLnk
	case sIFBLK:
		return ftypeBlk
	case sIFCHR:
		return ftypeChr
	case sIFSOCK:
		return ftypeSock
	case sIFIFO:
		return ftypeFifo
	default:
		return ftypeReg
	}
}

// blockSize is the unit fattr3.used is rounded to. NFSv3 states `used` in
// bytes, but every client divides it back into 512-byte blocks for `du`, so
// rounding here is what makes `du` agree with itself.
const blockSize = 512

// attrFor builds the attributes of one path.
//
// The caller must hold [Server.fsmu].
func (s *Server) attrFor(e *export, path string) (fattr, Status) {
	st, err := e.fs.Stat(path)
	if err != nil {
		return fattr{}, statusFor(err, StatusNoEnt)
	}
	if st == nil {
		// A driver returning (nil, nil) is a bug, but it is *this* process
		// that would take the nil dereference, in a per-connection goroutine
		// with no recover — one bad driver would kill every mount the server
		// holds. It is answered as a server fault instead.
		return fattr{}, StatusServerFault
	}
	return s.attrFromStat(e, path, st)
}

// attrFromStat converts a driver Stat into fattr3.
func (s *Server) attrFromStat(e *export, path string, st filesystem.Stat) (fattr, Status) {
	mode := st.Mode()
	a := fattr{
		ftype: ftypeOf(mode),
		mode:  uint32(mode & permBits),
		size:  st.Size(),
		fsid:  e.id,
		atime: s.start,
		mtime: s.start,
		ctime: s.start,
	}
	// The MODE describes the export, not the caller: a person who may read
	// but not write still sees the image's own permissions here, and learns
	// what THEY may do from ACCESS (RFC 1813 §3.3.4), which is the procedure
	// a client is supposed to ask. Answering per-caller here would make two
	// clients disagree about the same file's mode.
	if e.ro {
		// Clearing the write bits on a read-only export makes a client's own
		// permission check agree with the NFS3ERR_ROFS it would otherwise
		// only discover after trying to write.
		a.mode &^= uint32(writeBits)
	}
	a.used = (a.size + blockSize - 1) / blockSize * blockSize

	// nlink. Directories report 1, not the conventional 2, and that is
	// deliberate: GNU find's "leaf optimisation" reads a directory's link
	// count as 2 + (number of subdirectories) and skips descending when it
	// believes there are none. Computing the true count would mean a ListDir
	// plus a Stat per entry on every GETATTR, which READDIRPLUS on a large
	// directory cannot afford. Reporting 1 disables the optimisation instead
	// of feeding it a wrong number — the same choice btrfs makes on disk for
	// exactly this reason.
	a.nlink = 1

	// fileid. A driver's inode number is whatever its format offers, and on
	// FAT32 that is the first cluster — which is 0 for every empty file. A
	// client that sees two entries share a fileid may treat them as hard
	// links to one object and serve one's cached data for the other, so a
	// zero is replaced by a value derived from the path's handle id, which
	// is the same in every Server holding the handle key. The top bit marks
	// it synthetic and keeps it clear of any real inode number.
	a.fileid = st.Inode()
	if a.fileid == 0 {
		id, err := s.handles.fileID(e.id, path)
		if err != nil {
			return fattr{}, StatusServerFault
		}
		a.fileid = id
	}

	// Timestamps. A driver with filesystem.TimesReader gives its own; a Stat
	// with the older TimeStat probe gives one mtime; otherwise every file
	// carries the server's start time, which is visibly wrong in `ls -l`.
	tr, hasTimes := e.fs.(filesystem.TimesReader)
	if hasTimes {
		if ft, err := tr.Times(path); err == nil {
			a.setTimes(ft, s.start)
			return a, StatusOK
		}
	}
	if t, ok := st.(TimeStat); ok {
		m := uint32(t.ModTime())
		a.atime, a.mtime, a.ctime = m, m, m
	}
	return a, StatusOK
}

// nfstime3 returns a Timestamp as nfstime3 (RFC 1813 §2.5.2: unsigned seconds
// and nanoseconds since 1970-01-01 00:00:00 GMT). A time before 1970 has no
// representation and is clamped to 0; one past 2106 to the largest.
func nfstime3(ts filesystem.Timestamp) (sec, nsec uint32, ok bool) {
	t, ok := ts.Get()
	if !ok {
		return 0, 0, false
	}
	u := t.Unix()
	switch {
	case u < 0:
		return 0, 0, true
	case u > math.MaxUint32:
		return math.MaxUint32, 0, true
	}
	return uint32(u), uint32(t.Nanosecond()), true
}

// setTimes fills atime, mtime and ctime from what the filesystem records.
//
// fattr3 always carries all three: NFSv3 has no way to say "absent", and it has
// no birth time, so Btime is not sent. Where a format keeps fewer, the missing
// one is the nearest honest bound rather than 1970: a missing mtime is the
// server's start time (the same fallback as a driver with no times at all), a
// missing atime or ctime is the mtime. FAT has no ctime, for one: its last
// content change is also a change of the file's attributes, so ctime = mtime
// never claims an older change than the one it knows.
func (a *fattr) setTimes(ft filesystem.FileTimes, start uint32) {
	var ok bool
	a.mtime, a.mtimeNs, ok = nfstime3(ft.Mtime)
	if !ok {
		a.mtime, a.mtimeNs = start, 0
	}
	if a.atime, a.atimeNs, ok = nfstime3(ft.Atime); !ok {
		a.atime, a.atimeNs = a.mtime, a.mtimeNs
	}
	if a.ctime, a.ctimeNs, ok = nfstime3(ft.Ctime); !ok {
		a.ctime, a.ctimeNs = a.mtime, a.mtimeNs
	}
}

// encode writes a fattr3.
func (a fattr) encode(e *xdr.Encoder) {
	e.Uint32(a.ftype)
	e.Uint32(a.mode)
	e.Uint32(a.nlink)
	e.Uint32(a.uid)
	e.Uint32(a.gid)
	e.Uint64(a.size)
	e.Uint64(a.used)
	e.Uint32(0) // rdev major — no device nodes are exported
	e.Uint32(0) // rdev minor
	e.Uint64(a.fsid)
	e.Uint64(a.fileid)
	e.Uint32(a.atime)
	e.Uint32(a.atimeNs)
	e.Uint32(a.mtime)
	e.Uint32(a.mtimeNs)
	e.Uint32(a.ctime)
	e.Uint32(a.ctimeNs)
}

// encodePostOp writes a post_op_attr: a discriminated optional. Sending
// "absent" is always legal and merely costs the client a follow-up GETATTR,
// which is why every failure path here can safely encode false.
func encodePostOp(e *xdr.Encoder, a fattr, st Status) {
	if st != StatusOK {
		e.Bool(false)
		return
	}
	e.Bool(true)
	a.encode(e)
}

// encodeWcc writes a wcc_data: the weak cache-consistency pair a mutating
// procedure returns so a client can tell whether anything else changed the
// object between its own two operations.
func encodeWcc(e *xdr.Encoder, before fattr, beforeOK bool, after fattr, afterSt Status) {
	if beforeOK {
		e.Bool(true)
		e.Uint64(before.size)
		e.Uint32(before.mtime)
		e.Uint32(before.mtimeNs)
		e.Uint32(before.ctime)
		e.Uint32(before.ctimeNs)
	} else {
		e.Bool(false)
	}
	encodePostOp(e, after, afterSt)
}
