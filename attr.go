package nfs

import (
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
	// zero is replaced by a value derived from the handle table slot, which
	// is unique per path for the life of the process. The top bit marks it
	// synthetic and keeps it clear of any real inode number.
	a.fileid = st.Inode()
	if a.fileid == 0 {
		slot, err := s.handles.slotOf(e.id, path)
		if err != nil {
			return fattr{}, StatusServerFault
		}
		a.fileid = 1<<63 | slot
	}

	// Timestamps. No driver in the fleet reports one yet, so every file
	// carries the server's start time. That is visibly wrong in `ls -l` and
	// it is reported here rather than hidden: the fix is a timestamp
	// accessor on interface.Stat, not a guess in this module. The probe
	// below picks one up the day it exists.
	if t, ok := st.(TimeStat); ok {
		m := uint32(t.ModTime())
		a.atime, a.mtime, a.ctime = m, m, m
	}
	return a, StatusOK
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
	e.Uint32(0)
	e.Uint32(a.mtime)
	e.Uint32(0)
	e.Uint32(a.ctime)
	e.Uint32(0)
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
		e.Uint32(0)
		e.Uint32(before.ctime)
		e.Uint32(0)
	} else {
		e.Bool(false)
	}
	encodePostOp(e, after, afterSt)
}
