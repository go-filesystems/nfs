package nfs

// RPC program numbers and versions served by this module.
const (
	// ProgramNFS is the NFS program number (RFC 1813 §2.4).
	ProgramNFS uint32 = 100003
	// VersionNFS is the NFS version served.
	VersionNFS uint32 = 3
	// ProgramMount is the MOUNT program number (RFC 1813 appendix I).
	ProgramMount uint32 = 100005
	// VersionMount is the MOUNT version served.
	VersionMount uint32 = 3
)

// NFSv3 procedure numbers (RFC 1813 §3).
const (
	procNull        uint32 = 0
	procGetAttr     uint32 = 1
	procSetAttr     uint32 = 2
	procLookup      uint32 = 3
	procAccess      uint32 = 4
	procReadlink    uint32 = 5
	procRead        uint32 = 6
	procWrite       uint32 = 7
	procCreate      uint32 = 8
	procMkdir       uint32 = 9
	procSymlink     uint32 = 10
	procMknod       uint32 = 11
	procRemove      uint32 = 12
	procRmdir       uint32 = 13
	procRename      uint32 = 14
	procLink        uint32 = 15
	procReaddir     uint32 = 16
	procReaddirPlus uint32 = 17
	procFsstat      uint32 = 18
	procFsinfo      uint32 = 19
	procPathconf    uint32 = 20
	procCommit      uint32 = 21
)

// MOUNTv3 procedure numbers (RFC 1813 appendix I §5).
const (
	mountProcNull    uint32 = 0
	mountProcMnt     uint32 = 1
	mountProcDump    uint32 = 2
	mountProcUmnt    uint32 = 3
	mountProcUmntAll uint32 = 4
	mountProcExport  uint32 = 5
)

// Status is an NFSv3 nfsstat3 value (RFC 1813 §2.6).
//
// Every NFS procedure begins its reply with one of these. Note that an NFS
// error is carried inside a *successful* RPC: a missing file is an accepted
// RPC whose result is [StatusNoEnt], not an RPC-level failure.
type Status uint32

// The nfsstat3 values this server can produce.
const (
	StatusOK          Status = 0
	StatusPerm        Status = 1
	StatusNoEnt       Status = 2
	StatusIO          Status = 5
	StatusNXIO        Status = 6
	StatusAccess      Status = 13
	StatusExist       Status = 17
	StatusXDev        Status = 18
	StatusNoDev       Status = 19
	StatusNotDir      Status = 20
	StatusIsDir       Status = 21
	StatusInval       Status = 22
	StatusFBig        Status = 27
	StatusNoSpc       Status = 28
	StatusROFS        Status = 30
	StatusMLink       Status = 31
	StatusNameTooLong Status = 63
	StatusNotEmpty    Status = 66
	StatusDQuot       Status = 69
	StatusStale       Status = 70
	StatusRemote      Status = 71
	StatusBadHandle   Status = 10001
	StatusNotSync     Status = 10002
	StatusBadCookie   Status = 10003
	StatusNotSupp     Status = 10004
	StatusTooSmall    Status = 10005
	StatusServerFault Status = 10006
	StatusBadType     Status = 10007
	StatusJukebox     Status = 10008
)

// MOUNTv3 mountstat3 values (RFC 1813 appendix I §2.2). They share the
// numbering of the small nfsstat3 values, which is why MNT can answer
// mountProcMnt with an ordinary errno-shaped code.
const (
	mountOK        uint32 = 0
	mountErrNoEnt  uint32 = 2
	mountErrAccess uint32 = 13
	mountErrInval  uint32 = 22
)

// ftype3 values (RFC 1813 §2.5).
const (
	ftypeReg  uint32 = 1
	ftypeDir  uint32 = 2
	ftypeBlk  uint32 = 3
	ftypeChr  uint32 = 4
	ftypeLnk  uint32 = 5
	ftypeSock uint32 = 6
	ftypeFifo uint32 = 7
)

// POSIX S_IFMT type bits, as they appear in a
// [github.com/go-filesystems/interface.Stat] mode. They are spelled out here
// rather than taken from syscall so the module stays free of build-tagged
// per-OS constants — the values are on-disk facts, not host facts.
const (
	sIFMT   uint16 = 0o170000
	sIFIFO  uint16 = 0o010000
	sIFCHR  uint16 = 0o020000
	sIFDIR  uint16 = 0o040000
	sIFBLK  uint16 = 0o060000
	sIFREG  uint16 = 0o100000
	sIFLNK  uint16 = 0o120000
	sIFSOCK uint16 = 0o140000
	// permBits is everything below the type: rwx plus setuid/setgid/sticky,
	// which is exactly NFSv3's mode3.
	permBits uint16 = 0o7777
	// writeBits are the three write permissions, cleared when an export is
	// read-only so a client's own permission check agrees with the ROFS it
	// would otherwise only discover by trying.
	writeBits uint16 = 0o222
)

// ACCESS bitmask (RFC 1813 §3.4).
const (
	access3Read    uint32 = 0x0001
	access3Lookup  uint32 = 0x0002
	access3Modify  uint32 = 0x0004
	access3Extend  uint32 = 0x0008
	access3Delete  uint32 = 0x0010
	access3Execute uint32 = 0x0020
)

// FSINFO property bits (RFC 1813 §3.19).
const (
	fsf3Link        uint32 = 0x0001
	fsf3Symlink     uint32 = 0x0002
	fsf3Homogeneous uint32 = 0x0008
	fsf3CanSetTime  uint32 = 0x0010
)

// Write stability levels (RFC 1813 §3.7). This server always answers
// FILE_SYNC: a driver's WriteFile has already reached the backing image by
// the time the reply is built, so claiming anything weaker would invite a
// COMMIT that has nothing left to do.
const (
	writeUnstable uint32 = 0
	writeDataSync uint32 = 1
	writeFileSync uint32 = 2
)

// createUnchecked, createGuarded and createExclusive are createmode3
// (RFC 1813 §3.8).
const (
	createUnchecked uint32 = 0
	createGuarded   uint32 = 1
	createExclusive uint32 = 2
)

// nameMax is the longest single path component accepted. NFSv3 leaves the
// limit to the server; 255 is what every filesystem in the fleet allows or
// exceeds, and PATHCONF reports the same number.
const nameMax = 255

// maxPath bounds a fully resolved path. It exists so a deep tree of legal
// components cannot be walked into an unbounded string.
const maxPath = 4096
