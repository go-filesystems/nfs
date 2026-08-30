package nfs

import (
	"github.com/go-filesystems/nfs/rpc"
)

// mountProgram builds the MOUNTv3 program table.
//
// MOUNT is a separate RPC program from NFS, but it is served on the same
// listener here. Nothing in RFC 1813 requires two ports — the RPC header
// carries the program number, so one dispatcher can answer both — and using
// one means a client needs a single `port=`/`mountport=` pair and the server
// needs no rpcbind on privileged port 111. That is what makes this runnable
// as an ordinary user.
func (s *Server) mountProgram() *rpc.Program {
	return &rpc.Program{
		Prog: ProgramMount,
		Vers: VersionMount,
		Procs: map[uint32]rpc.Proc{
			mountProcNull:    func(*rpc.Call) rpc.Status { return rpc.StatusSuccess },
			mountProcMnt:     s.procMnt,
			mountProcDump:    s.procDump,
			mountProcUmnt:    s.procUmnt,
			mountProcUmntAll: s.procUmntAll,
			mountProcExport:  s.procExport,
		},
	}
}

// mntPathMax bounds a mount path argument (RFC 1813 MNTPATHLEN).
const mntPathMax = 1024

// MNT (RFC 1813 appendix I §5.2): resolve an export path to its root handle.
func (s *Server) procMnt(c *rpc.Call) rpc.Status {
	c.Args.SetLimit(mntPathMax)
	p, err := c.Args.String()
	if err != nil {
		return rpc.StatusGarbageArgs
	}
	e := s.exportByPath(cleanPath(p))
	if e == nil {
		c.Res.Uint32(mountErrNoEnt)
		return rpc.StatusSuccess
	}
	h, err := s.handles.Handle(e.id, "/")
	if err != nil {
		c.Res.Uint32(mountErrInval)
		return rpc.StatusSuccess
	}
	c.Res.Uint32(mountOK)
	c.Res.Opaque(h)
	// The auth flavours the client may use. AUTH_UNIX is listed first
	// because every client offers it; AUTH_NULL is listed because this
	// server genuinely does not read the credential (see the package
	// security note), so refusing an unauthenticated client would be
	// theatre.
	c.Res.Uint32(2)
	c.Res.Uint32(rpc.AuthUnix)
	c.Res.Uint32(rpc.AuthNull)
	return rpc.StatusSuccess
}

// DUMP (appendix I §5.3): the list of who has mounted what.
//
// This server keeps no mount table. NFSv3 is stateless — nothing about
// serving a file depends on a prior MNT — so a mount table would be a
// separate, always-slightly-wrong record of something the protocol does not
// use, and `showmount -a` is the only thing that reads it. An empty list is
// the honest answer.
func (s *Server) procDump(c *rpc.Call) rpc.Status {
	c.Res.Bool(false)
	return rpc.StatusSuccess
}

// UMNT (appendix I §5.4). It has no reply body and, with no mount table,
// nothing to do; a client still needs the RPC to succeed to unmount cleanly.
func (s *Server) procUmnt(c *rpc.Call) rpc.Status {
	c.Args.SetLimit(mntPathMax)
	if _, err := c.Args.String(); err != nil {
		return rpc.StatusGarbageArgs
	}
	return rpc.StatusSuccess
}

// UMNTALL (appendix I §5.5).
func (s *Server) procUmntAll(c *rpc.Call) rpc.Status { return rpc.StatusSuccess }

// EXPORT (appendix I §5.6): the export list, as `showmount -e` prints it.
func (s *Server) procExport(c *rpc.Call) rpc.Status {
	for _, e := range s.exportList() {
		c.Res.Bool(true)
		c.Res.String(e.path)
		// groups: an empty list means "no host restriction". Access control
		// here is the listener's bind address, not a name list the client
		// is free to ignore — advertising a restriction that is not
		// enforced would be worse than advertising none.
		c.Res.Bool(false)
	}
	c.Res.Bool(false)
	return rpc.StatusSuccess
}
