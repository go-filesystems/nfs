package rpcgss

import (
	"errors"

	"github.com/go-filesystems/nfs/xdr"
)

// Flavor is RPCSEC_GSS, the credential flavour this package evaluates.
const Flavor uint32 = 6

// Version is the only RPCSEC_GSS version defined (RFC 2203 §5).
const version uint32 = 1

// Control procedures (RFC 2203 §5.1).
const (
	procData         uint32 = 0
	procInit         uint32 = 1
	procContinueInit uint32 = 2
	procDestroy      uint32 = 3
)

// Services (RFC 2203 §5.1). Only svcNone is implemented; the other two are
// named so a call asking for them can be refused BY NAME rather than falling
// through a default that would serve it unprotected.
const (
	svcNone      uint32 = 1
	svcIntegrity uint32 = 2
	svcPrivacy   uint32 = 3
)

// auth_stat values RPCSEC_GSS adds (RFC 2203 §5.3.3.3).
//
// These two are not interchangeable with the generic AUTH_* failures. A
// client that hears CTXPROBLEM tears down its context and builds a new one;
// on AUTH_BADCRED it gives up. Answering the wrong one turns a ticket that
// merely expired into a mount that fails.
const (
	statCredProblem uint32 = 13
	statCtxProblem  uint32 = 14
)

// maxHandle caps a context handle a client echoes back. Handles are minted
// here and are 16 bytes; anything longer is not one of ours.
const maxHandle = 64

// cred is a decoded rpc_gss_cred_t (RFC 2203 §5.1).
type cred struct {
	version uint32
	proc    uint32
	seq     uint32
	service uint32
	handle  []byte
}

// errBadCred reports a credential body that does not decode. It is answered
// AUTH_BADCRED: nothing about it suggests a context worth rebuilding.
var errBadCred = errors.New("rpcgss: malformed credential")

// parseCred decodes the credential body.
func parseCred(body []byte) (cred, error) {
	var c cred
	d := xdr.NewDecoder(body)
	d.SetLimit(maxHandle)
	var err error
	if c.version, err = d.Uint32(); err != nil {
		return c, errBadCred
	}
	if c.proc, err = d.Uint32(); err != nil {
		return c, errBadCred
	}
	if c.seq, err = d.Uint32(); err != nil {
		return c, errBadCred
	}
	if c.service, err = d.Uint32(); err != nil {
		return c, errBadCred
	}
	if c.handle, err = d.Opaque(); err != nil {
		return c, errBadCred
	}
	if d.Remaining() != 0 {
		// Trailing bytes in a fixed-shape structure mean the client and this
		// decoder disagree about the shape. Accepting the prefix would be
		// authenticating something other than what was sent.
		return c, errBadCred
	}
	return c, nil
}

// GSS major status values this package returns to a client (RFC 2743 §8.4).
const (
	gssComplete       uint32 = 0
	gssDefectiveToken uint32 = 0x000A0000
	gssFailure        uint32 = 0x000D0000
)

// encodeInitRes writes an rpc_gss_init_res (RFC 2203 §5.2.2).
func encodeInitRes(e *xdr.Encoder, handle []byte, major, minor, window uint32, token []byte) {
	e.Opaque(handle)
	e.Uint32(major)
	e.Uint32(minor)
	e.Uint32(window)
	e.Opaque(token)
}
