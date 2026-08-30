package rpc

import (
	"errors"

	"github.com/go-filesystems/nfs/xdr"
)

// Message types (RFC 5531 §9).
const (
	msgCall  uint32 = 0
	msgReply uint32 = 1
)

// rpcVersion is the only ONC RPC version this server speaks.
const rpcVersion uint32 = 2

// Reply status (reply_stat).
const (
	msgAccepted uint32 = 0
	msgDenied   uint32 = 1
)

// Accept status (accept_stat).
const (
	stSuccess      uint32 = 0
	stProgUnavail  uint32 = 1
	stProgMismatch uint32 = 2
	stProcUnavail  uint32 = 3
	stGarbageArgs  uint32 = 4
	stSystemErr    uint32 = 5
)

// Reject status (reject_stat).
const (
	rjRPCMismatch uint32 = 0
	rjAuthError   uint32 = 1
)

// Authentication flavours (RFC 5531 §8).
const (
	// AuthNull is the "no credentials" flavour. Clients use it for NULL
	// pings and, on some stacks, for the MOUNT protocol.
	AuthNull uint32 = 0
	// AuthUnix carries an unverified uid/gid triple. See [Call.Cred].
	AuthUnix uint32 = 1
)

// maxAuthBody caps an opaque_auth body. RFC 5531 fixes this at 400 bytes;
// enforcing it stops a client from making the server buffer more.
const maxAuthBody = 400

// Auth is an opaque_auth: a flavour tag and an uninterpreted body.
type Auth struct {
	Flavor uint32
	Body   []byte
}

// authNone is the verifier a server sends back on every accepted reply. Both
// AUTH_NULL and AUTH_UNIX are answered with a null verifier.
var authNone = Auth{Flavor: AuthNull}

// UnixCred is a decoded AUTH_UNIX credential (RFC 5531 §8.2).
//
// Nothing in it is authenticated. A client asserts "I am uid 501" and the
// wire has no way to disagree; that is the flavour's design, not a defect in
// this implementation. Treat these fields as a hint for presentation and
// never as an authorisation decision — access control belongs to which
// address may reach the port and what the export allows.
type UnixCred struct {
	Stamp   uint32
	Machine string
	UID     uint32
	GID     uint32
	GIDs    []uint32
}

// maxAuxGIDs caps the auxiliary group list. RFC 5531 fixes it at 16.
const maxAuxGIDs = 16

// ErrBadCred reports an AUTH_UNIX body that does not decode.
var ErrBadCred = errors.New("rpc: malformed AUTH_UNIX credential")

// ParseUnix decodes an AUTH_UNIX credential body.
//
// A caller that only wants a uid for display can ignore the error and use the
// zero value; a caller must not use a decode failure to grant anything.
func ParseUnix(a Auth) (UnixCred, error) {
	var c UnixCred
	if a.Flavor != AuthUnix {
		return c, ErrBadCred
	}
	d := xdr.NewDecoder(a.Body)
	d.SetLimit(maxAuthBody)
	var err error
	if c.Stamp, err = d.Uint32(); err != nil {
		return UnixCred{}, ErrBadCred
	}
	if c.Machine, err = d.String(); err != nil {
		return UnixCred{}, ErrBadCred
	}
	if c.UID, err = d.Uint32(); err != nil {
		return UnixCred{}, ErrBadCred
	}
	if c.GID, err = d.Uint32(); err != nil {
		return UnixCred{}, ErrBadCred
	}
	n, err := d.Uint32()
	if err != nil {
		return UnixCred{}, ErrBadCred
	}
	if n > maxAuxGIDs {
		return UnixCred{}, ErrBadCred
	}
	c.GIDs = make([]uint32, 0, n)
	for range n {
		g, err := d.Uint32()
		if err != nil {
			return UnixCred{}, ErrBadCred
		}
		c.GIDs = append(c.GIDs, g)
	}
	return c, nil
}

// callHeader is the decoded fixed part of an RPC call.
type callHeader struct {
	xid  uint32
	prog uint32
	vers uint32
	proc uint32
	cred Auth
	verf Auth
}

// errNotCall reports a message whose type is not CALL. A server has nothing
// useful to say about a stray REPLY, so it drops the connection rather than
// answering a message it did not send.
var errNotCall = errors.New("rpc: message is not a call")

// errBadRPCVersion reports rpcvers != 2, which is answered with RPC_MISMATCH
// rather than by dropping the connection — the client can then downgrade.
var errBadRPCVersion = errors.New("rpc: unsupported RPC version")

// decodeAuth reads one opaque_auth.
func decodeAuth(d *xdr.Decoder) (Auth, error) {
	f, err := d.Uint32()
	if err != nil {
		return Auth{}, err
	}
	d.SetLimit(maxAuthBody)
	b, err := d.Opaque()
	if err != nil {
		return Auth{}, err
	}
	return Auth{Flavor: f, Body: b}, nil
}

// decodeCall parses the call header, leaving the decoder positioned at the
// procedure arguments.
func decodeCall(d *xdr.Decoder) (callHeader, error) {
	var h callHeader
	var err error
	if h.xid, err = d.Uint32(); err != nil {
		return h, err
	}
	mt, err := d.Uint32()
	if err != nil {
		return h, err
	}
	if mt != msgCall {
		return h, errNotCall
	}
	rv, err := d.Uint32()
	if err != nil {
		return h, err
	}
	if rv != rpcVersion {
		return h, errBadRPCVersion
	}
	if h.prog, err = d.Uint32(); err != nil {
		return h, err
	}
	if h.vers, err = d.Uint32(); err != nil {
		return h, err
	}
	if h.proc, err = d.Uint32(); err != nil {
		return h, err
	}
	if h.cred, err = decodeAuth(d); err != nil {
		return h, err
	}
	if h.verf, err = decodeAuth(d); err != nil {
		return h, err
	}
	// Procedure arguments are read with the caller's own ceiling, not the
	// 400-byte one that bounded the credentials.
	d.SetLimit(0)
	return h, nil
}

// encodeAccepted writes the header of an accepted reply and returns the
// encoder so the caller can append results. Results follow only for
// stSuccess; every other accept_stat is complete as written, except
// PROG_MISMATCH which appends its supported version range.
func encodeAccepted(e *xdr.Encoder, xid, stat uint32) {
	e.Uint32(xid)
	e.Uint32(msgReply)
	e.Uint32(msgAccepted)
	e.Uint32(authNone.Flavor)
	e.Opaque(authNone.Body)
	e.Uint32(stat)
}

// encodeDenied writes a complete MSG_DENIED reply.
func encodeDenied(e *xdr.Encoder, xid, why uint32, lo, hi uint32) {
	e.Uint32(xid)
	e.Uint32(msgReply)
	e.Uint32(msgDenied)
	e.Uint32(why)
	if why == rjRPCMismatch {
		e.Uint32(lo)
		e.Uint32(hi)
		return
	}
	// AUTH_ERROR carries an auth_stat; lo doubles as it.
	e.Uint32(lo)
}
