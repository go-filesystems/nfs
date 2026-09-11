package rpc

import (
	"net"

	"github.com/go-filesystems/nfs/xdr"
)

// Authenticator evaluates a credential flavour this package does not
// implement.
//
// RPCSEC_GSS (RFC 2203) is why this seam exists, and its three demands are
// what shaped it. It needs the RAW BYTES of the call header, because the
// verifier is a signature over them and re-encoding what was decoded is not
// the same bytes. It ANSWERS some calls itself: establishing a context is a
// NULLPROC call whose arguments and results belong entirely to the security
// flavour, not to NFS. And it writes a REPLY VERIFIER this package has no way
// to compute.
//
// All the weight that implies — a Kerberos library, a table of live contexts,
// a replay window — stays outside a package whose scope is "the subset of ONC
// RPC that NFSv3 needs".
//
// An Authenticator is used from several connections at once and must be safe
// for concurrent use.
type Authenticator interface {
	// Flavor is the credential flavour this evaluates. A call arriving with
	// any other flavour than this, AUTH_NULL or AUTH_UNIX is refused with
	// AUTH_TOOWEAK before the authenticator is consulted.
	Flavor() uint32

	// Authenticate evaluates one call before it is dispatched.
	Authenticate(*AuthCall) AuthDecision
}

// AuthCall is one call presented to an [Authenticator].
//
// Every field aliases a per-connection buffer and is valid only until
// Authenticate returns. An authenticator that keeps anything past that —
// a context handle, a sequence number — must copy it.
type AuthCall struct {
	// XID, Prog, Vers and Proc identify the call. Proc matters: RPCSEC_GSS
	// context establishment arrives as procedure 0 of the target program.
	XID, Prog, Vers, Proc uint32

	// Cred and Verf are the two opaque_auth structures from the header.
	Cred, Verf Auth

	// Header is the call header from the xid through the end of the
	// credential — exactly the bytes RFC 2203 §5.3.1 signs, and the reason
	// this seam passes bytes rather than a decoded struct.
	Header []byte

	// Args decodes the procedure arguments. For a call the authenticator
	// answers itself, they are its own arguments to read.
	Args *xdr.Decoder

	// Remote is the client's address.
	Remote net.Addr
}

// AuthDecision is what an [Authenticator] says about one call.
//
// The zero value accepts the call with a null verifier and no identity, which
// is what AUTH_NULL deserves and nothing else does.
type AuthDecision struct {
	// Reject, when non-zero, denies the call with this auth_stat (RFC 5531
	// §9: AUTH_BADCRED 1, AUTH_REJECTEDCRED 2, AUTH_BADVERF 3,
	// AUTH_REJECTEDVERF 4, AUTH_TOOWEAK 5, and the RPCSEC_GSS additions
	// RPCSEC_GSS_CREDPROBLEM 13 and RPCSEC_GSS_CTXPROBLEM 14).
	//
	// The last two are not interchangeable with the others: a client that
	// hears CTXPROBLEM destroys its context and establishes a new one, where
	// on AUTH_BADCRED it gives up. Answering the wrong one turns a
	// recoverable expiry into a failed mount.
	Reject uint32

	// Verf is the verifier for the reply header. The zero value is the null
	// verifier every AUTH_NULL and AUTH_UNIX reply carries.
	Verf Auth

	// Reply, when non-nil, means the authenticator answers this call itself:
	// the server writes an accepted reply header carrying Verf and then calls
	// this to write the results. The procedure is never dispatched.
	Reply func(*xdr.Encoder)

	// Principal is who the client proved itself to be, published to the
	// procedure as [Call.Principal]. It is empty for flavours that prove
	// nothing, which is every flavour but this one.
	Principal string

	// Args, when non-nil, is what the procedure reads its arguments from
	// instead of the wire. An authenticator that unwraps returns the
	// decoder over what it unwrapped.
	Args *xdr.Decoder

	// WrapResults, when non-nil, transforms what the procedure wrote before
	// it goes out. It is called only for a successful reply: an accept_stat
	// other than SUCCESS carries no results to wrap, and wrapping the empty
	// string would produce a reply no client expects.
	//
	// The bytes handed over alias the reply buffer and stop being valid
	// when it returns; the result is appended verbatim, so it must already
	// be XDR — a multiple of four bytes.
	WrapResults func(results []byte) []byte
}

// The two fields below exist for rpc_gss_svc_integrity (sec=krb5i), where the
// arguments and results do not travel as themselves: each is wrapped in an
// rpc_gss_integ_data carrying a sequence number and a signature over both
// (RFC 2203 §5.3.2). Without them an authenticator can decide WHETHER a call
// proceeds and not WHAT the procedure reads, which is half of what integrity
// means.
