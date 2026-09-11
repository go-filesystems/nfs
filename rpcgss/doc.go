// Package rpcgss authenticates ONC RPC calls with Kerberos (RFC 2203).
//
// It plugs into [github.com/go-filesystems/nfs/rpc] as an
// [rpc.Authenticator], and it is what "sec=krb5" means on an NFS mount: every
// call carries a signature over its own header, and the server answers with
// a signature of its own, so a client learns it is talking to the right
// server and the server learns WHO is calling — not the uid the client chose
// to assert, which is all AUTH_UNIX ever offered.
//
// # What it implements
//
// rpc_gss_svc_none, which is sec=krb5: the arguments and results travel as
// they always did, and what the signature protects is the header — the
// program, the procedure, the credential and the sequence number. A call
// cannot be replayed, redirected to another procedure, or attributed to
// somebody else.
//
// It does NOT implement rpc_gss_svc_integrity (sec=krb5i) or
// rpc_gss_svc_privacy (sec=krb5p), and it refuses a call asking for either
// rather than quietly serving it with less protection than the client
// believes it has. That refusal is the point: a client that asked for
// privacy and got none would never find out.
package rpcgss
