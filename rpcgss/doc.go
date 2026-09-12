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
// rpc_gss_svc_none, which is sec=krb5: what the signature protects is the
// header — the program, the procedure, the credential and the sequence
// number. A call cannot be replayed, redirected to another procedure, or
// attributed to somebody else.
//
// rpc_gss_svc_integrity, which is sec=krb5i: the arguments and results are
// signed as well, so a file handle or a block of data cannot be altered in
// flight. The sequence number then appears TWICE, once in the credential and
// once inside the signed body, and comparing the two is what catches a signed
// body moved onto another call's header.
//
// rpc_gss_svc_privacy, which is sec=krb5p: the arguments and results are
// encrypted. What it adds over integrity is confidentiality and nothing else
// — the sequence number is still carried inside and still compared against
// the credential's copy, because a sealed body is no harder to move onto
// another call's header than a signed one.
//
// A service number that is none of the three is REFUSED rather than served as
// svc_none. That refusal is the point: a client that asked for privacy and
// got none would never find out.
package rpcgss
