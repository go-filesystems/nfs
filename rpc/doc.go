// Package rpc implements the ONC RPC version 2 protocol (RFC 5531) over TCP,
// including record marking, the call/reply message framing, and AUTH_NULL /
// AUTH_UNIX credentials.
//
// # Scope, and what is deliberately missing
//
// This is the subset an NFSv3 server needs and nothing more:
//
//   - TCP only. NFSv3 over UDP exists, but a UDP server must reassemble and
//     retransmit by hand, and every current client (macOS, Linux, Windows)
//     negotiates TCP for v3. Serving UDP badly would be worse than not
//     serving it.
//   - No portmapper/rpcbind registration. Programs are served on a fixed port
//     the caller chooses, and clients are told that port directly
//     (`-o port=N,mountport=N`). Registering with rpcbind means binding
//     privileged port 111, which would demand root for the one thing this
//     module exists to avoid needing.
//   - No RPCSEC_GSS. AUTH_UNIX is what an unauthenticated loopback export
//     uses, and it is a claim, not a proof — see [Call.Cred].
//
// # Why not use an existing Go ONC RPC library
//
// Same reason as [github.com/go-filesystems/nfs/xdr]: the value proposition
// of this module is "your driver becomes mountable with the standard library
// and nothing else". RFC 5531 framing is roughly 300 lines. Importing it
// would trade that guarantee for the saving.
package rpc
