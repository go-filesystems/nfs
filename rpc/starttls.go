package rpc

import (
	"crypto/tls"
	"net"
)

// AuthTLS is the credential flavour a client uses to ask whether this server
// speaks TLS (RFC 9289 §5.1). It never authenticates anything: it is a probe,
// and the only thing it can carry is emptiness.
const AuthTLS uint32 = 7

// starttls is the token a server puts in the reply verifier to say yes. RFC
// 9289 fixes both the spelling and the length at eight bytes; a client that
// reads anything else MUST NOT start a handshake.
var starttls = []byte("STARTTLS")

// isTLSProbe reports whether a call is the AUTH_TLS probe, and it is strict
// on purpose.
//
// RFC 9289 requires the credential body to be empty and the verifier to be an
// AUTH_NONE of zero length. Answering STARTTLS to something else would tell a
// client to start a handshake on the strength of a message this server did
// not actually understand.
func isTLSProbe(h callHeader) bool {
	return h.cred.Flavor == AuthTLS &&
		h.proc == 0 &&
		len(h.cred.Body) == 0 &&
		h.verf.Flavor == AuthNull &&
		len(h.verf.Body) == 0
}

// upgrade turns a plain connection into a TLS one, in place.
//
// The handshake is performed here rather than lazily on the first read so
// that a failure closes the connection instead of surfacing as a malformed
// RPC record several layers up, where it would read like a protocol error.
func upgrade(c net.Conn, cfg *tls.Config) (net.Conn, *tls.ConnectionState, error) {
	tc := tls.Server(c, cfg)
	if err := tc.Handshake(); err != nil {
		return nil, nil, err
	}
	st := tc.ConnectionState()
	return tc, &st, nil
}
