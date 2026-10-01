package rpc

import (
	"crypto/tls"
	"net"
	"time"
)

// AuthTLS is the credential flavour a client uses to ask whether this server
// speaks TLS (RFC 9289 §5.1). It never authenticates anything: it is a probe,
// and the only thing it can carry is emptiness.
const AuthTLS uint32 = 7

// starttls is the token a server puts in the reply verifier to say yes. RFC
// 9289 fixes both the spelling and the length at eight bytes; a client that
// reads anything else MUST NOT start a handshake.
var starttls = []byte("STARTTLS")

// alpnSunRPC is the ALPN protocol id RFC 9289 §5.2 registers for RPC-with-TLS.
const alpnSunRPC = "sunrpc"

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
//
// The server offers the ALPN protocol "sunrpc", which RFC 9289 §5.2 makes
// mandatory, unless the configuration already names protocols of its own.
// With it, crypto/tls refuses a client that offers ALPN without "sunrpc"; a
// client that offers no ALPN at all is still served.
//
// timeout, when positive, bounds the handshake; the deadline is lifted again
// once it succeeds, and the caller sets the next one.
func upgrade(c net.Conn, cfg *tls.Config, timeout time.Duration) (net.Conn, *tls.ConnectionState, error) {
	if len(cfg.NextProtos) == 0 {
		cfg = cfg.Clone()
		cfg.NextProtos = []string{alpnSunRPC}
	}
	tc := tls.Server(c, cfg)
	if timeout > 0 {
		_ = c.SetDeadline(time.Now().Add(timeout))
	}
	if err := tc.Handshake(); err != nil {
		return nil, nil, err
	}
	_ = c.SetDeadline(time.Time{})
	st := tc.ConnectionState()
	return tc, &st, nil
}
