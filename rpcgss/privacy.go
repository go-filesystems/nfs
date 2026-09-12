package rpcgss

import (
	"github.com/go-filesystems/nfs/xdr"
)

// Privacy is rpc_gss_svc_privacy, RFC 2203 §5.3.2: sec=krb5p.
//
// Where integrity wraps the payload in a signed envelope, privacy ENCRYPTS
// it:
//
//	struct rpc_gss_priv_data {
//		opaque databody_priv<>;    /* GSS_Wrap(seq_num | data), sealed */
//	};
//
// One opaque, not two: the signature is inside the sealed token rather than
// beside it. The sequence number is still carried inside and still compared
// against the credential's copy, for the same reason it is under integrity —
// a sealed body is no harder to move onto another call's header than a signed
// one, and only comparing the two copies catches that.
//
// What this adds over sec=krb5i is confidentiality and nothing else. The
// file NAMES a client asks for still travel inside; it is what they contain
// that stops being readable on the wire.

// unwrapArgsPriv opens an rpc_gss_priv_data and returns a decoder over the
// real arguments.
func (c *context) unwrapArgsPriv(d *xdr.Decoder, seq uint32) (*xdr.Decoder, error) {
	d.SetLimit(maxIntegBody)
	sealed, err := d.Opaque()
	if err != nil {
		return nil, errShortInteg
	}
	body, err := c.gss.Unseal(sealed)
	if err != nil {
		return nil, err
	}
	inner := xdr.NewDecoder(body)
	got, err := inner.Uint32()
	if err != nil {
		return nil, errShortInteg
	}
	if got != seq {
		return nil, errBadIntegSeq
	}
	inner.SetLimit(0)
	return inner, nil
}

// wrapResultsPriv seals the results.
func (c *context) wrapResultsPriv(seq uint32, results []byte) []byte {
	body := xdr.NewEncoder(nil)
	body.Uint32(seq)
	body.Fixed(results)
	sealed, err := c.gss.Seal(body.Bytes())
	if err != nil {
		// Nothing honest to send: results that could not be sealed must not
		// go out in the clear under a flavour whose whole promise is that
		// they will not.
		return nil
	}
	e := xdr.NewEncoder(nil)
	e.Opaque(sealed)
	return e.Bytes()
}
