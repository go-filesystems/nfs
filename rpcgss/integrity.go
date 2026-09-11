package rpcgss

import (
	"errors"

	"github.com/go-filesystems/nfs/xdr"
)

// Integrity is rpc_gss_svc_integrity, RFC 2203 §5.3.2: sec=krb5i.
//
// Under it neither the arguments nor the results travel as themselves. Each
// is wrapped in an rpc_gss_integ_data:
//
//	struct rpc_gss_integ_data {
//		opaque databody_integ<>;   /* XDR of rpc_gss_data_t */
//		opaque checksum<>;         /* MIC over databody_integ */
//	};
//	struct rpc_gss_data_t {
//		unsigned int seq_num;
//		proc_req_arg_t arg;
//	};
//
// The sequence number appears TWICE — once in the credential, once inside the
// signed body — and that repetition is the whole mechanism. The credential is
// signed by the call verifier, the body by its own checksum, and a call whose
// two copies disagree is one where a signed body has been moved onto another
// call's header.

// maxIntegBody caps one wrapped body. It is the record ceiling in practice;
// a client cannot send more than the server will read anyway.
const maxIntegBody = 1 << 20

var (
	// errBadIntegSeq reports the two sequence numbers disagreeing.
	errBadIntegSeq = errors.New("rpcgss: sequence number differs between credential and signed body")
	// errShortInteg reports a body too short to hold its own sequence number.
	errShortInteg = errors.New("rpcgss: truncated integrity envelope")
)

// unwrapArgs opens an rpc_gss_integ_data and returns a decoder over the real
// arguments.
func (c *context) unwrapArgs(d *xdr.Decoder, seq uint32) (*xdr.Decoder, error) {
	d.SetLimit(maxIntegBody)
	body, err := d.Opaque()
	if err != nil {
		return nil, errShortInteg
	}
	mic, err := d.Opaque()
	if err != nil {
		return nil, errShortInteg
	}
	if err := c.gss.VerifyMIC(body, mic); err != nil {
		return nil, err
	}
	inner := xdr.NewDecoder(body)
	got, err := inner.Uint32()
	if err != nil {
		return nil, errShortInteg
	}
	if got != seq {
		// A signed body lifted onto another call's header. Both signatures
		// check out on their own; only comparing the two copies catches it.
		return nil, errBadIntegSeq
	}
	inner.SetLimit(0)
	return inner, nil
}

// wrapResults puts the results in an rpc_gss_integ_data of their own.
func (c *context) wrapResults(seq uint32, results []byte) []byte {
	body := xdr.NewEncoder(nil)
	body.Uint32(seq)
	body.Fixed(results)
	mic, err := c.gss.MIC(body.Bytes())
	if err != nil {
		// The reply cannot be signed, so there is no honest reply to send.
		// Returning the results unwrapped would hand the client something it
		// will refuse anyway, and returning nothing at all is what a dropped
		// call looks like — which is the truth here.
		return nil
	}
	e := xdr.NewEncoder(nil)
	e.Opaque(body.Bytes())
	e.Opaque(mic)
	return e.Bytes()
}
