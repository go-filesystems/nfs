package rpcgss

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/go-filesystems/nfs/rpc"
	"github.com/go-filesystems/nfs/xdr"
)

// These tests cover the branches a working Kerberos never reaches: signing
// does not fail with a real key, and the system CSPRNG does not run out.
// They are reached through the unexported seam in acceptor.go, because the
// alternative is untested code in a package whose job is refusing things.

type fakeContext struct {
	principal string
	expires   time.Time
	micErr    error
	verifyErr error
	sealErr   error
	unsealErr error
}

func (f *fakeContext) Principal() string           { return f.principal }
func (f *fakeContext) Expires() time.Time          { return f.expires }
func (f *fakeContext) VerifyMIC(_, _ []byte) error { return f.verifyErr }
func (f *fakeContext) MIC(msg []byte) ([]byte, error) {
	if f.micErr != nil {
		return nil, f.micErr
	}
	return append([]byte("mic:"), msg...), nil
}

type fakeAcceptor struct {
	ctx *fakeContext
	err error
}

func (f fakeAcceptor) Accept([]byte) (secContext, []byte, error) {
	if f.err != nil {
		return nil, nil, f.err
	}
	return f.ctx, []byte("ap-rep"), nil
}

func initCall(handle []byte) *rpc.AuthCall {
	e := xdr.NewEncoder(nil)
	e.Uint32(1)
	e.Uint32(procInit)
	e.Uint32(0)
	e.Uint32(svcNone)
	e.Opaque(handle)
	args := xdr.NewEncoder(nil)
	args.Opaque([]byte("a token"))
	return &rpc.AuthCall{
		Cred: rpc.Auth{Flavor: Flavor, Body: e.Bytes()},
		Args: xdr.NewDecoder(args.Bytes()),
	}
}

func dataCall(handle []byte, seq, service uint32) *rpc.AuthCall {
	e := xdr.NewEncoder(nil)
	e.Uint32(1)
	e.Uint32(procData)
	e.Uint32(seq)
	e.Uint32(service)
	e.Opaque(handle)
	return &rpc.AuthCall{
		Cred:   rpc.Auth{Flavor: Flavor, Body: e.Bytes()},
		Verf:   rpc.Auth{Flavor: Flavor, Body: []byte("signature")},
		Header: []byte("header"),
		Args:   xdr.NewDecoder(nil),
	}
}

func TestAHandleThatCannotBeMinted(t *testing.T) {
	// Without a handle there is no context, and answering anyway would give
	// the client one it can never address. CTXPROBLEM tells it to try again.
	s := newServer(fakeAcceptor{ctx: &fakeContext{principal: "alice@X"}})
	old := randRead
	randRead = func([]byte) (int, error) { return 0, errors.New("no entropy") }
	defer func() { randRead = old }()

	if got := s.Authenticate(initCall(nil)).Reject; got != statCtxProblem {
		t.Errorf("Reject = %d, want %d (CTXPROBLEM)", got, statCtxProblem)
	}
	if n := s.Contexts(); n != 0 {
		t.Errorf("a context was kept for a handle that was never minted: %d", n)
	}
}

func TestSigningFailureDoesNotEstablishAContext(t *testing.T) {
	// The creation reply is verified against the sequence window. A server
	// that could not sign it must not keep the context: the client would
	// discard the reply and then address a handle the server thinks is live.
	s := newServer(fakeAcceptor{ctx: &fakeContext{
		principal: "alice@X", micErr: errors.New("cannot sign"),
	}})
	if got := s.Authenticate(initCall(nil)).Reject; got != statCtxProblem {
		t.Errorf("Reject = %d, want %d (CTXPROBLEM)", got, statCtxProblem)
	}
}

func TestSigningFailureOnADataReply(t *testing.T) {
	ctx := &fakeContext{principal: "alice@X"}
	s := newServer(fakeAcceptor{ctx: ctx})
	dec := s.Authenticate(initCall(nil))
	if dec.Reject != 0 {
		t.Fatalf("establishment refused: %d", dec.Reject)
	}
	handle := onlyHandle(t, s)

	ctx.micErr = errors.New("cannot sign")
	if got := s.Authenticate(dataCall(handle, 1, svcNone)).Reject; got != statCtxProblem {
		t.Errorf("Reject = %d, want %d (CTXPROBLEM)", got, statCtxProblem)
	}
}

func TestAnExpiredTicketEndsTheContext(t *testing.T) {
	// A context outlives nothing: the ticket behind it has an end time, and
	// past it the server must stop honouring the handle even though the
	// signature still checks out.
	ctx := &fakeContext{principal: "alice@X", expires: time.Now().Add(-time.Second)}
	s := newServer(fakeAcceptor{ctx: ctx})
	if dec := s.Authenticate(initCall(nil)); dec.Reject != 0 {
		t.Fatalf("establishment refused: %d", dec.Reject)
	}
	handle := onlyHandle(t, s)
	if got := s.Authenticate(dataCall(handle, 1, svcNone)).Reject; got != statCtxProblem {
		t.Errorf("Reject = %d, want %d (CTXPROBLEM)", got, statCtxProblem)
	}
	if n := s.Contexts(); n != 0 {
		t.Errorf("the expired context is still held: %d", n)
	}
}

func TestAFailedVerificationIsRejectedVerf(t *testing.T) {
	ctx := &fakeContext{principal: "alice@X"}
	s := newServer(fakeAcceptor{ctx: ctx})
	s.Authenticate(initCall(nil))
	handle := onlyHandle(t, s)

	ctx.verifyErr = errors.New("bad signature")
	if got := s.Authenticate(dataCall(handle, 1, svcNone)).Reject; got != 4 {
		t.Errorf("Reject = %d, want 4 (AUTH_REJECTEDVERF)", got)
	}
}

// onlyHandle returns the one handle the server is holding.
func onlyHandle(t *testing.T, s *Server) []byte {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.contexts) != 1 {
		t.Fatalf("the server holds %d contexts, want 1", len(s.contexts))
	}
	for h := range s.contexts {
		return []byte(h)
	}
	return nil
}

// envelope builds an rpc_gss_integ_data the way a client does, using the fake
// context's MIC so the signature checks out.
func envelope(f *fakeContext, seq uint32, extra []byte) []byte {
	body := xdr.NewEncoder(nil)
	body.Uint32(seq)
	body.Fixed(extra)
	mic, _ := f.MIC(body.Bytes())
	e := xdr.NewEncoder(nil)
	e.Opaque(body.Bytes())
	e.Opaque(mic)
	return e.Bytes()
}

func TestUnwrapRefusesEveryTruncation(t *testing.T) {
	f := &fakeContext{principal: "alice@X"}
	c := &context{gss: f}
	full := envelope(f, 7, []byte{0, 0, 0, 1})
	for n := range len(full) {
		if _, err := c.unwrapArgs(xdr.NewDecoder(full[:n]), 7); err == nil {
			t.Errorf("an envelope cut to %d bytes was accepted", n)
		}
	}
	if _, err := c.unwrapArgs(xdr.NewDecoder(full), 7); err != nil {
		t.Errorf("the whole envelope was refused: %v", err)
	}
}

func TestUnwrapRefusesABodyWithoutItsSequenceNumber(t *testing.T) {
	// A signed, well-formed, EMPTY body. Its checksum is genuine; there is
	// simply no sequence number inside to compare against the credential's.
	f := &fakeContext{principal: "alice@X"}
	c := &context{gss: f}
	mic, _ := f.MIC(nil)
	e := xdr.NewEncoder(nil)
	e.Opaque(nil)
	e.Opaque(mic)
	if _, err := c.unwrapArgs(xdr.NewDecoder(e.Bytes()), 7); !errors.Is(err, errShortInteg) {
		t.Errorf("err = %v, want errShortInteg", err)
	}
}

func TestUnwrapRefusesAForgedChecksum(t *testing.T) {
	f := &fakeContext{principal: "alice@X", verifyErr: errors.New("bad signature")}
	c := &context{gss: f}
	if _, err := c.unwrapArgs(xdr.NewDecoder(envelope(f, 7, nil)), 7); err == nil {
		t.Error("an envelope with a refused checksum was accepted")
	}
}

func TestWrapResultsGivesNothingWhenItCannotSign(t *testing.T) {
	// There is no honest reply to send. Handing back the results unwrapped
	// would give the client something it refuses anyway; giving back nothing
	// is what a dropped call looks like, which is the truth here.
	f := &fakeContext{principal: "alice@X", micErr: errors.New("cannot sign")}
	c := &context{gss: f}
	if got := c.wrapResults(1, []byte{0, 0, 0, 0}); got != nil {
		t.Errorf("wrapResults = %x, want nil", got)
	}
}

// Seal and Unseal on the fake are deliberately NOT encryption: what these
// tests exercise is the envelope around them, and a real cipher here would
// only test gokrb5 a second time. The prefix is what makes an unsealed body
// distinguishable from a sealed one in a test that gets the two confused.
func (f *fakeContext) Seal(msg []byte) ([]byte, error) {
	if f.sealErr != nil {
		return nil, f.sealErr
	}
	return append([]byte("sealed:"), msg...), nil
}

func (f *fakeContext) Unseal(token []byte) ([]byte, error) {
	if f.unsealErr != nil {
		return nil, f.unsealErr
	}
	if !bytes.HasPrefix(token, []byte("sealed:")) {
		return nil, errors.New("not sealed")
	}
	return token[len("sealed:"):], nil
}

// privEnvelope builds an rpc_gss_priv_data around a body, using the fake's
// stand-in for sealing.
func privEnvelope(f *fakeContext, seq uint32, extra []byte) []byte {
	body := xdr.NewEncoder(nil)
	body.Uint32(seq)
	body.Fixed(extra)
	sealed, _ := f.Seal(body.Bytes())
	e := xdr.NewEncoder(nil)
	e.Opaque(sealed)
	return e.Bytes()
}

func TestUnwrapPrivRefusesEveryTruncation(t *testing.T) {
	f := &fakeContext{principal: "alice@X"}
	c := &context{gss: f}
	full := privEnvelope(f, 7, []byte{0, 0, 0, 1})
	for n := range len(full) {
		if _, err := c.unwrapArgsPriv(xdr.NewDecoder(full[:n]), 7); err == nil {
			t.Errorf("an envelope cut to %d bytes was accepted", n)
		}
	}
	if _, err := c.unwrapArgsPriv(xdr.NewDecoder(full), 7); err != nil {
		t.Errorf("the whole envelope was refused: %v", err)
	}
}

func TestUnwrapPrivRefusesABodyWithoutItsSequenceNumber(t *testing.T) {
	f := &fakeContext{principal: "alice@X"}
	c := &context{gss: f}
	sealed, _ := f.Seal(nil)
	e := xdr.NewEncoder(nil)
	e.Opaque(sealed)
	if _, err := c.unwrapArgsPriv(xdr.NewDecoder(e.Bytes()), 7); !errors.Is(err, errShortInteg) {
		t.Errorf("err = %v, want errShortInteg", err)
	}
}

func TestWrapResultsPrivGivesNothingWhenItCannotSeal(t *testing.T) {
	// Results that could not be sealed must not go out in the clear under a
	// flavour whose whole promise is that they will not.
	f := &fakeContext{principal: "alice@X", sealErr: errors.New("cannot seal")}
	c := &context{gss: f}
	if got := c.wrapResultsPriv(1, []byte{0, 0, 0, 0}); got != nil {
		t.Errorf("wrapResultsPriv = %x, want nil", got)
	}
}
