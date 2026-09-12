package rpcgss

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/go-authn/krb5"
	"github.com/go-filesystems/nfs/rpc"
	"github.com/go-filesystems/nfs/xdr"
)

// defaultWindow is the replay window announced to clients. RFC 2203 leaves
// the width to the server; 128 is what the Linux and Solaris servers use, and
// a client sizes its pipelining around whatever it is told.
const defaultWindow uint32 = 128

// handleLen is the length of a context handle. It is opaque to the client,
// which only echoes it back, so its only job is to be unguessable.
const handleLen = 16

// Server is an [rpc.Authenticator] speaking RPCSEC_GSS over Kerberos.
//
// Give it to [rpc.Server.Auth] and the server accepts sec=krb5 mounts:
//
//	a, err := krb5.Load("/etc/krb5.keytab")
//	srv.Auth = rpcgss.New(a)
//
// The zero value is not usable; use [New].
type Server struct {
	acceptor acceptor
	window   uint32

	mu       sync.Mutex
	contexts map[string]*context
}

// context is one established security context.
type context struct {
	gss     secContext
	window  *seqWindow
	service uint32
	expires time.Time
}

// New returns a Server accepting tickets for one service.
func New(a *krb5.Acceptor) *Server {
	return newServer(krb5Acceptor{a})
}

func newServer(a acceptor) *Server {
	return &Server{acceptor: a, window: defaultWindow, contexts: make(map[string]*context)}
}

// Flavor implements [rpc.Authenticator].
func (s *Server) Flavor() uint32 { return Flavor }

// Authenticate implements [rpc.Authenticator].
func (s *Server) Authenticate(c *rpc.AuthCall) rpc.AuthDecision {
	cr, err := parseCred(c.Cred.Body)
	if err != nil || cr.version != version {
		// AUTH_BADCRED (1): the credential itself is wrong, and no amount of
		// rebuilding a context will change that.
		return rpc.AuthDecision{Reject: 1}
	}
	switch cr.proc {
	case procInit:
		return s.init(c, cr)
	case procContinueInit:
		// Kerberos establishes a context in one exchange, so a client
		// continuing one is continuing a context this server never started.
		return rpc.AuthDecision{Reject: statCtxProblem}
	case procData, procDestroy:
		return s.data(c, cr)
	default:
		return rpc.AuthDecision{Reject: 1}
	}
}

// init handles RPCSEC_GSS_INIT: the client sends a ticket, the server answers
// with a handle and the token that proves it read the ticket.
func (s *Server) init(c *rpc.AuthCall, cr cred) rpc.AuthDecision {
	// RFC 2203 §5.2.2: a context creation call carries a null verifier —
	// there is no context yet to sign with.
	if c.Verf.Flavor != rpc.AuthNull || len(c.Verf.Body) != 0 {
		return rpc.AuthDecision{Reject: 3} // AUTH_BADVERF
	}
	c.Args.SetLimit(1 << 16)
	token, err := c.Args.Opaque()
	if err != nil {
		return rpc.AuthDecision{Reject: 1}
	}
	gss, apRep, err := s.acceptor.Accept(token)
	if err != nil {
		// The refusal is reported in the RESULTS, not as a denied reply: RFC
		// 2203 §5.2.3 has the client read gss_major, and a MSG_DENIED here
		// would tell it the credential was malformed rather than that its
		// ticket was refused.
		major := gssFailure
		if isMalformed(err) {
			major = gssDefectiveToken
		}
		return rpc.AuthDecision{Reply: func(e *xdr.Encoder) {
			encodeInitRes(e, nil, major, 0, 0, nil)
		}}
	}

	handle := make([]byte, handleLen)
	if _, err := randRead(handle); err != nil {
		return rpc.AuthDecision{Reject: statCtxProblem}
	}
	s.mu.Lock()
	s.contexts[string(handle)] = &context{
		gss:     gss,
		window:  newSeqWindow(s.window),
		service: cr.service,
		expires: gss.Expires(),
	}
	s.mu.Unlock()

	// RFC 2203 §5.2.3.1: the verifier on a successful creation reply is a
	// signature over the sequence window, which is how the client learns the
	// window it was told is the window the server meant.
	verf, err := gss.MIC(be32(s.window))
	if err != nil {
		return rpc.AuthDecision{Reject: statCtxProblem}
	}
	return rpc.AuthDecision{
		Verf:      rpc.Auth{Flavor: Flavor, Body: verf},
		Principal: gss.Principal(),
		Reply: func(e *xdr.Encoder) {
			encodeInitRes(e, handle, gssComplete, 0, s.window, apRep)
		},
	}
}

// data handles a call on an established context, and the DESTROY that ends
// one: RFC 2203 §5.4 has DESTROY authenticated exactly like a data call, so
// that a stranger cannot tear down somebody else's context.
func (s *Server) data(c *rpc.AuthCall, cr cred) rpc.AuthDecision {
	s.mu.Lock()
	ctx, ok := s.contexts[string(cr.handle)]
	s.mu.Unlock()
	if !ok {
		// RPCSEC_GSS_CTXPROBLEM (14) rather than AUTH_BADCRED: a client that
		// hears this destroys its context and establishes a new one, which is
		// exactly what a server restart or an expiry requires of it.
		return rpc.AuthDecision{Reject: statCtxProblem}
	}
	if !ctx.expires.IsZero() && time.Now().After(ctx.expires) {
		s.drop(cr.handle)
		return rpc.AuthDecision{Reject: statCtxProblem}
	}
	switch cr.service {
	case svcNone, svcIntegrity, svcPrivacy:
	default:
		// A service number this server does not implement. Serving it as
		// something weaker would give a client less protection than it
		// believes it has, with no way to find out.
		return rpc.AuthDecision{Reject: statCredProblem}
	}
	if c.Verf.Flavor != Flavor {
		return rpc.AuthDecision{Reject: 3} // AUTH_BADVERF
	}
	// RFC 2203 §5.3.1: the call verifier signs the RPC header through the end
	// of the credential — the raw bytes, which is why rpc hands them over.
	if err := ctx.gss.VerifyMIC(c.Header, c.Verf.Body); err != nil {
		return rpc.AuthDecision{Reject: 4} // AUTH_REJECTEDVERF
	}
	s.mu.Lock()
	fresh := ctx.window.accept(cr.seq)
	s.mu.Unlock()
	if !fresh {
		// A replayed or too-old sequence number. RFC 2203 §5.3.3.1 has the
		// server drop the call silently; this answers CTXPROBLEM instead,
		// because a silent drop is indistinguishable from a lost packet and
		// costs the client its whole retransmission timeout.
		return rpc.AuthDecision{Reject: statCtxProblem}
	}
	// RFC 2203 §5.3.3.2: the reply verifier signs the sequence number of the
	// call it answers. Signing anything else — the header, a constant — would
	// let a reply be lifted onto another call.
	verf, err := ctx.gss.MIC(be32(cr.seq))
	if err != nil {
		return rpc.AuthDecision{Reject: statCtxProblem}
	}
	dec := rpc.AuthDecision{
		Verf:      rpc.Auth{Flavor: Flavor, Body: verf},
		Principal: ctx.gss.Principal(),
	}
	if cr.proc == procData && cr.service != svcNone {
		var inner *xdr.Decoder
		var err error
		if cr.service == svcIntegrity {
			inner, err = ctx.unwrapArgs(c.Args, cr.seq)
		} else {
			inner, err = ctx.unwrapArgsPriv(c.Args, cr.seq)
		}
		if err != nil {
			// The envelope is protected by the same key as the verifier that
			// already checked out, so a failure here is not a bad context:
			// it is a body that does not belong to this call.
			return rpc.AuthDecision{Reject: 4} // AUTH_REJECTEDVERF
		}
		dec.Args = inner
		service := cr.service
		dec.WrapResults = func(results []byte) []byte {
			if service == svcIntegrity {
				return ctx.wrapResults(cr.seq, results)
			}
			return ctx.wrapResultsPriv(cr.seq, results)
		}
	}
	if cr.proc == procDestroy {
		s.drop(cr.handle)
		// The reply to DESTROY carries no results, but it does carry the
		// verifier above: the client has to be able to tell a destroyed
		// context from a lost call.
		dec.Reply = func(*xdr.Encoder) {}
	}
	return dec
}

// drop forgets a context.
func (s *Server) drop(handle []byte) {
	s.mu.Lock()
	delete(s.contexts, string(handle))
	s.mu.Unlock()
}

// Contexts is how many security contexts are established. It exists for a
// server that wants to report what it is holding.
func (s *Server) Contexts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.contexts)
}

// randRead is crypto/rand.Read, replaceable so that a handle that cannot be
// minted is something a test can produce rather than something only a broken
// machine would.
var randRead = rand.Read

// be32 renders a number the way RFC 2203 signs it: as the four bytes of an
// XDR unsigned int, not as its decimal spelling.
func be32(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}

// isMalformed reports an error that means the token itself was not a GSS
// token, as opposed to a ticket this service will not accept. The client is
// told the difference: a defective token is a bug on its side, a refusal is
// a decision on this one.
func isMalformed(err error) bool {
	return errors.Is(err, krb5.ErrNotAToken) || errors.Is(err, krb5.ErrNotAPReq)
}
