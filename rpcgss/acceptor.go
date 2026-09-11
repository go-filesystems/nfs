package rpcgss

import (
	"time"

	"github.com/go-authn/krb5"
)

// acceptor and secContext are the two things this package needs from
// Kerberos. They are unexported and add no public surface: [New] takes a
// *krb5.Acceptor and nothing else.
//
// They exist so that the failure paths can be REACHED. Signing cannot fail
// with a real context — it is AES over sixteen bytes — so the branch that
// handles a signing failure would otherwise be code nobody has ever run,
// sitting in a package whose whole job is to refuse things correctly. A
// coverage gate at 100% is the mechanism that says so.
type acceptor interface {
	Accept(token []byte) (secContext, []byte, error)
}

type secContext interface {
	Principal() string
	Expires() time.Time
	MIC(msg []byte) ([]byte, error)
	VerifyMIC(msg, token []byte) error
}

// krb5Acceptor adapts *krb5.Acceptor, whose Accept returns a concrete
// *krb5.Context.
type krb5Acceptor struct{ a *krb5.Acceptor }

func (k krb5Acceptor) Accept(token []byte) (secContext, []byte, error) {
	ctx, out, err := k.a.Accept(token)
	if err != nil {
		// A typed nil in an interface is not nil, and the caller here tests
		// the error rather than the value — but returning the typed nil
		// anyway would leave a trap for the next caller.
		return nil, nil, err
	}
	return ctx, out, nil
}
