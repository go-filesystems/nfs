package nfs

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/go-filesystems/nfs/rpc"
)

// RPC-with-TLS as an access control: see "RPC-with-TLS and who the caller is"
// in the package documentation for the bibliography and the Linux caveat.

// OIDFreeBSDCertUser is the otherName type FreeBSD's rpc.tlsservd -u reads:
// a UTF8String "user@domain" in the client certificate's SubjectAltName.
var OIDFreeBSDCertUser = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2238, 1, 1, 1}

// OIDNFSv4Principal is id-on-nfsv4Principal from
// draft-cel-nfsv4-rpc-tls-othername. It is nil because IANA has not assigned
// it yet; a program that knows the assigned value sets it before serving, and
// [OtherNamePrincipal] then accepts it exactly like [OIDFreeBSDCertUser] —
// including counting it towards the "more than one identity" refusal.
//
// It is read without a lock: set it once, at start-up.
var OIDNFSv4Principal asn1.ObjectIdentifier

// Errors returned by [OtherNamePrincipal].
var (
	// ErrNoIdentity reports a certificate with no identity otherName.
	ErrNoIdentity = errors.New("nfs: certificate carries no identity otherName")
	// ErrMultipleIdentities reports a certificate with more than one identity
	// otherName, which draft-cel-nfsv4-rpc-tls-othername says the server
	// MUST reject: choosing one would be choosing whom to believe.
	ErrMultipleIdentities = errors.New("nfs: certificate carries more than one identity otherName")
	// ErrBadIdentity reports an identity otherName that is not a UTF8String
	// of the form user@domain, or a SubjectAltName that does not parse.
	ErrBadIdentity = errors.New("nfs: malformed identity otherName")
)

// oidSubjectAltName is id-ce-subjectAltName (RFC 5280 §4.2.1.6).
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// isIdentityOID reports whether an otherName type names a user.
func isIdentityOID(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(OIDFreeBSDCertUser) || (len(OIDNFSv4Principal) > 0 && oid.Equal(OIDNFSv4Principal))
}

// OtherNamePrincipal returns the identity a client certificate names: the
// single identity otherName of the leaf's SubjectAltName, a UTF8String
// "user@domain" — the encoding FreeBSD's rpc.tlsservd -u reads and
// draft-cel-nfsv4-rpc-tls-othername describes. The otherName types it
// recognises are [OIDFreeBSDCertUser] and, once set, [OIDNFSv4Principal].
//
// No identity otherName is [ErrNoIdentity]; two or more are
// [ErrMultipleIdentities] (the draft's MUST); a value that is not a
// UTF8String with a non-empty user and domain is [ErrBadIdentity].
// Other otherName types and other SubjectAltName entries are ignored.
//
// It reads the certificate only. That the certificate is trusted — its chain,
// its validity period, its revocation — is for crypto/tls and for
// [AllowCall] to decide; [Server.SetCertificatePrincipal] only ever passes it
// a chain crypto/tls has verified.
//
// With [Server.SetCertificatePrincipal]:
//
//	srv.SetCertificatePrincipal(func(chain []*x509.Certificate) (string, bool) {
//		p, err := nfs.OtherNamePrincipal(chain[0])
//		return p, err == nil
//	})
func OtherNamePrincipal(leaf *x509.Certificate) (string, error) {
	found := ""
	n := 0
	for _, ext := range leaf.Extensions {
		if !ext.Id.Equal(oidSubjectAltName) {
			continue
		}
		var names []asn1.RawValue
		if rest, err := asn1.Unmarshal(ext.Value, &names); err != nil || len(rest) != 0 {
			return "", ErrBadIdentity
		}
		for _, gn := range names {
			// otherName is GeneralName [0], IMPLICIT SEQUENCE {type-id, [0] value}.
			if gn.Class != asn1.ClassContextSpecific || gn.Tag != 0 {
				continue
			}
			var oid asn1.ObjectIdentifier
			rest, err := asn1.Unmarshal(gn.Bytes, &oid)
			if err != nil {
				return "", ErrBadIdentity
			}
			if !isIdentityOID(oid) {
				continue
			}
			n++
			if n > 1 {
				return "", ErrMultipleIdentities
			}
			v, err := identityValue(rest)
			if err != nil {
				return "", err
			}
			found = v
		}
	}
	if n == 0 {
		return "", ErrNoIdentity
	}
	return found, nil
}

// identityValue decodes "[0] EXPLICIT UTF8String" and checks user@domain.
func identityValue(b []byte) (string, error) {
	var wrap asn1.RawValue
	if rest, err := asn1.Unmarshal(b, &wrap); err != nil || len(rest) != 0 ||
		wrap.Class != asn1.ClassContextSpecific || wrap.Tag != 0 || !wrap.IsCompound {
		return "", ErrBadIdentity
	}
	var s asn1.RawValue
	if rest, err := asn1.Unmarshal(wrap.Bytes, &s); err != nil || len(rest) != 0 ||
		s.Class != asn1.ClassUniversal || s.Tag != asn1.TagUTF8String {
		return "", ErrBadIdentity
	}
	v := string(s.Bytes)
	user, domain, ok := strings.Cut(v, "@")
	if !ok || user == "" || domain == "" || strings.Contains(domain, "@") ||
		!utf8.ValidString(v) || strings.ContainsFunc(v, isControl) {
		return "", ErrBadIdentity
	}
	return v, nil
}

// isControl reports a character no identity has any business containing.
func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

// SetCertificatePrincipal makes the server name the caller from its verified
// TLS client certificate, for calls that carry no RPCSEC_GSS principal: an
// AUTH_NONE or AUTH_UNIX call over TLS then reaches [AllowPrincipal] and
// [AllowCall] with [rpc.Call.Principal] set to what f returned.
//
// f is called ONCE per TLS connection, right after the handshake, with the
// first chain crypto/tls verified (leaf first) — never per call, and never
// with a certificate that was only presented. That needs a [crypto/tls.Config]
// passed to [Server.SetTLS] that verifies client certificates: ClientAuth
// [crypto/tls.RequireAndVerifyClientCert] or
// [crypto/tls.VerifyClientCertIfGiven], and ClientCAs. Returning ok=false (or
// an empty principal) leaves the principal empty, which [AllowPrincipal]
// predicates refuse like any other stranger. The answer is held by that
// connection alone: a principal cannot leak to another client.
//
// Revocation is not checked here, because it changes after the handshake and
// the connection may live for days: check it in [AllowCall], on every call.
//
// ⛔ Read the package documentation's note on Linux clients before relying on
// this for a shared machine: there the certificate identifies the MOUNT, not
// the person.
//
// Call it before Serve. A nil f turns it off.
func (s *Server) SetCertificatePrincipal(f func(chain []*x509.Certificate) (principal string, ok bool)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return ErrServing
	}
	s.rpcsrv.CertPrincipal = f
	return nil
}

// RequireTLS refuses, on this export, every call that did not arrive over
// RPC-with-TLS (RFC 9289): each NFS procedure answers NFS3ERR_ACCES. The NULL
// procedure and the AUTH_TLS probe are always answered — a client has to be
// able to ask for TLS in the clear before it has any.
//
// ⛔ MOUNT's MNT is answered in the clear, and that is not an oversight. The
// Linux kernel's MOUNT client (fs/nfs/mount_clnt.c, nfs_mount) creates its
// RPC client with authflavor RPC_AUTH_UNIX and no xprtsec at all: every
// NFSv3 mount with xprtsec=tls or mtls sends MNT over plain TCP — the
// live-mount-mtls CI lane captures it on the wire — and FreeBSD's mountd is
// a userland program with no TLS either. Refusing a cleartext MNT would make
// an export that requires TLS unmountable by every client that can speak
// TLS. What MNT hands out is the root file handle, and on this export a
// handle is useless without TLS: every procedure that takes one refuses a
// cleartext caller. A MNT that does arrive over TLS is judged by
// [AllowCall] / [AllowPrincipal] and refused MNT3ERR_ACCES when they deny.
// RFC 9289 does not say how a server that requires TLS should refuse a
// cleartext call; NFS3ERR_ACCES is the status NFSv3 has for "not you".
//
// RequireTLS composes with [AllowCall] and [AllowPrincipal]: TLS is checked
// first, and the predicate only sees calls that passed.
func RequireTLS() ExportOption { return func(e *export) { e.requireTLS = true } }

// AllowCall restricts an export to the calls a predicate accepts, and is the
// general form of [AllowPrincipal]: the predicate sees the whole
// [rpc.Call] — [rpc.Call.Principal], and [rpc.Call.TLS], whose
// VerifiedChains carry the client certificate for checks the principal
// cannot express (a revocation list, a groups extension).
//
// The predicate is called on EVERY operation, not once at mount, and for a
// write it may be called twice (once to reach the file, once to change it).
// NFSv3 is stateless: a file handle is a bearer token that outlives any
// mount, and a revocation that took effect only at the next mount would not
// take effect at all.
//
// It must be safe for concurrent use and should be cheap; it is on the path
// of every read. Only the fields named above are meaningful to it: the
// arguments have not been decoded yet and the results must not be written.
func AllowCall(allow func(c *rpc.Call) (read, write bool)) ExportOption {
	return func(e *export) { e.allow = allow }
}

// permits is the one place a caller is judged against an export.
//
// It answers for the CALLER only; whether the export itself is writable is
// [Server.mayWrite]'s other half.
func (e *export) permits(c *rpc.Call) (read, write bool) {
	if e.requireTLS && c.TLS == nil {
		return false, false
	}
	if e.allow == nil {
		return true, true
	}
	return e.allow(c)
}
