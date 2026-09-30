package nfs_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-filesystems/nfs"
)

// ---------------------------------------------------------------------------
// openssl is the judge of the encoding. Everything else in this file checks
// OtherNamePrincipal against an encoder written here, which can only confirm
// this repository's reading of RFC 5280; openssl read it independently, and
// it is what an administrator following FreeBSD's rpc.tlsservd(8) will use.
// ---------------------------------------------------------------------------

// needOpenSSL returns the openssl binary, skipping when it is absent — unless
// NFS_REQUIRE_OPENSSL is set, as CI sets it, where a missing judge is a
// failure: a skip is not a pass.
func needOpenSSL(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("openssl")
	if err != nil {
		if os.Getenv("NFS_REQUIRE_OPENSSL") != "" {
			t.Fatalf("NFS_REQUIRE_OPENSSL is set and openssl is not on PATH: %v", err)
		}
		t.Skip("openssl is not on PATH; set NFS_REQUIRE_OPENSSL=1 to make this a failure")
	}
	return bin
}

// opensslCert has openssl make a self-signed certificate with the given
// subjectAltName, written in openssl's own configuration syntax.
func opensslCert(t *testing.T, bin, san string) *x509.Certificate {
	t.Helper()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	cmd := exec.Command(bin, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
		"-keyout", filepath.Join(dir, "key.pem"), "-out", certPath, "-days", "1",
		"-subj", "/CN=nfs-othername-judge", "-addext", "subjectAltName="+san)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("openssl req: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		t.Fatal("openssl wrote no PEM block")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func sanOf(t *testing.T, c *x509.Certificate) []byte {
	t.Helper()
	for _, e := range c.Extensions {
		if e.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			return e.Value
		}
	}
	t.Fatal("no subjectAltName")
	return nil
}

const freebsdOID = "1.3.6.1.4.1.2238.1.1.1"

func TestOpenSSLCertificatesAreReadAsFreeBSDReadsThem(t *testing.T) {
	bin := needOpenSSL(t)
	for _, tc := range []struct {
		name, san string
		want      string
		err       error
	}{
		{"one identity", "otherName:" + freebsdOID + ";UTF8:alice@example.org", "alice@example.org", nil},
		{"beside a DNS name and an email", "DNS:host.example.org,email:x@example.org,otherName:" + freebsdOID + ";UTF8:bob@example.org", "bob@example.org", nil},
		{"two identities", "otherName:" + freebsdOID + ";UTF8:alice@example.org,otherName:" + freebsdOID + ";UTF8:bob@example.org", "", nfs.ErrMultipleIdentities},
		{"another otherName type only", "otherName:1.3.6.1.4.1.311.20.2.3;UTF8:alice@example.org", "", nfs.ErrNoIdentity},
		{"no otherName", "DNS:host.example.org", "", nfs.ErrNoIdentity},
		{"an IA5String, not a UTF8String", "otherName:" + freebsdOID + ";IA5STRING:alice@example.org", "", nfs.ErrBadIdentity},
		{"no domain", "otherName:" + freebsdOID + ";UTF8:alice", "", nfs.ErrBadIdentity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := nfs.OtherNamePrincipal(opensslCert(t, bin, tc.san))
			if !errors.Is(err, tc.err) || got != tc.want {
				t.Errorf("OtherNamePrincipal = (%q, %v), want (%q, %v)", got, err, tc.want, tc.err)
			}
		})
	}
}

func TestTheTestEncoderMatchesOpenSSLByteForByte(t *testing.T) {
	// The certificates the TLS tests use are built by otherNameSAN. Pinning
	// its bytes to openssl's makes those tests speak the same dialect as
	// the certificates an administrator would issue.
	bin := needOpenSSL(t)
	for _, ids := range [][]string{{"alice@example.org"}, {"alice@example.org", "bob@example.org"}} {
		var parts []string
		for _, id := range ids {
			parts = append(parts, "otherName:"+freebsdOID+";UTF8:"+id)
		}
		want := sanOf(t, opensslCert(t, bin, strings.Join(parts, ",")))
		got := otherNameSAN(t, nfs.OIDFreeBSDCertUser, ids...).Value
		if !bytes.Equal(got, want) {
			t.Errorf("%v:\n ours    %x\n openssl %x", ids, got, want)
		}
	}
}

func TestOpenSSLReadsTheTestEncoder(t *testing.T) {
	// The other direction: openssl prints what our encoder wrote as an
	// otherName of FreeBSD's type holding the identity.
	bin := needOpenSSL(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "x"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{otherNameSAN(t, nfs.OIDFreeBSDCertUser, "alice@example.org")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "c.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "x509", "-in", path, "-noout", "-ext", "subjectAltName").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl x509: %v\n%s", err, out)
	}
	s := strings.ToLower(string(out))
	if !strings.Contains(s, "othername") || !strings.Contains(s, freebsdOID) || !strings.Contains(s, "alice@example.org") {
		t.Errorf("openssl did not read an otherName %s holding alice@example.org:\n%s", freebsdOID, out)
	}
}

// ---------------------------------------------------------------------------
// The refusals, one at a time, on hand-built extensions.
// ---------------------------------------------------------------------------

func withSAN(value []byte) *x509.Certificate {
	return &x509.Certificate{Extensions: []pkix.Extension{
		{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Value: []byte{3, 2, 7, 128}}, // keyUsage: skipped
		{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: value},
	}}
}

// otherName builds one GeneralName [0] from a type-id and the bytes after it.
func otherName(t *testing.T, oid asn1.ObjectIdentifier, after []byte) asn1.RawValue {
	t.Helper()
	b, err := asn1.Marshal(oid)
	if err != nil {
		t.Fatal(err)
	}
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: append(b, after...)}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestOtherNamePrincipalRefusals(t *testing.T) {
	utf8 := func(s string) []byte {
		return mustMarshal(t, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagUTF8String, Bytes: []byte(s)})
	}
	explicit := func(inner []byte) []byte {
		return mustMarshal(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner})
	}
	san := func(names ...asn1.RawValue) []byte { return mustMarshal(t, names) }
	fb := nfs.OIDFreeBSDCertUser
	dns := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("h.example")}

	for _, tc := range []struct {
		name  string
		value []byte
		want  string
		err   error
	}{
		{"well-formed (control)", san(dns, otherName(t, fb, explicit(utf8("alice@example.org")))), "alice@example.org", nil},
		{"SAN is not DER", []byte{0x30, 0x05, 0x01}, "", nfs.ErrBadIdentity},
		{"SAN has trailing bytes", append(san(dns), 0), "", nfs.ErrBadIdentity},
		{"otherName type-id is not an OID", san(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: utf8("x")}), "", nfs.ErrBadIdentity},
		{"value not wrapped in [0]", san(otherName(t, fb, utf8("alice@example.org"))), "", nfs.ErrBadIdentity},
		{"value missing", san(otherName(t, fb, nil)), "", nfs.ErrBadIdentity},
		{"bytes after the value", san(otherName(t, fb, append(explicit(utf8("a@b")), 5, 0))), "", nfs.ErrBadIdentity},
		{"bytes after the string", san(otherName(t, fb, explicit(append(utf8("a@b"), 5, 0)))), "", nfs.ErrBadIdentity},
		{"not UTF-8", san(otherName(t, fb, explicit(utf8("a\xff@b")))), "", nfs.ErrBadIdentity},
		{"control character", san(otherName(t, fb, explicit(utf8("a\n@b")))), "", nfs.ErrBadIdentity},
		{"DEL", san(otherName(t, fb, explicit(utf8("a\x7f@b")))), "", nfs.ErrBadIdentity},
		{"empty user", san(otherName(t, fb, explicit(utf8("@b")))), "", nfs.ErrBadIdentity},
		{"empty domain", san(otherName(t, fb, explicit(utf8("a@")))), "", nfs.ErrBadIdentity},
		{"two at signs", san(otherName(t, fb, explicit(utf8("a@b@c")))), "", nfs.ErrBadIdentity},
		{"a malformed second identity is still a second identity", san(
			otherName(t, fb, explicit(utf8("alice@example.org"))),
			otherName(t, fb, nil)), "", nfs.ErrMultipleIdentities},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := nfs.OtherNamePrincipal(withSAN(tc.value))
			if !errors.Is(err, tc.err) || got != tc.want {
				t.Errorf("= (%q, %v), want (%q, %v)", got, err, tc.want, tc.err)
			}
		})
	}
	if _, err := nfs.OtherNamePrincipal(&x509.Certificate{}); !errors.Is(err, nfs.ErrNoIdentity) {
		t.Errorf("a certificate with no extensions: %v", err)
	}
}

func TestTheDraftOIDCountsOnceAssigned(t *testing.T) {
	// id-on-nfsv4Principal has no number yet. A consumer that learns it sets
	// OIDNFSv4Principal; from then on it is an identity like FreeBSD's, and
	// one of each is two identities, which the draft says MUST be refused.
	draft := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 99} // a stand-in, not the assignment
	one := func(oid asn1.ObjectIdentifier) []byte {
		return otherNameSAN(t, oid, "carol@example.org").Value
	}
	if _, err := nfs.OtherNamePrincipal(withSAN(one(draft))); !errors.Is(err, nfs.ErrNoIdentity) {
		t.Fatalf("an unset draft OID was honoured: %v", err)
	}

	old := nfs.OIDNFSv4Principal
	nfs.OIDNFSv4Principal = draft
	t.Cleanup(func() { nfs.OIDNFSv4Principal = old })

	if got, err := nfs.OtherNamePrincipal(withSAN(one(draft))); err != nil || got != "carol@example.org" {
		t.Errorf("draft OID once set = (%q, %v)", got, err)
	}
	var both []asn1.RawValue
	for _, oid := range []asn1.ObjectIdentifier{nfs.OIDFreeBSDCertUser, draft} {
		var names []asn1.RawValue
		if _, err := asn1.Unmarshal(one(oid), &names); err != nil {
			t.Fatal(err)
		}
		both = append(both, names...)
	}
	if _, err := nfs.OtherNamePrincipal(withSAN(mustMarshal(t, both))); !errors.Is(err, nfs.ErrMultipleIdentities) {
		t.Errorf("one FreeBSD and one draft identity = %v, want ErrMultipleIdentities", err)
	}
}
