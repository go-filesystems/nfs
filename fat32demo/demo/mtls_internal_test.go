package demo

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
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	fat32 "github.com/go-filesystems/fat32"
	"github.com/go-filesystems/nfs"
)

func TestOtherNameNamesOnlyAnIdentity(t *testing.T) {
	utf8, _ := asn1.Marshal(asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte("alice@example.org")})
	explicit, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, IsCompound: true, Bytes: utf8})
	oid, _ := asn1.Marshal(nfs.OIDFreeBSDCertUser)
	san, _ := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, IsCompound: true, Bytes: append(oid, explicit...)}})
	with := &x509.Certificate{Extensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: san}}}
	if p, ok := otherName([]*x509.Certificate{with}); !ok || p != "alice@example.org" {
		t.Errorf("with an identity: (%q, %v)", p, ok)
	}
	if p, ok := otherName([]*x509.Certificate{{}}); ok || p != "" {
		t.Errorf("without one: (%q, %v)", p, ok)
	}
}

func TestClientCAOnAServingServerIsRefused(t *testing.T) {
	// SetCertificatePrincipal and SetTLS both refuse a server that already
	// serves; the error must reach the caller rather than leave TLS half on.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cert, keyPath := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}

	srv, err := nfs.New()
	if err != nil {
		t.Fatal(err)
	}
	fsys, err := fat32.Open(image(t), -1)
	if err != nil {
		t.Fatal(err)
	}
	defer fsys.Close()
	if err := srv.Export("/", fsys); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	defer func() { srv.Close(); <-done }()
	// Serve marks the server started from its own goroutine, so this retries
	// until it has: the first refusal is the answer under test.
	var out bytes.Buffer
	for {
		err = applyTLS(srv, settings{certFile: cert, keyFile: keyPath, clientCA: cert}, &out)
		if err != nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !errors.Is(err, nfs.ErrServing) {
		t.Errorf("applyTLS on a serving server = %v, want ErrServing", err)
	}
}
