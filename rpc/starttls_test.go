package rpc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/go-filesystems/nfs/xdr"
)

// selfSigned makes a certificate for 127.0.0.1, and the pool that trusts it.
func selfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "nfs-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// tlsProbe writes the AUTH_TLS probe of RFC 9289 §5.1 and returns the reply's
// verifier and accept status.
func tlsProbe(t *testing.T, c net.Conn, cred Auth) (Auth, uint32, bool) {
	t.Helper()
	e := xdr.NewEncoder(nil)
	e.Uint32(1) // xid
	e.Uint32(0) // CALL
	e.Uint32(2) // RPC version
	e.Uint32(testProg)
	e.Uint32(testVers)
	e.Uint32(0) // NULL
	e.Uint32(cred.Flavor)
	e.Opaque(cred.Body)
	e.Uint32(AuthNull)
	e.Opaque(nil)
	body := e.Bytes()
	var frame [4]byte
	binary.BigEndian.PutUint32(frame[:], lastFragment|uint32(len(body)))
	if _, err := c.Write(append(frame[:], body...)); err != nil {
		t.Fatal(err)
	}

	if _, err := io.ReadFull(c, frame[:]); err != nil {
		t.Fatal(err)
	}
	n := binary.BigEndian.Uint32(frame[:]) &^ lastFragment
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	d := xdr.NewDecoder(buf)
	for range 2 {
		if _, err := d.Uint32(); err != nil { // xid, REPLY
			t.Fatal(err)
		}
	}
	stat, err := d.Uint32()
	if err != nil {
		t.Fatal(err)
	}
	if stat != msgAccepted {
		return Auth{}, 0, false
	}
	flavor, err := d.Uint32()
	if err != nil {
		t.Fatal(err)
	}
	d.SetLimit(maxAuthBody)
	vbody, err := d.Opaque()
	if err != nil {
		t.Fatal(err)
	}
	accept, err := d.Uint32()
	if err != nil {
		t.Fatal(err)
	}
	return Auth{Flavor: flavor, Body: vbody}, accept, true
}

func tlsServer(t *testing.T, cert tls.Certificate) (*Server, string) {
	t.Helper()
	s := &Server{TLS: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}}
	s.Register(&Program{Prog: testProg, Vers: testVers, Procs: map[uint32]Proc{
		1: func(c *Call) Status {
			// Report whether this call arrived protected. Nothing else
			// distinguishes a TLS call from one in the clear.
			c.Res.Bool(c.TLS != nil)
			return StatusSuccess
		},
	}})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(ln)
	t.Cleanup(func() { s.Close() })
	return s, ln.Addr().String()
}

func TestSTARTTLSUpgradesTheConnection(t *testing.T) {
	cert, pool := selfSigned(t)
	_, addr := tlsServer(t, cert)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))

	verf, accept, ok := tlsProbe(t, c, Auth{Flavor: AuthTLS})
	if !ok {
		t.Fatal("the probe was denied")
	}
	if accept != stSuccess {
		t.Fatalf("accept_stat = %d, want SUCCESS", accept)
	}
	// RFC 9289 §5.1 fixes both the flavour and the eight bytes. A client is
	// required to check them before sending a ClientHello, so a server that
	// got either wrong would have clients that never start a handshake.
	if verf.Flavor != AuthNull {
		t.Errorf("verifier flavour = %d, want AUTH_NONE", verf.Flavor)
	}
	if string(verf.Body) != "STARTTLS" {
		t.Fatalf("verifier body = %q, want %q", verf.Body, "STARTTLS")
	}

	tc := tls.Client(c, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("handshake on the same connection: %v", err)
	}
	// And the calls that follow go through it.
	body := callOver(t, tc, testProg, testVers, 1)
	d := xdr.NewDecoder(body)
	protected, err := d.Bool()
	if err != nil {
		t.Fatal(err)
	}
	if !protected {
		t.Error("the procedure saw a call with no TLS state after the upgrade")
	}
}

func TestWithoutATLSConfigTheProbeIsRefused(t *testing.T) {
	// RFC 9289: a client must not send a ClientHello unless it read
	// STARTTLS. Answering anything else is how a server says no — and this
	// server must not say yes when it has no certificate to offer.
	s := &Server{}
	s.Register(&Program{Prog: testProg, Vers: testVers, Procs: map[uint32]Proc{
		1: func(*Call) Status { return StatusSuccess },
	}})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(ln)
	t.Cleanup(func() { s.Close() })

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, _, ok := tlsProbe(t, c, Auth{Flavor: AuthTLS}); ok {
		t.Error("a server with no TLS config accepted the probe")
	}
}

func TestAMalformedProbeIsNotAnswered(t *testing.T) {
	// The probe is answered only in exactly the shape RFC 9289 fixes.
	// Answering STARTTLS to something else would tell a client to start a
	// handshake on the strength of a message this server did not understand.
	cert, _ := selfSigned(t)
	_, addr := tlsServer(t, cert)

	for _, tc := range []struct {
		name string
		cred Auth
	}{
		{"a credential with a body", Auth{Flavor: AuthTLS, Body: []byte("x")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			verf, _, ok := tlsProbe(t, c, tc.cred)
			if ok && string(verf.Body) == "STARTTLS" {
				t.Error("a malformed probe was answered STARTTLS")
			}
		})
	}
}

// callOver makes one call on an already-established connection and returns
// the reply's results.
func callOver(t *testing.T, c net.Conn, prog, vers, proc uint32) []byte {
	t.Helper()
	e := xdr.NewEncoder(nil)
	e.Uint32(2)
	e.Uint32(0)
	e.Uint32(2)
	e.Uint32(prog)
	e.Uint32(vers)
	e.Uint32(proc)
	e.Uint32(AuthNull)
	e.Opaque(nil)
	e.Uint32(AuthNull)
	e.Opaque(nil)
	body := e.Bytes()
	var frame [4]byte
	binary.BigEndian.PutUint32(frame[:], lastFragment|uint32(len(body)))
	if _, err := c.Write(append(frame[:], body...)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, frame[:]); err != nil {
		t.Fatal(err)
	}
	n := binary.BigEndian.Uint32(frame[:]) &^ lastFragment
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	d := xdr.NewDecoder(buf)
	// xid, REPLY, reply_stat, then the verifier's FLAVOUR and body, then
	// accept_stat. Skipping the flavour reads its four bytes as the body's
	// length, which decodes without complaint and leaves the cursor in the
	// wrong place — a test that then reads a plausible wrong answer.
	for range 4 {
		if _, err := d.Uint32(); err != nil {
			t.Fatal(err)
		}
	}
	d.SetLimit(maxAuthBody)
	if _, err := d.Opaque(); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Uint32(); err != nil {
		t.Fatal(err)
	}
	return buf[len(buf)-d.Remaining():]
}

func TestAHandshakeThatFailsDropsTheConnection(t *testing.T) {
	// The reply saying STARTTLS has already gone out, so there is no way to
	// take it back: if the handshake then fails, the only honest thing left
	// is to close. Carrying on in the clear would serve a client that
	// believes it is protected.
	cert, _ := selfSigned(t)
	_, addr := tlsServer(t, cert)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, _, ok := tlsProbe(t, c, Auth{Flavor: AuthTLS}); !ok {
		t.Fatal("the probe was denied")
	}
	// Bytes that are not a ClientHello.
	if _, err := c.Write([]byte("this is not a handshake at all!!")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(c); err != nil && !isClosed(err) {
		t.Fatalf("read after a failed handshake: %v", err)
	}
	// And nothing is served on it afterwards.
	if _, err := c.Write([]byte("more")); err == nil {
		if _, err := io.ReadAll(c); err == nil {
			// A closed connection reads EOF, which io.ReadAll reports as
			// success with no bytes; what must not happen is a reply.
			t.Log("connection closed, as it must be")
		}
	}
}

func isClosed(err error) bool {
	return err != nil && (err == io.EOF || err == io.ErrUnexpectedEOF ||
		containsAny(err.Error(), "closed", "reset", "broken pipe"))
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
	}
	return false
}
