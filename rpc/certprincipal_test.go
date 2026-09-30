package rpc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-filesystems/nfs/xdr"
)

// testCA makes a CA that also serves as the server's certificate for
// 127.0.0.1. It carries no ExtKeyUsage: crypto/tls checks usages along the
// whole chain, so a root restricted to serverAuth would refuse every client.
func testCA(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "nfs-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
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

// clientCert issues a client certificate with the given CN from ca.
func clientCert(t *testing.T, ca tls.Certificate, cn string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, ca.Leaf, &key.PublicKey, ca.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// principalServer serves one procedure that answers the principal it was
// called with, over a TLS config the test chooses.
func principalServer(t *testing.T, cfg *tls.Config, f func([]*x509.Certificate) (string, bool)) string {
	t.Helper()
	s := &Server{TLS: cfg, CertPrincipal: f}
	s.Register(&Program{Prog: testProg, Vers: testVers, Procs: map[uint32]Proc{
		1: func(c *Call) Status {
			c.Res.String(c.Principal)
			return StatusSuccess
		},
	}})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(ln)
	t.Cleanup(func() { s.Close() })
	return ln.Addr().String()
}

// dialTLS probes, upgrades, and returns the TLS connection.
func dialTLS(t *testing.T, addr string, cfg *tls.Config) (*tls.Conn, error) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	if _, _, ok := tlsProbe(t, c, Auth{Flavor: AuthTLS}); !ok {
		t.Fatal("the probe was denied")
	}
	tc := tls.Client(c, cfg)
	return tc, tc.Handshake()
}

func principalOver(t *testing.T, c net.Conn) string {
	t.Helper()
	p, err := xdr.NewDecoder(callOver(t, c, testProg, testVers, 1)).String()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTheCertificatePrincipalIsComputedOncePerConnection(t *testing.T) {
	ca, pool := testCA(t)
	var calls atomic.Int32
	addr := principalServer(t, &tls.Config{
		Certificates: []tls.Certificate{ca}, MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool,
	}, func(chain []*x509.Certificate) (string, bool) {
		calls.Add(1)
		return chain[0].Subject.CommonName, true
	})
	tc, err := dialTLS(t, addr, &tls.Config{
		RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{clientCert(t, ca, "alice@example.org")},
	})
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if p := principalOver(t, tc); p != "alice@example.org" {
			t.Fatalf("principal = %q", p)
		}
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("CertPrincipal was called %d times for one connection, want 1", n)
	}
}

func TestAPresentedButUnverifiedCertificateNamesNobody(t *testing.T) {
	// ⛔ RequestClientCert takes whatever the client sends and verifies
	// nothing. A certificate anybody can mint must not become a principal,
	// however well-formed its name.
	ca, pool := testCA(t)
	rogue, _ := testCA(t)
	var calls atomic.Int32
	for _, tc := range []struct {
		name string
		auth tls.ClientAuthType
		cert tls.Certificate
		want string
	}{
		{"unverified", tls.RequestClientCert, clientCert(t, rogue, "alice@example.org"), ""},
		{"verified (control)", tls.RequireAndVerifyClientCert, clientCert(t, ca, "alice@example.org"), "alice@example.org"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := principalServer(t, &tls.Config{
				Certificates: []tls.Certificate{ca}, MinVersion: tls.VersionTLS13,
				ClientAuth: tc.auth, ClientCAs: pool,
			}, func(chain []*x509.Certificate) (string, bool) {
				calls.Add(1)
				return chain[0].Subject.CommonName, true
			})
			c, err := dialTLS(t, addr, &tls.Config{
				RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13,
				Certificates: []tls.Certificate{tc.cert},
			})
			if err != nil {
				t.Fatal(err)
			}
			if p := principalOver(t, c); p != tc.want {
				t.Errorf("principal = %q, want %q", p, tc.want)
			}
		})
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("CertPrincipal called %d times, want 1 (the verified control only)", n)
	}
}

func TestPrincipalsDoNotCrossConnections(t *testing.T) {
	// Two clients, two certificates, interleaved as hard as the scheduler
	// allows: every answer must name the certificate of the connection that
	// asked.
	ca, pool := testCA(t)
	addr := principalServer(t, &tls.Config{
		Certificates: []tls.Certificate{ca}, MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool,
	}, func(chain []*x509.Certificate) (string, bool) {
		return chain[0].Subject.CommonName, true
	})
	var wg sync.WaitGroup
	for _, who := range []string{"alice@example.org", "bob@example.org"} {
		c, err := dialTLS(t, addr, &tls.Config{
			RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13,
			Certificates: []tls.Certificate{clientCert(t, ca, who)},
		})
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				if p := principalOver(t, c); p != who {
					t.Errorf("%s's connection was answered as %q", who, p)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestCertPrincipalBranches(t *testing.T) {
	chain := []*x509.Certificate{{Subject: pkix.Name{CommonName: "x@y"}}}
	withChain := &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{chain}}
	yes := func(c []*x509.Certificate) (string, bool) { return c[0].Subject.CommonName, true }
	no := func([]*x509.Certificate) (string, bool) { return "ignored", false }
	for _, tc := range []struct {
		name string
		f    func([]*x509.Certificate) (string, bool)
		st   *tls.ConnectionState
		want string
	}{
		{"no function", nil, withChain, ""},
		{"no verified chain", yes, &tls.ConnectionState{}, ""},
		{"function declines", no, withChain, ""},
		{"function answers", yes, withChain, "x@y"},
	} {
		s := &Server{CertPrincipal: tc.f}
		if got := s.certPrincipal(tc.st); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

// fixedAuth accepts one flavour and names a fixed principal.
type fixedAuth struct{ principal string }

func (fixedAuth) Flavor() uint32 { return 6 }
func (a fixedAuth) Authenticate(*AuthCall) AuthDecision {
	return AuthDecision{Principal: a.principal}
}

func TestTheCertificateNamesOnlyCallsThatProveNothingThemselves(t *testing.T) {
	// draft-cel-nfsv4-rpc-tls-othername: the certificate identity applies to
	// AUTH_NONE and AUTH_SYS; an RPCSEC_GSS call keeps its own principal.
	s := &Server{Auth: fixedAuth{"gss@REALM"}}
	var seen string
	s.Register(&Program{Prog: testProg, Vers: testVers, Procs: map[uint32]Proc{
		1: func(c *Call) Status { seen = c.Principal; return StatusSuccess },
	}})
	unix := xdr.NewEncoder(nil)
	unix.Uint32(1)
	unix.String("m")
	unix.Uint32(0)
	unix.Uint32(0)
	unix.Uint32(0)
	for _, tc := range []struct {
		flavor uint32
		body   []byte
		want   string
	}{
		{AuthNull, nil, "cert@example.org"},
		{AuthUnix, unix.Bytes(), "cert@example.org"},
		{6, nil, "gss@REALM"},
	} {
		seen = "unset"
		msg := callMsg(1, 2, testProg, testVers, 1, tc.flavor, tc.body, nil)
		if _, _, err := s.handle(msg, nil, nil, &tls.ConnectionState{}, "cert@example.org"); err != nil {
			t.Fatal(err)
		}
		if seen != tc.want {
			t.Errorf("flavour %d: principal %q, want %q", tc.flavor, seen, tc.want)
		}
	}
}

func TestTheServerOffersSunRPCOverALPN(t *testing.T) {
	// RFC 9289 §5.2 registers "sunrpc" and makes ALPN mandatory.
	cert, pool := selfSigned(t)
	_, addr := tlsServer(t, cert)
	for _, tc := range []struct {
		name   string
		protos []string
		want   string
		fails  bool
	}{
		{"sunrpc is selected", []string{"sunrpc"}, "sunrpc", false},
		{"no ALPN is still served", nil, "", false},
		{"only a foreign protocol is refused", []string{"h2"}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := dialTLS(t, addr, &tls.Config{
				RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13, NextProtos: tc.protos,
			})
			if tc.fails {
				if err == nil {
					t.Fatal("a client offering only h2 completed the handshake")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := c.ConnectionState().NegotiatedProtocol; got != tc.want {
				t.Errorf("negotiated %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAConfigNamingItsOwnProtocolsIsLeftAlone(t *testing.T) {
	cert, pool := selfSigned(t)
	s := &Server{TLS: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{"x-custom"}}}
	s.Register(&Program{Prog: testProg, Vers: testVers, Procs: map[uint32]Proc{}})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(ln)
	t.Cleanup(func() { s.Close() })
	c, err := dialTLS(t, ln.Addr().String(), &tls.Config{
		RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13, NextProtos: []string{"x-custom"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := c.ConnectionState().NegotiatedProtocol; got != "x-custom" {
		t.Errorf("negotiated %q", got)
	}
}
