package nfs_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-filesystems/nfs"
	"github.com/go-filesystems/nfs/rpc"
	"github.com/go-filesystems/nfs/xdr"
)

// ---------------------------------------------------------------------------
// A small PKI: one CA that also serves as the server's certificate, and
// client certificates that carry FreeBSD's identity otherName.
// ---------------------------------------------------------------------------

type pki struct {
	ca   tls.Certificate
	pool *x509.CertPool
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// No ExtKeyUsage: crypto/tls checks usages along the whole chain, and a
	// root restricted to serverAuth would refuse every client certificate.
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
	return &pki{ca: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool: pool}
}

// otherNameSAN encodes a SubjectAltName holding one FreeBSD identity
// otherName per value, the way RFC 5280 §4.2.1.6 lays it out. The test
// against openssl pins this encoder to an independent one.
func otherNameSAN(t *testing.T, oid asn1.ObjectIdentifier, values ...string) pkix.Extension {
	t.Helper()
	var names []asn1.RawValue
	for _, v := range values {
		utf8, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagUTF8String, Bytes: []byte(v)})
		if err != nil {
			t.Fatal(err)
		}
		explicit, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: utf8})
		if err != nil {
			t.Fatal(err)
		}
		typeID, err := asn1.Marshal(oid)
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: append(typeID, explicit...)})
	}
	b, err := asn1.Marshal(names)
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: b}
}

// client issues a client certificate carrying the given identities.
func (p *pki) client(t *testing.T, cn string, identities ...string) tls.Certificate {
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
	if len(identities) > 0 {
		tmpl.ExtraExtensions = []pkix.Extension{otherNameSAN(t, nfs.OIDFreeBSDCertUser, identities...)}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, p.ca.Leaf, &key.PublicKey, p.ca.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// serverConfig verifies client certificates against the CA.
func (p *pki) serverConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{p.ca},
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    p.pool,
	}
}

func (p *pki) clientConfig(certs ...tls.Certificate) *tls.Config {
	return &tls.Config{
		RootCAs: p.pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13,
		Certificates: certs, NextProtos: []string{"sunrpc"},
	}
}

// ---------------------------------------------------------------------------
// The wire client, taught RFC 9289.
// ---------------------------------------------------------------------------

// probe sends the AUTH_TLS probe (RFC 9289 §5.1) and reports whether the
// server answered STARTTLS.
func (w *wire) probe() bool {
	w.t.Helper()
	w.xid++
	e := xdr.NewEncoder(nil)
	e.Uint32(w.xid)
	e.Uint32(0)
	e.Uint32(2)
	e.Uint32(nfs.ProgramNFS)
	e.Uint32(nfs.VersionNFS)
	e.Uint32(0) // NULL
	e.Uint32(rpc.AuthTLS)
	e.Opaque(nil)
	e.Uint32(rpc.AuthNull)
	e.Opaque(nil)
	d := xdr.NewDecoder(w.raw(e.Bytes()))
	w.mustU32(d) // xid
	w.mustU32(d) // REPLY
	if w.mustU32(d) != replyAccepted {
		return false
	}
	w.mustU32(d) // verifier flavour
	verf, err := d.Opaque()
	if err != nil {
		w.t.Fatal(err)
	}
	return w.mustU32(d) == 0 && string(verf) == "STARTTLS"
}

// startTLS probes and upgrades this connection in place.
func (w *wire) startTLS(cfg *tls.Config) error {
	w.t.Helper()
	if !w.probe() {
		w.t.Fatal("the server did not answer STARTTLS")
	}
	_ = w.conn.SetDeadline(time.Now().Add(30 * time.Second))
	tc := tls.Client(w.conn, cfg)
	if err := tc.Handshake(); err != nil {
		return err
	}
	w.conn = tc
	return nil
}

func (w *wire) getattr(fh []byte) nfs.Status {
	w.t.Helper()
	st, _ := w.nfsCall(1, func(e *xdr.Encoder) { e.Opaque(fh) })
	return st
}

// ---------------------------------------------------------------------------
// RequireTLS
// ---------------------------------------------------------------------------

func TestRequireTLSRefusesCleartextAndServesTLS(t *testing.T) {
	p := newPKI(t)
	addr := serve(t, func(s *nfs.Server) {
		if err := s.SetTLS(p.serverConfig()); err != nil {
			t.Fatal(err)
		}
		if err := s.Export("/", fixture(), nfs.ReadWrite(), nfs.RequireTLS()); err != nil {
			t.Fatal(err)
		}
	})

	// Positive control FIRST: the same export, over TLS, serves.
	secure := dial(t, addr)
	if err := secure.startTLS(p.clientConfig()); err != nil {
		t.Fatal(err)
	}
	root := secure.mount("/")
	fh, st := secure.lookup(root, "hello.txt")
	if st != nfs.StatusOK {
		t.Fatalf("LOOKUP over TLS: %v", st)
	}
	data, _, st := secure.read(fh, 0, 64)
	if st != nfs.StatusOK || string(data) != "hello, nfs\n" {
		t.Fatalf("READ over TLS: %q %v", data, st)
	}
	if _, st := secure.write(fh, 0, []byte("HELLO")); st != nfs.StatusOK {
		t.Fatalf("WRITE over TLS: %v", st)
	}

	// Now the clear. NULL of both programs is answered: a client has to be
	// able to ping before it has TLS.
	clear := dial(t, addr)
	clear.call(nfs.ProgramNFS, nfs.VersionNFS, 0, nil)
	clear.call(nfs.ProgramMount, nfs.VersionMount, 0, nil)
	// MNT is answered too — the Linux kernel's MOUNT client has no TLS; see
	// RequireTLS. The handle it hands out is refused below.
	clearRoot := clear.mount("/")

	if st := clear.getattr(clearRoot); st != nfs.StatusAccess {
		t.Errorf("GETATTR in the clear = %v, want NFS3ERR_ACCES", st)
	}
	if _, st := clear.lookup(clearRoot, "hello.txt"); st != nfs.StatusAccess {
		t.Errorf("LOOKUP in the clear = %v, want NFS3ERR_ACCES", st)
	}
	// A handle is a bearer token: one obtained over TLS is no key in the clear.
	if _, _, st := clear.read(fh, 0, 64); st != nfs.StatusAccess {
		t.Errorf("READ in the clear with a handle obtained over TLS = %v, want NFS3ERR_ACCES", st)
	}
	if _, st := clear.write(fh, 0, []byte("pwned")); st != nfs.StatusAccess {
		t.Errorf("WRITE in the clear = %v, want NFS3ERR_ACCES", st)
	}

	// And the probe is answered in the clear, after which the same connection
	// is served: the refusal was about the transport, not the client.
	if err := clear.startTLS(p.clientConfig()); err != nil {
		t.Fatal(err)
	}
	if data, _, st := clear.read(fh, 0, 64); st != nfs.StatusOK || string(data) != "HELLO, nfs\n" {
		t.Errorf("READ after STARTTLS = %q %v", data, st)
	}
}

func TestAnExportWithoutRequireTLSStillServesTheClear(t *testing.T) {
	// The control for the test above: the refusal comes from the option, not
	// from SetTLS.
	p := newPKI(t)
	addr := serve(t, func(s *nfs.Server) {
		if err := s.SetTLS(p.serverConfig()); err != nil {
			t.Fatal(err)
		}
		if err := s.Export("/", fixture()); err != nil {
			t.Fatal(err)
		}
	})
	w := dial(t, addr)
	if st := w.getattr(w.mount("/")); st != nfs.StatusOK {
		t.Errorf("GETATTR in the clear on an export not requiring TLS = %v", st)
	}
}

// ---------------------------------------------------------------------------
// The certificate names the caller
// ---------------------------------------------------------------------------

// certServer serves fixture() at "/" to alice only, naming callers from
// their certificates, and counts how often the certificate is read.
func certServer(t *testing.T, p *pki, calls *atomic.Int32, seen func(*rpc.Call)) string {
	t.Helper()
	return serve(t, func(s *nfs.Server) {
		if err := s.SetTLS(p.serverConfig()); err != nil {
			t.Fatal(err)
		}
		if err := s.SetCertificatePrincipal(func(chain []*x509.Certificate) (string, bool) {
			calls.Add(1)
			pr, err := nfs.OtherNamePrincipal(chain[0])
			return pr, err == nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := s.Export("/", fixture(), nfs.RequireTLS(), nfs.AllowCall(func(c *rpc.Call) (bool, bool) {
			if seen != nil {
				seen(c)
			}
			return c.Principal == "alice@example.org", false
		})); err != nil {
			t.Fatal(err)
		}
	})
}

func TestTheCertificateDecidesWhoGetsIn(t *testing.T) {
	p := newPKI(t)
	var calls atomic.Int32
	addr := certServer(t, p, &calls, nil)
	// A handle is a bearer token, so a refused caller can hold one: take it
	// from a MNT in the clear and check that the per-call gate stops it.
	root := dial(t, addr).mount("/")

	for _, tc := range []struct {
		name string
		cert tls.Certificate
		want nfs.Status
	}{
		{"alice (positive control)", p.client(t, "alice", "alice@example.org"), nfs.StatusOK},
		{"bob", p.client(t, "bob", "bob@example.org"), nfs.StatusAccess},
		{"no otherName", p.client(t, "alice@example.org"), nfs.StatusAccess},
		{"two otherNames", p.client(t, "alice", "alice@example.org", "bob@example.org"), nfs.StatusAccess},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := dial(t, addr)
			if err := w.startTLS(p.clientConfig(tc.cert)); err != nil {
				t.Fatal(err)
			}
			if st := w.getattr(root); st != tc.want {
				t.Errorf("GETATTR = %v, want %v", st, tc.want)
			}
			if _, st := w.lookup(root, "hello.txt"); st != tc.want {
				t.Errorf("LOOKUP = %v, want %v", st, tc.want)
			}
		})
	}
	// Four connections, several calls each: the certificate was read once
	// per connection.
	if n := calls.Load(); n != 4 {
		t.Errorf("the certificate principal was computed %d times for 4 connections", n)
	}
}

func TestNoClientCertificateNamesNobody(t *testing.T) {
	// VerifyClientCertIfGiven lets a client in with no certificate at all.
	// It must then be nobody, not the last person who connected.
	p := newPKI(t)
	var calls atomic.Int32
	addr := certServer(t, p, &calls, nil)
	root := dial(t, addr).mount("/")
	w := dial(t, addr)
	if err := w.startTLS(p.clientConfig()); err != nil {
		t.Fatal(err)
	}
	if st := w.getattr(root); st != nfs.StatusAccess {
		t.Errorf("GETATTR with no client certificate = %v, want NFS3ERR_ACCES", st)
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("the principal function ran %d times with no certificate", n)
	}
}

func TestPrincipalsNeverCrossConnections(t *testing.T) {
	// Two clients with different certificates, hammering the same export at
	// the same time. Every call the predicate sees must carry the principal
	// of the certificate on ITS OWN connection — checked from the chain the
	// call carries, so the witness is not the value under test.
	p := newPKI(t)
	var calls atomic.Int32
	var mismatches atomic.Int32
	var mu sync.Mutex
	perPrincipal := map[string]int{}
	addr := certServer(t, p, &calls, func(c *rpc.Call) {
		want := ""
		if c.TLS != nil && len(c.TLS.VerifiedChains) > 0 {
			want = c.TLS.VerifiedChains[0][0].Subject.CommonName
		}
		if c.Principal != want {
			mismatches.Add(1)
		}
		mu.Lock()
		perPrincipal[c.Principal]++
		mu.Unlock()
	})

	type result struct {
		who     string
		ok, bad int
	}
	// The handle comes from a MNT in the clear, which the gate does not see
	// (see RequireTLS), so every call it counts below is a GETATTR.
	root := dial(t, addr).mount("/")
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for _, who := range []string{"alice@example.org", "bob@example.org"} {
		w := dial(t, addr)
		// CN = the identity, so the witness above can compare.
		if err := w.startTLS(p.clientConfig(p.client(t, who, who))); err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := result{who: who}
			for range 300 {
				if w.getattr(root) == nfs.StatusOK {
					r.ok++
				} else {
					r.bad++
				}
			}
			results <- r
		}()
	}
	wg.Wait()
	close(results)
	for r := range results {
		switch r.who {
		case "alice@example.org":
			if r.ok != 300 {
				t.Errorf("alice was refused %d of 300 calls", r.bad)
			}
		case "bob@example.org":
			if r.bad != 300 {
				t.Errorf("bob was let in %d of 300 calls", r.ok)
			}
		}
	}
	if n := mismatches.Load(); n != 0 {
		t.Errorf("%d calls carried a principal that was not their own connection's", n)
	}
	if perPrincipal["alice@example.org"] != 300 || perPrincipal["bob@example.org"] != 300 {
		t.Errorf("calls per principal: %v", perPrincipal)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("the certificate was read %d times for 2 connections", n)
	}
}

func TestSetCertificatePrincipalAfterServeIsRefused(t *testing.T) {
	s, err := nfs.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Export("/", fixture()); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	defer func() { s.Close(); <-done }()
	// Serve marks the server started before it accepts; a MNT round trip
	// proves it got there.
	dial(t, ln.Addr().String()).mount("/")
	if err := s.SetCertificatePrincipal(nil); !errors.Is(err, nfs.ErrServing) {
		t.Errorf("SetCertificatePrincipal on a serving server = %v, want ErrServing", err)
	}
}

// mntStatus performs MNT and returns only its mountstat3.
func (w *wire) mntStatus(path string) uint32 {
	w.t.Helper()
	d := w.call(nfs.ProgramMount, nfs.VersionMount, 1, func(e *xdr.Encoder) { e.String(path) })
	return w.mustU32(d)
}

const mnt3ErrAcces = 13

func TestAMountOverTLSIsJudgedByTheGate(t *testing.T) {
	// A MNT that arrived over TLS knows who is asking: a refused caller is
	// told so at MNT rather than "mounted" followed by NFS3ERR_ACCES on
	// every call.
	p := newPKI(t)
	var calls atomic.Int32
	addr := certServer(t, p, &calls, nil)
	for _, tc := range []struct {
		name string
		cert []tls.Certificate
		want uint32
	}{
		{"alice (positive control)", []tls.Certificate{p.client(t, "alice", "alice@example.org")}, 0},
		{"bob", []tls.Certificate{p.client(t, "bob", "bob@example.org")}, mnt3ErrAcces},
		{"no certificate", nil, mnt3ErrAcces},
		{"two identities", []tls.Certificate{p.client(t, "x", "alice@example.org", "bob@example.org")}, mnt3ErrAcces},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := dial(t, addr)
			if err := w.startTLS(p.clientConfig(tc.cert...)); err != nil {
				t.Fatal(err)
			}
			if st := w.mntStatus("/"); st != tc.want {
				t.Errorf("MNT = %d, want %d", st, tc.want)
			}
		})
	}
}

func TestAMountInTheClearIsAnsweredEvenWhenTLSIsRequired(t *testing.T) {
	// ⛔ Pinned on purpose. The Linux kernel sends MNT over plain TCP with
	// AUTH_UNIX whatever xprtsec= says (fs/nfs/mount_clnt.c), so refusing it
	// would make a RequireTLS export unmountable from Linux; the
	// live-mount-mtls CI lane captures that MNT on the wire. What protects
	// the export is that the handle is refused on every NFS call in the
	// clear, which TestRequireTLSRefusesCleartextAndServesTLS asserts.
	p := newPKI(t)
	var calls atomic.Int32
	addr := certServer(t, p, &calls, nil)
	w := dial(t, addr)
	if st := w.mntStatus("/"); st != 0 {
		t.Fatalf("MNT in the clear = %d, want 0", st)
	}
	if st := w.getattr(w.mount("/")); st != nfs.StatusAccess {
		t.Errorf("GETATTR in the clear on the handle MNT gave = %v, want NFS3ERR_ACCES", st)
	}
}
