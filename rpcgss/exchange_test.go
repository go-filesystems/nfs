package rpcgss_test

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/go-authn/krb5"
	"github.com/go-filesystems/nfs/rpc"
	"github.com/go-filesystems/nfs/rpcgss"
	"github.com/go-filesystems/nfs/xdr"

	"github.com/jcmturner/gokrb5/v8/client"
	krb5config "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
)

// These tests put a real Kerberos ticket, issued by a real KDC, through the
// whole RPCSEC_GSS exchange this package implements. The client half is
// written here rather than borrowed: what is being tested is the RFC 2203
// framing, and no library on this machine speaks it.
//
// The ticket, the keytab and the crypto underneath are NOT written here, and
// that is the point — see go-authn/krb5, whose own tests put MIT's gss-client
// in front of the acceptor.
//
//	eval "$(test/kdc.sh /tmp/krbtest)"
//	go test ./rpcgss/

const (
	testProg = 100003 // NFS, so the procedure numbering is the real one
	testVers = 3
)

func fixture(t *testing.T) (keytabPath, service string) {
	t.Helper()
	keytabPath, service = os.Getenv("KRB5_TEST_KEYTAB"), os.Getenv("KRB5_TEST_SERVICE")
	if keytabPath == "" || service == "" || os.Getenv("KRB5_CONFIG") == "" {
		if os.Getenv("KRB5_REQUIRE_JUDGE") != "" {
			t.Fatal("KRB5_REQUIRE_JUDGE is set but the KDC fixture is not: " +
				"KRB5_CONFIG, KRB5_TEST_KEYTAB and KRB5_TEST_SERVICE must all be set")
		}
		t.Skip("no KDC fixture; run test/kdc.sh and export what it prints")
	}
	return keytabPath, service
}

// initiator is the client half of RPCSEC_GSS: enough of it to drive a server.
type initiator struct {
	conn    net.Conn
	handle  []byte
	key     types.EncryptionKey
	seq     uint32
	xid     uint32
	window  uint32
	replies int
}

func dial(t *testing.T, addr string) *initiator {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	return &initiator{conn: c, xid: 1}
}

// cred encodes an rpc_gss_cred_t.
func (i *initiator) cred(proc, seq, service uint32) rpc.Auth {
	e := xdr.NewEncoder(nil)
	e.Uint32(1)
	e.Uint32(proc)
	e.Uint32(seq)
	e.Uint32(service)
	e.Opaque(i.handle)
	return rpc.Auth{Flavor: rpcgss.Flavor, Body: e.Bytes()}
}

// header builds the part of a call that the verifier signs: the xid through
// the end of the credential, and not a byte further. RFC 2203 §5.3.1 signs
// exactly this, which is why it has to exist before the verifier does.
func (i *initiator) header(proc uint32, cr rpc.Auth) []byte {
	e := xdr.NewEncoder(nil)
	e.Uint32(i.xid)
	e.Uint32(0) // CALL
	e.Uint32(2) // RPC version
	e.Uint32(testProg)
	e.Uint32(testVers)
	e.Uint32(proc)
	e.Uint32(cr.Flavor)
	e.Opaque(cr.Body)
	return append([]byte(nil), e.Bytes()...)
}

// send writes a call whose header was already built and signed.
func (i *initiator) send(t *testing.T, header []byte, verf rpc.Auth, args func(*xdr.Encoder)) {
	t.Helper()
	e := xdr.NewEncoder(nil)
	e.Fixed(header)
	e.Uint32(verf.Flavor)
	e.Opaque(verf.Body)
	if args != nil {
		args(e)
	}
	body := e.Bytes()
	var frame [4]byte
	binary.BigEndian.PutUint32(frame[:], 0x8000_0000|uint32(len(body)))
	if _, err := i.conn.Write(append(frame[:], body...)); err != nil {
		t.Fatal(err)
	}
	i.xid++
}

// reply reads one reply and returns its verifier, accept_stat and results.
func (i *initiator) reply(t *testing.T) (rpc.Auth, uint32, *xdr.Decoder) {
	t.Helper()
	var frame [4]byte
	if _, err := io.ReadFull(i.conn, frame[:]); err != nil {
		t.Fatal(err)
	}
	n := binary.BigEndian.Uint32(frame[:]) &^ 0x8000_0000
	buf := make([]byte, n)
	if _, err := io.ReadFull(i.conn, buf); err != nil {
		t.Fatal(err)
	}
	i.replies++
	d := xdr.NewDecoder(buf)
	mustU32(t, d) // xid
	mustU32(t, d) // REPLY
	stat := mustU32(t, d)
	if stat != 0 {
		why := mustU32(t, d)
		t.Fatalf("call denied: reject_stat %d, auth_stat %d", why, mustU32(t, d))
	}
	flavor := mustU32(t, d)
	d.SetLimit(400)
	body, err := d.Opaque()
	if err != nil {
		t.Fatal(err)
	}
	d.SetLimit(0)
	return rpc.Auth{Flavor: flavor, Body: body}, mustU32(t, d), d
}

func mustU32(t *testing.T, d *xdr.Decoder) uint32 {
	t.Helper()
	v, err := d.Uint32()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// mic signs a payload as the initiator does.
func (i *initiator) mic(t *testing.T, payload []byte) []byte {
	t.Helper()
	tok, err := gssapi.NewInitiatorMICToken(payload, i.key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := tok.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// verifyServerMIC checks a signature the server produced over payload.
func (i *initiator) verifyServerMIC(t *testing.T, payload, token []byte) {
	t.Helper()
	var mt gssapi.MICToken
	if err := mt.Unmarshal(token, true); err != nil {
		t.Fatalf("the server's verifier does not parse: %v", err)
	}
	mt.Payload = payload
	ok, err := mt.Verify(i.key, keyusage.GSSAPI_ACCEPTOR_SIGN)
	if err != nil || !ok {
		t.Fatalf("the server's verifier does not check out: ok=%v err=%v", ok, err)
	}
}

func be32(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}

// establish runs RPCSEC_GSS_INIT and leaves the initiator ready for data.
func establish(t *testing.T, addr, service string) *initiator {
	t.Helper()
	cfg, err := krb5config.Load(os.Getenv("KRB5_CONFIG"))
	if err != nil {
		t.Fatalf("krb5.conf: %v", err)
	}
	cl := client.NewWithPassword("alice", cfg.LibDefaults.DefaultRealm,
		password(), cfg, client.DisablePAFXFAST(true))
	if err := cl.Login(); err != nil {
		t.Fatalf("kinit: %v", err)
	}
	host, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	spn := service + "/" + host
	tkt, key, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("no service ticket for %s: %v", spn, err)
	}
	tok, err := spnego.NewKRB5TokenAPREQ(cl, tkt, key, []int{gssapi.ContextFlagInteg}, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := tok.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	i := dial(t, addr)
	// gokrb5's client sends no subkey, so the context key is the ticket's
	// session key. An initiator that sent one would have to use that instead.
	i.key = key
	i.send(t, i.header(0, i.cred(1 /* INIT */, 0, 1 /* svc_none */)), rpc.Auth{}, func(e *xdr.Encoder) {
		e.Opaque(raw)
	})
	verf, accept, d := i.reply(t)
	if accept != 0 {
		t.Fatalf("INIT accept_stat = %d", accept)
	}
	d.SetLimit(1 << 16)
	handle, err := d.Opaque()
	if err != nil {
		t.Fatal(err)
	}
	major, minor := mustU32(t, d), mustU32(t, d)
	if major != 0 {
		t.Fatalf("gss_major = %#x, minor %d: the server refused the ticket", major, minor)
	}
	i.window = mustU32(t, d)
	if _, err := d.Opaque(); err != nil { // the AP-REP
		t.Fatal(err)
	}
	i.handle = handle
	// RFC 2203 §5.2.3.1: the creation reply is verified against the sequence
	// window, which is how a client learns the window it was told is the
	// window the server meant.
	if verf.Flavor != rpcgss.Flavor {
		t.Fatalf("creation reply verifier flavour = %d, want %d", verf.Flavor, rpcgss.Flavor)
	}
	i.verifyServerMIC(t, be32(i.window), verf.Body)
	return i
}

func password() string {
	if p := os.Getenv("KRB5_TEST_PASSWORD"); p != "" {
		return p
	}
	return "alicepw"
}

// server starts an rpc.Server guarded by this package.
func server(t *testing.T, keytabPath string) string {
	t.Helper()
	a, err := krb5.Load(keytabPath)
	if err != nil {
		t.Fatalf("keytab: %v", err)
	}
	srv := &rpc.Server{Auth: rpcgss.New(a)}
	srv.Register(&rpc.Program{Prog: testProg, Vers: testVers, Procs: map[uint32]rpc.Proc{
		1: func(c *rpc.Call) rpc.Status {
			// Echo back who the caller proved itself to be. Under AUTH_UNIX
			// there would be nothing to echo.
			c.Res.String(c.Principal)
			return rpc.StatusSuccess
		},
	}})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

func TestEstablishAndCall(t *testing.T) {
	keytabPath, service := fixture(t)
	i := establish(t, server(t, keytabPath), service)

	i.seq = 1
	cr := i.cred(0 /* DATA */, i.seq, 1)
	header := i.header(1, cr)
	i.send(t, header, rpc.Auth{Flavor: rpcgss.Flavor, Body: i.mic(t, header)}, nil)
	verf, accept, d := i.reply(t)
	if accept != 0 {
		t.Fatalf("accept_stat = %d", accept)
	}
	// RFC 2203 §5.3.3.2: the reply verifier signs the sequence number of the
	// call it answers, not the header and not a constant.
	i.verifyServerMIC(t, be32(i.seq), verf.Body)
	who, err := d.String()
	if err != nil {
		t.Fatal(err)
	}
	if who == "" {
		t.Error("the procedure saw no principal: RPCSEC_GSS authenticated nobody")
	}
	t.Logf("the procedure was called by %s", who)
}

// denied reads a reply expected to be MSG_DENIED and returns its auth_stat.
// It cannot go through reply(), which fails the test on a denial — here the
// denial IS the result.
func (i *initiator) denied(t *testing.T) uint32 {
	t.Helper()
	var frame [4]byte
	if _, err := io.ReadFull(i.conn, frame[:]); err != nil {
		t.Fatal(err)
	}
	n := binary.BigEndian.Uint32(frame[:]) &^ 0x8000_0000
	buf := make([]byte, n)
	if _, err := io.ReadFull(i.conn, buf); err != nil {
		t.Fatal(err)
	}
	d := xdr.NewDecoder(buf)
	mustU32(t, d) // xid
	mustU32(t, d) // REPLY
	if stat := mustU32(t, d); stat != 1 {
		t.Fatalf("reply_stat = %d, want 1 (MSG_DENIED)", stat)
	}
	if why := mustU32(t, d); why != 1 {
		t.Fatalf("reject_stat = %d, want 1 (AUTH_ERROR)", why)
	}
	return mustU32(t, d)
}

// dataCall sends one signed data call.
func (i *initiator) dataCall(t *testing.T, seq, service uint32) {
	t.Helper()
	h := i.header(1, i.cred(0, seq, service))
	i.send(t, h, rpc.Auth{Flavor: rpcgss.Flavor, Body: i.mic(t, h)}, nil)
}

func TestReplayIsRefused(t *testing.T) {
	keytabPath, service := fixture(t)
	i := establish(t, server(t, keytabPath), service)

	i.dataCall(t, 5, 1)
	if _, accept, _ := i.reply(t); accept != 0 {
		t.Fatalf("the first call was not accepted: accept_stat %d", accept)
	}
	// The same sequence number again. The signature is valid — it is the same
	// bytes — so nothing but the window can tell these two apart.
	i.dataCall(t, 5, 1)
	if got := i.denied(t); got != 14 {
		t.Errorf("auth_stat = %d, want 14 (RPCSEC_GSS_CTXPROBLEM)", got)
	}
}

func TestAForgedVerifierIsRefused(t *testing.T) {
	keytabPath, service := fixture(t)
	i := establish(t, server(t, keytabPath), service)

	// A signature over a DIFFERENT header: valid in itself, and attached to
	// a call it does not describe. Accepting it would let a recorded call be
	// re-aimed at another procedure.
	other := i.header(2, i.cred(0, 9, 1))
	h := i.header(1, i.cred(0, 9, 1))
	i.send(t, h, rpc.Auth{Flavor: rpcgss.Flavor, Body: i.mic(t, other)}, nil)
	if got := i.denied(t); got != 4 {
		t.Errorf("auth_stat = %d, want 4 (AUTH_REJECTEDVERF)", got)
	}
}

func TestAnUnknownServiceIsRefusedNotDowngraded(t *testing.T) {
	// Three services are defined and this server implements all three, so
	// the refusal to test is of a number that means nothing. Serving it as
	// svc_none would give a client less protection than it believes it has,
	// which is the one failure a client cannot detect for itself.
	keytabPath, service := fixture(t)
	for _, svc := range []uint32{0, 4, 99} {
		i := establish(t, server(t, keytabPath), service)
		i.dataCall(t, 1, svc)
		if got := i.denied(t); got != 13 {
			t.Errorf("service %d: auth_stat = %d, want 13 (RPCSEC_GSS_CREDPROBLEM)", svc, got)
		}
	}
}

func TestAnUnknownHandleAsksForANewContext(t *testing.T) {
	keytabPath, service := fixture(t)
	i := establish(t, server(t, keytabPath), service)

	i.handle = []byte("not a handle this server minted")[:16]
	i.dataCall(t, 1, 1)
	// CTXPROBLEM and not AUTH_BADCRED: the client must rebuild its context,
	// which is what a server restart requires of it. AUTH_BADCRED would have
	// it give up on a mount that is one exchange from working.
	if got := i.denied(t); got != 14 {
		t.Errorf("auth_stat = %d, want 14 (RPCSEC_GSS_CTXPROBLEM)", got)
	}
}

func TestDestroyEndsTheContext(t *testing.T) {
	keytabPath, service := fixture(t)
	addr := server(t, keytabPath)
	i := establish(t, addr, service)

	h := i.header(0, i.cred(3 /* DESTROY */, 1, 1))
	i.send(t, h, rpc.Auth{Flavor: rpcgss.Flavor, Body: i.mic(t, h)}, nil)
	verf, accept, _ := i.reply(t)
	if accept != 0 {
		t.Fatalf("DESTROY accept_stat = %d", accept)
	}
	// The reply to DESTROY still carries a verifier: a client has to be able
	// to tell a context that was destroyed from a call that was lost.
	i.verifyServerMIC(t, be32(1), verf.Body)

	i.dataCall(t, 2, 1)
	if got := i.denied(t); got != 14 {
		t.Errorf("after DESTROY, auth_stat = %d, want 14 (RPCSEC_GSS_CTXPROBLEM)", got)
	}
}

func TestAnUnsignedCallIsRefused(t *testing.T) {
	keytabPath, service := fixture(t)
	i := establish(t, server(t, keytabPath), service)

	// A null verifier, which is what every AUTH_UNIX call carries. Under
	// RPCSEC_GSS it proves nothing at all.
	h := i.header(1, i.cred(0, 1, 1))
	i.send(t, h, rpc.Auth{}, nil)
	if got := i.denied(t); got != 3 {
		t.Errorf("auth_stat = %d, want 3 (AUTH_BADVERF)", got)
	}
}

// bare opens a connection with no context, for the calls that are refused
// before one could exist.
func bare(t *testing.T, addr string) *initiator {
	t.Helper()
	i := dial(t, addr)
	i.xid = 1
	return i
}

func TestCredentialsRefusedBeforeAnyContext(t *testing.T) {
	keytabPath, _ := fixture(t)
	addr := server(t, keytabPath)
	for _, tc := range []struct {
		name          string
		version, proc uint32
		want          uint32
	}{
		// A version this server does not speak. AUTH_BADCRED, not
		// CTXPROBLEM: rebuilding a context would not change the version.
		{"a version from the future", 2, 1 /* INIT */, 1},
		// Kerberos establishes a context in ONE exchange, so a client
		// continuing one is continuing a context that never started.
		{"continuing a context nobody started", 1, 2 /* CONTINUE_INIT */, 14},
		// A control procedure that does not exist.
		{"an invented control procedure", 1, 9, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			i := bare(t, addr)
			e := xdr.NewEncoder(nil)
			e.Uint32(tc.version)
			e.Uint32(tc.proc)
			e.Uint32(0)
			e.Uint32(1)
			e.Opaque(nil)
			cr := rpc.Auth{Flavor: rpcgss.Flavor, Body: e.Bytes()}
			i.send(t, i.header(0, cr), rpc.Auth{}, func(e *xdr.Encoder) { e.Opaque(nil) })
			if got := i.denied(t); got != tc.want {
				t.Errorf("auth_stat = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestAMalformedCredentialIsRefused(t *testing.T) {
	keytabPath, _ := fixture(t)
	i := bare(t, server(t, keytabPath))
	cr := rpc.Auth{Flavor: rpcgss.Flavor, Body: []byte{0, 0, 0}}
	i.send(t, i.header(0, cr), rpc.Auth{}, nil)
	if got := i.denied(t); got != 1 {
		t.Errorf("auth_stat = %d, want 1 (AUTH_BADCRED)", got)
	}
}

func TestContextCreationTakesANullVerifier(t *testing.T) {
	keytabPath, _ := fixture(t)
	i := bare(t, server(t, keytabPath))
	// There is no context yet, so there is nothing a verifier here could have
	// been signed with. RFC 2203 §5.2.2 requires the null one.
	cr := i.cred(1, 0, 1)
	i.send(t, i.header(0, cr), rpc.Auth{Flavor: rpcgss.Flavor, Body: []byte("not a signature")},
		func(e *xdr.Encoder) { e.Opaque(nil) })
	if got := i.denied(t); got != 3 {
		t.Errorf("auth_stat = %d, want 3 (AUTH_BADVERF)", got)
	}
}

func TestARefusedTicketIsReportedInTheResults(t *testing.T) {
	keytabPath, _ := fixture(t)
	for _, tc := range []struct {
		name  string
		token []byte
		want  uint32
	}{
		// Not a GSS token at all: the client has a bug, and gss_major says so.
		{"bytes that are not a token", []byte("hello"), 0x000A0000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			i := bare(t, server(t, keytabPath))
			cr := i.cred(1, 0, 1)
			i.send(t, i.header(0, cr), rpc.Auth{}, func(e *xdr.Encoder) { e.Opaque(tc.token) })
			// An ACCEPTED reply carrying a failure: RFC 2203 §5.2.3 has the
			// client read gss_major. A denied reply would have told it the
			// credential was malformed rather than that its ticket was refused.
			_, accept, d := i.reply(t)
			if accept != 0 {
				t.Fatalf("accept_stat = %d, want 0", accept)
			}
			d.SetLimit(1 << 16)
			if _, err := d.Opaque(); err != nil {
				t.Fatal(err)
			}
			if major := mustU32(t, d); major != tc.want {
				t.Errorf("gss_major = %#x, want %#x", major, tc.want)
			}
		})
	}
}

func TestInitWithoutATokenIsRefused(t *testing.T) {
	keytabPath, _ := fixture(t)
	i := bare(t, server(t, keytabPath))
	cr := i.cred(1, 0, 1)
	i.send(t, i.header(0, cr), rpc.Auth{}, nil) // no arguments at all
	if got := i.denied(t); got != 1 {
		t.Errorf("auth_stat = %d, want 1 (AUTH_BADCRED)", got)
	}
}

func TestContextsCountsWhatIsHeld(t *testing.T) {
	keytabPath, service := fixture(t)
	a, err := krb5.Load(keytabPath)
	if err != nil {
		t.Fatal(err)
	}
	auth := rpcgss.New(a)
	srv := &rpc.Server{Auth: auth}
	srv.Register(&rpc.Program{Prog: testProg, Vers: testVers, Procs: map[uint32]rpc.Proc{
		1: func(*rpc.Call) rpc.Status { return rpc.StatusSuccess },
	}})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	if n := auth.Contexts(); n != 0 {
		t.Fatalf("a fresh server holds %d contexts", n)
	}
	i := establish(t, ln.Addr().String(), service)
	if n := auth.Contexts(); n != 1 {
		t.Errorf("after one establishment the server holds %d contexts, want 1", n)
	}
	h := i.header(0, i.cred(3, 1, 1))
	i.send(t, h, rpc.Auth{Flavor: rpcgss.Flavor, Body: i.mic(t, h)}, nil)
	i.reply(t)
	if n := auth.Contexts(); n != 0 {
		t.Errorf("after DESTROY the server still holds %d contexts", n)
	}
}

// integWrap builds an rpc_gss_integ_data around args, as a krb5i client does.
func (i *initiator) integWrap(t *testing.T, seq uint32, args func(*xdr.Encoder)) []byte {
	t.Helper()
	body := xdr.NewEncoder(nil)
	body.Uint32(seq)
	if args != nil {
		args(body)
	}
	e := xdr.NewEncoder(nil)
	e.Opaque(body.Bytes())
	e.Opaque(i.mic(t, body.Bytes()))
	return e.Bytes()
}

// integUnwrap opens the reply's envelope and checks its signature.
func (i *initiator) integUnwrap(t *testing.T, seq uint32, d *xdr.Decoder) *xdr.Decoder {
	t.Helper()
	d.SetLimit(1 << 20)
	body, err := d.Opaque()
	if err != nil {
		t.Fatalf("the reply is not an integrity envelope: %v", err)
	}
	mic, err := d.Opaque()
	if err != nil {
		t.Fatal(err)
	}
	var mt gssapi.MICToken
	if err := mt.Unmarshal(mic, true); err != nil {
		t.Fatalf("the reply's checksum does not parse: %v", err)
	}
	mt.Payload = body
	ok, err := mt.Verify(i.key, keyusage.GSSAPI_ACCEPTOR_SIGN)
	if err != nil || !ok {
		t.Fatalf("the reply body is not signed by the server: ok=%v err=%v", ok, err)
	}
	inner := xdr.NewDecoder(body)
	got, err := inner.Uint32()
	if err != nil {
		t.Fatal(err)
	}
	if got != seq {
		t.Errorf("the signed reply body carries seq %d, want %d", got, seq)
	}
	inner.SetLimit(0)
	return inner
}

func TestIntegrityProtectsArgumentsAndResults(t *testing.T) {
	keytabPath, service := fixture(t)
	i := establish(t, server(t, keytabPath), service)

	const seq = 11
	cr := i.cred(0, seq, 2 /* rpc_gss_svc_integrity */)
	h := i.header(1, cr)
	i.send(t, h, rpc.Auth{Flavor: rpcgss.Flavor, Body: i.mic(t, h)}, func(e *xdr.Encoder) {
		e.Fixed(i.integWrap(t, seq, nil))
	})
	verf, accept, d := i.reply(t)
	if accept != 0 {
		t.Fatalf("accept_stat = %d", accept)
	}
	i.verifyServerMIC(t, be32(seq), verf.Body)

	inner := i.integUnwrap(t, seq, d)
	who, err := inner.String()
	if err != nil {
		t.Fatalf("the unwrapped results do not decode: %v", err)
	}
	if who == "" {
		t.Error("the procedure saw no principal")
	}
	t.Logf("sec=krb5i: %s, arguments and results both signed", who)
}

func TestASignedBodyCannotBeMovedOntoAnotherCall(t *testing.T) {
	keytabPath, service := fixture(t)
	i := establish(t, server(t, keytabPath), service)

	// Both signatures are genuine: the verifier signs a header built for
	// sequence 21, and the body was signed for sequence 20. Only comparing
	// the credential's copy against the one inside the body catches it —
	// which is why RFC 2203 puts the number in two places.
	const credSeq, bodySeq = 21, 20
	cr := i.cred(0, credSeq, 2)
	h := i.header(1, cr)
	i.send(t, h, rpc.Auth{Flavor: rpcgss.Flavor, Body: i.mic(t, h)}, func(e *xdr.Encoder) {
		e.Fixed(i.integWrap(t, bodySeq, nil))
	})
	if got := i.denied(t); got != 4 {
		t.Errorf("auth_stat = %d, want 4 (AUTH_REJECTEDVERF)", got)
	}
}

func TestAnAlteredArgumentIsRefused(t *testing.T) {
	keytabPath, service := fixture(t)
	i := establish(t, server(t, keytabPath), service)

	const seq = 31
	cr := i.cred(0, seq, 2)
	h := i.header(1, cr)
	env := i.integWrap(t, seq, func(e *xdr.Encoder) { e.Uint32(0xDEADBEEF) })
	// Flip one bit of the signed body. Under sec=krb5 this call would have
	// been served: the header signature is untouched, and only integrity
	// covers what the arguments say.
	env[len(env)-1] ^= 1
	i.send(t, h, rpc.Auth{Flavor: rpcgss.Flavor, Body: i.mic(t, h)}, func(e *xdr.Encoder) {
		e.Fixed(env)
	})
	if got := i.denied(t); got != 4 {
		t.Errorf("auth_stat = %d, want 4 (AUTH_REJECTEDVERF)", got)
	}
}

// sealAsInitiator produces what a krb5p client sends: GSS_Wrap with
// confidentiality over the sequence number and the real arguments. gokrb5
// cannot do this, so the token is built here from the same primitives
// go-authn/krb5 uses on the other side.
func (i *initiator) sealAsInitiator(t *testing.T, seq uint32, args func(*xdr.Encoder)) []byte {
	t.Helper()
	body := xdr.NewEncoder(nil)
	body.Uint32(seq)
	if args != nil {
		args(body)
	}
	hdr := make([]byte, 16)
	hdr[0], hdr[1] = 0x05, 0x04
	hdr[2] = 0x02 // Sealed, sent by the initiator
	hdr[3] = 0xFF
	plain := append(append([]byte{}, body.Bytes()...), hdr...)

	et, err := crypto.GetEtype(i.key.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	_, cipher, err := et.EncryptMessage(i.key.KeyValue, plain, keyusage.GSSAPI_INITIATOR_SEAL)
	if err != nil {
		t.Fatal(err)
	}
	e := xdr.NewEncoder(nil)
	e.Opaque(append(hdr, cipher...))
	return e.Bytes()
}

// openAsInitiator opens what a krb5p server sends back.
func (i *initiator) openAsInitiator(t *testing.T, seq uint32, d *xdr.Decoder) *xdr.Decoder {
	t.Helper()
	d.SetLimit(1 << 20)
	sealed, err := d.Opaque()
	if err != nil {
		t.Fatalf("the reply is not a privacy envelope: %v", err)
	}
	if len(sealed) < 16 {
		t.Fatalf("the sealed reply is %d bytes", len(sealed))
	}
	if sealed[2]&0x02 == 0 {
		t.Fatalf("the reply is NOT sealed: flags %#x", sealed[2])
	}
	et, err := crypto.GetEtype(i.key.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := et.DecryptMessage(i.key.KeyValue, sealed[16:], keyusage.GSSAPI_ACCEPTOR_SEAL)
	if err != nil {
		t.Fatalf("the reply does not decrypt: %v", err)
	}
	inner := xdr.NewDecoder(plain[:len(plain)-16])
	got, err := inner.Uint32()
	if err != nil {
		t.Fatal(err)
	}
	if got != seq {
		t.Errorf("the sealed reply carries seq %d, want %d", got, seq)
	}
	inner.SetLimit(0)
	return inner
}

func TestPrivacyEncryptsArgumentsAndResults(t *testing.T) {
	keytabPath, service := fixture(t)
	i := establish(t, server(t, keytabPath), service)

	const seq = 51
	cr := i.cred(0, seq, 3 /* rpc_gss_svc_privacy */)
	h := i.header(1, cr)
	i.send(t, h, rpc.Auth{Flavor: rpcgss.Flavor, Body: i.mic(t, h)}, func(e *xdr.Encoder) {
		e.Fixed(i.sealAsInitiator(t, seq, nil))
	})
	verf, accept, d := i.reply(t)
	if accept != 0 {
		t.Fatalf("accept_stat = %d", accept)
	}
	i.verifyServerMIC(t, be32(seq), verf.Body)

	inner := i.openAsInitiator(t, seq, d)
	who, err := inner.String()
	if err != nil {
		t.Fatalf("the decrypted results do not decode: %v", err)
	}
	if who == "" {
		t.Error("the procedure saw no principal")
	}
	t.Logf("sec=krb5p: %s, arguments and results both encrypted", who)
}

func TestASealedBodyCannotBeMovedOntoAnotherCall(t *testing.T) {
	keytabPath, service := fixture(t)
	i := establish(t, server(t, keytabPath), service)

	// Encryption does not make a body harder to move: both the header
	// signature and the sealed body are genuine, and only the two copies of
	// the sequence number disagree.
	const credSeq, bodySeq = 61, 60
	cr := i.cred(0, credSeq, 3)
	h := i.header(1, cr)
	i.send(t, h, rpc.Auth{Flavor: rpcgss.Flavor, Body: i.mic(t, h)}, func(e *xdr.Encoder) {
		e.Fixed(i.sealAsInitiator(t, bodySeq, nil))
	})
	if got := i.denied(t); got != 4 {
		t.Errorf("auth_stat = %d, want 4 (AUTH_REJECTEDVERF)", got)
	}
}

func TestAnUnsealedBodyIsRefusedUnderPrivacy(t *testing.T) {
	// The client asked for privacy and then sent something readable. Serving
	// it would mean the flavour promised confidentiality and delivered none,
	// which is the one failure a client cannot detect for itself.
	keytabPath, service := fixture(t)
	i := establish(t, server(t, keytabPath), service)

	const seq = 71
	cr := i.cred(0, seq, 3)
	h := i.header(1, cr)
	i.send(t, h, rpc.Auth{Flavor: rpcgss.Flavor, Body: i.mic(t, h)}, func(e *xdr.Encoder) {
		e.Fixed(i.integWrap(t, seq, nil)) // an INTEGRITY envelope, in the clear
	})
	if got := i.denied(t); got != 4 {
		t.Errorf("auth_stat = %d, want 4 (AUTH_REJECTEDVERF)", got)
	}
}
