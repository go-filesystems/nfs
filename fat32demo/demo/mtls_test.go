package demo_test

import (
	"bytes"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-filesystems/nfs"
	"github.com/go-filesystems/nfs/fat32demo/demo"
	"github.com/go-filesystems/nfs/xdr"
)

// TestClientCertificateOptions: the options that make the live-mount-mtls
// lane possible each say what they did, and each one that cannot do it stops
// the server rather than serving with less protection than was asked for.
func TestClientCertificateOptions(t *testing.T) {
	path, _ := makeImage(t)
	certPath, keyPath := writeCert(t)

	for _, tc := range []struct {
		name string
		opts []demo.Option
	}{
		{"-require-tls without a certificate", []demo.Option{demo.RequireTLS()}},
		{"-tls-client-ca without a certificate", []demo.Option{demo.ClientCA(certPath)}},
		{"an unreadable CA", []demo.Option{demo.TLS(certPath, keyPath), demo.ClientCA(filepath.Join(t.TempDir(), "absent.pem"))}},
		{"a CA file with no certificate", []demo.Option{demo.TLS(certPath, keyPath), demo.ClientCA(keyPath)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if _, _, err := demo.SetupOpts(path, "127.0.0.1:0", false, false, &out, tc.opts...); err == nil {
				t.Fatal("accepted")
			}
		})
	}

	t.Run("all of them, announced", func(t *testing.T) {
		var out bytes.Buffer
		srv, ln, err := demo.SetupOpts(path, "127.0.0.1:0", false, false, &out,
			demo.TLS(certPath, keyPath), demo.ClientCA(certPath), demo.RequireTLS(),
			demo.Allow("alice@example.org", "carol@example.org"))
		if err != nil {
			t.Fatalf("SetupOpts: %v", err)
		}
		defer srv.Close()
		defer ln.Close()
		for _, want := range []string{
			"TLS REQUIRED",
			"export restricted to alice@example.org, carol@example.org",
			"client certificates verified against " + certPath,
		} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("missing %q in:\n%s", want, out.String())
			}
		}
	})

	t.Run("-allow refuses a caller it does not name", func(t *testing.T) {
		var out bytes.Buffer
		srv, ln, err := demo.SetupOpts(path, "127.0.0.1:0", false, false, &out, demo.Allow("alice@example.org"))
		if err != nil {
			t.Fatalf("SetupOpts: %v", err)
		}
		t.Cleanup(func() { srv.Close() })
		go srv.Serve(ln)
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		c.SetDeadline(time.Now().Add(time.Minute))
		w := &client{t: t, conn: c}
		root := w.mustCall(nfs.ProgramMount, nfs.VersionMount, 1, func(e *xdr.Encoder) { e.String("/") })
		if st := w.u32(root); st != 0 {
			t.Fatalf("MNT = %d", st)
		}
		fh, err := root.Opaque()
		if err != nil {
			t.Fatal(err)
		}
		// Nobody proved anything in the clear, so the principal is empty
		// and not on the list.
		res := w.mustCall(nfs.ProgramNFS, nfs.VersionNFS, 1, func(e *xdr.Encoder) { e.Opaque(fh) })
		if st := w.u32(res); st != uint32(nfs.StatusAccess) {
			t.Errorf("GETATTR by nobody = %d, want NFS3ERR_ACCES", st)
		}
	})

	t.Run("Main passes the flags through", func(t *testing.T) {
		var out, errOut bytes.Buffer
		rc := demo.Main([]string{"-image", path, "-require-tls", "-tls-client-ca", certPath,
			"-allow", "alice@example.org,bob@example.org"}, &out, &errOut)
		if rc != 1 || !strings.Contains(errOut.String(), "need -tls-cert") {
			t.Fatalf("Main = %d, %q", rc, errOut.String())
		}
	})
}
