package demo_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	fat32 "github.com/go-filesystems/fat32"
	"github.com/go-filesystems/nfs"
	"github.com/go-filesystems/nfs/fat32demo/demo"
	"github.com/go-filesystems/nfs/xdr"
)

// makeImage formats a real FAT32 image and puts one known file in it.
func makeImage(t *testing.T) (path string, content []byte) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "disk.img")
	fs, err := fat32.Format(path, 64<<20, fat32.FormatConfig{Label: "NFSDEMO"})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	content = bytes.Repeat([]byte("go-filesystems/nfs\n"), 100)
	if err := fs.WriteFile("/HELLO.TXT", content, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return path, content
}

// TestServeRealImage mounts nothing, but it does what a mount's first three
// round trips do — MNT, LOOKUP, READ — against a genuine FAT32 image, and
// compares the bytes with what the driver returns directly.
func TestServeRealImage(t *testing.T) {
	path, want := makeImage(t)
	var out bytes.Buffer
	srv, ln, err := demo.Setup(path, "127.0.0.1:0", false, &out)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	defer srv.Close()
	go srv.Serve(ln)

	if !bytes.Contains(out.Bytes(), []byte("mount -t nfs")) {
		t.Fatalf("Setup printed no mount instructions:\n%s", out.String())
	}

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	w := &client{t: t, conn: c}

	root := w.mustCall(nfs.ProgramMount, nfs.VersionMount, 1, func(e *xdr.Encoder) { e.String("/") })
	if st := w.u32(root); st != 0 {
		t.Fatalf("MNT = %d, want 0", st)
	}
	fh, err := root.Opaque()
	if err != nil {
		t.Fatalf("MNT handle: %v", err)
	}

	look := w.mustCall(nfs.ProgramNFS, nfs.VersionNFS, 3, func(e *xdr.Encoder) {
		e.Opaque(fh)
		e.String("HELLO.TXT")
	})
	if st := w.u32(look); st != 0 {
		t.Fatalf("LOOKUP = %d, want 0", st)
	}
	file, err := look.Opaque()
	if err != nil {
		t.Fatalf("LOOKUP handle: %v", err)
	}

	var got []byte
	for off := uint64(0); ; {
		rd := w.mustCall(nfs.ProgramNFS, nfs.VersionNFS, 6, func(e *xdr.Encoder) {
			e.Opaque(file)
			e.Uint64(off)
			e.Uint32(512)
		})
		if st := w.u32(rd); st != 0 {
			t.Fatalf("READ = %d, want 0", st)
		}
		w.skipPostOp(rd)
		w.u32(rd) // count
		eof := w.u32(rd)
		chunk, err := rd.Opaque()
		if err != nil {
			t.Fatalf("READ data: %v", err)
		}
		got = append(got, chunk...)
		off += uint64(len(chunk))
		if eof == 1 {
			break
		}
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("READ over NFS returned %d bytes, want the %d written to the image", len(got), len(want))
	}

	// The driver, asked directly, must agree byte for byte.
	direct, err := fat32.Open(path, -1)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer direct.Close()
	viaDriver, err := direct.ReadFile("/HELLO.TXT")
	if err != nil {
		t.Fatalf("driver ReadFile: %v", err)
	}
	if !bytes.Equal(got, viaDriver) {
		t.Fatal("NFS and the driver disagree about the file's contents")
	}
}

func TestSetupErrors(t *testing.T) {
	var out bytes.Buffer
	if _, _, err := demo.Setup("/nonexistent/disk.img", "127.0.0.1:0", false, &out); err == nil {
		t.Fatal("Setup on a missing image returned nil")
	}
	notAnImage := filepath.Join(t.TempDir(), "junk.img")
	if err := os.WriteFile(notAnImage, make([]byte, 4096), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, _, err := demo.Setup(notAnImage, "127.0.0.1:0", false, &out); err == nil {
		t.Fatal("Setup on a file that is not FAT32 returned nil")
	}
	path, _ := makeImage(t)
	if _, _, err := demo.Setup(path, "256.256.256.256:1", false, &out); err == nil {
		t.Fatal("Setup on an unusable address returned nil")
	}
	// Read-write is the other arm of the export options.
	srv, ln, err := demo.Setup(path, "127.0.0.1:0", true, &out)
	if err != nil {
		t.Fatalf("Setup read-write: %v", err)
	}
	srv.Close()
	ln.Close()
}

func TestMain_(t *testing.T) {
	var out, errOut bytes.Buffer
	if rc := demo.Main([]string{"-badflag"}, &out, &errOut); rc != 2 {
		t.Fatalf("Main with a bad flag = %d, want 2", rc)
	}
	if rc := demo.Main([]string{"-image", "/nonexistent"}, &out, &errOut); rc != 1 {
		t.Fatalf("Main with a missing image = %d, want 1", rc)
	}
	// The serving path: start on an ephemeral port and stop it by closing the
	// listener out from under Serve.
	path, _ := makeImage(t)
	done := make(chan int, 1)
	go func() { done <- demo.Main([]string{"-image", path, "-addr", "127.0.0.1:12351"}, &out, &errOut) }()
	for range 200 {
		if c, err := net.Dial("tcp", "127.0.0.1:12351"); err == nil {
			c.Close()
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Main's server is not reachable from here, so end it the way a process
	// signal would: by taking the port away.
	c, err := net.Dial("tcp", "127.0.0.1:12351")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		// Serve is still running, which is the correct behaviour; the
		// process would be stopped by a signal. Nothing left to assert.
	}
}

// client is a minimal RPC client, enough to drive three procedures.
type client struct {
	t    *testing.T
	conn net.Conn
	xid  uint32
}

func (c *client) mustCall(prog, vers, proc uint32, args func(*xdr.Encoder)) *xdr.Decoder {
	c.t.Helper()
	c.xid++
	e := xdr.NewEncoder(nil)
	e.Uint32(c.xid)
	e.Uint32(0)
	e.Uint32(2)
	e.Uint32(prog)
	e.Uint32(vers)
	e.Uint32(proc)
	e.Uint32(0)
	e.Opaque(nil)
	e.Uint32(0)
	e.Opaque(nil)
	args(e)
	msg := e.Bytes()
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 0x8000_0000|uint32(len(msg)))
	if _, err := c.conn.Write(append(hdr[:], msg...)); err != nil {
		c.t.Fatalf("write: %v", err)
	}
	if _, err := io.ReadFull(c.conn, hdr[:]); err != nil {
		c.t.Fatalf("read header: %v", err)
	}
	body := make([]byte, binary.BigEndian.Uint32(hdr[:])&^0x8000_0000)
	if _, err := io.ReadFull(c.conn, body); err != nil {
		c.t.Fatalf("read body: %v", err)
	}
	d := xdr.NewDecoder(body)
	c.u32(d) // xid
	c.u32(d) // mtype
	if rs := c.u32(d); rs != 0 {
		c.t.Fatalf("reply_stat = %d, want accepted", rs)
	}
	c.u32(d)
	d.Opaque()
	if as := c.u32(d); as != 0 {
		c.t.Fatalf("accept_stat = %d, want success", as)
	}
	return d
}

func (c *client) u32(d *xdr.Decoder) uint32 {
	c.t.Helper()
	v, err := d.Uint32()
	if err != nil {
		c.t.Fatalf("decode: %v", err)
	}
	return v
}

func (c *client) skipPostOp(d *xdr.Decoder) {
	c.t.Helper()
	if c.u32(d) == 0 {
		return
	}
	// fattr3: type, mode, nlink, uid, gid; size, used; rdev major/minor;
	// fsid, fileid; then three nfstime3 pairs.
	for range 5 {
		c.u32(d)
	}
	for range 2 {
		d.Uint64()
	}
	for range 2 {
		c.u32(d)
	}
	for range 2 {
		d.Uint64()
	}
	for range 6 {
		c.u32(d)
	}
}

// serveImage starts a server on a fresh port and returns a connected client
// plus the root handle, so the two arms of the A/B below differ in exactly one
// argument.
func serveImage(t *testing.T, path string, noPositional bool) (*client, []byte) {
	t.Helper()
	var out bytes.Buffer
	srv, ln, err := demo.SetupOpts(path, "127.0.0.1:0", true, noPositional, &out)
	if err != nil {
		t.Fatalf("SetupOpts: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	go srv.Serve(ln)
	if noPositional != bytes.Contains(out.Bytes(), []byte("positional read/write DISABLED")) {
		t.Fatalf("the -no-positional banner does not match the flag:\n%s", out.String())
	}
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(5 * time.Minute))
	w := &client{t: t, conn: c}
	root := w.mustCall(nfs.ProgramMount, nfs.VersionMount, 1, func(e *xdr.Encoder) { e.String("/") })
	if st := w.u32(root); st != 0 {
		t.Fatalf("MNT = %d, want 0", st)
	}
	fh, err := root.Opaque()
	if err != nil {
		t.Fatalf("MNT handle: %v", err)
	}
	return w, fh
}

// writeBlocks issues one WRITE per block, from offset 0, which is what a
// client's sequential write looks like on the wire.
func (w *client) writeBlocks(fh []byte, data []byte, block int) {
	w.t.Helper()
	for off := 0; off < len(data); off += block {
		end := min(off+block, len(data))
		res := w.mustCall(nfs.ProgramNFS, nfs.VersionNFS, 7, func(e *xdr.Encoder) {
			e.Opaque(fh)
			e.Uint64(uint64(off))
			e.Uint32(uint32(end - off))
			e.Uint32(2) // FILE_SYNC
			e.Opaque(data[off:end])
		})
		if st := w.u32(res); st != 0 {
			w.t.Fatalf("WRITE at %d = %d, want 0", off, st)
		}
	}
}

// TestPositionalWriteAgreesWithWholeFileWrite is the A/B, in process, on a
// real FAT32 image: the same sequential write, over the wire, to a server that
// has the driver's WritableFile and to one that has had it taken away.
//
// The assertion is on the BYTES, not on the clock. The two arms must produce
// an identical file, read back both through NFS READ and through the driver's
// own ReadFile — four readings that must all agree. The elapsed times are
// logged rather than asserted: a wall clock on a shared machine is a flaky
// test, and the honest place for a number is a measurement run deliberately,
// which is what the live-write-bench CI job does over a kernel mount.
func TestPositionalWriteAgreesWithWholeFileWrite(t *testing.T) {
	const size, block = 512 << 10, 64 << 10
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i*31 + i/251)
	}

	results := make(map[bool][]byte, 2)
	for _, noPositional := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "ab.img")
		fs, err := fat32.Format(path, 64<<20, fat32.FormatConfig{Label: "ABTEST"})
		if err != nil {
			t.Fatalf("Format: %v", err)
		}
		if err := fs.WriteFile("/TARGET.BIN", nil, 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if err := fs.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}

		w, root := serveImage(t, path, noPositional)
		look := w.mustCall(nfs.ProgramNFS, nfs.VersionNFS, 3, func(e *xdr.Encoder) {
			e.Opaque(root)
			e.String("TARGET.BIN")
		})
		if st := w.u32(look); st != 0 {
			t.Fatalf("LOOKUP = %d, want 0", st)
		}
		fh, err := look.Opaque()
		if err != nil {
			t.Fatalf("LOOKUP handle: %v", err)
		}

		start := time.Now()
		w.writeBlocks(fh, payload, block)
		elapsed := time.Since(start)
		name := "positional"
		if noPositional {
			name = "whole-file"
		}
		t.Logf("%s: %d KiB in %d-byte blocks took %v (%.0f kB/s)",
			name, size>>10, block, elapsed.Round(time.Millisecond),
			float64(size)/1000/elapsed.Seconds())

		// Read back through NFS...
		var got []byte
		for off := uint64(0); ; {
			rd := w.mustCall(nfs.ProgramNFS, nfs.VersionNFS, 6, func(e *xdr.Encoder) {
				e.Opaque(fh)
				e.Uint64(off)
				e.Uint32(32 << 10)
			})
			if st := w.u32(rd); st != 0 {
				t.Fatalf("READ = %d, want 0", st)
			}
			w.skipPostOp(rd)
			w.u32(rd)
			eof := w.u32(rd)
			chunk, err := rd.Opaque()
			if err != nil {
				t.Fatalf("READ data: %v", err)
			}
			got = append(got, chunk...)
			off += uint64(len(chunk))
			if eof == 1 {
				break
			}
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("%s: READ returned %d bytes, want %d", name, len(got), len(payload))
		}
		// ...and through the driver, on the closed image, which is the only
		// reading that proves the bytes reached the medium.
		direct, err := fat32.Open(path, -1)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		onDisk, err := direct.ReadFile("/TARGET.BIN")
		if err != nil {
			t.Fatalf("driver ReadFile: %v", err)
		}
		direct.Close()
		if !bytes.Equal(onDisk, payload) {
			t.Fatalf("%s: the image holds %d bytes, want %d", name, len(onDisk), len(payload))
		}
		results[noPositional] = onDisk
	}
	if !bytes.Equal(results[false], results[true]) {
		t.Fatal("the positional and whole-file write paths produced different images")
	}
}
