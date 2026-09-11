package rpcgss

import (
	"testing"

	"github.com/go-filesystems/nfs/xdr"
)

func credBytes(t *testing.T, version, proc, seq, service uint32, handle []byte) []byte {
	t.Helper()
	e := xdr.NewEncoder(nil)
	e.Uint32(version)
	e.Uint32(proc)
	e.Uint32(seq)
	e.Uint32(service)
	e.Opaque(handle)
	return e.Bytes()
}

func TestParseCred(t *testing.T) {
	got, err := parseCred(credBytes(t, 1, procData, 7, svcNone, []byte("abcd")))
	if err != nil {
		t.Fatalf("parseCred: %v", err)
	}
	want := cred{version: 1, proc: procData, seq: 7, service: svcNone}
	if got.version != want.version || got.proc != want.proc ||
		got.seq != want.seq || got.service != want.service {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if string(got.handle) != "abcd" {
		t.Errorf("handle = %q, want %q", got.handle, "abcd")
	}
}

func TestParseCredRefusesTrailingBytes(t *testing.T) {
	// A fixed-shape structure with bytes left over means the client and this
	// decoder disagree about the shape. Accepting the prefix would
	// authenticate something other than what was sent.
	b := append(credBytes(t, 1, procData, 7, svcNone, nil), 0, 0, 0, 0)
	if _, err := parseCred(b); err == nil {
		t.Error("trailing bytes accepted")
	}
}

func TestParseCredRefusesTruncation(t *testing.T) {
	full := credBytes(t, 1, procInit, 1, svcNone, []byte("xy"))
	for n := range len(full) {
		if _, err := parseCred(full[:n]); err == nil {
			t.Errorf("a credential cut to %d bytes was accepted", n)
		}
	}
}

func TestParseCredRefusesAnOversizedHandle(t *testing.T) {
	big := make([]byte, maxHandle+4)
	if _, err := parseCred(credBytes(t, 1, procData, 1, svcNone, big)); err == nil {
		t.Error("an oversized handle was accepted")
	}
}
