package nfs

import (
	"errors"
	"math"
	"testing"
	"time"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/nfs/xdr"
)

func TestNFSTime3(t *testing.T) {
	for _, tc := range []struct {
		name      string
		ts        filesystem.Timestamp
		sec, nsec uint32
		ok        bool
	}{
		{"not recorded", filesystem.Timestamp{}, 0, 0, false},
		{"normal", filesystem.NewTimestamp(time.Unix(1234567890, 123456789), time.Nanosecond), 1234567890, 123456789, true},
		{"before 1970 clamps to 0", filesystem.NewTimestamp(time.Date(1960, 1, 1, 0, 0, 0, 5, time.UTC), time.Second), 0, 0, true},
		{"past 2106 clamps", filesystem.NewTimestamp(time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC), time.Second), math.MaxUint32, 0, true},
	} {
		sec, nsec, ok := nfstime3(tc.ts)
		if sec != tc.sec || nsec != tc.nsec || ok != tc.ok {
			t.Errorf("%s: got %d.%09d %v", tc.name, sec, nsec, ok)
		}
	}
}

func TestSetTimesFallbacks(t *testing.T) {
	m := filesystem.NewTimestamp(time.Unix(1000, 7), time.Nanosecond)
	at := filesystem.NewTimestamp(time.Unix(900, 0), 24*time.Hour)
	ct := filesystem.NewTimestamp(time.Unix(1100, 9), time.Nanosecond)

	var a fattr
	a.setTimes(filesystem.FileTimes{Mtime: m, Atime: at, Ctime: ct}, 55)
	if a.mtime != 1000 || a.mtimeNs != 7 || a.atime != 900 || a.ctime != 1100 || a.ctimeNs != 9 {
		t.Errorf("all recorded: %+v", a)
	}

	// FAT: no ctime. ctime is the mtime, atime is its own date.
	a = fattr{}
	a.setTimes(filesystem.FileTimes{Mtime: m, Atime: at}, 55)
	if a.ctime != 1000 || a.ctimeNs != 7 || a.atime != 900 {
		t.Errorf("no ctime: %+v", a)
	}

	// Only mtime: atime and ctime follow it.
	a = fattr{}
	a.setTimes(filesystem.FileTimes{Mtime: m}, 55)
	if a.atime != 1000 || a.ctime != 1000 {
		t.Errorf("only mtime: %+v", a)
	}

	// Nothing recorded: the server's start time, never 1970.
	a = fattr{}
	a.setTimes(filesystem.FileTimes{}, 55)
	if a.mtime != 55 || a.atime != 55 || a.ctime != 55 || a.mtimeNs != 0 {
		t.Errorf("none: %+v", a)
	}
}

type tfs struct {
	nopFS
	ft  filesystem.FileTimes
	err error
}

func (f tfs) Stat(string) (filesystem.Stat, error) {
	return filesystem.NewStat(sIFREG|0o644, 3, 9), nil
}
func (f tfs) Times(string) (filesystem.FileTimes, error) { return f.ft, f.err }

func TestAttrUsesTimesReader(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	ft := filesystem.FileTimes{Mtime: filesystem.NewTimestamp(time.Unix(1234567890, 500), time.Nanosecond)}
	if err := s.Export("/", tfs{ft: ft}); err != nil {
		t.Fatal(err)
	}
	a, st := s.attrFor(s.byPath["/"], "/f")
	if st != StatusOK || a.mtime != 1234567890 || a.mtimeNs != 500 {
		t.Fatalf("attr = %+v, %v", a, st)
	}
	// On the wire: atime, mtime, ctime each as seconds then nanoseconds.
	e := xdr.NewEncoder(nil)
	a.encode(e)
	b := e.Bytes()
	tail := b[len(b)-24:]
	be := func(o int) uint32 {
		return uint32(tail[o])<<24 | uint32(tail[o+1])<<16 | uint32(tail[o+2])<<8 | uint32(tail[o+3])
	}
	if be(8) != 1234567890 || be(12) != 500 {
		t.Errorf("encoded mtime = %d.%d", be(8), be(12))
	}
}

func TestAttrTimesErrorFallsBack(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Export("/", tfs{err: errors.New("boom")}); err != nil {
		t.Fatal(err)
	}
	a, st := s.attrFor(s.byPath["/"], "/f")
	if st != StatusOK || a.mtime != s.start {
		t.Fatalf("attr = %+v, %v; want the server's start time", a, st)
	}
}
