package nfs

import (
	"testing"

	"github.com/go-filesystems/nfs/rpc"
	"github.com/go-filesystems/nfs/xdr"
)

// A restricted export is the thing NFSv3 could not do until a credential
// carried a name. These tests are about the two answers it now gives, and
// about the one that must be given when nobody configured Kerberos at all.

// callFor builds a Call as the dispatcher would, with a principal on it.
func callFor(t *testing.T, principal string, handle []byte) *rpc.Call {
	t.Helper()
	e := xdr.NewEncoder(nil)
	e.Opaque(handle)
	return &rpc.Call{Principal: principal, Args: xdr.NewDecoder(e.Bytes()), Res: xdr.NewEncoder(nil)}
}

func TestAnUnauthenticatedCallerIsRefusedARestrictedExport(t *testing.T) {
	// ⛔ The important default. A predicate that refuses the empty principal
	// refuses everybody when no authenticator is configured, so a server that
	// forgot to set one serves NOTHING rather than serving everything.
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Export("/private", nopFS{}, AllowPrincipal(func(p string) (bool, bool) {
		return p == "alice@REALM", p == "alice@REALM"
	})); err != nil {
		t.Fatal(err)
	}
	h, err := s.handles.Handle(1, "/")
	if err != nil {
		t.Fatal(err)
	}

	e, _, st, garbage := s.fhArg(callFor(t, "", h))
	if garbage {
		t.Fatal("the handle did not decode")
	}
	if st != StatusAccess {
		t.Errorf("an unauthenticated caller got %v, want NFS3ERR_ACCES", st)
	}
	if e != nil {
		t.Error("a refused caller was handed the export anyway")
	}

	// And the person it is for gets through.
	e, _, st, _ = s.fhArg(callFor(t, "alice@REALM", h))
	if st != StatusOK || e == nil {
		t.Errorf("alice got %v", st)
	}
}

func TestReadingAndWritingAreSeparateAnswers(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	// bob may look and not touch; alice may do both. The export itself is
	// writable, so anything refused here is refused because of WHO is asking.
	if err := s.Export("/shared", nopFS{}, ReadWrite(), AllowPrincipal(func(p string) (bool, bool) {
		switch p {
		case "alice@REALM":
			return true, true
		case "bob@REALM":
			return true, false
		}
		return false, false
	})); err != nil {
		t.Fatal(err)
	}
	e := s.exportByPath("/shared")
	if e == nil {
		t.Fatal("no export")
	}
	for _, tc := range []struct {
		who         string
		read, write bool
	}{
		{"alice@REALM", true, true},
		{"bob@REALM", true, false},
		{"mallory@REALM", false, false},
		{"", false, false},
	} {
		r, _ := e.allow(tc.who)
		if r != tc.read {
			t.Errorf("%s may read = %v, want %v", tc.who, r, tc.read)
		}
		if got := s.mayWrite(&rpc.Call{Principal: tc.who}, e); got != tc.write {
			t.Errorf("%s may write = %v, want %v", tc.who, got, tc.write)
		}
	}
}

func TestAReadOnlyExportRefusesEverybodysWrites(t *testing.T) {
	// The two gates are not the same question: ro is a property of the IMAGE,
	// the predicate is a property of the CALLER. A share served read-only
	// refuses a writer the predicate would have allowed.
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Export("/ro", nopFS{}, AllowPrincipal(func(string) (bool, bool) {
		return true, true
	})); err != nil {
		t.Fatal(err)
	}
	e := s.exportByPath("/ro")
	if s.mayWrite(&rpc.Call{Principal: "alice@REALM"}, e) {
		t.Error("a read-only export accepted a write because the caller was allowed")
	}
}

func TestAnExportWithNoPredicateIsUnchanged(t *testing.T) {
	// Every existing caller must keep working: no predicate means the export
	// answers as it always did, to a principal or to nobody.
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Export("/open", nopFS{}, ReadWrite()); err != nil {
		t.Fatal(err)
	}
	e := s.exportByPath("/open")
	for _, who := range []string{"", "alice@REALM"} {
		if !s.mayWrite(&rpc.Call{Principal: who}, e) {
			t.Errorf("%q could not write an unrestricted read-write export", who)
		}
	}
}
