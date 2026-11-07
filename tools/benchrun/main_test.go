package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseLine(t *testing.T) {
	s, ok := parseLine("BenchmarkRead/lat=100µs/conns=4-16   \t 200\t 33924 ns/op\t3863.65 MB/s\t  160924 B/op\t      37 allocs/op")
	if !ok || s.cell != "lat=100µs/conns=4" || s.mbps != 3863.65 || s.allocs != 37 {
		t.Fatalf("got %+v ok=%v", s, ok)
	}
	for _, bad := range []string{"PASS", "BenchmarkOther/x-4 1 2 ns/op", "BenchmarkRead/x-4 1 2 ns/op"} {
		if _, ok := parseLine(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestMedian(t *testing.T) {
	if got := median([]float64{3, 1, 2}); got != 2 {
		t.Errorf("odd median = %v", got)
	}
	if got := median([]float64{4, 1, 2, 3}); got != 2.5 {
		t.Errorf("even median = %v", got)
	}
	if median(nil) != 0 {
		t.Error("empty median")
	}
}

func TestRunRefusesBadArguments(t *testing.T) {
	for _, args := range [][]string{nil, {"nocolon"}, {"-rounds"}, {"-rounds", "x", "a:b"}} {
		var o, e bytes.Buffer
		if code := run(args, &o, &e); code != 2 {
			t.Errorf("run(%v) = %d, want 2", args, code)
		}
	}
}

func TestRunRefusesUnderLoad(t *testing.T) {
	var o, e bytes.Buffer
	if code := run([]string{"-maxload", "0", "/nonexistent:default"}, &o, &e); code != 3 || !strings.Contains(e.String(), "skipped") {
		t.Fatalf("code %d, stderr %q", code, e.String())
	}
}

func TestRunReportsAMissingBinary(t *testing.T) {
	var o, e bytes.Buffer
	if code := run([]string{"-maxload", "1000", "/nonexistent:default"}, &o, &e); code != 1 {
		t.Fatalf("code %d", code)
	}
}
