package xdr

import (
	"bytes"
	"errors"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	e := NewEncoder(nil)
	e.Uint32(0xdeadbeef)
	e.Uint64(0x0123456789abcdef)
	e.Int32(-7)
	e.Bool(true)
	e.Bool(false)
	e.Fixed([]byte{1, 2, 3})  // padded to 4
	e.Opaque([]byte("hello")) // 4 + 5 + 3 pad
	e.String("nfs")

	d := NewDecoder(e.Bytes())
	if v, err := d.Uint32(); err != nil || v != 0xdeadbeef {
		t.Fatalf("Uint32 = (%#x, %v)", v, err)
	}
	if v, err := d.Uint64(); err != nil || v != 0x0123456789abcdef {
		t.Fatalf("Uint64 = (%#x, %v)", v, err)
	}
	if v, err := d.Int32(); err != nil || v != -7 {
		t.Fatalf("Int32 = (%d, %v)", v, err)
	}
	if v, err := d.Bool(); err != nil || !v {
		t.Fatalf("Bool = (%v, %v)", v, err)
	}
	if v, err := d.Bool(); err != nil || v {
		t.Fatalf("Bool = (%v, %v)", v, err)
	}
	if v, err := d.Fixed(3); err != nil || !bytes.Equal(v, []byte{1, 2, 3}) {
		t.Fatalf("Fixed = (%v, %v)", v, err)
	}
	if v, err := d.Opaque(); err != nil || string(v) != "hello" {
		t.Fatalf("Opaque = (%q, %v)", v, err)
	}
	if v, err := d.String(); err != nil || v != "nfs" {
		t.Fatalf("String = (%q, %v)", v, err)
	}
	if d.Remaining() != 0 {
		t.Fatalf("%d bytes left over after decoding everything", d.Remaining())
	}
}

// TestAlignment pins the wire layout itself: every item must land on a 4-byte
// boundary with zero padding, which is the property a peer's decoder relies
// on and the one a hand-rolled encoder is most likely to get wrong.
func TestAlignment(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []byte
	}{
		{"", []byte{0, 0, 0, 0}},
		{"a", []byte{0, 0, 0, 1, 'a', 0, 0, 0}},
		{"ab", []byte{0, 0, 0, 2, 'a', 'b', 0, 0}},
		{"abc", []byte{0, 0, 0, 3, 'a', 'b', 'c', 0}},
		{"abcd", []byte{0, 0, 0, 4, 'a', 'b', 'c', 'd'}},
	} {
		e := NewEncoder(nil)
		e.String(tc.in)
		if !bytes.Equal(e.Bytes(), tc.want) {
			t.Errorf("String(%q) = % x, want % x", tc.in, e.Bytes(), tc.want)
		}
		if len(e.Bytes())%4 != 0 {
			t.Errorf("String(%q) encoded to %d bytes, not a multiple of 4", tc.in, len(e.Bytes()))
		}
	}
}

func TestEncoderTruncateAndLen(t *testing.T) {
	e := NewEncoder(make([]byte, 0, 64))
	e.Uint32(1)
	mark := e.Len()
	e.Uint32(2)
	e.Truncate(mark)
	if e.Len() != 4 {
		t.Fatalf("Len after Truncate = %d, want 4", e.Len())
	}
	e.Truncate(0)
	if e.Len() != 0 {
		t.Fatalf("Len after Truncate(0) = %d, want 0", e.Len())
	}
}

func TestDecodeShort(t *testing.T) {
	empty := NewDecoder(nil)
	if _, err := empty.Uint32(); !errors.Is(err, ErrShort) {
		t.Errorf("Uint32 on an empty buffer = %v, want ErrShort", err)
	}
	if _, err := empty.Uint64(); !errors.Is(err, ErrShort) {
		t.Errorf("Uint64 on an empty buffer = %v, want ErrShort", err)
	}
	if _, err := empty.Int32(); !errors.Is(err, ErrShort) {
		t.Errorf("Int32 on an empty buffer = %v, want ErrShort", err)
	}
	if _, err := empty.Bool(); !errors.Is(err, ErrShort) {
		t.Errorf("Bool on an empty buffer = %v, want ErrShort", err)
	}
	if _, err := empty.Opaque(); !errors.Is(err, ErrShort) {
		t.Errorf("Opaque on an empty buffer = %v, want ErrShort", err)
	}
	if _, err := empty.String(); !errors.Is(err, ErrShort) {
		t.Errorf("String on an empty buffer = %v, want ErrShort", err)
	}
	if _, err := NewDecoder([]byte{1, 2}).Fixed(3); !errors.Is(err, ErrShort) {
		t.Errorf("Fixed past the end = %v, want ErrShort", err)
	}
	// A length prefix that is honest about a body the buffer does not hold.
	if _, err := NewDecoder([]byte{0, 0, 0, 8, 1, 2}).Opaque(); !errors.Is(err, ErrShort) {
		t.Errorf("Opaque with a truncated body = %v, want ErrShort", err)
	}
	// Data present but the padding is not.
	if _, err := NewDecoder([]byte{0, 0, 0, 1, 'x'}).Opaque(); !errors.Is(err, ErrShort) {
		t.Errorf("Opaque with missing padding = %v, want ErrShort", err)
	}
}

// TestHostileLength is the allocation-safety property: a 4 GiB length prefix
// on a 4-byte message must cost one comparison, not 4 GiB.
func TestHostileLength(t *testing.T) {
	if _, err := NewDecoder([]byte{0xff, 0xff, 0xff, 0xff}).Opaque(); !errors.Is(err, ErrLimit) {
		t.Fatalf("Opaque with a 4 GiB length = %v, want ErrLimit", err)
	}
	if _, err := NewDecoder([]byte{0x00, 0x20, 0x00, 0x00}).Opaque(); !errors.Is(err, ErrLimit) {
		t.Fatalf("Opaque above DefaultLimit = %v, want ErrLimit", err)
	}
	if _, err := NewDecoder(make([]byte, 64)).Fixed(-1); !errors.Is(err, ErrLimit) {
		t.Fatalf("Fixed(-1) = %v, want ErrLimit", err)
	}
	if _, err := NewDecoder(make([]byte, 64)).Fixed(DefaultLimit + 1); !errors.Is(err, ErrLimit) {
		t.Fatalf("Fixed above DefaultLimit = %v, want ErrLimit", err)
	}
}

func TestSetLimit(t *testing.T) {
	d := NewDecoder([]byte{0, 0, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8})
	d.SetLimit(4)
	if _, err := d.Opaque(); !errors.Is(err, ErrLimit) {
		t.Fatalf("Opaque above a 4-byte limit = %v, want ErrLimit", err)
	}
	d2 := NewDecoder([]byte{0, 0, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8})
	d2.SetLimit(0) // restores DefaultLimit
	if v, err := d2.Opaque(); err != nil || len(v) != 8 {
		t.Fatalf("Opaque after SetLimit(0) = (%v, %v)", v, err)
	}
}

// TestPaddingMustBeZero: RFC 4506 requires the alignment tail to be zero.
// Accepting non-zero bytes would leave a covert channel in the protocol.
func TestPaddingMustBeZero(t *testing.T) {
	if _, err := NewDecoder([]byte{0, 0, 0, 1, 'x', 0, 0, 1}).Opaque(); !errors.Is(err, ErrPadding) {
		t.Fatalf("Opaque with dirty padding = %v, want ErrPadding", err)
	}
}

// TestBoolMustBeZeroOrOne: coercing anything else would let two peers
// disagree about what they just exchanged.
func TestBoolMustBeZeroOrOne(t *testing.T) {
	if _, err := NewDecoder([]byte{0, 0, 0, 2}).Bool(); err == nil {
		t.Fatal("Bool accepted a value other than 0 or 1")
	}
}

func TestFixedCopiesRatherThanAliases(t *testing.T) {
	// The decoder's buffer is a reusable connection read buffer. Handing out
	// an alias would let the next request rewrite data the caller still holds.
	buf := []byte{0, 0, 0, 4, 1, 2, 3, 4}
	d := NewDecoder(buf)
	d.Uint32()
	got, err := d.Fixed(4)
	if err != nil {
		t.Fatalf("Fixed: %v", err)
	}
	buf[4] = 0xff
	if got[0] != 1 {
		t.Fatal("Fixed returned an alias of the decoder's buffer")
	}
}
