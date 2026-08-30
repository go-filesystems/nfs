package xdr

import (
	"encoding/binary"
	"errors"
	"math"
)

// Errors returned by a Decoder. They are deliberately few and coarse: an RPC
// server turns any of them into the single wire answer GARBAGE_ARGS, so
// distinguishing "ran out of bytes" from "length prefix is absurd" buys the
// caller nothing but costs the reader a branch to think about.
var (
	// ErrShort reports that the buffer ended in the middle of an item.
	ErrShort = errors.New("xdr: buffer too short")
	// ErrLimit reports a length prefix larger than the caller's ceiling.
	// It is returned *before* any allocation, so an absurd prefix costs a
	// comparison rather than the memory it asks for.
	ErrLimit = errors.New("xdr: length exceeds limit")
	// ErrPadding reports non-zero bytes in the 0-3 byte alignment tail.
	// RFC 4506 requires those bytes to be zero. Rejecting them keeps a
	// covert channel out of the protocol rather than merely unused.
	ErrPadding = errors.New("xdr: non-zero padding")
)

// pad returns the number of alignment bytes that follow n data bytes.
func pad(n int) int { return (4 - n%4) % 4 }

// Encoder accumulates XDR-encoded values in an internal buffer.
//
// Encoding cannot fail: every input is already a valid Go value of a type XDR
// can represent, and the buffer grows. That is why no method returns an
// error, which in turn keeps the NFS procedure bodies free of error checks on
// the reply path where nothing can actually go wrong.
type Encoder struct {
	buf []byte
}

// NewEncoder returns an Encoder that appends to buf. Passing a recycled
// buffer with spare capacity avoids an allocation per reply.
func NewEncoder(buf []byte) *Encoder { return &Encoder{buf: buf[:0]} }

// Bytes returns the encoded message. The slice aliases the Encoder's buffer
// and stays valid until the next write.
func (e *Encoder) Bytes() []byte { return e.buf }

// Len reports how many bytes have been encoded so far. Used to backfill a
// length that is only known after the body has been written.
func (e *Encoder) Len() int { return len(e.buf) }

// Truncate discards everything after the first n bytes. An NFS procedure that
// discovers halfway through building a reply that it must fail instead rewinds
// to the end of the RPC header and encodes the error, rather than assembling
// the reply twice.
func (e *Encoder) Truncate(n int) { e.buf = e.buf[:n] }

// Uint32 encodes a 32-bit unsigned integer.
func (e *Encoder) Uint32(v uint32) { e.buf = binary.BigEndian.AppendUint32(e.buf, v) }

// Uint64 encodes a 64-bit unsigned integer (XDR "hyper").
func (e *Encoder) Uint64(v uint64) { e.buf = binary.BigEndian.AppendUint64(e.buf, v) }

// Int32 encodes a 32-bit signed integer. XDR signed and unsigned 32-bit
// values share a representation, so this is a two's-complement reinterpret.
func (e *Encoder) Int32(v int32) { e.Uint32(uint32(v)) }

// Bool encodes an XDR boolean, which is an enum over {0,1} — not a byte.
func (e *Encoder) Bool(v bool) {
	if v {
		e.Uint32(1)
		return
	}
	e.Uint32(0)
}

// Fixed encodes a fixed-length opaque array: the bytes and their padding, with
// no length prefix. The peer is expected to know the length from the protocol
// definition.
func (e *Encoder) Fixed(b []byte) {
	e.buf = append(e.buf, b...)
	e.buf = append(e.buf, make([]byte, pad(len(b)))...)
}

// Opaque encodes a variable-length opaque array: a 4-byte length, the bytes,
// then padding.
func (e *Encoder) Opaque(b []byte) {
	e.Uint32(uint32(len(b)))
	e.Fixed(b)
}

// String encodes an XDR string, which is wire-identical to a variable-length
// opaque array. NFS filenames arrive and leave through this.
func (e *Encoder) String(s string) {
	e.Uint32(uint32(len(s)))
	e.buf = append(e.buf, s...)
	e.buf = append(e.buf, make([]byte, pad(len(s)))...)
}

// Decoder reads XDR-encoded values from a byte slice.
//
// Every method returns an error rather than panicking, because the bytes come
// from the network and a panic in a per-connection goroutine would take the
// server down on a malformed packet.
type Decoder struct {
	buf []byte
	off int
	// limit caps any single variable-length item. Zero means DefaultLimit.
	limit int
}

// DefaultLimit is the ceiling applied to a single variable-length item when
// the caller does not set one. NFSv3 READ/WRITE payloads are negotiated
// through FSINFO's rtmax/wtmax, which this module keeps well under 1 MiB, so
// anything larger is a malformed or hostile message.
const DefaultLimit = 1 << 20

// NewDecoder returns a Decoder reading buf with DefaultLimit.
func NewDecoder(buf []byte) *Decoder { return &Decoder{buf: buf} }

// SetLimit sets the maximum accepted length for a single variable-length
// item. A non-positive value restores DefaultLimit.
func (d *Decoder) SetLimit(n int) {
	if n <= 0 {
		n = DefaultLimit
	}
	d.limit = n
}

func (d *Decoder) cap() int {
	if d.limit <= 0 {
		return DefaultLimit
	}
	return d.limit
}

// Remaining reports how many undecoded bytes are left.
func (d *Decoder) Remaining() int { return len(d.buf) - d.off }

// Uint32 decodes a 32-bit unsigned integer.
func (d *Decoder) Uint32() (uint32, error) {
	if d.Remaining() < 4 {
		return 0, ErrShort
	}
	v := binary.BigEndian.Uint32(d.buf[d.off:])
	d.off += 4
	return v, nil
}

// Uint64 decodes a 64-bit unsigned integer.
func (d *Decoder) Uint64() (uint64, error) {
	if d.Remaining() < 8 {
		return 0, ErrShort
	}
	v := binary.BigEndian.Uint64(d.buf[d.off:])
	d.off += 8
	return v, nil
}

// Int32 decodes a 32-bit signed integer.
func (d *Decoder) Int32() (int32, error) {
	v, err := d.Uint32()
	return int32(v), err
}

// Bool decodes an XDR boolean. Any value other than 0 or 1 is a protocol
// violation and is rejected rather than coerced, because coercing it would
// let two peers disagree about what they just exchanged.
func (d *Decoder) Bool() (bool, error) {
	v, err := d.Uint32()
	if err != nil {
		return false, err
	}
	if v > 1 {
		return false, ErrShort
	}
	return v == 1, nil
}

// skipPad consumes and validates the alignment bytes after n data bytes.
func (d *Decoder) skipPad(n int) error {
	p := pad(n)
	if d.Remaining() < p {
		return ErrShort
	}
	for _, b := range d.buf[d.off : d.off+p] {
		if b != 0 {
			return ErrPadding
		}
	}
	d.off += p
	return nil
}

// Fixed decodes a fixed-length opaque array of exactly n bytes plus padding.
// The result is a copy: the Decoder's buffer is a reusable connection read
// buffer, so handing out an alias would let the next request rewrite data the
// caller is still holding.
func (d *Decoder) Fixed(n int) ([]byte, error) {
	if n < 0 || n > d.cap() {
		return nil, ErrLimit
	}
	if d.Remaining() < n {
		return nil, ErrShort
	}
	out := make([]byte, n)
	copy(out, d.buf[d.off:d.off+n])
	d.off += n
	return out, d.skipPad(n)
}

// Opaque decodes a variable-length opaque array. The length prefix is checked
// against the limit before a single byte is allocated.
func (d *Decoder) Opaque() ([]byte, error) {
	n, err := d.Uint32()
	if err != nil {
		return nil, err
	}
	if n > math.MaxInt32 || int(n) > d.cap() {
		return nil, ErrLimit
	}
	return d.Fixed(int(n))
}

// String decodes an XDR string.
//
// The bytes are returned as-is, with no validation of UTF-8 or of path
// syntax. That is deliberate: this layer's job is framing. Whether a
// filename may contain a slash or a NUL is an NFS question, and answering it
// here would silently change what the layer above thinks it received.
func (d *Decoder) String() (string, error) {
	b, err := d.Opaque()
	if err != nil {
		return "", err
	}
	return string(b), nil
}
