package rpcgss

// seqWindow is the replay window of RFC 2203 §5.3.3.1.
//
// A client numbers its calls and a server must refuse a number it has already
// answered. It cannot simply demand strictly increasing numbers: calls are
// pipelined and arrive out of order, so a window of recently-seen numbers is
// what the protocol asks for. The width is announced to the client during
// context creation; it must not be widened afterwards, since the client sizes
// its own retransmission around it.
type seqWindow struct {
	high uint32   // the highest sequence number accepted so far
	seen []uint64 // bitmap of the width numbers at or below high
	max  uint32
}

// maxSeq is the ceiling RFC 2203 §5.3.3.1 puts on a sequence number. A client
// reaching it must destroy the context and build another; the server refuses
// anything at or above rather than wrapping, because wrapping would make a
// replayed call indistinguishable from a fresh one.
const maxSeq uint32 = 0x8000_0000

func newSeqWindow(width uint32) *seqWindow {
	return &seqWindow{seen: make([]uint64, (width+63)/64), max: width}
}

// accept records a sequence number and reports whether it is usable: not seen
// before, not older than the window, and below the ceiling.
func (w *seqWindow) accept(seq uint32) bool {
	if seq >= maxSeq {
		return false
	}
	switch {
	case seq > w.high:
		// Slide. Numbers between the old high and the new one were never
		// seen, so their bits must be cleared as they enter the window —
		// otherwise a number the window once held would be refused as a
		// replay of a call that never happened.
		shift := seq - w.high
		if shift >= w.max {
			for i := range w.seen {
				w.seen[i] = 0
			}
		} else {
			w.shiftLeft(shift)
		}
		w.high = seq
		w.set(0)
		return true
	case w.high-seq >= w.max:
		// Older than anything the window still remembers. Refusing is the
		// only safe answer: "not in the bitmap" would be true of a replay
		// from an hour ago just as much as of a fresh call.
		return false
	default:
		off := w.high - seq
		if w.get(off) {
			return false
		}
		w.set(off)
		return true
	}
}

// get and set address a bit by its distance BELOW high, so bit 0 is always
// the newest number.
func (w *seqWindow) get(off uint32) bool { return w.seen[off/64]&(1<<(off%64)) != 0 }
func (w *seqWindow) set(off uint32)      { w.seen[off/64] |= 1 << (off % 64) }

// shiftLeft moves every bit n places away from high.
func (w *seqWindow) shiftLeft(n uint32) {
	words, bitsIn := int(n/64), n%64
	for i := len(w.seen) - 1; i >= 0; i-- {
		var v uint64
		if i-words >= 0 {
			v = w.seen[i-words] << bitsIn
			if bitsIn > 0 && i-words-1 >= 0 {
				v |= w.seen[i-words-1] >> (64 - bitsIn)
			}
		}
		w.seen[i] = v
	}
}
