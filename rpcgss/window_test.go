package rpcgss

import "testing"

func TestWindowAcceptsEachNumberOnce(t *testing.T) {
	w := newSeqWindow(8)
	for i := uint32(1); i <= 8; i++ {
		if !w.accept(i) {
			t.Fatalf("seq %d refused the first time", i)
		}
	}
	for i := uint32(1); i <= 8; i++ {
		if w.accept(i) {
			t.Errorf("seq %d accepted twice", i)
		}
	}
}

func TestWindowAcceptsOutOfOrderWithinTheWindow(t *testing.T) {
	// Clients pipeline, so calls arrive out of order. A window that demanded
	// strictly increasing numbers would refuse perfectly good calls, and the
	// symptom would be a mount that stalls under load and works when idle.
	w := newSeqWindow(64)
	if !w.accept(40) {
		t.Fatal("40 refused")
	}
	for _, seq := range []uint32{39, 38, 20, 1} {
		if !w.accept(seq) {
			t.Errorf("%d refused although it is inside the window", seq)
		}
	}
	if w.accept(39) {
		t.Error("39 accepted twice")
	}
}

func TestWindowRefusesWhatSlidOutOfIt(t *testing.T) {
	w := newSeqWindow(8)
	if !w.accept(100) {
		t.Fatal("100 refused")
	}
	if w.accept(92) {
		t.Error("92 accepted although it is exactly the width below the high mark")
	}
	if !w.accept(93) {
		t.Error("93 refused although it is the oldest number still in the window")
	}
}

func TestWindowSlideClearsWhatItPassesOver(t *testing.T) {
	// A number that enters the window as the window slides was never seen.
	// If the slide leaves a stale bit set, that call is refused as a replay
	// of something that never happened — and the client, hearing CTXPROBLEM,
	// tears down a context that was fine.
	w := newSeqWindow(64)
	for i := uint32(1); i <= 64; i++ {
		w.accept(i)
	}
	w.accept(200) // slides the whole window past every bit set above
	for _, seq := range []uint32{199, 150, 137} {
		if !w.accept(seq) {
			t.Errorf("%d refused: a bit survived the slide", seq)
		}
	}
}

func TestWindowRefusesTheCeiling(t *testing.T) {
	// RFC 2203 §5.3.3.1 stops at 2^31: past it a client must build a new
	// context. Wrapping instead would make a replay indistinguishable from a
	// fresh call.
	w := newSeqWindow(8)
	if w.accept(maxSeq) {
		t.Error("the ceiling itself was accepted")
	}
	if w.accept(maxSeq + 1) {
		t.Error("a number past the ceiling was accepted")
	}
}

func TestWindowSlideOfExactlyTheWidth(t *testing.T) {
	w := newSeqWindow(64)
	w.accept(10)
	if !w.accept(74) {
		t.Fatal("74 refused")
	}
	if w.accept(10) {
		t.Error("10 accepted again after the window moved exactly its width")
	}
}
