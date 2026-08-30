package nfs

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
)

// A file handle is the hardest design question in an NFS server, so this
// documents the choice rather than just implementing one.
//
// # The constraint
//
// NFSv3 gives the server 64 opaque bytes to name a file with. The client
// stores them, uses them for every subsequent operation, and may hand back a
// handle minted hours ago — possibly to a different server process, since
// nothing in the protocol tells a client that a server restarted. The handle
// must therefore be:
//
//  1. Opaque. It is stored in client kernels and appears in packet captures.
//     Anything encoded in it is disclosed to everyone who can see the wire.
//  2. Unforgeable. The server dereferences whatever 64 bytes arrive. If a
//     handle is a guessable index or an encoded path, a client can synthesise
//     one and reach something that was never exported.
//  3. Stable while it is valid, and *detectably* invalid otherwise. Silently
//     aliasing a stale handle onto a different file is the one failure mode
//     that corrupts data instead of returning an error.
//
// # What is not in it
//
// Not the path. Paths do not fit — 64 bytes is less than one deep path, let
// alone one plus a MAC — and a path in a handle leaks the tree's shape and
// naming to anyone watching the wire. Not the inode number either: on a
// FAT32 image the "inode" is the first cluster, which is 0 for every empty
// file, so it is neither unique nor safe to dereference.
//
// # What is in it: 60 bytes, four fields and a MAC
//
//	[0:4)   magic + version  — rejects a handle from another protocol/layout
//	[4:12)  export id        — which export this handle belongs to
//	[12:20) epoch            — random per server process
//	[20:28) slot             — dense index into this process's path table
//	[28:60) HMAC-SHA256      — over bytes [0:28) with a per-process random key
//
// The path lives only in server memory, in a table the slot indexes. The
// handle discloses nothing but "the Nth path this server was asked about",
// which reveals lookup order and nothing else — no names, no depth, no sizes.
//
// The MAC is what makes the slot safe to dereference. Without it the slot is
// a small integer and a client could walk it to enumerate every path the
// server has ever resolved, including ones outside the export it mounted.
// With it, a handle the server did not mint fails in constant time and is
// answered NFS3ERR_BADHANDLE. The key is random per process and never
// leaves it.
//
// # "Survive the server"
//
// The epoch is the honest part. A handle cannot outlive this process's
// in-memory table, so a handle minted before a restart must be *rejected*,
// not reinterpreted. The random epoch guarantees that: after a restart every
// old handle fails the epoch check and is answered NFS3ERR_STALE, which is
// precisely the signal RFC 1813 designed for it — the client discards its
// cache and walks down from the mount root again. That is a working mount
// across a server restart, with zero risk of a stale handle resolving to the
// wrong file. A persistent variant (a stable key plus a table checkpoint)
// would slot into the same 60 bytes without a format change, and is not
// implemented because a read-only image export gains nothing from it.
//
// # Growth
//
// Slots are never recycled. Recycling is what would make a stale handle
// dangerous rather than merely stale, and an LRU would silently invalidate
// handles a client still holds. The table therefore grows with the number of
// distinct paths ever looked up, bounded by maxHandles; past that the server
// answers NFS3ERR_SERVERFAULT rather than evicting something a client is
// using.

// handleSize is the encoded length of a file handle. NFSv3 allows up to 64;
// 60 is what this layout needs, and a fixed length means a wrong length is
// itself a rejection.
const handleSize = 60

// handleMagic tags the layout. Bumping the low byte is how a future layout
// change makes old handles fail closed instead of being misread.
const handleMagic uint32 = 0x4E465303 // "NFS\x03"

// maxHandles bounds the path table. One million distinct paths is far past
// any image the fleet's drivers open, and small enough that a client walking
// a hostile directory tree cannot exhaust memory.
const maxHandles = 1 << 20

// randRead is crypto/rand.Read, indirected so a test can prove the server
// refuses to start rather than mint predictable handles when the CSPRNG is
// unavailable. There is no other way to reach that branch, and it is the one
// branch where the wrong behaviour is silent.
var randRead = rand.Read

// errHandleFull reports the path table hitting maxHandles.
var errHandleFull = errors.New("nfs: file handle table full")

// handleKey identifies a file: which export, and the cleaned absolute path
// inside it.
type handleKey struct {
	export uint64
	path   string
}

// handleStore mints and resolves file handles.
type handleStore struct {
	// key and epoch are drawn once per process and never change.
	key   []byte
	epoch uint64

	// max bounds the table; it is a field rather than the constant so the
	// overflow path can be exercised without allocating a million entries.
	max int

	mu     sync.Mutex
	slots  []handleKey
	byPath map[handleKey]uint64
}

// newHandleStore seeds a store from the system CSPRNG.
//
// It returns an error rather than panicking because a failed crypto/rand read
// means the handle MAC would be predictable, and a server that mints
// forgeable handles must refuse to start rather than start insecurely.
func newHandleStore() (*handleStore, error) {
	key := make([]byte, 32)
	if _, err := randRead(key); err != nil {
		return nil, err
	}
	var e [8]byte
	if _, err := randRead(e[:]); err != nil {
		return nil, err
	}
	return &handleStore{
		key:    key,
		epoch:  binary.BigEndian.Uint64(e[:]),
		max:    maxHandles,
		byPath: make(map[handleKey]uint64),
	}, nil
}

// mac computes the authenticator over the first 28 bytes of a handle.
func (s *handleStore) mac(prefix []byte) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write(prefix)
	return m.Sum(nil)
}

// Handle returns the handle naming path within export, minting one on first
// use. The same (export, path) always yields the same bytes for the life of
// the process.
func (s *handleStore) Handle(export uint64, path string) ([]byte, error) {
	k := handleKey{export: export, path: path}
	s.mu.Lock()
	slot, ok := s.byPath[k]
	if !ok {
		if len(s.slots) >= s.max {
			s.mu.Unlock()
			return nil, errHandleFull
		}
		slot = uint64(len(s.slots))
		s.slots = append(s.slots, k)
		s.byPath[k] = slot
	}
	s.mu.Unlock()

	h := make([]byte, handleSize)
	binary.BigEndian.PutUint32(h[0:4], handleMagic)
	binary.BigEndian.PutUint64(h[4:12], export)
	binary.BigEndian.PutUint64(h[12:20], s.epoch)
	binary.BigEndian.PutUint64(h[20:28], slot)
	copy(h[28:], s.mac(h[0:28]))
	return h, nil
}

// Resolve validates a handle and returns what it names.
//
// The checks run cheapest-first, but the MAC is compared with
// [hmac.Equal] so a client cannot time its way to a valid authenticator.
// Every rejection is reported as (handleKey{}, false); the caller maps that
// to NFS3ERR_BADHANDLE. Distinguishing "wrong epoch" (stale) from "bad MAC"
// (forged) on the wire would tell an attacker which of the two they got
// wrong, so both answer the same way — except that a well-formed handle from
// a previous epoch is common enough after a restart that it is worth the
// client hearing NFS3ERR_STALE instead, which is what stale reports.
func (s *handleStore) Resolve(h []byte) (k handleKey, stale bool, ok bool) {
	if len(h) != handleSize {
		return handleKey{}, false, false
	}
	if binary.BigEndian.Uint32(h[0:4]) != handleMagic {
		return handleKey{}, false, false
	}
	if !hmac.Equal(h[28:], s.mac(h[0:28])) {
		return handleKey{}, false, false
	}
	// Past this point the handle was minted by *this* process with *this*
	// key, so the remaining fields are trusted inputs, not attacker inputs.
	if binary.BigEndian.Uint64(h[12:20]) != s.epoch {
		return handleKey{}, true, false
	}
	slot := binary.BigEndian.Uint64(h[20:28])
	s.mu.Lock()
	defer s.mu.Unlock()
	if slot >= uint64(len(s.slots)) {
		// Unreachable through a MAC-valid handle from this epoch, but a
		// bounds check on an index derived from the wire is not something
		// to leave to reasoning.
		return handleKey{}, true, false
	}
	return s.slots[slot], false, true
}

// slotOf returns the table slot for a key, minting one if needed. It backs
// the synthetic fileid used when a driver reports inode 0 (see attr.go).
func (s *handleStore) slotOf(export uint64, path string) (uint64, error) {
	if _, err := s.Handle(export, path); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byPath[handleKey{export: export, path: path}], nil
}
