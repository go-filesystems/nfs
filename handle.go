package nfs

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"time"
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
// # What is in it: 60 bytes, three fields and a MAC
//
//	[0:4)   magic + version  — rejects a handle from another protocol/layout
//	[4:12)  export id        — which export; keyed hash of the export path
//	[12:28) path id          — keyed hash of (export id, path)
//	[28:60) HMAC-SHA256      — over bytes [0:28) with the handle key
//
// The path lives only in server memory, in a table the path id indexes. The
// handle discloses nothing a client could read back: both ids are HMACs
// under a key the client never sees, so they reveal no names, no depth and
// no sizes — only whether two handles name the same file, which the client
// knows anyway.
//
// The MAC is what makes the handle safe to dereference: a handle the server
// did not mint fails in constant time and is answered NFS3ERR_BADHANDLE.
//
// # Why the ids are hashes and not a counter
//
// Up to v0.4.0 the handle carried a slot number — "the Nth path this process
// resolved" — and a random per-process key. A handle therefore meant nothing
// to any other [Server], even one in the same process serving the same
// exports; a program that rebuilds its Server on a configuration change
// turned every handle its clients held into NFS3ERR_BADHANDLE, which a Linux
// client reports as EIO on every open file.
//
// A keyed hash of the path means the same (key, export, path) is the same
// handle in every Server that holds the key. A Server that has never been
// asked about a path, and is then handed a genuine handle for it, finds the
// path again by walking the export and hashing what it sees (see
// [Server.rediscover]); after one walk every existing path is known. The key
// is random per Server unless the caller supplies one with
// [Server.SetHandleKey], and supplying the same key to the next Server — or
// to the next process — is what keeps a client's handles working.
//
// # Stale, and what survives what
//
// A MAC-valid handle whose path no longer exists — deleted, renamed, or on
// an export that is gone — is answered NFS3ERR_STALE, which is precisely the
// signal RFC 1813 designed for it: the client discards its cache and looks
// the name up again. It can never resolve to a different file: the path id
// is the hash of the very path it names, so a new file at that path is, to
// NFSv3, the same name — exactly what a path-addressed server serves anyway.
//
// A handle minted under a different key fails the MAC and is
// NFS3ERR_BADHANDLE. Without [Server.SetHandleKey] that is every handle
// after a restart.
//
// # Growth
//
// Entries are never evicted. Eviction is what would make a valid handle
// unresolvable under a client that still holds it. The table therefore grows
// with the number of distinct paths ever looked up, bounded by maxHandles;
// past that the server answers NFS3ERR_SERVERFAULT rather than forgetting
// something a client is using.

// handleSize is the encoded length of a file handle. NFSv3 allows up to 64;
// 60 is what this layout needs, and a fixed length means a wrong length is
// itself a rejection.
const handleSize = 60

// handleMagic tags the layout. Bumping the low byte is how a layout change
// makes old handles fail closed instead of being misread; 3 was the
// slot-numbered layout up to v0.4.0.
const handleMagic uint32 = 0x4E465304 // "NFS\x04"

// HandleKeySize is the least a key given to [Server.SetHandleKey] may hold,
// and the size [NewHandleKey] draws: the full block of HMAC-SHA256.
const HandleKeySize = 32

// pathIDSize is the width of the path id: 128 bits, so that two paths
// colliding is not a thing to design around.
const pathIDSize = 16

// pathID is the keyed hash naming one path of one export.
type pathID [pathIDSize]byte

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

// ErrHandleKey reports a key given to [Server.SetHandleKey] shorter than
// [HandleKeySize].
var ErrHandleKey = errors.New("nfs: a handle key must hold at least 32 bytes")

// NewHandleKey draws a key for [Server.SetHandleKey] from the system CSPRNG.
//
// Keep it as secret as a password: whoever holds it can mint a handle for
// any path of any export, bypassing LOOKUP and the directory permissions
// along the way (the export's own gates — [RequireTLS], [AllowCall] — still
// apply on every call).
func NewHandleKey() ([]byte, error) {
	key := make([]byte, HandleKeySize)
	if _, err := randRead(key); err != nil {
		return nil, err
	}
	return key, nil
}

// handleKey identifies a file: which export, and the cleaned absolute path
// inside it.
type handleKey struct {
	export uint64
	path   string
}

// handleStore mints and resolves file handles.
type handleStore struct {
	// key never changes for the life of the store.
	key []byte
	// epoch is random per store. It is no longer in the handle; it is the
	// WRITE/COMMIT verifier (see writeVerf), which must change whenever
	// unstable writes could have been lost — and a new Server is that.
	epoch uint64

	// max bounds the table; it is a field rather than the constant so the
	// overflow path can be exercised without allocating a million entries.
	max int

	mu     sync.Mutex
	byID   map[pathID]handleKey
	byPath map[handleKey]pathID
}

// newHandleStore seeds a store from the system CSPRNG.
//
// It returns an error rather than panicking because a failed crypto/rand read
// means the handle MAC would be predictable, and a server that mints
// forgeable handles must refuse to start rather than start insecurely.
func newHandleStore() (*handleStore, error) {
	key, err := NewHandleKey()
	if err != nil {
		return nil, err
	}
	var e [8]byte
	if _, err := randRead(e[:]); err != nil {
		return nil, err
	}
	return newHandleStoreWith(key, binary.BigEndian.Uint64(e[:])), nil
}

// newHandleStoreWith builds a store around a given key. The key is copied: a
// caller that later scrubs or reuses its slice must not change this one.
func newHandleStoreWith(key []byte, epoch uint64) *handleStore {
	return &handleStore{
		key:    bytes.Clone(key),
		epoch:  epoch,
		max:    maxHandles,
		byID:   make(map[pathID]handleKey),
		byPath: make(map[handleKey]pathID),
	}
}

// Domain labels keep the three uses of the one key apart: no export id can
// double as a path id or a handle MAC.
const (
	domainExport = "nfs export id\x00"
	domainPath   = "nfs path id\x00"
	domainHandle = "nfs handle mac\x00"
)

// hmacOf computes HMAC-SHA256 under the store's key.
func (s *handleStore) hmacOf(domain string, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(domain))
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

// exportID derives the id of the export published at path. It is a function
// of the key and the path only — not of the order exports were added in — so
// a Server that adds, removes or reorders exports keeps the handles of the
// ones it kept. It is also the FSINFO/GETATTR fsid.
func (s *handleStore) exportID(path string) uint64 {
	return binary.BigEndian.Uint64(s.hmacOf(domainExport, []byte(path)))
}

// idFor derives the path id. The export id is fixed-width and comes first,
// so no (export, path) pair can be spelled as another.
func (s *handleStore) idFor(export uint64, path string) pathID {
	var e [8]byte
	binary.BigEndian.PutUint64(e[:], export)
	var id pathID
	copy(id[:], s.hmacOf(domainPath, e[:], []byte(path)))
	return id
}

// mac computes the authenticator over the first 28 bytes of a handle.
func (s *handleStore) mac(prefix []byte) []byte {
	return s.hmacOf(domainHandle, prefix)
}

// learn records a path in the table, so that its handle resolves, and
// returns its id.
func (s *handleStore) learn(export uint64, path string) (pathID, error) {
	k := handleKey{export: export, path: path}
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.byPath[k]; ok {
		return id, nil
	}
	if len(s.byPath) >= s.max {
		return pathID{}, errHandleFull
	}
	id := s.idFor(export, path)
	s.byPath[k] = id
	s.byID[id] = k
	return id, nil
}

// Handle returns the handle naming path within export, recording the path
// so the handle resolves. The same key, export and path always yield the
// same bytes, in this Server and in any other holding the key.
func (s *handleStore) Handle(export uint64, path string) ([]byte, error) {
	id, err := s.learn(export, path)
	if err != nil {
		return nil, err
	}
	h := make([]byte, handleSize)
	binary.BigEndian.PutUint32(h[0:4], handleMagic)
	binary.BigEndian.PutUint64(h[4:12], export)
	copy(h[12:28], id[:])
	copy(h[28:], s.mac(h[0:28]))
	return h, nil
}

// Resolve validates a handle and returns what it names.
//
// The checks run cheapest-first, but the MAC is compared with [hmac.Equal]
// so a client cannot time its way to a valid authenticator. A handle that is
// malformed or not authentic is (handleKey{}, false, false): the caller
// answers NFS3ERR_BADHANDLE, and nothing on the wire tells an attacker which
// check failed.
//
// An AUTHENTIC handle this store has no entry for is reported stale, with
// k.export set: it was minted with this key — by this Server before the path
// went away, or by another Server sharing the key — and the caller may look
// for the path (see [Server.rediscover]) before answering NFS3ERR_STALE.
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
	// Past this point the handle was minted with this key, so the remaining
	// fields are trusted inputs, not attacker inputs.
	export := binary.BigEndian.Uint64(h[4:12])
	id := handleID(h)
	s.mu.Lock()
	defer s.mu.Unlock()
	k, known := s.byID[id]
	if !known || k.export != export {
		return handleKey{export: export}, true, false
	}
	return k, false, true
}

// handleID extracts the path id of a handle Resolve has authenticated.
func handleID(h []byte) pathID {
	var id pathID
	copy(id[:], h[12:28])
	return id
}

// lookupID reports what an id names, if the table knows it.
func (s *handleStore) lookupID(id pathID) (handleKey, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.byID[id]
	return k, ok
}

// fileID returns the synthetic fileid for a path (see attr.go): the top bit
// set, the rest from the path id. It is derived, not counted, so it is the
// same in every Server sharing the key — a client that saw a fileid change
// under a handle it holds would take the file for a different one. The path
// is recorded too, as for a handle: a fileid names what a handle would.
func (s *handleStore) fileID(export uint64, path string) (uint64, error) {
	id, err := s.learn(export, path)
	if err != nil {
		return 0, err
	}
	return 1<<63 | binary.BigEndian.Uint64(id[:8])>>1, nil
}

// rediscoverInterval bounds how often unknown handles may cost a walk of one
// export. One walk records every path that exists, so a second walk soon
// after can only find what was created behind the server's back since.
const rediscoverInterval = 10 * time.Second

// rediscover looks for the path an authentic but unknown handle names, by
// walking the export and recording every path it sees.
//
// This is how a Server that shares its handle key with an earlier one (see
// [Server.SetHandleKey]) honours the handles that one minted: it has never
// been asked about those paths, but the path id is a hash of the path, so
// hashing what the export contains finds it. A whole walk is done, not one
// stopped at the first match: the client that presents one old handle holds
// dozens, and after one walk they all resolve from the table.
//
// The walk holds [Server.fsmu] — the driver is not safe for concurrent use —
// so it stalls every other call while it runs; it is bounded by maxHandles
// and by rediscoverInterval per export. Only a MAC-valid handle reaches it, so
// a client cannot trigger it with handles it made up.
func (s *Server) rediscover(e *export, id pathID) (string, bool) {
	s.fsmu.Lock()
	defer s.fsmu.Unlock()
	// A walk that finished while this call waited for the lock may already
	// have found it.
	if k, ok := s.handles.lookupID(id); ok && k.export == e.id {
		return k.path, true
	}
	now := time.Now()
	if !e.lastWalk.IsZero() && now.Sub(e.lastWalk) < rediscoverInterval {
		return "", false
	}
	e.lastWalk = now
	found := ""
	if got, err := s.handles.learn(e.id, "/"); err != nil {
		return "", false
	} else if got == id {
		found = "/"
	}
	queue := []string{"/"}
	for len(queue) > 0 {
		dir := queue[0]
		queue = queue[1:]
		names, st := s.listDir(e, dir)
		if st != StatusOK {
			continue
		}
		for _, n := range names {
			full, st := joinName(dir, n)
			if st != StatusOK {
				continue
			}
			got, err := s.handles.learn(e.id, full)
			if err != nil {
				// The table is full: what has been found is all there is.
				return found, found != ""
			}
			if got == id {
				found = full
			}
			if fi, err := e.fs.Stat(full); err == nil && fi.Mode()&sIFMT == sIFDIR {
				queue = append(queue, full)
			}
		}
	}
	return found, found != ""
}
