package nfs

import (
	"errors"

	filesystem "github.com/go-filesystems/interface"
)

// File is a random-access handle on a regular file inside an exported
// filesystem. It is [github.com/go-filesystems/interface.File] itself, not a
// copy of it.
//
// It used to be a local redeclaration, matched against a driver's method by a
// reflection probe on the method's shape, because the interface module had no
// tagged release carrying Opener and this module could not require one. That
// version is published now, so the aliases below are the real types and every
// probe is an ordinary type assertion the compiler can see through. Nothing is
// matched by shape any more: a driver either implements the fleet's interface
// or it does not, and the difference is a compile-time fact.
type File = filesystem.File

// Opener is the optional capability a driver implements to serve NFS READ
// without materialising whole files:
// [github.com/go-filesystems/interface.Opener].
type Opener = filesystem.Opener

// WritableFile is the optional upgrade of a File that lets NFS WRITE land the
// bytes a client sent AT THE OFFSET IT SENT THEM, instead of reading the whole
// file, splicing, and writing the whole file back:
// [github.com/go-filesystems/interface.WritableFile].
//
// This is the difference between a mount that works and one that does not.
// With the read-modify-write fallback a 2 MiB sequential write over a real
// Linux kernel NFS mount took 23 s — 90 kB/s — and a soft,timeo=50 mount gave
// up with EIO partway through, because a single WRITE round exceeded the
// client's timeout. The cost is O(filesize) per request, so it grows with the
// file: the failure gets worse exactly as the file gets more valuable.
//
// It is probed on the File rather than on the Filesystem, because writability
// is a property of the opened object — ext4, for instance, returns a plain
// File for an inline-data or block-map inode it cannot write positionally, and
// this server falls back for those alone rather than for the whole driver.
type WritableFile = filesystem.WritableFile

// errNilFile reports a driver whose OpenFile returned (nil, nil).
//
// That is a driver bug, not a protocol condition, but it is checked rather
// than trusted: the alternative is a nil dereference inside the server on a
// code path a client can reach at will, and a server that panics on a
// malformed driver is worse than one that answers NFS3ERR_IO.
var errNilFile = errors.New("nfs: driver OpenFile returned a nil File with no error")

// openerFor returns the driver's random-access capability, or nil if it has
// none.
//
// The probe is a plain type assertion, and the assertion is checked at compile
// time in the interface module by the drivers themselves. It runs once per
// export, not per request, and a nil result is not an error: it means this
// server must read through ReadFile and write through ReadFile+WriteFile,
// which is correct and slow, and which the doc comments on both paths say out
// loud.
//
// Identity, not shape, is what matters here, and it is worth being explicit
// about why. Go matches method sets by TYPE IDENTITY: a driver whose OpenFile
// returns its own structurally identical File interface does not satisfy
// [github.com/go-filesystems/interface.Opener] and is not accepted. That is
// the correct answer — the fleet's drivers return the fleet's type — and it is
// also the reason this code could not be written this way before v0.3.0 of the
// interface module was tagged. A local redeclaration would have been satisfied
// by nothing at all, silently, and every driver would have fallen back to
// whole-file reads with no diagnostic anywhere.
func openerFor(fs any) Opener {
	o, _ := fs.(Opener)
	return o
}

// openFile opens path through the driver's Opener, rejecting the (nil, nil)
// return rather than dereferencing it.
//
// The caller must hold [Server.fsmu].
func (e *export) openFile(path string) (File, error) {
	f, err := e.open.OpenFile(path)
	if err != nil {
		return nil, err
	}
	if f == nil {
		return nil, errNilFile
	}
	return f, nil
}

// TimeStat is the optional capability a driver's
// [github.com/go-filesystems/interface.Stat] may implement to report a real
// modification time.
//
// No driver in the fleet does today, so every file this server exports
// currently reports the same three timestamps (see [attrFor]). The probe
// exists so that the day a driver starts reporting mtime, mounts get real
// times without a change here — and so that the gap is visible in the API
// instead of buried in a comment.
type TimeStat interface {
	ModTime() int64 // seconds since the Unix epoch
}
