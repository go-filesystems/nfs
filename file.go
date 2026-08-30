package nfs

import (
	"errors"
	"io"
	"reflect"
)

// File is a random-access handle on a regular file inside an exported
// filesystem: exactly [github.com/go-filesystems/interface.File].
//
// It is redeclared here rather than imported so that this module does not
// require a version of the interface module that has it yet. The two are
// structurally identical, and the probe below matches either — see
// [openerFor].
type File interface {
	io.ReaderAt
	io.Closer
	// Size reports the file's length in bytes.
	Size() int64
}

// Opener is the optional capability a driver implements to serve NFS READ
// without materialising whole files: exactly
// [github.com/go-filesystems/interface.Opener].
type Opener interface {
	OpenFile(path string) (File, error)
}

// errNilFile reports a driver whose OpenFile returned (nil, nil).
var errNilFile = errors.New("nfs: driver OpenFile returned a nil File with no error")

var (
	fileType  = reflect.TypeFor[File]()
	errorType = reflect.TypeFor[error]()
)

// openerFor returns a random-access opener for fs, or nil if the driver has
// none.
//
// # Why reflection, and why it is not a hack
//
// The capability is declared in the interface module as
//
//	OpenFile(path string) (filesystem.File, error)
//
// A driver's method therefore has the return type filesystem.File. This
// module declares its own structurally identical [File], and Go method sets
// are matched by *type identity*, not structure: a plain type assertion to a
// locally declared Opener would not match a driver returning
// filesystem.File, and would silently fall back to whole-file reads on every
// driver in the fleet. Importing the real type would instead pin this module
// to an interface-module version that may not be tagged yet.
//
// Reflection resolves both: the probe checks the method's *shape* — one
// string in, two out, second assignable to error, first satisfying [File] —
// so it matches the real filesystem.Opener, this module's [Opener], and any
// future spelling of the same idea. It runs once per export, not per read.
//
// The static Implements check on the first result is what makes the returned
// closure safe: the value cannot fail to be a File except by being nil.
func openerFor(fs any) func(string) (File, error) {
	// The fast path costs nothing and covers a driver that happens to use
	// this module's own declaration.
	if o, ok := fs.(Opener); ok {
		return o.OpenFile
	}
	m := reflect.ValueOf(fs).MethodByName("OpenFile")
	if !m.IsValid() {
		return nil
	}
	t := m.Type()
	if t.NumIn() != 1 || t.In(0).Kind() != reflect.String {
		return nil
	}
	if t.NumOut() != 2 || !t.Out(1).Implements(errorType) || !t.Out(0).Implements(fileType) {
		return nil
	}
	return func(path string) (File, error) {
		out := m.Call([]reflect.Value{reflect.ValueOf(path)})
		if e, _ := out[1].Interface().(error); e != nil {
			return nil, e
		}
		f, ok := out[0].Interface().(File)
		if !ok {
			return nil, errNilFile
		}
		return f, nil
	}
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
