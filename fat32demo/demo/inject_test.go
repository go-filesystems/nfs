package demo

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	fat32 "github.com/go-filesystems/fat32"
	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/nfs"
)

// image formats a small FAT32 image and returns its path.
func image(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "d.img")
	fs, err := fat32.Format(p, 32<<20, fat32.FormatConfig{Label: "INJ"})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	fs.Close()
	return p
}

// stubFS is just enough of the contract to occupy an export path.
type stubFS struct{}

func (stubFS) Close() error                                  { return nil }
func (stubFS) ReadFile(string) ([]byte, error)               { return nil, nil }
func (stubFS) ListDir(string) ([]filesystem.DirEntry, error) { return nil, nil }
func (stubFS) Stat(string) (filesystem.Stat, error)          { return nil, nil }
func (stubFS) WriteFile(string, []byte, os.FileMode) error   { return nil }
func (stubFS) ReadLink(string) (string, error)               { return "", nil }
func (stubFS) MkDir(string, os.FileMode) error               { return nil }
func (stubFS) DeleteFile(string) error                       { return nil }
func (stubFS) DeleteDir(string) error                        { return nil }
func (stubFS) Rename(string, string) error                   { return nil }

func TestSetupServerConstructionFails(t *testing.T) {
	orig := newServer
	t.Cleanup(func() { newServer = orig })
	boom := errors.New("no server")
	newServer = func() (*nfs.Server, error) { return nil, boom }
	var out bytes.Buffer
	if _, _, err := Setup(image(t), "127.0.0.1:0", false, &out); !errors.Is(err, boom) {
		t.Fatalf("Setup = %v, want %v", err, boom)
	}
}

func TestSetupExportFails(t *testing.T) {
	orig := newServer
	t.Cleanup(func() { newServer = orig })
	newServer = func() (*nfs.Server, error) {
		s, err := orig()
		if err != nil {
			return nil, err
		}
		// "/" is already taken, so Setup's own Export must fail — and must
		// still close the driver it opened.
		return s, s.Export("/", stubFS{})
	}
	var out bytes.Buffer
	if _, _, err := Setup(image(t), "127.0.0.1:0", false, &out); !errors.Is(err, nfs.ErrExportExists) {
		t.Fatalf("Setup = %v, want ErrExportExists", err)
	}
}
