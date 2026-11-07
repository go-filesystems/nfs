package nfs_test

import (
	"fmt"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/nfs"
	"github.com/go-filesystems/nfs/xdr"
)

// latFS is a read-only driver whose ReadAt costs a fixed time, standing for a
// driver that decodes an image or a remote store. Its path calls are lock-free
// over immutable data, so it is a driver that may assert
// WithConcurrentPathOps. Everything but the one file comes from memFS.
type latFS struct {
	*memFS
	data []byte
	lat  time.Duration
}

const benchFile = "/big.bin"

func (l *latFS) Stat(p string) (filesystem.Stat, error) {
	if p == benchFile {
		return memStat{mode: 0o100644, size: uint64(len(l.data)), inode: 77}, nil
	}
	return l.memFS.Stat(p)
}

func (l *latFS) OpenFile(p string) (filesystem.File, error) {
	if p != benchFile {
		return nil, os.ErrNotExist
	}
	return &latFile{l: l}, nil
}

type latFile struct{ l *latFS }

func (f *latFile) Size() int64  { return int64(len(f.l.data)) }
func (f *latFile) Close() error { return nil }
func (f *latFile) ReadAt(p []byte, off int64) (int, error) {
	if f.l.lat > 0 {
		time.Sleep(f.l.lat)
	}
	if off >= int64(len(f.l.data)) {
		return 0, io.EOF
	}
	n := copy(p, f.l.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// BenchmarkRead measures pipelined READs of one file over 1, 4 and 8
// connections, with ReadAt costing 0, 100 µs and 1 ms. The export option set
// is chosen by BENCH_MODE (see bench_modes_test.go): default, reads, pathops.
// Each connection keeps `window` READs in flight, as a kernel client does.
//
//	BENCH_MODE=pathops go test -run '^$' -bench Read -benchmem -benchtime 2s
//
// time.Sleep rounds up to the timer's grain, so the "100 µs" row is a floor,
// the same for every mode. Throughput is MB/s of file data per second of wall
// time; allocs/op count server and client together (the same client for every
// mode) per READ.
func BenchmarkRead(b *testing.B) {
	mode := os.Getenv("BENCH_MODE")
	if mode == "" {
		mode = "default"
	}
	opts, ok := benchModes[mode]
	if !ok {
		b.Fatalf("BENCH_MODE %q is not one of default, reads, pathops", mode)
	}
	const (
		size   = 8 << 20
		chunk  = 128 << 10
		window = 8
	)
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i)
	}
	for _, lat := range []time.Duration{0, 100 * time.Microsecond, time.Millisecond} {
		for _, conns := range []int{1, 4, 8} {
			b.Run(fmt.Sprintf("lat=%v/conns=%d", lat, conns), func(b *testing.B) {
				fs := &latFS{memFS: fixture(), data: data, lat: lat}
				addr := serve(b, func(s *nfs.Server) {
					if err := s.Export("/", fs, opts...); err != nil {
						b.Fatal(err)
					}
				})
				ws := make([]*wire, conns)
				var fh []byte
				for i := range ws {
					ws[i] = dial(b, addr)
					root := ws[i].mount("/")
					var st nfs.Status
					if fh, st = ws[i].lookup(root, "big.bin"); st != nfs.StatusOK {
						b.Fatalf("LOOKUP: %v", st)
					}
				}
				per := b.N / conns
				if per < 1 {
					per = 1
				}
				b.SetBytes(int64(chunk))
				b.ReportAllocs()
				b.ResetTimer()
				var wg sync.WaitGroup
				for c, w := range ws {
					wg.Add(1)
					go func() {
						defer wg.Done()
						sent, got := 0, 0
						send := func() {
							e := xdr.NewEncoder(nil)
							e.Opaque(fh)
							e.Uint64(uint64(((c*per + sent) * chunk) % size))
							e.Uint32(chunk)
							w.sendCall(6, e.Bytes())
							sent++
						}
						for sent < per && sent < window {
							send()
						}
						for got < per {
							_, d := w.recvReply()
							if st := w.mustU32(d); st != 0 {
								b.Errorf("READ status %d", st)
								return
							}
							got++
							if sent < per {
								send()
							}
						}
					}()
				}
				wg.Wait()
				b.StopTimer()
			})
		}
	}
}
