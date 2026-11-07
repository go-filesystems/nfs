package nfs_test

import "github.com/go-filesystems/nfs"

// benchModes maps the BENCH_MODE environment variable of [BenchmarkRead] to the
// export options it measures. It lives apart from the benchmark so that the
// benchmark itself compiles against older tags (v0.11.1 has no
// WithConcurrentPathOps): to measure a tag, copy bench_test.go and
// client_test.go beside a copy of this file without the "pathops" line.
var benchModes = map[string][]nfs.ExportOption{
	"default": nil,
	"reads":   {nfs.WithConcurrentReads()},
	"pathops": {nfs.WithConcurrentPathOps()},
}
