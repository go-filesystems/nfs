module github.com/go-filesystems/nfs/fat32demo

go 1.26.4

require (
	github.com/go-filesystems/fat32 v0.3.0
	github.com/go-filesystems/interface v0.3.0
	github.com/go-filesystems/nfs v0.0.0
)

require (
	github.com/go-volumes/gpt v0.0.0-20260622072431-e1d6ba3b531c // indirect
	github.com/go-volumes/safeio v0.0.0-20260622072324-7f8eb19f6f8c // indirect
)

// The parent module is this repository; it is not resolvable from the proxy
// at a version that contains the code under test, and never will be for the
// commit being built.
replace github.com/go-filesystems/nfs => ..
