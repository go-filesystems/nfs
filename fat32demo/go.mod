module github.com/go-filesystems/nfs/fat32demo

go 1.26.4

require (
	github.com/go-authn/krb5 v0.2.1
	github.com/go-filesystems/fat32 v0.3.0
	github.com/go-filesystems/interface v0.3.0
	github.com/go-filesystems/nfs v0.3.0
	github.com/jcmturner/gokrb5/v8 v8.4.4
)

require (
	github.com/go-volumes/gpt v0.0.0-20260622072431-e1d6ba3b531c // indirect
	github.com/go-volumes/safeio v0.0.0-20260622072324-7f8eb19f6f8c // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/goidentity/v6 v6.0.1 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	golang.org/x/crypto v0.6.0 // indirect
	golang.org/x/net v0.7.0 // indirect
)

// The parent module is this repository; it is not resolvable from the proxy
// at a version that contains the code under test, and never will be for the
// commit being built.
replace github.com/go-filesystems/nfs => ..
