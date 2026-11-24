module github.com/go-filesystems/nfs/fat32demo

// Raised with the root module on 2026-11-15 for GO-2026-6859 (net/http, fixed
// in 1.27.4); the reasoning is in ../go.mod.
//
// ⛔ A NESTED MODULE KEEPS ITS OWN DIRECTIVE, so a raise that stops at the root
// leaves this one behind and the sweep keeps reporting the repository. Measured
// the same day: go-fleettools/landingkit had `example` at 1.27.4 and
// `example-i18n` still at 1.27.3 — two of three modules moved, which reads
// exactly like finished work in a diff.
go 1.27.4

require (
	github.com/go-authn/krb5 v0.5.0
	github.com/go-filesystems/fat32 v0.13.1
	github.com/go-filesystems/interface v0.6.0
	github.com/go-filesystems/nfs v0.16.0
	github.com/jcmturner/gokrb5/v8 v8.4.4
)

require (
	github.com/go-filesystems/inflight v0.5.0 // indirect
	github.com/go-volumes/gpt v0.3.0 // indirect
	github.com/go-volumes/safeio v0.1.0 // indirect
	github.com/hashicorp/go-uuid v1.0.4 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/goidentity/v6 v6.0.1 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/net v0.62.0 // indirect
)

// The parent module is this repository; it is not resolvable from the proxy
// at a version that contains the code under test, and never will be for the
// commit being built.
replace github.com/go-filesystems/nfs => ..
