module github.com/go-filesystems/nfs

// ⛔ THE PATCH, AND THIS REPOSITORY IS ONE OF THE NINE THE FLEET SWEEPS FOR
// EXPOSURE. This line is the only one of the three Go pins a CONSUMER honours:
// `go install` with GOTOOLCHAIN=local obeys it, while the CI pin merely builds
// our artefacts and the toolchain stamped in a binary describes one executable.
//
// Raised to 1.27.4 on 2026-11-15 for GO-2026-6859 — published 2026-11-11,
// CVE-2026-97054, "HTTP/1 server crash due to MaxBytesReader header race in
// net/http", stdlib, fixed in 1.26.11 and 1.27.4. Read at
// https://vuln.go.dev/ID/GO-2026-6859.json rather than quoted from notes.
//
// ⛔ AND HERE IT IS NOT MERELY A CONTRACT. This repository is named in
// go-fleettools/fleettools/.github/vulnscan-exposed.txt, the list cut BY
// EXPOSURE rather than by convenience: both repositories that actually REACHED
// an advisory in the fleet's 58 decoders were network-facing ones.
//
// Measured, not assumed: `modfloor --floor 1.27.4` read the directive this
// module PUBLISHED at v0.14.0 as `go 1.27.3`, so every consumer installing it
// under GOTOOLCHAIN=local built against an unpatched standard library. Eight of
// the nine network-facing modules read BELOW at that moment; only
// go-webengine/engine was already at 1.27.4.
//
// ⛔ Renovate will never offer this edit, measured on 2026-11-15: its
// github-actions manager maintains the CI pin (`with: go-version`, dependency
// `go`, type uses-with) and its gomod manager SEES this directive — the
// dependency dashboard lists it — while proposing nothing for it. Of the three
// pins, the only one a consumer honours is the unwatched one.
go 1.27.4

require (
	github.com/go-authn/krb5 v0.3.3
	github.com/go-filesystems/inflight v0.2.0
	github.com/go-filesystems/interface v0.6.0
	github.com/jcmturner/gokrb5/v8 v8.4.4
)

require (
	github.com/hashicorp/go-uuid v1.0.4 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/goidentity/v6 v6.0.1 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/net v0.62.0 // indirect
)
