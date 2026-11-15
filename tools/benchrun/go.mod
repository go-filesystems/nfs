module github.com/go-filesystems/nfs/tools/benchrun

// Raised with the root module on 2026-11-15 for GO-2026-6859 (net/http, fixed
// in 1.27.4); the reasoning is in ../../go.mod.
//
// ⛔ A NESTED MODULE KEEPS ITS OWN DIRECTIVE, so a raise that stops at the root
// leaves this one behind. This repository has THREE modules — root, fat32demo
// and this one — and the fleet sweep lists each separately, so missing one
// keeps the repository on the report while looking finished in the diff.
go 1.27.4
