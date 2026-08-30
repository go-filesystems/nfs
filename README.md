<p align="center"><img src="https://raw.githubusercontent.com/go-filesystems/brand/main/social/go-filesystems.png" alt="go-filesystems/nfs" width="720"></p>

# nfs

[![Go Reference](https://pkg.go.dev/badge/github.com/go-filesystems/nfs.svg)](https://pkg.go.dev/github.com/go-filesystems/nfs)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![CI](https://github.com/go-filesystems/nfs/actions/workflows/ci.yml/badge.svg)](https://github.com/go-filesystems/nfs/actions/workflows/ci.yml)

Pure-Go (CGO=0) **NFSv3 server** that exports any
[`go-filesystems/interface`](https://github.com/go-filesystems/interface)
`Filesystem` — so every driver in the family becomes something you can
`mount` and browse with ordinary tools, on **macOS, Linux and Windows**, from
one portable binary.

No kernel extension. No FSKit entitlement. No cgo. No root on the server side.

## Why NFS and not FUSE or FSKit

This is the whole design decision, so it is worth stating plainly.

Mounting an arbitrary filesystem *natively* on macOS means **FSKit**: an app
extension carrying the `com.apple.developer.fskit.fsmodule` entitlement, which
requires a provisioning profile issued by Apple. That is a distribution wall,
not a programming problem — no amount of correct code gets past it, and the
result would only ever mount on macOS anyway. **FUSE** means a kernel
extension (or macFUSE's system extension), which is a second wall plus a
per-OS C ABI.

NFS is already in every one of those kernels **as a client**. macOS mounts it,
Linux mounts it, Windows mounts it. So the mountable surface is a network
protocol, the server is ordinary portable Go, and there is no kext, no
entitlement, no cgo and no OS-specific code anywhere in this module — which
preserves exactly the property `go-filesystems` exists for: independence from
the host operating system.

The cost is honest and worth naming: a loopback TCP round trip per operation
instead of a syscall, and NFSv3's stateless model (no open file descriptors,
no byte-range locks, no change notifications).

## Install

```sh
go get github.com/go-filesystems/nfs
```

## Usage

```go
fsys, err := fat32.Open("disk.img", -1)
if err != nil {
    log.Fatal(err)
}
defer fsys.Close()

srv, err := nfs.New()
if err != nil {
    log.Fatal(err)
}
if err := srv.Export("/", fsys); err != nil {   // read-only by default
    log.Fatal(err)
}
log.Fatal(srv.ListenAndServe("127.0.0.1:12049"))
```

Both the **MOUNT** and **NFS** programs are served on that single port, so no
`rpcbind` — and therefore no privileged port 111, and therefore no root on the
server side — is involved. Clients are pointed at it directly:

```sh
# macOS
sudo mount -t nfs -o vers=3,tcp,port=12049,mountport=12049,noresvport \
    127.0.0.1:/ /Volumes/img

# Linux
sudo mount -t nfs -o vers=3,tcp,port=12049,mountport=12049,nolock \
    127.0.0.1:/ /mnt/img

# Windows (Client for NFS)
mount -o anon,mtype=hard 127.0.0.1:/ X:
```

Mounting still needs root on the **client** side. That is the OS's rule about
who may alter the namespace, and nothing here can or should change it.

### Try it on a real image

`fat32demo` is a nested module that wires a real FAT32 image to the server:

```sh
cd fat32demo && go run . -image disk.img -addr 127.0.0.1:12049
```

It prints the exact `mount` line for your platform.

## What is implemented

| | |
|---|---|
| **RPC / XDR** | ONC RPC v2 over TCP with record marking (RFC 5531), XDR (RFC 4506), AUTH_NULL and AUTH_UNIX — all written here, zero dependencies outside the standard library |
| **MOUNT v3** | NULL, MNT, DUMP, UMNT, UMNTALL, EXPORT |
| **NFS v3 read** | NULL, GETATTR, LOOKUP, ACCESS, READLINK, READ, READDIR, READDIRPLUS, FSSTAT, FSINFO, PATHCONF |
| **NFS v3 write** | SETATTR, WRITE, CREATE, MKDIR, SYMLINK, REMOVE, RMDIR, RENAME, LINK, COMMIT |
| **Refused, truthfully** | MKNOD (`NFS3ERR_NOTSUPP`) — device, socket and FIFO nodes have no representation in the `Filesystem` contract, and a silent regular file would be worse than an error |

Write support is gated per export: exports are **read-only by default**, since
most of what this is pointed at is a forensic or build artefact and an
accidental write to one is unrecoverable. Opt in with `nfs.ReadWrite()`.

Not implemented, deliberately: UDP transport (every current client negotiates
TCP for v3), rpcbind registration (it needs privileged port 111 — the one
thing this module exists to avoid), NLM byte-range locking (mount with
`nolock`), and RPCSEC_GSS.

## File handles

64 opaque bytes is the hardest design question in an NFS server, so the choice
is documented rather than merely implemented. A handle is 60 bytes:

```
[0:4)   magic + version   rejects a handle from another layout
[4:12)  export id         which export this handle belongs to
[12:20) epoch             random per server process
[20:28) slot              dense index into this process's path table
[28:60) HMAC-SHA256       over bytes [0:28) with a per-process random key
```

- **It discloses nothing.** No path — paths do not fit in 64 bytes and would
  leak the tree's shape to anyone watching the wire — and no inode number
  either: on FAT32 the "inode" is the first cluster, which is `0` for every
  empty file. All a handle reveals is "the *N*th path this server was asked
  about".
- **It cannot be forged.** Without the MAC, the slot is a small integer a
  client could walk to enumerate every path the server ever resolved,
  including outside the export it mounted. With it, a handle the server did
  not mint fails in constant time (`hmac.Equal`) and is answered
  `NFS3ERR_BADHANDLE`.
- **"Surviving the server" means being detectably stale.** A handle cannot
  outlive this process's in-memory table, so one minted before a restart must
  be *rejected*, never reinterpreted. The random epoch guarantees that: old
  handles fail the epoch check and are answered `NFS3ERR_STALE`, which is
  precisely the signal RFC 1813 designed — the client drops its cache and
  walks down from the mount root again. That is a working mount across a
  restart with zero risk of a stale handle resolving to the wrong file. A
  persistent variant (stable key plus a table checkpoint) fits the same 60
  bytes without a format change.
- **Slots are never recycled.** Recycling is what would make a stale handle
  *dangerous* rather than merely stale, and an LRU would silently invalidate
  handles a client still holds. The table grows with the number of distinct
  paths looked up, bounded by 2²⁰; past that the server answers
  `NFS3ERR_SERVERFAULT` rather than evicting something in use.

## Performance, and the two gaps in the contract

Both are properties of
[`interface`](https://github.com/go-filesystems/interface), not of this
server, and both are measured rather than assumed:

**Reads.** A driver implementing the optional `Opener` capability
(`OpenFile(path) (File, error)` returning an `io.ReaderAt`) is read at the
offset the client asked for. A driver *without* it is read through `ReadFile`,
which materialises the **entire file** for every READ — so streaming a 4 GiB
image in 128 KiB reads costs 32768 full-file reads. Correct, but only usable
for small files.

**Writes.** A driver whose `OpenFile` returns a
[`filesystem.WritableFile`](https://pkg.go.dev/github.com/go-filesystems/interface#WritableFile)
— `io.WriterAt` + `Truncate` + `Sync` — is written **at the offset the client
sent**, and the request costs the bytes it carries.

A driver *without* one is written the only way `Filesystem` allows: `WriteFile`
replaces a whole file, so a WRITE at a non-zero offset reads the file, splices,
and writes it back, at **O(filesize) per request**. A client streaming a file
in `wtpref`-sized blocks pays that per block, so the transfer is quadratic.

The numbers below are taken by the `live-write-bench` CI job, whose arms run
**in the same job on the same runner** against the same image, differing in one
flag (`fat32demo -no-positional`, which hides the driver's capability). A real
Linux kernel NFS client writes with `wsize=65536` and `oflag=direct`, so each
64 KiB block is one WRITE RPC:

| write path | 2 MiB | 8 MiB |
|---|---|---|
| whole-file (`ReadFile` + splice + `WriteFile`) | 0.66 s (3.2 MB/s) | **31.13 s (269 kB/s)** |
| positional (`filesystem.WritableFile`) | 0.81 s (2.6 MB/s) | **1.51 s (5.5 MB/s)** |

Two sizes, because the claim is a **shape**, not a number. At 2 MiB the fixed
per-request cost dominates and the two paths are inside each other's run-to-run
variance — the whole-file arm even wins, which is exactly why a single small
measurement proves nothing. Quadruple the data and the whole-file path costs
**47× more** while the positional path costs **1.9×**: quadratic against linear,
which is the cost model, visible. The job fails if the 8 MiB ratio drops below
5×.

The 23 s / 90 kB/s that this section used to quote was measured on another
machine at an unrecorded size; the 8 MiB row above is the same defect, taken
reproducibly. Pinning the driver back to `fat32` v0.1.0 — the version named in
this module's `go.mod` when that figure was taken — is a third arm of the job,
and it lands within noise of the second, which says the gain is the positional
write and not the allocator fix that shipped alongside it in `fat32` v0.3.0.

The original defect was not only slowness: a `soft,timeo=50` mount reported
`EIO` partway through, because a single WRITE round-trip exceeded the client's
timeout. That mount is now part of the same job, and must complete.

**FSSTAT.** There is no statfs in the contract, so an export with no
[`WithCapacity`](https://pkg.go.dev/github.com/go-filesystems/nfs#WithCapacity)
reports zeros rather than inventing a plausible number that would make `df`
confidently wrong.

**Timestamps.** No driver reports an mtime, so every file currently carries
the server's start time. This is visible in `ls -l` and is reported here
rather than hidden; the fix is a timestamp accessor on `interface.Stat`.

**Error taxonomy.** `interface` defines no sentinel errors, so drivers report
"not found" however they like (`iso9660` has typed sentinels that do not wrap
`fs.ErrNotExist`; `fat32` uses bare `fmt.Errorf`). Every procedure that can
afford to establishes existence and type with an explicit `Stat`; a small
substring table is the documented last resort. The real fix belongs upstream.

## Security posture

AUTH_UNIX credentials are **claims, not proofs**: a client says "uid 501" and
the wire cannot disagree. This server therefore does not use them for access
decisions at all. Access is controlled by two things you choose: **which
address the listener is bound to** (bind to loopback unless you mean
otherwise), and **whether an export is read-only**. Do not put this on a
public interface expecting the uid fields to protect anything.

Everything that arrives from the network is treated as hostile input: the XDR
decoder never allocates on a length it has not first checked (a 4 GiB length
prefix on a 40-byte message costs one comparison), RFC 4506's zero-padding
requirement is enforced rather than ignored, and the only untrusted name that
enters the path space — the single component in a `diropargs3` — is validated
in one place, with `..` clamped at the export root so no sequence of lookups
can name anything above it.

## Verification

`go test` drives the server **through the wire**, not through its Go API: an
in-process call cannot catch a wrong XDR alignment, a missing discriminant, or
a reply whose fields are in the wrong order, and those are exactly the defects
that make a real mount fail.

Beyond that, the server has been mounted by a **real Linux kernel NFS client**
against a FAT32 image created and populated by **macOS's own tools**
(`hdiutil` + `newfs_msdos`), with `ls`, `cat`, `find` and `sha256sum` over the
mount matching the source bytes exactly — see the pull request that introduced
this module for the transcript.

Coverage is **100 % of statements**, error branches included, gated in CI, on
amd64, arm64, riscv64, loong64, ppc64le and s390x (big-endian — NFS is a
big-endian protocol, so this is not a formality).

## License

BSD-3-Clause — see [LICENSE](LICENSE).
