// Package xdr implements just enough of the External Data Representation
// standard (RFC 4506) to speak ONC RPC, NFSv3 and MOUNTv3.
//
// # Why hand-roll it
//
// The whole point of this module is that a go-filesystems image becomes
// mountable with no cgo, no kernel extension and no third-party runtime. A
// dependency on an external XDR package would put someone else's release
// cadence between a driver and a working `mount`, for a wire format that has
// not changed since 1987 and fits in a few hundred lines. So it lives here.
//
// # The whole format, in one paragraph
//
// XDR is big-endian and 4-byte aligned. Every scalar is 4 or 8 bytes.
// Variable-length data carries a 4-byte length, then the bytes, then 0-3 zero
// bytes of padding so the next item starts on a 4-byte boundary. There is no
// type tag on the wire: the reader must already know the shape it is
// decoding, which is why every decode here is driven by the caller.
//
// # Hostile input
//
// A Decoder never allocates on a length it has not first checked against the
// bytes actually remaining in the buffer. A 4 GiB length prefix on a 40-byte
// message therefore costs one comparison, not 4 GiB of RAM. This matters:
// an NFS server accepts unauthenticated bytes from anything that can reach
// its port.
package xdr
