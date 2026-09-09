# Pinned protocol source

Imported unchanged from the cached crates.io `noq-proto-1.1.1.crate` package.
Package SHA256 (matching the prior workspace Cargo.lock registry checksum):
`baa7b5ccd819a9c68a0d955e67a881032d09b1a17219b1f90b0997a0888e1a15`.

This is a local patch location for the bounded ACK-allocation experiment
tracked by `eversh-5fc.23`, not a protocol version upgrade or production
performance approval. The initial import changes no upstream source or
feature default. Original licenses, package manifest and VCS metadata remain.

Subsequent experimental changes must remain opt-in, retain a feature-off
control, and preserve ACK, multipath, loss, migration, congestion and security
semantics. Do not edit the shared Cargo registry source.

The opt-in `ack-inline-storage` feature keeps the common one-path
`SentFrames::largest_acked` value in an enum containing one inline `(PathId,
packet number)` pair.  A second path promotes it to the original `FxHashMap`,
so multipath replacement and iteration semantics remain unchanged.  The same
feature also avoids the temporary path-id `Vec` when a packet-number space has
exactly one path; multipath retains the existing collection fallback.  The
feature is disabled by default and is not a production approval.

Measured x86_64 debug layouts (feature off/on): largest-ACK storage 32/40
bytes, SentFrames 88/96 bytes, SentPacket 112/120 bytes. The experiment trades
8 extra bytes per tracked packet for avoiding common-path heap requests.
This is not a claim about net memory reduction or latency improvement; both
remain subject to the measured resource and performance gates.

Validation: complete standalone protocol library suites passed with feature
off (388 tests) and on (391 tests), including inline replacement with lower
packet numbers and multipath map promotion/replacement. The isolated test
copy's source and Cargo.toml matched this worktree; no registry source changed.
