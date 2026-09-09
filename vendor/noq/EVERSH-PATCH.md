# Downstream noQ latency experiment

This directory is the exact `noq` 1.1.1 crate published on crates.io, whose
crate SHA-256 is
`09e4bb6601fa543c110d8957813267d5a8d775a0f8fbaccf1f615d06ba9b10da`.
Upstream is licensed `MIT OR Apache-2.0`; the unmodified licence texts remain
in `LICENSE-MIT` and `LICENSE-APACHE`.

The workspace patch exists only for the feature-gated everudp QUIC DATAGRAM
experiment. The downstream delta is deliberately confined to:

- `Cargo.toml` and `Cargo.toml.orig`: declare the
  `immediate-datagram-flush` and `inline-received-events` features; the
  normalized manifest also has an empty workspace marker so the vendored
  crate can run its own verification suite;
- `src/connection.rs`: expose a best-effort immediate transmit pass and, when
  enabled, apply endpoint-routed events before waking the ordinary connection
  driver; and
- `src/endpoint.rs`: retain a weak connection handle for that inline event
  path without changing connection ownership; and
- `examples/README.md`: remove five trailing spaces required by the parent
  repository's whitespace gate, with no content change.

The ordinary noQ connection driver remains responsible for timers, blocked
socket recovery, retransmission, congestion control, migration, and shutdown.
Without both downstream features, behavior is the published 1.1.1 behavior.
This vendoring is experimental evidence, not an upstream provenance claim or
approval for production release.
