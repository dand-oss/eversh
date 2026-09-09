# everudp Quinn evaluation

This is an isolated, bounded engine comparison package. It compiles the
production `everudp` sources by path and aliases the source-level `noq` crate
name to Quinn 0.11.11. The package is an evaluation engine, not a facade and
not the default transport; the root workspace and production Cargo manifests
remain unchanged.

The path dependency on `everssh` is kept on the vendored NoQ implementation by
the local workspace patches. This permits the shared bootstrap, identity, and
policy code to be exercised without changing the default production dependency
graph (the root workspace's lint registration is the only shared source change
needed to recognize the evaluation cfg).

The package deliberately contains only the bounded comparison surface and the
admission, handshake, transport, resume, wire, and process tests. No benchmark
or qualification command is part of this package; those remain governed by the
existing frozen gates and are run only after the compatibility build is green.

The `everudp_quinn_evaluation` cfg is emitted by `build.rs` so the production
transport module can isolate the small number of NoQ-specific configuration
calls. Security policy, stream layout, reconnect behavior, queue limits, and
the frozen performance thresholds are unchanged.

## Reviewed API mapping

The package pins Quinn 0.11.11, quinn-proto 0.11.15 and rustls 0.23.43,
with default engine features off and ring, Tokio and bloom enabled. The lock
was seeded from the production lock; existing shared dependency versions remain
unchanged. Added engine dependencies still require the full dependency audit.
Quinn and its protocol crate declare MIT OR Apache-2.0 and Rust 1.85; the
project's Rust 1.88 check remains mandatory for the resolved Linux build.

- Quinn re-exports rustls, so the existing SPKI and client-certificate verifiers
  share the same rustls types with everssh. No TLS compatibility facade is used.
- `Endpoint::set_default_client_config` requires mutable access during Quinn
  endpoint construction. The cfg adds only that local mutable binding.
- Quinn uses the existing connection idle timeout and keepalive settings. It
  has no additional NoQ per-path timeout settings.
- NoQ's observed-address, multipath, NAT traversal and nonstandard server
  handshake migration setters are omitted only for this evaluation. Quinn
  lacks these draft extensions. In quinn-proto 0.11.15,
  `connection/mod.rs::handle_packet` rejects a changed remote during handshake;
  `handle_event` rejects remote migration when the local side is a client.
  Standard post-handshake client migration remains enabled. These source checks
  do not replace behavioral migration/admission gates.

Primary API reference: [Quinn 0.11.11](https://docs.rs/quinn/0.11.11/quinn/).
The downloaded versioned crate sources, rather than inferred API similarity,
are authoritative for the mapping above.

From the repository root, the feasibility test command is:

```sh
cargo test --manifest-path spikes/everudp-quinn-eval/Cargo.toml \
  --features cli --locked --lib --test admission --test handshake \
  --test transport --test resume --test wire -- --test-threads=1
```

NoQ-only experiment/diagnostic cfg names are registered for shared-source
checking, but are not exposed as package features or silently implemented as
no-ops. No timing or production acceptance is implied by a successful build.
