# M1 Implementation Plan — Rust workspace and protocol skeleton (eversh-chl.2)

Decision-complete. No functional session behavior (that is M2/M3); everything
here compiles, is tested at its boundaries, and fails closed. Normative
sources: plans/design.md §2–§4, §5.2/5.4, §6.2, §7, §8, §10–§13 (Milestone 1);
plans/reference.md (adopted references); M0 results
(spikes/noq-m0/results.md).

## 1. Locked workspace layout

```
eversh/
├── Cargo.toml              # [workspace] resolver = "2"; members = crates/*; exclude = ["fuzz", "spikes"]
├── Cargo.lock              # committed; exact pins per §3
├── rust-toolchain.toml     # channel 1.95.0 (M0 build toolchain)
├── deny.toml               # M0 policy (permissive-only; ban list in §3)
├── .github/workflows/ci.yml
├── crates/
│   ├── everpty/            # lib + bin `everpty`; integration tests in crates/everpty/tests/
│   ├── everlink/           # lib + bin `everlink`; integration tests in crates/everlink/tests/
│   └── eversh/             # lib + bin `eversh` (multi-role); cross-crate boundary tests in crates/eversh/tests/
└── fuzz/                   # separate [workspace] (cargo-fuzz targets only; see §7)
```

One workspace, three library crates, **exactly three binary targets**:
`everpty`, `everlink`, `eversh`. The `eversh` binary links all three libs and
dispatches private roles (`eversh __everpty …`, `eversh __everlink …`) via a
pure `select_role(args) -> Role` function that chooses exactly one logical
role **before** any runtime initialization; a role-dispatched process never
constructs a Tokio runtime for a non-everlink role and never passes terminal
bytes through the supervisor library. There is **no root `tests/`
directory** — all integration tests live in their owning crate's `tests/`.
`spikes/noq-m0/` stays outside the workspace (own `[workspace]` marker) and
is frozen as evidence; `fuzz/` is its own workspace excluded from the root so
production builds yield exactly the three binaries.

## 2. Crate boundaries (enforced by deny.toml graph policy + metadata tests)

| Crate | may depend on | must NOT depend on |
|---|---|---|
| everpty (core lib, M1) | std only — **no PTY syscall dependency in M1**; schemas, limits, and pure state machines only | tokio, noq, rustls, ring, rcgen, libc/nix (until M2), any async runtime, terminal emulator |
| everpty-bin (`[[bin]]` in everpty) | everpty lib + `clap = "=4.6.6"` (`default-features = false`, `features = ["std", "derive", "help", "usage", "error-context"]`) at the binary edge only | |
| everpty (M2 additions) | `nix = "=0.31.3"` with minimal features `fs, poll, process, signal, socket, term, user` (`term` provides pty); direct `libc` only for APIs nix lacks, behind tiny audited wrappers | |
| everlink (lib) | tokio 1 (one runtime, owned), `noq =1.1.1` (M0 features), `ring` 0.17, `rcgen = "=0.13.2"` (features `ring` only), `rustls` **only via `noq::rustls`** (no direct rustls dep) | second async runtime, aws-lc, any SSH implementation, Asupersync, a custom X.509/DER generator |
| everlink-bin | everlink lib, tokio | |
| eversh (lib) | everpty, everlink libs (typed APIs), std | QUIC endpoint, PTY fd, relay loop, terminal I/O |
| eversh-bin | eversh lib + the other roles' entry points via lib APIs + clap as above | |

- clap 4.6.6 (MIT/Apache-2.0, Rust ≥1.85 ≤ our MSRV 1.88) is pinned exactly
  and exposed as an **optional `cli` feature** in each crate; each `[[bin]]`
  declares `required-features = ["cli"]`. No hand-written parser. Parsing
  stays in `[[bin]]`/CLI modules; libraries take typed `Config` structs and
  never read global args, print, or exit. A dedicated gate proves the core
  libraries build without clap:
  `cargo +1.95.0 check --workspace --no-default-features --lib --locked`
  (plus deny.toml allows clap only when a CLI feature is enabled).
- rcgen 0.13.2 (MIT OR Apache-2.0) is kept, audited, and used by everlink
  for ephemeral self-signed certificate generation in M3. No rcgen ban, no
  custom DER **generator**; everlink still owns the read-only SPKI
  **extraction** walker (M0-ported, vector-tested) for pinning — parsing is
  not generation.

## 3. Dependency pins (from M0, in workspace Cargo.lock)

- Toolchain: build 1.95.0 (`rust-toolchain.toml`); all crates
  `rust-version = "1.88"`; CI checks both.
- `noq = { version = "=1.1.1", default-features = false,
  features = ["runtime-tokio", "rustls", "ring", "bloom"] }`
  (crate SHA-256 `09e4bb…10da` verified in the lockfile gate).
- `tokio = 1` with features `rt-multi-thread, net, process, io-util, io-std,
  time, sync, macros` — everlink only.
- `ring = 0.17` (SHA-256, CSPRNG; M0's rcgen certificate path uses
  ring-backed ECDSA P-256, not Ed25519) — everlink only.
- `rcgen = "=0.13.2"`, `default-features = false`, `features = ["ring"]` —
  everlink only, M3-facing but pinned and audited now so the graph is stable.
- `clap = "=4.6.6"`, `default-features = false`, `features = ["std",
  "derive", "help", "usage", "error-context"]` — optional `cli` feature per
  crate; binary edges only.
- `nix = "=0.31.3"` (`fs, poll, process, signal, socket, term, user`) — M2,
  everpty only; `libc` only as tiny audited wrappers for gaps.
- Dev/test-only: `cargo_metadata = "=0.23.1"` (for the §8 graph test; no
  production impact). Fixtures are byte vectors generated deterministically in-tree —
  no proptest.
- deny.toml: M0 allow-list (MIT, Apache-2.0, Apache-2.0 WITH LLVM-exception,
  BSD-3-Clause, ISC, Unicode-3.0, Zlib) + bans: russh/thrussh/ssh2/
  libssh2-sys/openssh, async-std/smol, aws-lc-rs/aws-lc-sys;
  `yanked = deny`; unknown registries/git denied. (No rcgen ban.)

## 4. Wire schemas (v1, all length-checked before allocation, all integers big-endian)

### 4.1 everpty local frame (design §5.2, §4)

```
u32 body_length (BE) | u8 protocol_version=1 | u8 message_kind | payload[]
```
- Header is 6 bytes; `body_length` counts version+kind+payload. Default max
  body 64 KiB (`Limits::frame_max_body`, contract value); **reject before
  allocation** — read header, validate `body_length <= max`, only then size
  the buffer (asserted by a reader that panics on oversized reads).
- Kinds (u8): `Hello=1, HelloAck=2, Busy=3, Input=4, Output=5, Resize=6,
  Ownership=7, DetachWriter=8, Kill=9, Ping=10, Pong=11, Exit=12, Error=13`.
- Raw PTY bytes appear **only** in `Input`/`Output` payloads (`&[u8]`, no
  UTF-8 assumption). Control strings (Hello names, Error text) are UTF-8 and
  bounded (name ≤ 64 bytes, charset `[A-Za-z0-9._-]`, first char
  alphanumeric; error text ≤ 256 bytes).
- **Hello**: `u8 role (1=Writer, 2=Observer) | u8 take_over (0/1) |
  u16 name_len(BE) | name bytes | u16 rows(BE) | u16 cols(BE)`.
- **HelloAck**: `u32 client_id(BE) | u8 broker_protocol_version | u8 status
  (1=WriterGranted, 2=ObserverAccepted)`. A busy writer request returns the
  separate **Busy** frame instead; there is no Busy status here.
- **Busy**: `u32 current_writer_id(BE)`.
- **Input/Output**: raw bytes filling the remainder of the body.
- **Resize**: `u16 rows(BE) | u16 cols(BE)`.
- **Ownership**: `u8 event (1=Granted, 2=Revoked)` — takeover is expressed
  as Revoked to the old writer followed by Granted to the new one; no third
  state.
- **DetachWriter / Kill / Ping / Pong**: empty payload.
- **Exit**: `u8 kind (0=exit code, 1=signal) | u32 value(BE)`.
- **Error**: `u16 code(BE) | u16 len(BE) | UTF-8 bytes (≤256)`.
- Unknown kind or unsupported version ⇒ typed `FrameError`, connection
  closed, nothing allocated past the cap.

### 4.2 everlink bootstrap record (design §6.1, §4)

One newline-terminated line over authenticated SSH stdout, cap 4096 bytes
including the newline (contract value), checked before parse; trailing
bytes, duplicate records, or a second line fail closed. v1 encoding:
`everlink v1 HOST PORT SPKI_HEX TOKEN_HEX PID\n` — HOST is an IPv4 or IPv6
literal (no name resolution at parse), SPKI_HEX and TOKEN_HEX are exactly 64
hex characters, PID is decimal ≤ u32. The parser is total: every byte
position validated, no trailing fields. The token is 256-bit, constant-time
compared, never logged or placed in argv/environment/metadata.

### 4.3 everlink auth frame (design §6.2)

Exactly 35 bytes, first bytes of the single bidirectional QUIC stream:
`u8 version=1 | token[32] | u16 target_port(BE)` — read_exact or reject.
ALPN `eversh-link/1`; TLS 1.3 via the noq rustls path; 0-RTT disabled
(resumption disabled); SPKI-pinned verifier (M0 DER walker + verifier
ported with unit vectors). Extra streams, datagrams, wrong version, wrong
target, or token reuse ⇒ connection close; server Retry/address validation
forced.

### 4.4 eversh remote-control request (design §7)

`u8 version=1 | u16 arg_count(BE) | repeated[u32 arg_len(BE) | arg bytes]`,
total cap 64 KiB before decode (contract value). Decoding rejects NUL inside
any arg, rejects `arg_count > 64`, and produces `Vec<Vec<u8>>`; encoded
bytes are **never** evaluated as shell syntax; fixed command words only.
Session names validated as §4.1 before any path construction.

### 4.5 Unix socket pathname

Pathname-form socket paths are capped at **107 bytes plus NUL**
(`sun_path[108]` includes the NUL); checked before bind. The session-name
rules and state-root layout keep constructed paths far below the cap; a
near-limit path is a typed error, never truncation.

## 5. Typed errors and library API shape

- Each crate owns `enum Error` (e.g. `everpty::Error::{AlreadyExists,
  NotLive, Busy{current_writer_id: u32}, Frame(FrameError), Io, NameInvalid,
  SocketStale, StartupDeadline, PathTooLong, …}`), implements
  `std::error::Error + Send + Sync` (static trait assertions in tests), no
  swallowed sources. No panics on protocol input; `unwrap` forbidden outside
  `#[cfg(test)]` (clippy `unwrap_used` enabled per crate).
- Libraries take `&Config` structs, return `Result`; **no** printing,
  `std::env::args`, or `process::exit` anywhere under a crate's lib target.
- M1 delivers: full encode/decode for §4 schemas, `Limits` structs with all
  design §4 values named, lifecycle **state enums** (`everpty::Lifecycle:
  Starting|WaitingForWriter|Running|Exited|Failed`, writer ownership
  `NoWriter|Writer(u32)`) with pure transition functions + exhaustive
  tests — but no running broker/PTY/QUIC (M2/M3). Binary targets compile,
  print clap help, and dispatch roles with typed "not implemented in M1"
  errors (exit code 3) — nonfunctional by design §13.M1.

## 6. Limits

Contract (non-provisional) values: `frame_max_body` 64 KiB,
`bootstrap_record_max` 4096, `auth_frame_len` 35, `remote_control_max`
64 KiB, `name_max` 64, `error_text_max` 256, `arg_count_max` 64,
`unix_path_max` 107+NUL, **token length 32 bytes (256-bit)**, and **exactly
one application bidirectional QUIC stream**.

**All runtime limits are PROVISIONAL (M0 candidates; remeasure in M2/M3 per
design §4)** and are marked so in doc comments plus a
`limits-are-provisional` inventory test naming every one: copy_buf 16 KiB,
send/receive_window 384 KiB, max_bi_streams 1, server_lease 30 s,
handshake_timeout 10 s, idle_timeout 30 s, stall_timeout 20 s,
drain_timeout 5 s, finalize_timeout 5 s, bootstrap_timeout 20 s,
max_pending_handshakes 4; everpty-facing (M2-consuming, defined now):
startup_deadline 10 s, kill_grace 5 s, writer_queue_bytes 256 KiB,
observer_queue_bytes 64 KiB, observer_count 8, aggregate_queue_bytes 1 MiB.

## 7. Tests, fixtures, fuzzing, audits (M1 scope)

1. **Unit**: codec round-trips for every frame/record; total-parser tests
   (every truncation 0..=n, every invalid kind/version/length,
   over-length rejected **before** allocation via the panicking-reader
   assertion).
2. **Arbitrary-byte fixtures**: deterministic LCG-generated buffers
   (0 B…1 MiB, incl. all-0xFF, partial UTF-8, embedded NUL, CR/LF) in
   `crates/everpty/tests/fixtures.rs` (shared via a test-support module);
   multi-frame codec byte-identity tests stream fixtures through
   encode→decode sequences (many frames per buffer, partial reads, and
   arbitrary split points) asserting exact byte round-trips with no `str`
   conversion (payload types are `Vec<u8>` — compile-time guarantee).
3. **Lifecycle state machines**: exhaustive transition tables for everpty
   lifecycle + writer ownership (Busy without mutation, atomic takeover =
   Revoked→Granted at an output boundary, first-cause-wins shutdown —
   M0's ShutdownState tests ported).
4. **Binaries**: clap help snapshot per binary; role dispatch is pure
   `select_role` and is exhaustively tested (§8).
5. **Fuzz** — `fuzz/` is a **separate cargo workspace** (own Cargo.toml
   `[workspace]`, root `exclude`s it), containing `fuzz_frame`,
   `fuzz_bootstrap_record`, `fuzz_auth_frame`, `fuzz_remote_control`.
   Targets pin `libfuzzer-sys = "=0.4.13"` and assert no panic and no
   allocation over the caps. Building them requires cargo-fuzz (pinned
   release 0.13.2) and a nightly toolchain (`nightly-2026-08-20`) — both
   **installations are ask-first**, never automatic; CI only formats,
   checks, and audits the fuzz workspace separately on stable. **Actual
   fuzz runs are ask-first, and M1 cannot close until all four bounded runs
   are authorized and executed**; the gate list records them as
   pending-by-approval.
6. **Gates** (local + CI, all must pass): `cargo +1.95.0 fmt --all --
   --check`; `cargo +1.95.0 clippy --workspace --all-targets --all-features
   -- -D warnings` (+ `unwrap_used`); `cargo +1.95.0 test --workspace
   --all-features --locked`; `cargo +1.88.0 check --workspace --all-targets
   --locked`; `cargo +1.95.0 check --target aarch64-unknown-linux-gnu
   --locked`; `cargo +1.95.0 check --manifest-path fuzz/Cargo.toml
   --all-targets --locked`; `cargo-deny --all-features --locked check`
   (cargo-deny 0.20.2); the §8 metadata graph test runs inside the workspace
   test suite.
7. **Licence/attribution**: per-crate `license = "MIT OR Apache-2.0"`;
   LICENSE files already present; NOTICE not needed in M1 (Keepty is
   reference-only, nothing adapted).

## 8. Boundary enforcement — metadata and API assertions

- **cargo-metadata graph test** (dev-dependency `cargo_metadata`; runs
  `cargo metadata --format-version 1` on the workspace): asserts workspace
  members are exactly `crates/everpty`, `crates/everlink`, `crates/eversh`;
  `fuzz` and `spikes` are not members; the workspace exposes exactly three
  binary targets (`everpty`, `everlink`, `eversh`); everpty's transitive
  closure contains no tokio/noq/ring/rcgen/clap; everlink's contains no SSH
  implementation or second async runtime; feature unification does not leak
  tokio into everpty.
- **Compile-time trait assertions**: each crate's tests assert
  `Error: std::error::Error + Send + Sync + 'static`.
- **Runtime isolation by pure role selection + injected counter**: role
  dispatch is `select_role(args) -> Role` (pure); everlink's runtime builder
  exposes a test-only construction counter. Tests dispatch every
  non-everlink role (`__everpty`, supervisor commands, help, no-args) and
  assert the counter stays **zero**; only `__everlink` constructs the single
  Tokio runtime. No source greps, no cargo-tree-failure checks, no
  self-reported dependency constants.

## 9. CI (concrete, `.github/workflows/ci.yml`, added in commit 6)

All jobs: `runs-on: ubuntu-24.04`, pinned
`actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8`, explicit
`cargo +<toolchain>` commands (no bare `cargo`), cargo-deny pinned to
**0.20.2**. No nightly anywhere; no fuzz execution.

- `check` (1.95.0): `cargo +1.95.0 fmt --all -- --check`;
  `cargo +1.95.0 clippy --workspace --all-targets --all-features -- -D
  warnings`; `cargo +1.95.0 test --workspace --all-features --locked`.
- `msrv` (1.88.0): `cargo +1.88.0 check --workspace --all-targets --locked`.
- `cross` (1.95.0, after `rustup target add aarch64-unknown-linux-gnu`):
  `cargo +1.95.0 check --target aarch64-unknown-linux-gnu --locked`.
- `fuzz` (stable only, separate workspace): `cargo +1.95.0 fmt
  --manifest-path fuzz/Cargo.toml -- --check`; `cargo +1.95.0 check
  --manifest-path fuzz/Cargo.toml --all-targets --locked`; then
  `cargo +1.95.0 install cargo-deny --version 0.20.2 --locked` and
  `cargo-deny --manifest-path fuzz/Cargo.toml --all-features --locked
  check`.
- `audit`: `cargo +1.95.0 install cargo-deny --version 0.20.2 --locked`
  then `cargo-deny --all-features --locked check`.
- Every job installs its Rust toolchain explicitly with `rustup toolchain
  install <version> --profile minimal` before running cargo commands.

## 10. Atomic commit sequence (each green before the next)

1. `Added: workspace: Establish three-crate workspace with pins, toolchain, deny policy`
   — workspace Cargo.toml/lock, rust-toolchain.toml, deny.toml, crate
   skeletons (`rust-version = 1.88`), **plus plans/m1-plan.md** (this
   document, the record of decisions).
2. `Added: everpty: Define versioned length-prefixed frame codec with boundary tests`
   — §4.1 codec + name validation + panicking-reader allocation tests.
3. `Added: everpty: Add lifecycle and writer-ownership state machines`
   — §5 transitions + exhaustive tests.
4. `Added: everlink: Define bootstrap record, auth frame, SPKI pinning types`
   — §4.2/4.3 total parsers, DER extraction walker + pin verifier with
   vectors (no direct rustls dep).
5. `Added: eversh: Define bounded remote-control request encoding`
   — §4.4 + session-name rules + path-length checks.
6. `Added: bins: Wire clap CLIs, help, single-role dispatch, CI workflow`
   — clap 4.6.6 at three edges, pure `select_role` + runtime-counter
   isolation tests, `.github/workflows/ci.yml`.
7. `Added: fuzz: Add isolated cargo-fuzz workspace for wire decoders`
   — separate workspace + four targets (stable check only).
8. `Added: tests: Add arbitrary-byte fixtures and cargo-metadata boundary gates`
   — LCG fixtures, graph test, trait assertions, provisional-limits
   inventory.

Every commit message carries the Beads ID **only** in the `Refs:
eversh-chl.2` trailer (never in the subject) and no AI attribution. Close
sequence: run the §7.6 gates, obtain authority for and execute the fuzz
runs (M1 cannot close without them), record results as a comment on
eversh-chl.2, close M1; `bd ready` then shows M2/M3 unblocked.

## 11. Explicitly out of scope (guardrails)

No PTY creation, no broker loop, no socket bind/accept, no QUIC endpoint, no
ssh spawn, no terminal handling, no Kitty integration (M2–M5). No branch
`main`; no `bd dolt push`; no commit/push without fresh approval; installing
cargo-fuzz or any nightly toolchain is ask-first; spikes/ remains frozen
evidence; design.md/reference.md touched only if an M1 fact contradicts
them (recorded, then ask).
