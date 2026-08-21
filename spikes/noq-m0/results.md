# noq-m0 spike results and runbook (M0, eversh-chl.1)

Disposable evidence record for the bounded noq feasibility gate. All commands
run from `spikes/noq-m0/` unless noted. Date: 2026-08-21.

## Pins

| Item | Value |
|---|---|
| Toolchain (build) | rustc 1.95.0 (59807616e 2026-04-14), cargo 1.95.0 (f2d3ce0bd) |
| MSRV (checked, not build) | rustc 1.88.0 (6b00bc388 2025-06-23); `rust-version = "1.88"` |
| noq | `=1.1.1`, default-features off, features `runtime-tokio, rustls, ring, bloom` |
| noq crate SHA-256 | `09e4bb6601fa543c110d8957813267d5a8d775a0f8fbaccf1f615d06ba9b10da` (Cargo.lock verified) |
| noq upstream tag | noq-v1.1.1 @ 12a4bf0b42070b570fb8cf90fe315c630b03f56e |
| rustls (via noq) | 0.23.43, ring provider; `noq::rustls` re-export used throughout |
| Direct deps | noq, tokio 1 (rt-multi-thread, net, process, io-util, io-std, time, sync, macros), rcgen 0.13 (ring, pem), ring 0.17 |
| Cross-build | `cargo +1.95.0 check --target aarch64-unknown-linux-gnu --locked` — pass |

Extra dependencies are justified: `rcgen` (MIT OR Apache-2.0) generates the
ephemeral self-signed server certificate; `ring` is already the noq crypto
provider and supplies SHA-256 + CSPRNG. Both are already in the ordinary M1
dependency review path; no special licence residual exists.

## Reproduction

```
cargo +1.95.0 fmt -- --check
cargo +1.95.0 clippy --all-targets -- -D warnings
cargo +1.95.0 test --locked            # 25 tests, 8 targets, all green
cargo +1.88.0 check --all-targets --locked
cargo +1.95.0 check --target aarch64-unknown-linux-gnu --locked
cargo tree -e features
cargo-deny --all-features --locked check   # advisories/bans/licenses/sources ok
./net/test-bootstrap.sh                # real system ssh -> isolated sshd
./net/test-e2e.sh                      # OpenSSH ProxyCommand, SCP, SFTP, -L, -R
sudo ./net/test-migration.sh           # netns/veth real address migration
```

## Gate outcomes

1. **First green gate** — fmt/clippy/`test --locked`/MSRV-1.88 check: PASS.
2. **Authenticated SSH bootstrap** (`net/test-bootstrap.sh`): system ssh into
   an isolated unprivileged sshd (temp host keys, loopback, high port) runs
   `bootstrap-parent`, which spawns the detached one-shot server and relays
   exactly one newline record. PASS: single record line, correct magic,
   token absent from argv and `/proc/<pid>/environ`, server child exits by
   lease, no surviving processes.
3. **Pin/token auth** (tests/bridge.rs): custom rustls `ServerCertVerifier`
   hashes the certificate's real SubjectPublicKeyInfo DER (minimal DER
   walker, unit-tested) and fails closed on any other key. Wrong pin =>
   TLS failure; wrong token => auth failure with zero target connects;
   no-connect-before-auth is structural (server code connects only after
   `server_accept_auth` returns Ok) and asserted in tests. Retry/address
   validation forced on the server accept path. PASS.
4. **One-stream bridge + shutdown** (tests/bridge.rs,
   tests/binary_harness.rs, tests/shutdown_gate.rs): byte-transparent both
   directions with arbitrary binary; both-direction EOF; half-close
   propagation; Request->Drain->Finalize first-cause-wins (unit + concurrent
   16-thread exactly-one-winner test); cancellation at handshake boundary;
   stalled QUIC peer and stalled TCP peer bounded by the stall deadline;
   client disappearance and process kill end everything with no surviving
   owned task/process. PASS. (Two real bugs found and fixed here: proxy
   stdout needed explicit flush on pipes; the bridge drain deadline
   originally killed healthy live connections after 5 s — now the drain
   deadline bounds only the second direction after the first terminal
   event.)
5. **Migration + hard failure** (tests/migration.rs, net/test-migration.sh):
   API rebind preserves `stable_id` and the stream with no loss/dup/reorder
   (120 KiB verified frame-by-frame). Real netns/veth gate (sudo, fully
   cleaned up): client migrated 10.231.0.2 -> 10.231.1.2 mid-stream under
   5 % netem loss + 10 ms delay on the old path; same `stable_id`;
   409 600 bytes delivered exactly once with every frame index verified.
   Total path loss (all veths destroyed): server exited within deadline;
   fresh connection emitted no replayed byte. PASS.
6. **OpenSSH compatibility** (`net/test-e2e.sh`): real OpenSSH over the
   spike ProxyCommand into the isolated sshd. PASS: remote command, exit
   code propagation (42), 64 KiB random binary round-trip byte-identical,
   SFTP batch, SCP, local forwarding, remote forwarding, ProxyCommand
   stdout carries only SSH bytes (diagnostics on stderr), bounded one-shot
   server exit, no surviving processes. A plain-TCP baseline was not
   separately timed; no latency claims are made.
7. **Resource bounds + audit** (tests/resources.rs, deny.toml): sustained
   6.5 MB uplink (16x the configured 384 KiB receive window) against a slow
   consumer; RSS plateau ~12 MB (warm spread < 600 kB, explained by windows
   + two fixed 16 KiB copy buffers); fds constant at 15. cargo-deny:
   advisories/bans/licenses/sources all ok; bans exclude any second SSH
   implementation, alternate runtimes, aws-lc; no terminal emulation,
   no Asupersync, no GPL/AGPL in the graph.

## Decision

**noq 1.1.1 is selected.** Every M0 acceptance criterion passed with
reproducible commands on this machine, including the real address-migration
gate on real veth paths under loss. Quinn fallback is not needed and is not
maintained. Environment caveats recorded: none of the failures encountered
were noq library failures; the two implementation bugs were in spike code.

## Residual notes for M1

- rcgen/ring carry no licence residual (both MIT OR Apache-2.0); they stay in the ordinary M1 dependency review.
- The bootstrap record format, auth frame, and role names are disposable.
- `Limits` values here are spike candidates; M1 must re-measure (design 4).
- Inner-ssh bootstrap observed occasional empty-record failures under heavy
  parallel load (harness-level flake, never reproduced in 12/12 isolated
  runs); the production client should handle bootstrap failure as an
  ordinary OpenSSH failure per design section 7.
