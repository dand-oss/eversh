# everudp v1 production contract

Status: frozen; released in v2 on 2026-09-09 by product decision with the custom-zmosh-UDP performance gate recorded as FAIL (section 13) | Last updated: 2026-09-09

This contract and its hash-sealed M6 evidence are immutable historical records. The
post-M6 direct-PTY fast-path experiment is governed by
[everudp-v2-fast-path.md](everudp-v2-fast-path.md); it must not reinterpret the v1
result or weaken any byte-delivery, recovery, security, or terminal-free invariant.

This document is the frozen contract for `everudp`, an optional direct-QUIC terminal product above the raw `everpty` and `everssh` primitives. It authorizes bounded opaque application-level delivery replay in `everudp` only. It does not weaken the permanent core non-goals in [design.md](design.md): `everpty` remains a byte-transparent PTY broker, `everssh` remains an opaque OpenSSH byte link, and `eversh` remains a supervisor that never relays terminal bytes.

## 1. Decision and prior spike

The decision spike closed `NOT-BUILD` at source `7d4a432`: its measured p50 keystroke-to-render ratio was 1.277 against zmosh 0.5.9 and therefore missed the preregistered 1.10 ceiling, while p95 passed at 0.35. The result and immutable evidence under `docs/release-evidence/20260905-everudp/final-7d4a432` remain valid for that implementation.

The user explicitly overrode the spike's product decision and authorized a production implementation because the measured fixture included Tokio, subprocess, and allocation overhead and the zmosh callback accepted an expected byte anywhere in a response. Production `everudp` receives a new gate; the old evidence is never reinterpreted. A production miss produces a sealed `FAIL` receipt and stops release.

## 2. Product invariants

- SSH is an authenticated bootstrap and low-frequency recovery-control channel only. No terminal payload travels over SSH or TCP after the QUIC association commits.
- The data plane is TLS 1.3 over direct reliable ordered QUIC streams and UDP. Terminal payload never uses QUIC datagrams.
- There is no terminal parser, virtual screen, prediction, local echo, snapshot, remote scrollback, semantic replay, synthetic repaint, browser transport, WebRTC, relay, rendezvous service, custom NAT traversal, multipath, or 0-RTT.
- On a healthy association, every accepted input operation and every accepted PTY output record is delivered exactly once and in order.
- During a bounded outage, unacknowledged complete operations are retained in bounded queues and replayed after an authenticated resume handshake. Delivered duplicates are suppressed.
- The association may reconnect for the entire lifetime of its `everpty` session. Network loss is temporary; authentication, pin, protocol, PTY exit, explicit kill, and local cancellation failures are terminal.
- A full input queue backpressures stdin. Input is never intentionally dropped, reordered, or converted into a terminal failure merely because the peer is unavailable.
- Output overrun preserves the PTY and future output, not stale output. Exactly one explicit GAP record identifies each discarded epoch.
- The local terminal owns rendering, width, history, and repaint. `everudp` never injects or recommends a repaint control sequence.

## 3. Process topology and lifetime

~~~text
eversh connect --transport everudp HOST --session NAME
    |
    | re-exec local eversh __everudp __client-v1 with inherited stdio
    v
everudp client -- SSH bootstrap/recovery --> eversh __everudp __bootstrap-parent-v1
    |                                                   |
    | TLS 1.3 / QUIC / UDP                              | private same-UID control socket
    v                                                   v
local terminal <===========================> persistent per-session gateway
                                                            |
                                                            | one persistent writer attachment
                                                            v
                                                      everpty broker -> PTY -> child
~~~

One detached gateway exists per named PTY session. Its state directory is mode 0700, its Unix control socket is mode 0600, and peer credentials must match the gateway UID. The gateway becomes and remains the single `everpty` writer after the first authenticated association commits. It drains PTY output even with no connected QUIC client so the child never stalls indefinitely.

The gateway supports one writer association and at most eight observers. `--take-over` moves writer ownership explicitly inside the gateway; it never silently displaces an active writer. An observer has no input stream, cannot resize, signal, detach, kill, or influence writer flow control, and is independently gapped or disconnected if slow.

The gateway survives sequential client connections until the PTY exits or is explicitly killed. A replacement gateway may be started only after the authenticated recovery probe proves the old gateway is absent. A gateway crash creates a new generation: the client reports the count of input operations whose acknowledgement was ambiguous, replays none of them, and receives future output only after the new association handshake.

The standalone `everudp` binary and the embedded `eversh __everudp` roles call the same typed library API. Installing the combined `eversh` binary is sufficient; local and remote hidden roles re-exec that same executable and do not require a sibling binary.

## 4. Bootstrap and admission

The client invokes the system OpenSSH client under the existing SSH configuration and authentication policy. The remote bootstrap parent re-execs `eversh __everudp __gateway-v1` or contacts the existing gateway, then returns one bounded `everudp v1` bootstrap record containing the endpoint, server-certificate SPKI pin, one-use invitation, association ID, gateway generation, and PID.

Each invitation has 32 random bytes, expires after 20 seconds, and is consumed atomically at the first admissible handshake. A gateway holds at most eight pending invitations. Initial authorization binds the invitation, association ID, requested role, session identity, gateway generation, and client-certificate SPKI. Resume authorization requires the same association ID, generation, role, and client key. Token comparison is constant time, token reuse fails closed, and secrets are redacted from status and diagnostics.

The QUIC profile uses ALPN `everudp-link/1`, TLS 1.3, an ephemeral server identity pinned through the SSH bootstrap, a bootstrap-bound client certificate, Retry/address validation, one bidi stream, one client-to-server uni stream, one server-to-client uni stream, migration enabled, 0-RTT disabled, datagrams disabled, multipath disabled, and no application NAT traversal. Unknown protocol versions, pins, keys, associations, generations, roles, stream types, extra streams, or oversized records close the connection without allocating from attacker-declared lengths.

## 5. Streams and wire contract

Every record starts with the fixed 14-byte header `version:u8 | kind:u8 | sequence:u64be | length:u32be`. Version 1 is the only accepted version. Sequence numbers are absolute per stream and epoch, begin at zero, and increment once per complete operation. A cumulative acknowledgement value is the next expected sequence, so ACK `n` commits every record with sequence less than `n`. Sequence overflow is terminal.

The client opens control stream C as the sole bidirectional stream. Its first record is `CLIENT_HELLO` with the association identity, gateway generation, role, input epoch and next sequence, output epoch and next sequence, and cumulative delivered output ACK. The server replies `SERVER_HELLO` with acceptance, authoritative epochs, cumulative accepted input ACK, and any pending GAP. Subsequent control records are cumulative ACKs, ownership state, bounded link status, GAP, detach, kill, and protocol close. Control payloads are at most 4 KiB.

The writer client opens input stream I as the sole client-to-server unidirectional stream after the hello succeeds. `INPUT`, `RESIZE`, and `SIGNAL` records share one ordered sequence. `INPUT` carries at most 64 KiB of opaque bytes. `RESIZE` has fixed unsigned row, column, pixel-width, and pixel-height fields. `SIGNAL` is an allow-listed process-group signal. The gateway acknowledges a record only after `everpty` accepts the complete corresponding operation. Observers must not open stream I.

The gateway opens output stream O as the sole server-to-client unidirectional stream after the hello succeeds. `OUTPUT`, ownership transition, and child-exit records share one ordered sequence. `OUTPUT` carries at most 64 KiB of opaque bytes. The client acknowledges a record only after the complete bytes or event have been accepted by the corresponding local sink; output delivery time is measured only after stdout accepts the bytes.

Stream roles are established by the hello and QUIC direction, not by arrival timing. Missing required streams, duplicate streams, unexpected writer streams from an observer, or records of the wrong kind are protocol errors. Half-close is explicit: closing stdin finishes stream I but leaves stream O and control alive until the child exits or the user cancels.

## 6. Allocation-stable queues, epochs, and gaps

`everudp` owns a preallocated slab/ring implementation with per-association cursors. It does not use or modify `everssh::resume::ReplayQueue` or the one-stream `AssociationCore`. The hot path performs no per-record heap allocation after warmup and uses reusable 16 KiB copy buffers.

Each direction is bounded to 4 MiB and 1,024 unacknowledged operations. All observers together and the writer share a 48 MiB gateway slab budget. Limits are checked before copying payloads or opening per-peer state.

When input reaches either cap, the client stops polling stdin until cumulative ACKs free capacity. Resize and signal operations remain ordered behind already accepted input. Local cancellation remains responsive through the control task.

When output reaches either cap during an outage, the gateway resets the old output stream, clears the unacknowledged queue, increments the output epoch, and marks one pending gap. It continues reading and discarding PTY output until the next authenticated resume handshake completes. It then sends exactly one GAP for the abandoned epoch and begins buffering only subsequent complete output records. No byte from the stale tail is shown. Repeated overrun before a completed handshake coalesces into that one pending GAP; a later epoch can independently gap.

## 7. Reconnect and recovery state machine

The route watcher uses noq's public `Endpoint::rebind` and Linux network-change notifications. A live connection attempts standard QUIC migration first. A hard failure starts sequential new connections after 0, 100, 250, and 500 milliseconds, then 1 and 2 seconds, then every 5 seconds with deterministic ±20 percent jitter for the remainder of the PTY lifetime. Attempts never overlap for one association.

The connection profile sends a keepalive every 10 seconds and treats 30 seconds without authenticated peer activity as idle failure. After 30 seconds without QUIC, the client performs one authenticated SSH recovery probe; further probes occur no more than once per minute. A probe may refresh an endpoint/invitation or replace a proven-dead gateway, but never carries terminal bytes and never transfers ambiguous input between gateway generations.

Status uses the separate line protocol `everudp-status-v1`. A record is written on every transition and once per disconnected minute. At minimum it distinguishes `connecting`, `carrying`, `migrating`, `reconnecting`, `recovering-over-ssh`, `gapped`, and terminal closure with a typed cause. Temporary states never make the supervisor abandon the client merely because an outage is long.

## 8. User interface and fallback

`eversh connect`, `attach`, `observe`, and `resume-all` accept `--transport everssh|everudp|auto`; the default remains `everssh`. `everudp connect HOST --session NAME`, `attach`, and `observe` expose the standalone equivalent. `list`, `detach`, and `kill` remain SSH control operations. Raw SSH, forwarding, SCP, and SFTP remain `everssh` operations.

Strict `--transport everudp` allows three seconds for the initial UDP/QUIC commit. If it cannot commit before raw terminal mode, before terminal traffic, and before gateway writer ownership is committed, it exits with 69 (`EX_UNAVAILABLE`). `--transport auto` catches exactly that pre-commit exit, prints one visible fallback line, and invokes `everssh` once. It never falls back after traffic, during reconnect, on authentication or protocol errors, or when an existing gateway owns the writer.

`resume-all --transport everudp|auto` lists sessions through SSH and opens each live session in a new Kitty tab. It may replace a known-disconnected client generation future-only with a GAP, but it never replaces an active writer without `--take-over`.

## 9. Locked limits

| Limit | Value |
| --- | ---: |
| Initial UDP unavailable budget | 3 s |
| Invitation entropy | 256 bits |
| Invitation lifetime | 20 s |
| Pending invitations per gateway | 8 |
| Writer associations per gateway | 1 |
| Observer associations per gateway | 8 |
| Control/bootstrap record payload | 4 KiB |
| Terminal record payload | 64 KiB |
| Unacknowledged bytes per direction | 4 MiB |
| Unacknowledged operations per direction | 1,024 |
| Global gateway replay slabs | 48 MiB |
| Reused copy buffer | 16 KiB |
| QUIC keepalive | 10 s |
| QUIC idle timeout | 30 s |
| First SSH recovery probe | 30 s without QUIC |
| Later SSH recovery probes | at most one per minute |
| Reconnect backoff cap | 5 s ±20% |
| Safe initial UDP payload | 1,200 bytes with discovery enabled |

These are contract limits, not suggestions. Changing one requires tests, resource evidence, a compatibility decision, and review of amplification and slow-sink behavior.

## 10. Dependency and runtime boundary

`everudp` is the fourth workspace crate and fourth standalone binary. It may depend on `everssh` with default features disabled only for reviewed transport-independent public primitives whose contracts match: secret tokens and constant-time comparison, SPKI pinning, ephemeral identities, SSH policy/bootstrap acquisition, association identifiers and authorization values, and UDP binding.

`everudp` owns one current-thread Tokio runtime. It must not use `everssh::runtime::build`, the everssh association actor, the allocating everssh replay queue, or its private route supervisor. It must not change either existing data path to obtain its behavior. An `everquic` extraction crate is explicitly deferred until another independent consumer proves that extraction reduces rather than enlarges the compatibility surface.

Every resolved production dependency closure must exclude `vt100`, `vte`, `alacritty_terminal`, `wezterm-term`, a second SSH implementation, GPL/AGPL code, and custom-restricted code.

## 11. Performance protocol

The timed workload is one rotating printable byte through one compiled raw-PTY echo fixture shared by all candidates. No shell or Python wrapper is present between the public send call, remote PTY fixture, and local output sink. The timer starts immediately before the candidate's public send API and stops only after the exact expected transcript has been accepted by the local sink. A 100 ms quiet window catches extras. A wrong, missing, duplicate, extra, zero, negative, or timed-out transcript is a failed observation and fails the cell; it is never recorded as a zero latency.

Final cells are 0 percent and 5 percent symmetric independent loss. Each cell runs six blocks of 200 observations per implementation, for 1,200 observations per implementation per cell. With three candidates, the six blocks use each candidate-order permutation once. Release binaries, CPU affinity, governor, fixed seeds, qdisc before/after counters, kernel, hardware, tool versions, command lines, source trees, and artifact hashes are recorded.

The baselines are frozen to zmosh 0.5.9 custom UDP commit `dfc8395b5edcd237bf82712fbde879c6e8be7dfa`, tree `1a3a615fd69d25e2c4c058e1d86b1d7be5e9f514`, and the current zmosh QUIC build commit `21db4a4de6040b254531f2131b6f1c0cd146a7a1`, tree `38ea33069ce480a1b6465d4c49eafc59c3b6edd8`. Both are built from clean detached source with isolated caches.

For each cell and each baseline independently, 20,000 block-stratified bootstrap resamples produce one-sided upper-95 ratio bounds. The production gate requires zero transcript failures, p50 point-estimate ratio no greater than 1.00, p50 ratio upper-95 no greater than 1.10, and p95 ratio upper-95 no greater than 1.00. Every comparison must pass; pooling cannot hide a failed cell or baseline.

Before final qualification, a disjoint-seed tuning pass evaluates initial RTT 25/100/333 ms × ACK policy off/every packet at 1 ms/every other packet at 5 ms × GSO on/off. The preregistered default is 100 ms, every packet at 1 ms, GSO off. Correctness is mandatory; candidates rank by worst-cell p95, then p50, then CPU. The default changes only if the paired block-stratified 95 percent interval for the winner/default p95 ratio lies wholly below 1.00. The selected profile is frozen before final seeds run.

The eligible 200-trial development sweep at source `c032e9c09e03fd9b367ec8b70bc812a6d0389a8e` evaluated all 18 profiles at both 0 and 5 percent loss with tuning-only seeds `910001` and `910003`; all 36 cells passed exact delivery. It selected 100 ms, every packet at 1 ms, GSO on. The winner's paired worst-cell p95 ratio interval versus the preregistered GSO-off default was `[0.9671247642, 0.9977349943]`, wholly below 1.00. The immutable raw samples, component timings, process measurements, manifest, analyzer result, and hashes are under `docs/release-evidence/20260905-everudp-tuning-c032e9c`. Production final qualification must use different seeds.

## 12. Reliability, security, and compatibility gates

The exact replay gates cover 0/1/5/10/25 percent loss, 25/50 ms jitter, 2 percent reorder and duplication, MTU reduction, IPv4 and IPv6, address change, interface change, sleep/wake, and five forced reconnects during a 10 MiB byte-identity transfer. Total loss for five and thirty minutes is a release gate; a twelve-hour loss run is a reported soak, not a gate.

The overrun gate forces output above both caps, proves continued PTY progress, exactly one GAP, no stale-tail byte, and intact future output. Input tests prove cap backpressure without loss. Ownership tests cover Busy, takeover, observer isolation, slow observers, client restart, gateway crash/rebootstrap, and PTY exit.

Hostile admission tests cover wrong pin, token, client SPKI, association, role, generation, token reuse and expiry, malformed lengths, integer boundaries, extra streams, amplification, slow sinks, file-descriptor/task cleanup, and secret redaction. Compatibility runs include shells, tmux, nvim, Claude Code, and Codex without injected repaint. Packet and process tracing must prove that no SSH/TCP process carries terminal payload after commit.

## 13. Evidence and release decision

`fuzz/qualify-m6.sh` writes evidence under `docs/release-evidence/<date>-m6/`. Every run first records exact source and tree identity, all candidate and fixture hashes, frozen baseline identities, configuration, and start time. A finalizer always writes `receipt.json` and `SHA256SUMS`, even when a build, correctness, reliability, or performance gate fails. The receipt outcome is `PASS`, `FAIL`, or `UNAVAILABLE` only for a preregistered environmental capability such as an absent Tailscale interface; unavailable mandatory local/netns gates are failures.

Acceptance requires the full workspace format, clippy, locked tests, MSRV 1.88, dependency/licence audit, fuzz, reliability, security, compatibility, and both-baseline performance gates to pass at one exact clean candidate SHA. An independent maximum-reasoning review then requires zero blocker or major findings. One repair round is allowed; any repair creates a new candidate SHA and reruns every affected gate.

Version bump, tag, merge, push, and fleet rollout are a follow-on release epic after this receipt and review are accepted.

### Release decision (2026-09-09)

The product owner released `everudp` in v2 with the frozen performance gate recorded as `FAIL`. Nothing in the gate, its thresholds, or its sealed receipts is reinterpreted: the median ratio against the custom-UDP zmosh baseline did not meet 1.00, and every receipt that says so remains the record. The decision rests on the following measured facts.

- Every non-performance gate passed at the exact reviewed candidate `9989564` (evidence `docs/release-evidence/20260906-m6-9989564cff6e`), and the independent maximum-reasoning review at that candidate found zero blockers, majors, or minors (`eversh-5fc.10`). The release candidate reruns the full `fuzz/qualify-m6.sh` matrix at its own exact SHA and retains that receipt, including the expected performance `FAIL`.
- The production full-gate archive `docs/release-evidence/20260908-everudp-fairness-bd53692` (7,200 exact trials) measured everudp p50/p95 of 550/957 us against zmosh UDP 382/828 us at zero loss, and 562/3876 us against 387/50626 us at 5 percent symmetric loss. Both zmosh-QUIC comparisons passed. The zero-loss median deficit is about 170 us per keystroke, below any human-perceptible threshold and two orders of magnitude below a typical network round trip; the 5 percent-loss p95 is about thirteen times better than the baseline.
- The independent Quinn 0.11 comparison (`docs/release-evidence/20260909-everudp-quinn-screen-f1287d22`) landed at the same ratio as the noq engine, and the native stream floor, direct PTY, immediate-flush, ACK-hold, datagram, PGO, and scheduling experiments recorded under `eversh-5fc.67` did not close the gap. Two independent QUIC engines converging on the same deficit identifies it as the cost of QUIC framing, acknowledgement, and TLS record processing on this host, not an implementation defect that another repair round would remove.

The gate is not lowered and no future candidate may cite this decision as a pass. A later candidate that changes the transport must requalify against the same frozen baselines.

## 14. Reviewed references

The complete pinned reference inventory is in [reference.md](reference.md). StableSSH motivates application acknowledgements, bounded replay, and persistent association lifetime; quic-send, fsend, and QCP provide transfer and tuning comparisons; bitbang, p2psh, sshx, Terminal7, the Rust WebRTC article, and trickled ICE over SSH inform reachability and trust boundaries; ws-terminal/ws-relay and the MoQ WebRTC comparison reinforce why relays and browser transports are not this product; neqo remains an alternate implementation reference, not a selected dependency.
