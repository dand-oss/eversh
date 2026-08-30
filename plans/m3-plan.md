# Milestone 3 plan: secure roaming everlink

Status: PairEngine-verified execution contract | Owner: `eversh-chl.4` | Updated: 2026-08-30

## 1. Objective and completion boundary

Promote the already-qualified Rust/noq Milestone 0 spike into the production `everlink` library and executable. The result is a transparent OpenSSH `ProxyCommand`: an authenticated system-SSH bootstrap starts one remote one-shot server, one TLS 1.3 QUIC connection carries exactly one ordered bidirectional stream, and that stream bridges byte-for-byte to only the loopback sshd endpoint authorized by the bootstrap.

Milestone 3 is complete only when the production `everlink` executable—not the spike—passes real OpenSSH PTY, command, SFTP, SCP, local-forwarding, remote-forwarding, migration, hard-loss, shutdown, security-negative, fuzz, and bounded-resource gates. Milestone 3 does not implement the user-facing `eversh` supervisor, automatic fresh-SSH reconnect, remote everpty commands, terminal restoration, or release packaging.

## 2. Frozen sources and how they are used

| Source | Frozen identity | M3 use |
| --- | --- | --- |
| Normative contract | [design.md](design.md), especially sections 4, 6, 8, 11–14 | Controls behavior and overrides every donor implementation. |
| Production destination | `crates/everlink` at the clean exact base selected when the first implementation run starts | Existing bootstrap/auth codecs, SPKI verifier, typed errors, finite limits, runtime owner, boundary tests, and binary edge remain the production source of truth. |
| Rust/noq M0 spike | `spikes/noq-m0` as completed by `1b3324bb53d0b5e3fabb1ae546e694f473381f11` | Direct Rust donor for identity/SPKI generation, noq/rustls configuration, Retry, one-stream admission and bridging, rebind, shutdown, process roles, and harness structure. Production types replace disposable wire helpers, strings, panic paths, wildcard/loopback assumptions, forced `BatchMode`, test-only proxy/migrate roles, and spike diagnostics. |
| zmosh-on-zmx QUIC work | [dand-oss/zmosh `205e8394c8841798d96c21d66bdba5155ee04868`](https://github.com/dand-oss/zmosh/tree/205e8394c8841798d96c21d66bdba5155ee04868), replanted on zmx `cd88d1b9dd04805b628d609058559cef2e920d38` | Behavioral and adversarial-test donor for gateway isolation, absolute deadlines, bounded turns, path validation, egress ownership, failure precedence, construction rollback, IPv4/IPv6, migration, loss/reorder/duplicate handling, flow-control exhaustion, and orphan cleanup. No Zig source is copied mechanically. |
| Transport dependency | noq `=1.1.1` and its reviewed rustls/ring path, selected in M0 | Remains selected unless `eversh-7zi` proves a replacement graph through the complete transport qualification. Quinn and quicz do not enter the production graph. |

The frozen zmosh work is only a lifecycle, failure-state, construction-rollback, bounded-egress, IPv4/IPv6, and adversarial-test donor. Its quicz adapter, the zmx daemon, Zig transport structure, Ghostty VT, snapshots, replay, output epochs, ZMQ1 multi-stream protocol, zmosh command protocol, PSK transport, and custom auto-reconnect semantics are excluded. zmx process/session lessons already informed everpty in Milestone 2; they are not a second session engine inside everlink. If any distinctive zmosh structure is adapted rather than independently expressed from the contract, record provenance and complete the dual-licence review before landing it.

## 3. Locked ownership and state model

- System OpenSSH owns user authentication, host authentication, ssh_config interpretation, the inner SSH protocol, PTY allocation, commands, forwarding, SFTP, SCP, and user-visible exit behavior.
- `ssh_bootstrap` owns the short authenticated bootstrap child, bounded record acquisition, fixed remote role invocation, stderr capture, timeout, and the only handle permitted to reap that child. It totally parses `SSH_CONNECTION` into typed authenticated peer and local endpoints but owns no route or interface policy.
- `identity` owns the ephemeral certificate/key, SPKI hash, one-use 256-bit token, and their explicit zeroization/drop boundary.
- `transport` owns noq client/server endpoints, UDP route selection and binding, rustls configuration, Retry/address validation, ALPN, connection/stream cardinality, the bounded route supervisor, standard path migration, and QUIC close.
- `admission` owns the frozen 35-byte authentication frame, constant-time token comparison, selector equality with a bootstrap-derived `AuthorizedTarget`, one-use consumption, and the rule that target TCP cannot open before success.
- `bridge` owns only two bounded concurrent copy directions, exact bytes, half-close, direct backpressure, stall detection, and no persistence or replay.
- `shutdown` coordinates a typed `Running -> Requested -> Draining -> Finalized` state machine and a first-cause-wins discriminated union. It freezes absolute deadlines and invokes cleanup through each resource owner; it performs no global wait or kill and never reaps system sshd.
- Binary code owns CLI parsing and argv, bounded diagnostic presentation on stderr, process exit codes, and the single call to `runtime::build`. Library code does not read global arguments, print, or exit.

Absence, terminal causes, phases, and role outcomes use Rust `Option`, `Result`, and explicit enums; no null-like sentinel, magic integer, or contradictory boolean combination represents lifecycle state.

Finalize proves that no owned transient proxy/bootstrap/server process, Tokio task, socket or file descriptor, target TCP connection, or secret state remains. The target system sshd is not owned: the real-sshd gate must prove it remains alive and accepts a later ordinary SSH connection.

## 4. Production module shape

Keep the existing `bootstrap.rs`, `pinning.rs`, `limits.rs`, `error.rs`, and `runtime.rs`. Add narrowly owned modules rather than one promoted `spike.rs`:

| Module | Responsibility |
| --- | --- |
| `identity.rs` | Generate and scrub the ephemeral certificate/key and token; expose only the certificate chain, server key, SPKI hash, and guarded token owner required by adjacent layers. |
| `transport.rs` | Build configured noq endpoints, force Retry, disable 0-RTT/datagrams/experimental modes, enforce one connection/stream, select and bind the authorized UDP endpoint, supervise the route, and expose bounded client/server operations plus the production rebind seam. |
| `admission.rs` | Own the full bootstrap-derived loopback `AuthorizedTarget`; read the existing 35-byte auth frame, validate its version/token/port selector, consume the token once, and return a typed admitted stream before any target connect. |
| `bridge.rs` | Copy opaque bytes between QUIC and TCP or stdio with fixed buffers, correct flush and half-close behavior, and no retained data after termination. |
| `shutdown.rs` | First-cause-wins state, Request/Drain/Finalize transitions, absolute deadlines, owner-cleanup coordination, and typed completion evidence. |
| `ssh_bootstrap.rs` | Construct authoritative argv without a local shell, prevent recursive ProxyCommand/TTY/forwarding, read exactly one record, totally parse `SSH_CONNECTION`, keep stdout pure, bound stderr, and exclusively reap the owned bootstrap process. |
| `roles.rs` | Typed library entrypoints for client proxy, bootstrap parent, and one-shot server; private versioned role dispatch contains no business logic. |

The exact split may be reduced when two modules would only forward calls, but ownership must not collapse into the CLI or mix process/bootstrap policy into byte bridging.

## 5. Execution slices and green checkpoints

### Slice 0: clean base, donor ledger, and dependency preflight

1. Preserve the current documentation work in an authorized commit or start from a separate clean worktree; PairEngine must receive one clean exact base and may not adopt unrelated dirty state.
2. Record the exact base SHA, Rust toolchain, M0 donor commit, zmosh reference commit, noq/rustls/ring/rcgen graph, and baseline gate receipts.
3. Run `eversh-7zi` as a bounded preflight: qualify an available noq update against the complete M0 transport matrix. Upgrade and remove both `chacha20@0.10.1` exceptions only if every gate passes. Otherwise retain the already-qualified `=1.1.1`, keep the exceptions explicitly temporary, leave `eversh-7zi` open, and do not block M3 on an unqualified dependency change.
4. Produce a symbol-by-symbol promotion ledger from M0: promote, rewrite against production types, retain as test only, or delete. Explicitly rewrite its text-oriented wire helpers, `unwrap`/panic paths, wildcard and loopback assumptions, forced `BatchMode`, test-only proxy/migrate roles, and spike diagnostics. No blind directory copy is allowed.

Checkpoint: clean exact base, reproducible baseline, dependency decision recorded, and no production behavior changed.

### Slice 1: identity, endpoint, and admission core

1. Promote ephemeral certificate/key and CSPRNG token generation through the existing noq rustls/ring provider; compute the pin over SubjectPublicKeyInfo, not the whole certificate.
2. Configure TLS 1.3 and ALPN `eversh-link/1`; disable 0-RTT, tickets/resumption where exposed, datagrams, QAD, multipath, QNT, and every extra application stream.
3. Define the typed authenticated SSH connection and derive `AuthorizedTarget` from its local sshd port plus the matching IPv4 or IPv6 loopback address. Preserve the existing v1 auth schema: `u8 version | token[32] | u16 target_port(BE)`. Neither the schema nor the client gains a target address.
4. Define three disjoint UDP policies. Default uses the kernel's unique usable route-selected source address in the authenticated peer's family and port zero. A bounded port range searches only ports on that same address. Only a literal endpoint that passes family, address, port, and bind validation may override the address. Do not enumerate interfaces or resolve DNS; reject a loopback peer without an override, no/ambiguous route, unusable source, overlay conflict, invalid override/range, and failed or exhausted binds.
5. Require Retry/address validation before committed connection state. Limit pending unauthenticated work and anchor handshake/lease deadlines to the original bootstrap event so malformed traffic cannot extend them.
6. Accept exactly the first client-opened bidirectional stream. Read the 35-byte frame incrementally, validate the production version, compare the token in constant time, require its port selector to equal `AuthorizedTarget.port`, atomically consume the token once, and reject reuse or extra streams.
7. Open one TCP connection to the complete `AuthorizedTarget` only after admission succeeds. Structural tests count target accepts and prove zero for malformed `SSH_CONNECTION`, wrong selector/pin/token, token reuse, extra auth/stream, route/bind failures, timeout, and allocation failure. No admission path resolves or substitutes a target.

Checkpoint: focused identity, pin, endpoint-policy, Retry, authentication, token-reuse, exact-target, extra-stream, timeout, and allocation-failure tests pass; no bridge or CLI path is enabled prematurely.

### Slice 2: transparent bridge and deterministic shutdown

1. Promote the M0 direct two-direction bridge using fixed buffers and noq/Tokio flow control rather than an application replay queue.
2. Preserve arbitrary bytes, flush pipe-backed stdout, propagate EOF as the correct half-close, and allow the surviving direction to drain only to its frozen deadline.
3. Implement first-cause-wins Request/Drain/Finalize. Stop admitting work at Request; finish or bound both copy directions and protocol close at Drain; then ask each owner to close sockets, abort/join tasks, reap its own children, and scrub secrets. Repeated cleanup is idempotent, no work resurrects after Request, no global process wait/kill occurs, and system sshd is never reaped.
4. Port zmosh failure-precedence cases at the application boundary: simultaneous readable data plus socket failure, blocked final write plus peer FIN, permanent send/receive failure, timer-only expiry, partial construction, and repeated cancellation. There is one durable cause and no resurrection after failure.

Checkpoint: exact binary round trip, both half-close directions, concurrent causes, stalls, cancellation, and owned-resource leak gates pass under controlled Tokio time.

### Slice 3: authenticated SSH bootstrap and executable roles

1. Implement `everlink ssh-proxy SSH_DESTINATION SSH_PORT [--ssh-option OPTION...]` and private versioned bootstrap-parent/server roles as thin CLI edges over typed library calls.
2. Launch the installed system `ssh` with argv, never a local shell. Because OpenSSH retains the first obtained value, normalize the audited option allowlist so mandatory bootstrap constraints are authoritative before any duplicate, or reject the conflict; never rely on an override ordered last. Effective bootstrap policy disables recursive ProxyCommand, TTY, unrelated forwarding (`ClearAllForwardings` or its exact equivalent), and any remote command except the fixed private role without changing the proxied outer SSH behavior.
3. Totally parse the authenticated server's `SSH_CONNECTION` as exactly four literal, nonzero, family-compatible peer/local fields. Derive the exact loopback target from the local family and sshd port. Route selection then starts only from the typed peer; parsing performs no interface choice or DNS lookup.
4. Pass sensitive server state only through inherited protected pipes. No token or private key appears in argv, environment, metadata, diagnostics, or process listings. The bootstrap parent emits exactly one capped newline record on stdout; all diagnostics are bounded stderr.
5. Apply endpoint policy before readiness. Isolated tests use a non-loopback veth peer or an explicit validated endpoint override, never an accidental loopback default. The server detaches only after successful bind/readiness, accepts one client until the absolute lease, and exits after the bridge or lease. Every bootstrap failure reaps its owned child and leaves no UDP listener.

Checkpoint: production bootstrap tests replace the spike binary, including malformed `SSH_CONNECTION`, endpoint-policy failures, chatter/multiple-line/truncation/timeout, process-list secret scan, conflicting SSH options, mixed-version failure, early child death, and no-owned-orphan proofs.

### Slice 4: production migration and path failure

1. Keep migration within one noq connection and stable stream. Server-observed NAT/source changes must validate the candidate path before switching; old, stale, wrong-path, or duplicated responses cannot authorize it.
2. Put the production trigger in a bounded transport-owned route supervisor. On detected process wake, an available Linux route/interface notification, UDP socket failure, and a mandatory finite fallback poll, recompute the kernel route to the fixed literal server endpoint and compare its selected source address/interface.
3. When that selection changes, create a freshly bound UDP socket and call noq `Endpoint::rebind`. A healthy identical poll is a no-op. If a failed socket still selects the same route, attempt at most one bounded replacement or enter ordinary path-failure shutdown; never spin or leave an unusable socket silently installed. A test-only direct call is insufficient.
4. Exercise the production process across source-port and source-address/interface changes, Wi-Fi-like blackout/recovery within the QUIC deadline, IPv4, IPv6, sleep/wake timer advancement, and traffic returning to an old path. Assert the same noq stable identity and live stream with ordered byte-exact delivery.
5. On total path loss, close the old QUIC stream and target TCP by the absolute configured deadline. Emit no old application byte on a fresh connection; EverLink itself does not reconnect. Do not add custom NAT traversal, a second QUIC connection/runtime, a replay queue, or application-level sequencing.

Checkpoint: API-level and production-process netns/veth migration preserve the same connection identity and stream and deliver numbered frames exactly once; same-route socket failure is bounded; hard loss terminates without replay or owned orphan state.

### Slice 5: real OpenSSH compatibility and hardening

1. Move the M0 isolated-sshd harness to production `everlink`. Verify `%n` preserves the original alias and `%p` the effective port; preserve user, port, custom ssh_config, agent, key, certificate, host-key policy, remote command and exit status, interactive PTY, random binary stdin/stdout, SFTP batch, SCP, local/remote forwarding, and ProxyCommand stdout purity.
2. Test captured bootstrap argv and effective `ssh -G` output against conflicting command-line and config values. Prove the mandatory first-value policy cannot be preempted and does not leak into the proxied outer connection. Do not blindly retain the spike's forced `BatchMode`. Honor ProxyJump only when its effective path is nonrecursive and the published UDP endpoint is explicitly reachable; otherwise reject it clearly without inferring a jump.
3. Adapt zmosh fault ideas without duplicating noq internals: inject loss, delay, duplication, reordering, corruption/truncation where the public boundary permits, slow peers, exhausted stream credit, invalid streams, malformed auth/bootstrap bytes, signal races, and process death.
4. Add a named production `everlink-resource-bounds` gate covering sustained traffic, stalled TCP/QUIC consumers, exhausted stream/connection credit, pending unauthenticated handshakes and token attempts, idle operation, and every shutdown cause. Before completion, freeze measured pass/fail ceilings tied to configured windows, buffers, counts, and deadlines. Assert bounded RSS, fds, tasks/processes, CPU, queue/window use, amplification/work, and shutdown latency, then return owned resources to baseline. Measurement without assertions is not a pass.
5. Run `fuzz_bootstrap_record`, `fuzz_auth_frame`, `fuzz_everlink_close_sequence`, and `fuzz_everlink_stream_boundary` for at least 60 seconds each on the exact final diff. The new targets cover EOF/half-close/error/cancel/deadline orderings and incremental auth boundaries with opaque arbitrary payload/chunking. Preserve crashing inputs and add deterministic regressions; `fuzz_remote_control` remains M4-only.
6. Re-run root and fuzz cargo-deny, dependency-boundary tests, MSRV, aarch64 Linux cross-check, and absence checks for terminal emulators, replay/log buffers, second SSH implementations, alternate runtimes, restricted licences, and secrets in diagnostics.

Checkpoint: every `eversh-chl.4` acceptance criterion has a named test or retained external gate receipt, and all production gates pass on the exact final diff.

## 6. Required gates

Fast gates run after each coherent slice; full/network gates run before M3 completion. Commands may be normalized by the repository gate profile, but their semantic coverage may not be weakened.

- `git diff --check`
- `cargo +1.95.0 fmt --all -- --check`
- `cargo +1.95.0 check --workspace --all-targets --all-features --locked`
- `cargo +1.95.0 clippy --workspace --all-targets --all-features --locked -- -D warnings`
- `cargo +1.95.0 test --workspace --all-features --locked`
- `cargo +1.95.0 test -p everlink --all-features --locked`
- `cargo +1.88.0 check --workspace --all-targets --all-features --locked`
- `cargo +1.95.0 check --workspace --target aarch64-unknown-linux-gnu --locked`
- `cargo deny --all-features --locked check`
- `cargo deny --manifest-path fuzz/Cargo.toml --all-features --locked check`
- Production bootstrap and real-OpenSSH scripts derived from `spikes/noq-m0/net/test-bootstrap.sh` and `test-e2e.sh`
- Root-required real netns/veth migration script derived from `spikes/noq-m0/net/test-migration.sh`, with deterministic cleanup on success, failure, signal, and timeout
- Effective-OpenSSH configuration/argv matrix plus the full real-OpenSSH feature matrix from Slice 5
- Production `everlink-resource-bounds` gate with frozen asserted ceilings and return-to-baseline checks
- Four at-least-60-second campaigns: `fuzz_bootstrap_record`, `fuzz_auth_frame`, `fuzz_everlink_close_sequence`, and `fuzz_everlink_stream_boundary`

No passing claim may substitute spike results for production results. A skipped privileged/network, real-sshd, fuzz, or resource gate is an explicit incomplete result, not a pass.

## 7. PairEngine operating contract

M3 is too broad for one unattended run. Execute one bounded slice per PairEngine run, always from a clean exact base, with `--preset eversh-ci`, `--routing strong`, architect `zai/glm-5.3:max`, persistent builder `openai-codex/gpt-5.6-sol:max`, high risk, exact included paths, and observable slice-specific acceptance. Security or semantic evidence always receives the fresh strong reviewer.

This roadmap is source context, not a `--plan-file` candidate for the whole milestone. For each slice, extract a task-bounded candidate under PairEngine's size limit and pass that slice plan with `--plan-file`; the persistent Sol builder challenges it once before implementation. PairEngine must not commit, push, merge, deploy, sync Dolt, clean evidence, modify zmosh, or start M4. The controller's exact diff, gate receipts, scope receipt, and final-diff identity—not model prose—prove completion.

## 8. Scope, commits, and stopping rules

Allowed production scope is `crates/everlink/**`, shared protocol/boundary tests only when required, production M3 network harnesses, dependency metadata required by the qualified transport graph, and documentation/evidence for M3. `crates/everpty/**` behavior, terminal logic, M4 supervisor composition, installers, deployment, and unrelated cleanup are excluded.

Create a green atomic commit at each coherent slice checkpoint during implementation, then use the repository's commit-cleanup workflow before review if the history is noisy. Do not hide review repairs by squashing before their evidence is recorded. No commit, push, merge, deployment, or Dolt synchronization occurs without fresh user authority.

Stop and escalate instead of guessing if the selected noq version cannot meet migration, rebind/path-validation, or admission requirements through public APIs; route selection is ambiguous or conflicts with the requested overlay without a validated override; admission would require DNS, a client-selected target, a schema change, or target access before authentication; authoritative OpenSSH bootstrap constraints cannot preserve required behavior; a production trigger requires a private fork, privileged daemon, or second runtime; a required real-sshd, root netns/veth, fuzz, or resource gate cannot run; or any change would add terminal parsing/replay, start M4, or widen the target beyond the authenticated loopback sshd. A skipped required gate remains incomplete.

## 9. Final evidence and handoff

The M3 handoff records the clean base and final diff identities; donor and dependency pins; model assignments and PairEngine receipts; every fast/full/network/fuzz/resource gate; asserted measured limits; effective and behavioral OpenSSH matrices; residual platform caveats; changed paths; and confirmation that no owned transient proxy/bootstrap/server process, task, socket or fd, target TCP connection, secret state, or replay buffer survives Finalize. The isolated system sshd must remain healthy and accept a later ordinary SSH connection. Close `eversh-chl.4` only after that evidence is present and independently reviewed with no blocker or major finding. Milestone 4 then consumes the typed EverLink API without moving relay or transport logic into the `eversh` supervisor.
