# eversh v1 design

Status: Rust implementation contract and staged delivery baseline | Last updated: 2026-09-03

Design revision 2 (2026-09-03): the qualified v2 everssh association resume is
normative. Standard migration remains the live-connection mobility contract;
after a QUIC connection dies, a bounded association may reconnect and
retransmit opaque frames retained until cumulatively acknowledged. Historical
one-shot/no-replay statements below this notice are revised in place. everpty
byte transparency, attachment drain/discard, and every terminal-state non-goal
are unchanged.

This document is normative for v1 of `everpty`, `everssh`, and `eversh`. The terms MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are normative. A change to a MUST or MUST NOT requires a recorded design revision.

## 1. Locked product decisions

- All original implementation code is Rust.
- The repository is one Cargo workspace with one Cargo.lock, three reusable library crates, and separate `everpty`, `everssh`, and `eversh` executables.
- The project is dual-licensed MIT OR Apache-2.0; dependencies and incorporated code must be distributable under both choices.
- `everpty` owns one PTY, one child process, a private Unix socket, writer ownership, observers, resize, signals, and child status.
- `everpty` MUST NOT depend on or initialize Tokio or noq in its core; a small poll-based event loop or bounded fixed workers are permitted.
- `everpty` MUST NOT parse terminal data or maintain a screen model, scrollback, retained/session/replay output buffer, log, replay ring, snapshot, prediction state, or attach-time redraw.
- `everpty` MUST drain and discard PTY output only when no attached client can accept it; a live observer continues receiving future output while no writer is attached.
- The current writer is lossless while healthy: finite live queues MAY backpressure the PTY, but a writer that exceeds the configured stall deadline is detached and its undelivered live queue is discarded so the broker can resume draining.
- A second writer returns `Busy` by default; ownership changes only after explicit `--take-over`.
- Observers receive future output only, never control input or resize, and are disconnected rather than allowed to block the writer or child.
- `everssh` is a transparent one-stream QUIC ProxyCommand bridge to the authorized localhost OpenSSH server, with a bounded resumable association above individual QUIC connections.
- `everssh` uses exactly one Tokio runtime, noq, its reviewed rustls path, TLS 1.3, one reliable ordered bidirectional stream, standard migration, and bounded flow control.
- OpenSSH remains the authority for user authentication, host keys, ssh_config, PTY negotiation, command execution, forwarding, SFTP, and SCP.
- QUIC bootstrap trust is ephemeral and delivered through an already authenticated SSH bootstrap; users do not manage a second eversh identity.
- A QUIC connection failure opens a bounded reconnect epoch: the client retransmits opaque frames retained until cumulatively acknowledged, the receiver suppresses already-delivered duplicates, and either side ends the association after its measured lease/budget.
- A terminal association failure, expired lease/budget, or exhausted queue ends the old SSH stream; eversh then probes and opens a fresh SSH connection only to reattach the surviving everpty session.
- Unbounded or semantic replay, and resumption after association expiry, remain prohibited.
- `eversh` is a thin supervisor and MUST NOT relay or parse terminal data.
- V1 targets Linux and directly reachable UDP, including ZeroTier or Tailscale overlay addresses.
- Quinn is retained only as a documented Rust fallback if noq fails the required standard migration feasibility tests; no parallel production implementation is maintained.

## 2. Crate and process architecture

The workspace contains `crates/everpty`, `crates/everssh`, and `crates/eversh`, with exactly three physical binary targets: standalone `everpty`, standalone `everssh`, and the combined/multi-role user-facing `eversh` executable. The combined `eversh` executable links all three libraries and exposes private role dispatch for remote startup.

The three physical executables call the same typed library APIs. The combined executable does not merge a broker or QUIC server into the supervisor process: each PTY session is a daemon-per-session process, and each bootstrap launches one association server process that may accept sequential connections for that association until its lease ends.

Private combined-binary dispatch selects exactly one logical role before runtime initialization. A process dispatched to the everpty role runs the everpty attach or broker edge, and a process dispatched to the everssh role runs the QUIC edge; neither initializes or passes terminal bytes through the eversh supervisor library.

CLI parsing, terminal mode changes, process exit codes, and stderr presentation stay at binary edges. Libraries accept typed configuration and return typed errors; library functions MUST NOT inspect global arguments, print diagnostics, or call process exit.

`everpty` has no async-runtime dependency in its core. A poll-based broker is preferred; if blocking workers are required, their count and queue capacity are fixed by configuration and tested. `everssh` owns the single Tokio runtime for its process; eversh launches and supervises child processes and does not create a second relay loop.

## 3. Ownership and byte invariants

The local terminal emulator is the only owner of rendering, screen state, scrollback, copy, paste, keyboard encoding, and terminal feature support. PTY, SSH, and QUIC payloads are arbitrary byte slices and MUST NOT require UTF-8.

No component may parse, translate, filter, normalize, inject, or synthesize terminal escape sequences. No component may perform userspace newline conversion. The attach client MAY put the outer terminal into raw mode but MUST restore the original termios settings after normal exit and every handled signal.

Attach stdout contains only child PTY output. ProxyCommand stdout contains only the target OpenSSH byte stream. Diagnostics, state changes, retries, and errors go to stderr. Secrets and arbitrary payload bytes MUST NOT appear in diagnostics.

everpty retains no session/replay output buffer in memory, on disk, in protocol frames, or in metadata; bounded live delivery queues and kernel queues are discarded when their attachment ends. everssh's association layer retains only bounded opaque transport frames not yet cumulatively acknowledged, discards them after acknowledgement or association end, and never interprets them as terminal or SSH semantics.

### 3.1 Application-owned redisplay

Terminal history is not PTY state. A PTY byte stream does not reveal whether retained bytes represent a shell log, a semantic agent conversation, an alternate-screen repaint, a transient progress frame, sensitive output, or a terminal query whose replay would cause new input or other side effects. `everpty` therefore MUST NOT infer a restoration boundary or decide when or what to redisplay.

On attachment, `everpty` applies only the writer's actual dimensions under section 5.3 and begins future-byte delivery at the accepted output boundary. The child application owns any semantic transcript, repaint, reconnect, or session resume. An application MAY redraw from its own state after a real resize or an explicit user or application command; `everpty` MUST NOT synthesize such commands, input, signals, or terminal output to provoke it.

Agent CLIs that retain structured conversations are a primary compatible workload, but application-owned recovery is not an `everpty` dependency or guarantee. An opaque application without its own redraw or history receives future bytes only. Exact visual restoration requires an optional product above `everpty`, such as zmosh, tty7, tmux, or an application-native equivalent; it does not belong in the broker. `everpty` is a process-continuity substrate for self-restoring applications, not a universal exact-screen-restoration multiplexer.

## 4. Resource and protocol limits

Every limit is named in the implementation, exposed in diagnostic configuration where appropriate, and covered by boundary tests. Values that affect interactive behavior are selected by measurement in Milestone 0 or Milestone 5 and recorded with the release profile; the design does not claim unsupported performance numbers.

| Category | Required v1 rule |
| --- | --- |
| Local frame length | A length-prefixed frame has a big-endian u32 body length, protocol version, message kind, and payload; the default maximum body is 64 KiB and is rejected before allocation if exceeded. |
| Bootstrap record | The newline-terminated versioned bootstrap record is capped at 4 KiB; malformed, duplicate, missing, or trailing records fail closed. |
| Remote control request | An encoded request is capped at 64 KiB before decoding, contains a version and typed fields, rejects NUL in Unix argv elements, and is never evaluated as shell source. |
| Token | The bootstrap token contains 256 bits of cryptographically secure randomness, is one-use, compared in constant time, and never logged or placed in argv, environment, or metadata. |
| Session name | Names use a documented conservative character set and maximum length; names are validated before path construction and never interpolated as shell source. |
| Unix path | The final state and socket paths are checked against the Linux Unix-socket length limit before bind. |
| Local clients | Broker client count, observer count, per-client live queue bytes, and aggregate live queue bytes are configured finite values. |
| PTY output | The current writer has a bounded live queue and finite stall deadline; the PTY may backpressure only while that writer remains healthy. A stalled writer is detached and its queue discarded, observers are evicted on queue exhaustion, and no detached queue is allowed. |
| QUIC streams | Only one application bidirectional stream carries SSH data; extra streams and QUIC datagrams are rejected or unused. |
| QUIC windows | Connection and stream flow-control windows are finite and selected from measured memory/backpressure tests. |
| QUIC handshake | Retry, authentication, bootstrap wait, idle, path validation, and close deadlines are finite configured durations. |
| Unauthenticated state | The server limits pending handshakes, source amplification, token attempts, and total pre-authentication lifetime before allocating the target TCP connection. |
| Target connections | An association server connects only to its bootstrap-authorized loopback sshd endpoint and owns one target TCP connection per association. |
| Association replay | Per-direction retained wire bytes, frame counts, association lease, and each outage's reconnect budget are finite configured values with measured release evidence. |
| Retry policy | eversh uses finite attempts, bounded exponential backoff, jitter, and a configured overall retry deadline; it never spins. |
| Process resources | Broker processes, child process groups, sockets, file descriptors, worker count, and open SSH/QUIC processes have explicit cleanup and finite test gates. |
| Metadata | Metadata is discovery-only and bounded; it contains no output, keystrokes, token, child arguments, environment, or private key. |
| Diagnostics | Event fields and qlog output are bounded, opt-in where payload-adjacent, and scrubbed of secrets and terminal bytes. |

The release profile records the selected values, measurement method, test environment, and rationale for every configurable limit. A value may be tuned without changing the wire contract only when the boundary tests remain green.

## 5. everpty contract

### 5.1 Responsibilities and lifecycle

`everpty` owns one named child and PTY, a private versioned Unix-socket protocol, writer and observer membership, resize and signal handling, child reaping, secure session discovery, and stale-socket cleanup. It does not own network, SSH, terminal rendering, layouts, logs, or redraw.

There is one broker process per session and no central always-running manager. The broker remains alive while the child runs and exits when the child exits or the session is killed.

The broker MUST bind its private socket and establish readiness before spawning the child. `everpty start` launches the broker and becomes its initial writer; it is not a detached-start command. The start sequence is: validate name and command; create private state and socket; signal readiness; connect the start client with real rows and columns; register writer output delivery; create the PTY and child process group; spawn the child; and begin reading the PTY immediately. If the initial writer does not arrive before the configured startup deadline, the broker exits without spawning the child.

The lifecycle is `Starting -> WaitingForWriter -> Running -> Exited` with `Failed` for startup failure. Writer ownership is independent: `NoWriter <-> Writer(client_id)`. This is an application lifecycle, not a generic staged runtime framework.

### 5.2 Local protocol

The v1 frame is `u32 body_length (big endian), u8 protocol_version, u8 message_kind, u8[] payload`. Version one is rejected if unsupported, and a complete header is validated before allocation.

The protocol includes `Hello`, `HelloAck`, `Busy`, `Input`, `Output`, `Resize`, `Ownership`, `DetachWriter`, `Kill`, `Ping`, `Pong`, `Exit`, and `Error`. Raw PTY bytes occur only in `Input` and `Output`; control strings are UTF-8 and bounded.

A writer request while another writer exists returns `Busy` without changing the current writer. A request with explicit takeover atomically revokes the old writer, discards its undelivered live output queue, grants the new writer at the next output boundary, and causes queued input and resize from the old writer to be rejected. The old writer may remain connected as an observer and receives an ownership event before any subsequent output.

Observers receive only output produced after accepted attachment. They cannot input, resize, kill, or request redraw. No observer is promoted automatically. A lagging observer is disconnected when its finite live queue fills and MUST NOT block the writer or child.

### 5.3 PTY, output, resize, and signals

The initial writer dimensions are applied before child spawn. Only the current writer may resize; the broker applies TIOCSWINSZ only when the actual dimensions changed. The broker never nudges dimensions, moves the cursor, clears the screen, injects a redraw, or synthesizes a SIGWINCH.

The child inherits the creator environment subject to explicit overrides; TERM is not hard-coded. The child has its own session and process group with the PTY slave as controlling terminal. Kill sends SIGTERM to the process group, waits the configured grace deadline, then sends SIGKILL if required; the broker reaps and reports code or signal.

The current writer receives every PTY byte in order while it remains within its finite queue and stall deadline. A full writer queue applies PTY backpressure rather than silently dropping bytes. If the writer disconnects or exceeds the deadline, the broker atomically revokes it, discards its undelivered live queue, resumes reading the PTY, and forwards subsequent bytes to any observers that can accept them. Observers are best-effort and are disconnected when their own finite queues fill. When no attached client can accept output, the broker continues draining the PTY and discards bytes immediately. A live observer remains eligible to receive future output when no writer is attached. A new attachment starts at the next output boundary after acceptance. The broker never counts discarded bytes as pending output or replays them.

The attach client forwards all input bytes, including control characters and partial escape sequences, without reserving a detach key. EOF, connection loss, terminal close, handled signal, and explicit detach all end the attachment while leaving the child alive.

### 5.4 State and security

The state root is the first usable value among `EVERSH_STATE_DIR`, `XDG_RUNTIME_DIR/eversh`, `XDG_STATE_HOME/eversh`, and `$HOME/.local/state/eversh`. Root and per-session directories use mode 0700; sockets and metadata use mode 0600. Metadata contains only bounded discovery fields such as name, broker PID, child PID, creation time, executable label without arguments, and origin labels. The broker sets `EVERPTY_SESSION` to the validated session name in the child environment; `everpty current` prints that value only after confirming that the corresponding owned broker is live.

A stale socket is removed only after a connection attempt fails and an exclusive per-session lock is acquired. On Linux, peer credentials are checked so the connecting UID matches the broker owner. Metadata updates are atomic. Session names are never shell fragments.

The public interface is `everpty start NAME [-- COMMAND...]`, `everpty attach NAME [--take-over]`, `everpty observe NAME`, `everpty list [--json]`, `everpty current`, `everpty detach NAME`, and `everpty kill NAME`. `start` fails with `AlreadyExists` when the name is live, `detach NAME` revokes the current writer without sending a terminal byte, and the internal attach-or-create operation used by eversh is atomic under the per-session lock.

## 6. everssh contract

### 6.1 SSH bootstrap and association server

There is no installed always-on gateway in v1. Each ProxyCommand performs an ordinary system SSH bootstrap that launches one remote `everssh` server.

The server binds the selected directly reachable UDP address and port, creates an ephemeral TLS certificate and one-use token, detaches from the bootstrap process, writes exactly one bounded bootstrap record, waits for one authenticated QUIC client, and connects only to the loopback sshd port derived from the authenticated bootstrap connection's `SSH_CONNECTION`. The first authentication binds the one-use token, bootstrap-derived association ID, client certificate SPKI, authorized target, and association lease. The server then accepts only authenticated resume connections presenting the same client key and association ID until the association ends or its renewed lease expires. The client cannot select an arbitrary target.

The bootstrap record is versioned, newline-terminated, and delivered over authenticated SSH. It contains application protocol version, endpoint, SPKI SHA-256 pin, token, and diagnostics-safe process identity. The client validates the exact pin and sends the token only after the QUIC TLS handshake. Bootstrap diagnostics use stderr.

### 6.2 QUIC and stream protocol

ALPN is `everssh-link/2`. TLS 1.3 uses noq's reviewed rustls integration. 0-RTT is disabled. Server Retry and address validation occur before expensive unauthenticated state. The first client-opened bidirectional stream begins with a bounded versioned authentication frame containing the one-use token and authorized target selector; after authentication, the remaining stream bytes are opaque SSH data.

Only one ordered reliable stream is used for SSH at a time. QUIC datagrams, stream multiplexing, terminal state, prediction, and custom SSH semantics are absent. The association layer versions opaque frames, exchanges cumulative acknowledgements, retransmits bounded frames retained until acknowledged, and suppresses delivered duplicates on reconnect. Extra authentication attempts, duplicate tokens, wrong pins, wrong protocol versions, wrong target selectors, foreign client keys, duplicate association IDs, or extra streams close the connection.

The association server is never an open proxy. It connects only to the loopback sshd endpoint authorized by the bootstrap and rejects target changes. OpenSSH remains responsible for user and host authentication inside the proxied stream.

### 6.3 Runtime, migration, and shutdown

`everssh` uses exactly one Tokio runtime and one noq rustls path. It does not add Asupersync, a second async runtime, or a custom noq runtime/UDP adapter. Quinn is a documented fallback only if noq fails the bounded standard-migration gate; selecting Quinn requires a recorded dependency and security review.

Standard migration is the only live-connection mobility contract. The implementation validates a changed path and preserves the same QUIC connection when possible. After a connection dies, the client opens one bounded reconnect epoch, retrying route selection, bind, and connect failures until its per-outage budget expires; the server renews its accept lease from resume acceptance. QAD, multipath, QNT, and custom NAT traversal are disabled in v1.

The supervisor implements Request -> Drain -> Finalize explicitly. Request stops new work after the first terminal condition and records the cause; Drain closes or completes owned copy directions, half-closes where valid, drains protocol close work, and waits only until configured deadlines; Finalize closes sockets, joins or aborts owned tasks, closes the target TCP connection, scrubs secret state, and verifies no owned task remains. everssh reaps only processes it actually owns and never reaps the system sshd target. Every terminal condition is idempotent and the first cause wins.

A stalled or expired path ends that QUIC connection under the configured stall deadline. The association then either resumes inside its measured lease/budget or terminates; on termination, the old SSH stream and target TCP close and eversh decides whether to create a fresh SSH connection. Acknowledged frames are discarded, unacknowledged frames are retransmitted once per resumed connection within queue bounds, and no frame is delivered after association expiry.

### 6.4 Bootstrap OpenSSH and standalone interface

The public standalone interface is `everssh ssh-proxy SSH_DESTINATION SSH_PORT [--ssh-option OPTION...]`; an OpenSSH ProxyCommand uses `%n` for the original destination token and `%p` for the effective port so a configured host alias is not silently replaced by `%h`. everssh launches the bootstrap with the system `ssh` executable, the same destination/user/port/authentication/host-key inputs, and explicit overrides that prevent recursive ProxyCommand, remote commands, TTY allocation, and unrelated forwarding. eversh passes an audited allowlist of applicable command-line SSH options to both the inner SSH process and bootstrap instead of copying session-only options blindly. ProxyJump follows the explicit policy in section 8.

Internal server and bootstrap roles are private versioned entry points used by eversh and the combined executable. Library APIs are typed and do not read terminal state or print diagnostics.

## 7. eversh supervisor contract

eversh parses commands, resolves effective OpenSSH configuration, starts everssh, constructs bounded versioned remote control requests, invokes the installed `ssh` binary, preserves inherited stdin/stdout/stderr for the live terminal path, records session origin metadata, and applies retry policy. Remote command strings contain only fixed command words, validated conservative identifiers, and at most one bounded unpadded-base64url token containing a versioned child-argument request; decoded bytes are never evaluated as shell syntax, NUL is rejected before Unix process creation, and bootstrap tokens are never placed in command strings, argv, or environment.

eversh MUST preserve ssh_config aliases and options, agent and key use, host-key checks, user and port selection, certificates, forwarding, SFTP, SCP, and normal OpenSSH exit behavior. Bootstrap connections explicitly avoid recursive eversh ProxyCommand use. Remote control requests validate session names and encode arbitrary child argument vectors without shell interpolation.

For `connect HOST --session NAME [-- COMMAND...]`, eversh starts the bootstrap and proxy, starts ordinary OpenSSH over the proxy, requests a TTY, and performs an atomic remote attach-or-create under the session lock. Existing writer ownership produces `Busy` unless takeover was explicit.

eversh distinguishes child/session exit, strict attach errors, local termination, unexpected SSH termination, and bootstrap/authentication failure. A clean child exit returns its status. While the local link-status channel reports `reconnecting`, eversh waits and never probes or launches a replacement SSH operation: the transport owns that bounded reconnect epoch. After a terminal association failure ends an established named `connect`, `attach`, or `observe` session, eversh uses a fresh authenticated bootstrap to ask whether the same broker is still alive and retries only when it is; the retry uses finite exponential backoff, jitter, and an overall deadline, including the bounded old-association drain window. `eversh ssh`, arbitrary raw commands, forwarding-only connections, SFTP, and SCP are never restarted automatically because doing so could duplicate application work, although their live everssh association may retransmit bounded opaque transport frames within its lease. Bootstrap, authentication, and protocol-version failures remain ordinary fail-closed OpenSSH failures. The same local terminal process remains visible across a permitted reattach, preserving its existing local scrollback; detached remote output is not recovered. If the transport and child fail concurrently and the child status cannot be recovered without retaining state, eversh reports the transport failure rather than inventing a child status.

The public interface is `eversh connect HOST [--session NAME] [--take-over] [-- COMMAND...]`, `eversh attach HOST NAME [--take-over]`, `eversh observe HOST NAME`, `eversh list HOST [--local-host NAME] [--json]`, `eversh resume-all HOST [--local-host NAME]`, `eversh detach HOST NAME`, `eversh kill HOST NAME`, and `eversh ssh HOST [-- SSH_OPTIONS...]`.

`resume-all` lists matching live sessions, launches one Kitty tab per session when configured, targets `KITTY_LISTEN_ON` when available, keeps failed attaches visible, closes cleanly ended tabs, and reports every partial failure. Kitty integration remains in eversh and is absent from everpty and everssh.

## 8. Deployment and version policy

The remote host must already have a compatible combined `eversh` executable or the required standalone `everpty` and `everssh` roles on `PATH`. V1 does not upload binaries, install missing binaries, self-update, or run an upgrade agent. Installation and upgrades are operator actions; managed signed upgrades are a v2 candidate.

The everpty Unix-socket protocol and everssh bootstrap/QUIC protocol each carry an explicit protocol version. Unknown, unsupported, malformed, or downgraded versions fail closed and produce a clear stderr diagnostic that names the component and protocol version. Compatibility is determined by the wire protocol version, not by an assumed binary version or filename. A broker may continue running across an on-disk binary replacement; each later client must advertise and support the broker's live protocol version, and an incompatible client must fail without unlinking or replacing the broker.

Bootstrap SSH connections disable recursive eversh ProxyCommand use explicitly. V1 does not silently infer or synthesize ProxyJump behavior: a ProxyJump configuration is either handled by the user's ordinary bootstrap SSH path when the resulting UDP endpoint is explicitly reachable, or rejected with a clear diagnostic. Direct UDP and ZeroTier/Tailscale endpoint policy is explicit and independently testable.

The deterministic default endpoint policy selects the local address from the kernel route to the authenticated SSH bootstrap peer, uses the bootstrap peer's address family, binds port zero, and publishes the kernel-selected ephemeral UDP port. The implementation does not guess by enumerating unrelated interfaces. An operator may configure a bounded UDP port range for firewall policy. If the route yields no single usable address, if the peer is loopback, if no permitted port can be bound, or if the desired overlay path differs from the bootstrap route, startup fails with a clear stderr diagnostic requiring `--udp-endpoint ADDRESS:PORT`, `--udp-port-range START:END`, or the equivalent configuration override. An explicit endpoint override always wins and is validated before the bootstrap record is emitted.

## 9. Failure contracts

| Event | Required result |
| --- | --- |
| Local terminal closes | Attachment ends; child and broker continue. |
| Writer socket dies | Writer ownership becomes empty; future output continues to healthy observers and is otherwise drained and discarded. |
| Writer exceeds stall deadline | Writer is detached, its undelivered live queue is discarded, and PTY draining resumes without replay. |
| Observer stalls | Observer is disconnected; writer and child continue. |
| Writer without takeover | `Busy`; current writer is unchanged. |
| Explicit takeover | Ownership changes atomically; old writer becomes observer. |
| Child exits | Exit status is delivered; broker reaps and cleans state. |
| Broker startup fails | No child is left behind; typed error is returned. |
| Stale socket | Remove only after failed connect and exclusive lock. |
| UDP path changes | noq validates or switches the path and preserves the same stream when possible. |
| QUIC connection stalls or expires | That connection closes; the association opens one bounded reconnect epoch and retransmits only unacknowledged opaque frames. |
| Association lease/budget expires or queue exhausts | Terminal association failure: target TCP and SSH close, the server exits, and no expired frame is later delivered. |
| eversh sees terminal transport failure | Fresh bootstrap and SSH connection attach the same session. |
| Output while detached | Attached observers continue receiving future bytes; bytes are drained and discarded only when no attached client can accept them, and never replayed. |
| New terminal attaches | Future bytes only; no synthetic screen reconstruction. |
| Authentication fails | OpenSSH remains authoritative; no fallback trust. |
| Bootstrap client absent | Association server exits after its initial lease. |
| Shutdown direction fails | Request -> Drain -> Finalize completes within configured deadlines and reports the first cause. |

## 10. Security contract

- State directories, sockets, locks, and metadata are private to the owning UID.
- Protocol lengths, versions, message kinds, client counts, handshakes, token attempts, and deadlines are bounded before allocation or work.
- TLS certificate identity is checked by the exact SPKI pin received over authenticated SSH.
- The one-use token is random, constant-time compared, never logged, and never placed in argv, environment, metadata, or persistent storage.
- Server Retry and address validation protect unauthenticated QUIC allocation and amplification.
- The association server permits only its bootstrap-authorized loopback target, and only the first token-authenticated client key/association ID may resume it.
- Association replay memory is bounded by both wire bytes and frame count per direction; acknowledged frames are discarded, secrets are scrubbed at Finalize, and no frame is delivered after association expiry.
- 0-RTT is disabled.
- ProxyCommand and attach stdout contain only protocol data; diagnostics cannot corrupt it.
- Complete child environments, arbitrary secrets, and private keys never enter tracing or metadata.
- Dependency source, licence, vulnerability, and feature audits run before release.

## 11. Boundary-focused test contract

A feature is incomplete until its failure and ownership boundaries are exercised. Tests use deterministic arbitrary-byte fixtures, controlled clocks where useful, process fault injection, and Linux integration environments; measured gates record the environment rather than asserting unsupported universal performance.

### 11.1 everpty byte and ownership tests

- Forward NUL, invalid UTF-8, CSI, OSC, DCS, Kitty keyboard and graphics sequences, bracketed paste, alternate-screen bytes, CR, LF, CRLF, and partial sequences split across PTY reads byte-for-byte.
- Prove attach stdout has no synthetic bytes before child output and that no clear, cursor, redraw, status, newline conversion, or parser output is added.
- Prove output generated while detached is absent after reattach and a new observer receives no historical output.
- Race simultaneous attachers, same-name creators, writer disconnect, observer attach, takeover, queued old-writer input, and child exit; prove one writer boundary and explicit Busy.
- Fill observer queues, the writer queue, PTY output, and socket buffers independently; prove observers cannot block the writer, a healthy writer sees no silent loss, writer backpressure is finite, a stalled writer is detached at its deadline, and detached output is drained.
- Verify initial dimensions precede child spawn, only the writer resizes, no artificial nudge occurs, and real SIGWINCH reaches the child.
- Verify termios restoration after success, EOF, protocol error, SIGTERM, SIGHUP, and failed startup.

### 11.2 everpty lifecycle and security tests

- Start, attach, observe, detach, reattach, list, current, kill, child exit, process-group cleanup, broker crash, stale-socket recovery, and atomic metadata update.
- Verify permissions, peer UID checks, path limits, frame limits, malformed headers, unsupported versions, and partial-frame EOF.
- Prove no output, token, arguments, environment, or keystrokes enter metadata or persistent files.
- Run under resource pressure and assert configured finite client, queue, descriptor, worker, and child cleanup gates.

### 11.3 everssh protocol and network tests

- Verify exact bidirectional bytes for interactive SSH, arbitrary binary streams, EOF, half-close, remote command exit, SFTP, SCP, local forwarding, and remote forwarding.
- Accept only the pinned certificate, valid token, authorized target, and supported protocol; reject wrong pin, invalid token, reuse, expiry, duplicate auth, malformed bootstrap, and unauthenticated target access.
- Verify no target TCP connection is opened before QUIC authentication and no server becomes an open proxy.
- Exercise Retry, handshake limits, source validation, flow-control limits, stalled readers, close deadlines, and association process cleanup.
- Rebind or replace the UDP path and prove the same QUIC connection and SSH stream survive only when standard migration succeeds.
- Inject loss, duplication, reordering, fragmentation, delayed packets, path failure, sleep/wake, and interface changes; prove ordered delivery and configured finite memory.
- Destroy every path and prove bounded association reconnect, cumulative acknowledgement, duplicate suppression, terminal expiry, Request -> Drain -> Finalize cleanup, no surviving task, no delivery after expiry, and bounded eversh handoff.
- Fuzz bootstrap records, auth frames, resume handshakes, close sequences, stream boundaries, and arbitrary payload without treating payload as text.

### 11.4 eversh supervisor tests

Use fake ssh, everssh, remote-control, and Kitty launcher binaries to capture exact argv, environment allowlists, inherited descriptors, stdout/stderr separation, and exit mapping. Verify ssh_config and host arguments are preserved, recursive bootstrap is avoided, arbitrary child argv cannot become shell syntax, a live named broker is reattached after terminal transport failure, a missing or exited broker is not restarted, raw SSH commands and transfers are never replaced with a second OpenSSH operation, child exit does not retry, Busy/NotFound/auth failures remain visible, and resume-all reports partial launch failure.

At least one Linux release test runs real OpenSSH through everssh into everpty, and separate tests exercise the standalone everpty and everssh executables. No release claim is made from fakes alone.

## 12. Dependency and build policy

The workspace pins an exact reviewed Rust toolchain and MSRV, exact noq release and checksum, rustls features, and all direct dependencies in Cargo.lock. No dependency may be selected solely because it exposes an attractive experimental feature.

The baseline checks are `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-features`, `cargo deny check`, protocol fuzz targets, and Linux integration tests. The release job also checks licence notices, dependency advisories, reproducible package contents, and absence of terminal-emulation, second-SSH, Tokio/noq-in-everpty-core, Asupersync, GPL, AGPL, or custom-restricted production dependencies.

## 13. Staged delivery plan

Milestone 0-2 records below are historical outcomes and retain their original
scope wording. Milestones 3-5 are governed by this revision 2 contract.

### Milestone 0: bounded Rust/noq feasibility and dependency pin gate

Build a minimal Rust/noq one-stream ProxyCommand to a loopback byte server with the SSH bootstrap record, ephemeral pin/token, rustls path, Retry, half-close, bounded backpressure, address rebinding, standard migration, complete path loss, cancellation, Request -> Drain -> Finalize shutdown, process exit, and no-replay assertions. Inspect noq's maintained Tokio integration and API stability, test the exact rustls feature path, record compiler/MSRV and cross-build results, and pin the exact release and checksum.

Exit criteria are a passing migration test on the intended Linux network setup, passing hard-failure and shutdown tests, bounded resource evidence, acceptable dependency/licence audit, and a recorded fallback decision. If noq fails a required standard migration test or cannot provide a supportable pinned integration, run the same bounded test against Quinn and record why it is selected. No alternative implementation is maintained.

**Milestone 0 outcome (2026-08-21, evidence in `spikes/noq-m0/results.md` and eversh-chl.1): noq is selected.** Pins: Rust 1.95.0 build toolchain with MSRV 1.88 (`rust-version = "1.88"`); `noq = "=1.1.1"` with default features disabled and exactly `runtime-tokio`, `rustls`, `ring`, `bloom` enabled; crate SHA-256 `09e4bb6601fa543c110d8957813267d5a8d775a0f8fbaccf1f615d06ba9b10da` (upstream tag noq-v1.1.1 at 12a4bf0b42070b570fb8cf90fe315c630b03f56e); rustls 0.23.43 through the `noq::rustls` re-export using the ring provider. Real address rebinding preserved the same QUIC connection and stream on netns/veth paths under loss with byte-exact delivery; total path loss closed bounded without replay; the full OpenSSH ProxyCommand compatibility gate passed. Quinn was not selected and is not maintained. Spike limit values remain candidates for Milestone 1 remeasurement (section 4).

### Milestone 1: Cargo workspace and wire skeleton

Create one Cargo workspace, three libraries, three binary targets, licenses, attribution, CI, typed errors, versioned everpty frames, bootstrap/auth schemas, limit configuration, deterministic byte fixtures, and fuzz harnesses. Keep implementation stubs nonfunctional until boundary tests compile.

Exit criteria are clean formatting, clippy, dependency audit, workspace tests, binary help, and protocol fixtures that are reviewed before behavior is added.

### Milestone 2: transparent everpty

Implement the daemon-per-session PTY broker, initial-writer-before-spawn ordering, Unix-socket framing, Busy/takeover ownership, observers, resize, signals, stale cleanup, session commands, bounded live queues, and drain/discard. Adapt Keepty only where compatible and preserve required attribution; delete replay/parser/screen/redraw/logging/input-interception behavior.

Exit criteria are all everpty byte, ownership, lifecycle, security, fault, and resource tests under a real Linux PTY.

### Milestone 3: secure everssh

Implement SSH-assisted bootstrap, ephemeral pin/token, one authenticated noq stream, loopback target restriction, half-close, flow control, migration, bounded association resume, path failure, and Request -> Drain -> Finalize. Verify the raw OpenSSH, SFTP, SCP, and forwarding paths.

Exit criteria are real OpenSSH compatibility and all bootstrap, migration, shutdown, fuzz, and resource tests.

### Milestone 4: thin eversh composition

Implement connect, attach, observe, list, resume-all, detach, kill, raw ssh mode, combined-binary role dispatch, generated origin metadata, Kitty tab launching, reconnecting-link deferral, and fresh-SSH reconnect after terminal association failure. Keep terminal stdin/stdout inherited through OpenSSH and keep all relay work in everssh.

Exit criteria are transport retry versus child-exit distinction, same-session reattach, visible attach failures, preserved local scrollback, and proven absence of detached-output replay.

### Milestone 5: release hardening

Run hostile-network, race, crash, security, fuzz, descriptor, memory, CPU-idle, sleep/wake, overlay, real-sshd, packaging, licence, and vulnerability gates. Measure configured timeout and resource values on supported Linux environments, document exact limits and assumptions, and publish install/upgrade instructions.

Exit criteria are every v1 acceptance criterion below, with evidence artifacts retained in CI or release notes.

## 14. v1 release acceptance

A v1 release is accepted only when all of the following are true:

- Linux install produces exactly three physical executables from the same Rust workspace: standalone everpty, standalone everssh, and combined/multi-role eversh.
- A real OpenSSH client authenticates through everssh to system sshd, including a PTY shell, command execution, SFTP, SCP, local forwarding, and remote forwarding.
- The system OpenSSH configuration, host-key policy, agent, keys, and exit semantics remain authoritative.
- everpty preserves arbitrary PTY bytes, survives attachment loss, drains and discards detached output, and never parses or restores terminal state.
- Busy, explicit takeover, observer future-only output, writer resize, process-group cleanup, and stale-socket rules pass race and fault tests.
- Standard QUIC migration preserves a live SSH stream on the supported direct or overlay UDP setup; complete path loss inside the measured association lease resumes the SSH stream byte-exactly, and loss past the lease/budget causes a terminal failure followed by fresh SSH attach.
- Request -> Drain -> Finalize leaves no owned task, socket, child, or secret-bearing process after each tested terminal condition.
- All configured protocol, memory, queue, handshake, timeout, process, descriptor, and retry limits are finite, tested, and documented with measured selection evidence.
- Fuzz, hostile-network, sanitization, licence, vulnerability, reproducibility, and real-OpenSSH tests pass.
- No release artifact contains terminal-emulation, semantic replay, remote scrollback, second-SSH, Asupersync, GPL/AGPL, or custom-restricted production code.

## 15. Permanent core non-goals

Remote scrollback, terminal parsing or state restoration, local prediction, semantic output replay, per-observer virtual terminal viewports, resumption after association expiry, server-side rendering, terminal snapshots, and application-level exactly-once reconnect are permanent core non-goals. They are not deferred features and must not be smuggled into a v1 or v2 implementation under another name. everssh v2's bounded opaque transport-frame retransmission, retained only until cumulative acknowledgement and always suppressed as duplicates after delivery, is the reviewed exception; it never becomes terminal state, SSH semantics, or unbounded history.

Any future feature that needs terminal parsing or replay belongs in an optional product above these raw primitives, not in the everpty or everssh data paths.

## 16. Review checklist

Every change review answers: does it inject bytes into PTY or ProxyCommand stdout; retain output for later attachment; let an observer block a writer; change ownership without explicit takeover; deliver bytes after association expiry or beyond the bounded replay queues; bypass OpenSSH authentication; create an unbounded resource; expose a secret; add a second runtime; make eversh relay terminal data; or weaken the Rust workspace and licence boundary? Any answer that violates the locked contract blocks the change until this design is revised.
