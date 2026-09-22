# eversh design

Status: current product contract | Last updated: 2026-09-19

This document describes eversh as released: four executables built from one Cargo workspace, the contract each component implements, and the rules a change must respect. The terms MUST, MUST NOT, SHOULD, and MAY are normative; changing a MUST or MUST NOT requires a recorded revision here. The everudp wire contract is frozen in [plans/everudp-v1.md](../plans/everudp-v1.md); this document summarizes it and defers to it.

## 1. Overview and released scope

eversh provides persistent remote shells without a terminal multiplexer or a remote screen buffer. Two failure classes stay independent: everpty keeps the remote PTY and child alive when its client disappears, and the QUIC transports carry the connection over a roaming path that survives address changes and short outages.

The released product installs exactly four physical executables: standalone `everpty`, standalone `everssh`, standalone `everudp`, and the combined multi-role `eversh` supervisor. eversh targets Linux with directly reachable UDP between client and remote host, including ZeroTier or Tailscale overlay addresses. OpenSSH remains the authority for user and host authentication, ssh_config, PTY negotiation, command execution, forwarding, SFTP, and SCP.

No component provides terminal prediction or local echo. QUIC is a reliable ordered transport, not latency magic; interactive latency remains network round-trip time.

## 2. Architecture and ownership

~~~text
Kitty or another local terminal emulator
  owns rendering, screen state, scrollback, copy, paste, and keyboard handling
                  |
                  v
          system OpenSSH client
                  |
                  | ProxyCommand stdin/stdout
                  v
        everssh client ===== QUIC/UDP ===== everssh server
                                                |
                                                | TCP loopback
                                                v
                                         remote OpenSSH sshd
                                                |
                                                | remote command
                                                v
               everpty attach -- Unix socket -- PTY broker -- child process
~~~

With `--transport everudp` the data path changes after bootstrap: terminal bytes travel directly on QUIC streams between the local terminal and a persistent per-session gateway on the remote host, which owns the everpty writer. SSH is used only for the authenticated bootstrap and low-frequency recovery control.

Ownership boundaries are deliberate and enforced: the local terminal owns rendering and scrollback; OpenSSH owns authentication and SSH features; everssh owns the roaming encrypted byte transport; everudp owns direct terminal delivery above everpty; everpty owns PTY and child lifetime; eversh owns composition and reconnect policy and never relays or parses terminal bytes.

Process model:

- One broker process per everpty session; no central manager. The broker lives while the child lives.
- One association server process per everssh bootstrap, which may accept sequential resume connections until its lease ends.
- One persistent gateway process per everudp session, alive for the entire PTY lifetime.
- The combined `eversh` binary links all libraries and dispatches a private role marker to exactly one role before runtime initialization; brokers, gateways, and QUIC servers always run as separate operating-system processes.
- CLI parsing, terminal mode changes, exit codes, and stderr presentation stay at binary edges. Libraries accept typed configuration and return typed errors; library functions MUST NOT inspect global arguments, print diagnostics, or call process exit.
- everpty has no async-runtime dependency (a small poll loop or bounded fixed workers). everssh and everudp each own exactly one Tokio runtime. eversh supervises child processes and creates no relay loop.

## 3. Core invariants

- Byte transparency: PTY, SSH, and QUIC payloads are arbitrary byte slices and MUST NOT require UTF-8. No component parses, translates, filters, normalizes, injects, or synthesizes terminal escape sequences; there is no userspace newline conversion.
- No terminal state: no component maintains a screen model, scrollback, session history, replay buffer, snapshot, prediction state, or attach-time redraw. Terminal history is not PTY state; the child application owns any semantic transcript, repaint, or resume.
- Output while detached: everpty continues draining the PTY and discards bytes when no attached client can accept them. A new attachment receives only bytes produced after its accepted attachment. Kernel queues, bounded live delivery queues, and bounded QUIC retransmission state are delivery buffers, not retained session history.
- stdout purity: attach stdout contains only child PTY output; ProxyCommand stdout contains only the target OpenSSH byte stream. Diagnostics, state changes, retries, and errors go to stderr and MUST NOT contain secrets or payload bytes.
- Bounded before allocation or work: protocol lengths, versions, message kinds, client counts, handshakes, token attempts, queues, and deadlines are finite configured values (section 9).
- Fail-closed versioning: every wire protocol carries an explicit version; unknown, unsupported, malformed, or downgraded versions fail closed with a stderr diagnostic naming the component and protocol version (section 5).
- The attach client MAY put the outer terminal into raw mode and MUST restore the original termios settings after normal exit and every handled signal.

## 4. Component contracts

### 4.1 everpty — named PTY session broker

everpty owns one named child and PTY, a private versioned Unix-socket protocol, writer and observer membership, resize and signal handling, child reaping, discovery metadata, and stale-socket cleanup. It does not own network, SSH, terminal rendering, logs, or redraw.

Lifecycle: the broker MUST bind its private socket and establish readiness before spawning the child. `everpty start NAME [-- COMMAND...]` launches the broker and becomes its initial writer; it is not a detached-start command. The sequence is: validate name and command; create private state and socket; signal readiness; connect the start client with real rows and columns; register writer delivery; create the PTY and child process group; spawn the child; begin reading the PTY immediately. If the initial writer does not arrive before the startup deadline, the broker exits without spawning the child. States are `Starting -> WaitingForWriter -> Running -> Exited` (`Failed` for startup failure); writer ownership is independent (`NoWriter <-> Writer(client_id)`).

Local protocol: the frame is `u32 body_length (big endian), u8 protocol_version, u8 message_kind, u8[] payload`. Kinds are `Hello`, `HelloAck`, `Busy`, `Input`, `Output`, `Resize`, `Ownership`, `DetachWriter`, `Kill`, `Ping`, `Pong`, `Exit`, and `Error`. Raw PTY bytes occur only in `Input` and `Output`; control strings are bounded UTF-8; a complete header is validated before allocation.

Ownership: a second writer returns `Busy` without changing the current writer; only explicit `--take-over` changes ownership. Takeover atomically revokes the old writer at the next output boundary, discards its undelivered live queue, and rejects its queued input and resize. The old writer may remain as an observer and receives an ownership event before any subsequent output. Observers receive future output only, never input control or resize, and are disconnected when their finite queues fill; no observer is promoted automatically.

PTY and signals: the initial writer's dimensions are applied before child spawn; only the current writer may resize, and TIOCSWINSZ is applied only when dimensions actually changed. The broker never nudges dimensions, moves the cursor, clears the screen, injects a redraw, or synthesizes SIGWINCH. The child has its own session and process group with the PTY slave as controlling terminal and inherits the creator environment (TERM is not hard-coded). Kill sends SIGTERM to the process group, waits the grace deadline, then SIGKILL; the broker reaps and reports code or signal.

Output delivery: the current writer receives every PTY byte in order while it remains within its finite queue and stall deadline; a full queue backpressures the PTY rather than dropping bytes. A writer that disconnects or exceeds the stall deadline is revoked, its undelivered queue is discarded, and PTY draining resumes. Observers are best-effort and are disconnected when their finite queues fill.

State and security: the state root is the first usable value among `EVERSH_STATE_DIR`, `XDG_RUNTIME_DIR/eversh`, `XDG_STATE_HOME/eversh`, and `$HOME/.local/state/eversh` (0700 directories, 0600 sockets and metadata), shared by the eversh remote role. Metadata is discovery-only and bounded: name, broker PID, child PID, creation time, executable label without arguments, origin labels. The broker sets `EVERPTY_SESSION` in the child environment. A stale socket is removed only after a failed connection attempt plus an exclusive per-session lock; peer credentials are checked so the connecting UID matches the broker owner. Metadata updates are atomic; session names are never shell fragments.

Public interface: `everpty start NAME [-- COMMAND...]`, `everpty attach NAME [--take-over]`, `everpty observe NAME`, `everpty list [--json]`, `everpty current`, `everpty detach NAME`, `everpty kill NAME`. `start` fails with `AlreadyExists` when the name is live; `detach` revokes the writer without sending a terminal byte; the internal attach-or-create operation used by eversh is atomic under the per-session lock.

### 4.2 everssh — roaming QUIC transport

everssh is a transparent one-stream QUIC ProxyCommand bridge to the authorized loopback OpenSSH server, with a bounded resumable association above individual QUIC connections. It does not parse SSH or terminal data, implement SSH authentication, own PTYs, or predict input.

Bootstrap: each ProxyCommand performs an ordinary system SSH bootstrap that launches one remote everssh server. The server binds the selected directly reachable UDP address and port, creates an ephemeral TLS certificate and one-use token, detaches from the bootstrap process, writes exactly one bounded newline-terminated bootstrap record (application protocol version, endpoint, SPKI SHA-256 pin, token, diagnostics-safe process identity), waits for one authenticated QUIC client, and connects only to the loopback sshd port derived from the authenticated connection's `SSH_CONNECTION`. The first authentication binds the one-use token, association ID, client certificate SPKI, authorized target, and association lease; the server then accepts only resume connections presenting the same client key and association ID until the association ends or the lease expires. The client cannot select an arbitrary target and the server is never an open proxy.

Wire: ALPN `everssh-link/2`, TLS 1.3 via noq's reviewed rustls path, 0-RTT disabled, server Retry and address validation before expensive unauthenticated state. The first client-opened bidirectional stream begins with a bounded versioned authentication frame (token plus authorized target selector); the remaining stream bytes are opaque SSH data. Exactly one ordered reliable stream carries SSH at a time; QUIC datagrams and multiplexing are unused; extra streams, duplicate tokens, wrong pins, wrong versions or targets, foreign client keys, or duplicate association IDs close the connection.

Resume: standard QUIC migration is the live-connection mobility contract. After a connection dies, the client opens one bounded reconnect epoch (default budget about 350 s beneath the 360 s association lease) and retransmits opaque frames retained until cumulatively acknowledged; the receiver suppresses already-delivered duplicates. Each direction retains at most 4 MiB / 1,024 frames; acknowledged frames are discarded. Loss past the lease or budget is a terminal association failure: the target TCP connection and SSH stream close and no expired frame is later delivered.

Shutdown: Request -> Drain -> Finalize is explicit. Request stops new work after the first terminal condition and records the cause; Drain closes or completes owned copy directions and waits only until configured deadlines; Finalize closes sockets, joins or aborts owned tasks, closes the target TCP connection, scrubs secret state, and verifies no owned task remains. Every terminal condition is idempotent and the first cause wins. everssh reaps only processes it owns and never the system sshd target.

Runtime and interface: exactly one Tokio runtime per process. The public standalone interface is `everssh ssh-proxy SSH_DESTINATION SSH_PORT [--ssh-option OPTION...]` (an OpenSSH ProxyCommand passes `%n` and `%p`); `--remote-bin ABSOLUTE_PATH` selects the remote binary by canonical path. Bootstrap connections disable recursive ProxyCommand use, remote commands, TTY allocation, and unrelated forwarding. SSH options are vetted by the audited allowlist in `crates/everssh/src/ssh_policy.rs`; anything else, including `-oProxyCommand=...` or `-J`, is rejected before any process is spawned.

### 4.3 everudp — direct QUIC terminal transport

everudp adds direct terminal delivery above everpty without carrying terminal bytes through SSH after bootstrap. After the SSH-authenticated bootstrap and a QUIC association commit, a persistent per-session gateway on the remote host owns the everpty writer (through a revocable PTY fast-path lease) and every terminal byte travels directly over TLS 1.3 QUIC streams between the local terminal and the gateway. Delivery on a healthy association is exact-once and in order; bounded replay queues (4 MiB / 1,024 operations per direction, one GAP record per output overrun) reconnect the same association for the entire PTY lifetime.

Strict `--transport everudp` allows three seconds for the initial commit and exits 69 (`EX_UNAVAILABLE`) if it cannot commit before raw terminal mode, terminal traffic, or gateway writer ownership. `--transport auto` catches exactly that pre-commit exit, prints one visible fallback line, and invokes everssh once; it never falls back after traffic, during reconnect, on authentication or protocol errors, or when an existing gateway owns the writer.

A new `attach` client has a fresh authenticated association and no durable output position. Its initial GAP is relative to that fresh position, even after the persistent gateway has confirmed earlier gaps for another client. Updated clients also accept a validated initial GAP from older gateways without restarting them; this initialization is allowed only on first admission. Same-association network resume retains strict epoch continuity and duplicate suppression. Reattachment preserves the broker, PTY child, and application state; it does not restore discarded terminal history.

During everudp recovery, a bootstrap parent that reports the named session is no longer live (for example after a host reboot) exits 5 — the same value as the supervisor's probe not-live contract — and the client reports the session ended instead of the detached exit 7, so wrappers never offer a resume that cannot succeed. A remote that predates this contract keeps its generic prepare failure, which the client still classifies as an unconfirmed detach.

The frozen everudp contract, its performance release decision, and its evidence are in [plans/everudp-v1.md](../plans/everudp-v1.md).

### 4.4 eversh — supervisor

eversh parses commands, resolves effective OpenSSH configuration, starts the everssh or everudp transport, constructs bounded versioned remote control requests, invokes the installed `ssh` binary, preserves inherited stdin/stdout/stderr for the live terminal path, records session origin metadata, and applies reconnect policy. It MUST NOT relay terminal bytes or become a second SSH implementation. Remote command strings contain only fixed command words, validated conservative identifiers, and at most one bounded unpadded-base64url token containing a versioned child-argument request; decoded bytes are never evaluated as shell syntax, NUL is rejected before process creation, and bootstrap tokens never appear in argv or environment.

Link-status channel: every structured interactive operation (`connect`, `attach`, `observe`) and every reconnect probe allocates a private per-spawn link-status file under the eversh state root and passes its path to the local everssh edge as a `--status-file` argument, never an environment variable. The file records `carrying` once the QUIC stream first delivers remote-originated bytes and a terminal `cause <clean-close|transport-failure> carried=<0|1>` on every exit path. Allocation is fail-closed: if no state root resolves or the path cannot travel as a quoted argument, the operation fails locally before any ssh child exists.

Classification and retry: on ssh exit 255, `clean-close` is an ordinary SSH failure (including authentication failures and remote commands exiting 255), reported with no probe and no retry; `transport-failure`, or a missing or unparseable status file, enters a bounded probe-gated reconnect episode. eversh uses a fresh authenticated bootstrap to ask whether the same broker is still alive and retries only when it is, with finite exponential backoff, jitter, an overall deadline, and an invocation-wide episode-restart cap; a Busy reattach never consumes the attempt budget. `eversh ssh`, arbitrary raw commands, forwarding-only connections, SFTP, and SCP are never restarted automatically because doing so could duplicate application work; their live association may still resume within its lease. The same local terminal process remains visible across a permitted reattach, preserving local scrollback; detached remote output is not recovered. If transport and child fail concurrently such that child status cannot be recovered, eversh reports the transport failure rather than inventing a child status.

Public interface: `eversh [--remote-eversh WORD_OR_PATH] connect HOST [--session NAME] [--transport everssh|everudp|auto] [--take-over] [--ssh-option OPTION]... [-- COMMAND...]`, plus `attach`, `observe`, `list [--local-host NAME] [--json]`, `resume-all [--local-host NAME] [--transport ...]`, `detach`, `kill`, and `ssh HOST [-- SSH_OPTIONS [-- COMMAND]]`. `resume-all` lists matching live sessions, opens one Kitty tab per session (targeting `KITTY_LISTEN_ON`, keeping failed attaches visible until stdin closes, closing cleanly ended tabs), and reports every partial failure. Kitty integration stays in eversh.

## 5. Deployment, versions, and upgrades

The remote host must already have a compatible combined `eversh` binary on the login `PATH`, or the caller must point at it (`--remote-eversh` on eversh, `--remote-program` on everudp, `--remote-bin` on everssh). eversh does not upload binaries, install missing binaries, self-update, or run an upgrade agent; installation and upgrades are operator actions.

Compatibility is decided by wire protocol version, never by binary version or filename: the everpty socket protocol, the everssh bootstrap record (`everssh v2`) and ALPN (`everssh-link/2`), the private role grammar (`v1`), and the everudp bootstrap each fail closed with a diagnostic naming the component and version. A running broker survives an on-disk binary replacement; a later client must speak the broker's live protocol version and must fail without disturbing the broker. The pinned pre-v2 product (`everlink`, bootstrap prefix `everlink v1`, ALPN `eversh-link/1`) is not wire-compatible in either direction; upgrade both endpoints in one maintenance action.

everudp's SSH bootstrap request carries the client's `TERM` as a trailing optional field: a client without the field still bootstraps against a remote that has it, while a client with the field against an older remote fails closed at the bootstrap boundary. Upgrade the remote host first.

Bootstrap SSH connections disable recursive eversh ProxyCommand use explicitly. ProxyJump is not inferred or synthesized: a ProxyJump configuration is either handled by the user's ordinary bootstrap SSH path when the resulting UDP endpoint is explicitly reachable, or rejected with a clear diagnostic. The deterministic default UDP endpoint policy selects the local address from the kernel route to the authenticated SSH peer, uses the peer's address family, binds port zero, and publishes the kernel-selected port; an operator may configure `--udp-endpoint ADDRESS:PORT` or a bounded `--udp-port-range START:END`, and an explicit override always wins and is validated before the bootstrap record is emitted. Startup fails with a clear diagnostic when the route yields no single usable address, the peer is loopback, or no permitted port binds.

## 6. Security contract

- State directories, sockets, locks, and metadata are private to the owning UID (0700 directories, 0600 files).
- Protocol lengths, versions, message kinds, client counts, handshakes, token attempts, and deadlines are bounded before allocation or work.
- TLS certificate identity is checked by the exact SPKI pin received over authenticated SSH; the one-use token is random, constant-time compared, never logged, and never placed in argv, environment, metadata, or persistent storage.
- Server Retry and address validation protect unauthenticated QUIC allocation and amplification; the association server permits only its bootstrap-authorized loopback target, and only the first token-authenticated client key and association ID may resume it.
- Association and replay memory is bounded by wire bytes and frame count per direction; secrets are scrubbed at Finalize; 0-RTT is disabled.
- ProxyCommand and attach stdout contain only protocol data, so diagnostics cannot corrupt them. Complete child environments, arbitrary secrets, and private keys never enter tracing or metadata.
- Dependency source, licence, vulnerability, and feature audits run before release (section 8).

## 7. Failure contracts

| Event | Required result |
| --- | --- |
| Local terminal closes | Attachment ends; child and broker continue. |
| Writer socket dies | Writer ownership becomes empty; future output continues to healthy observers and is otherwise drained and discarded. |
| Writer exceeds stall deadline | Writer is detached, its undelivered live queue is discarded, and PTY draining resumes. |
| Observer stalls | Observer is disconnected; writer and child continue. |
| Writer without takeover | `Busy`; current writer is unchanged. |
| Explicit takeover | Ownership changes atomically; old writer becomes observer. |
| Child exits | Exit status is delivered; broker reaps and cleans state. |
| Broker startup fails | No child is left behind; typed error is returned. |
| Stale socket | Remove only after failed connect and exclusive lock. |
| UDP path changes | The QUIC stack validates or switches the path and preserves the same stream when possible. |
| QUIC connection stalls or expires | That connection closes; the association opens one bounded reconnect epoch and retransmits only unacknowledged opaque frames. |
| Association lease/budget expires or queue exhausts | Terminal association failure: target TCP and SSH close, the server exits, and no expired frame is later delivered. |
| eversh sees terminal transport failure | Fresh bootstrap and SSH connection attach the same session. |
| Output while detached | Attached observers continue receiving future bytes; bytes are drained and discarded when no attached client can accept them. |
| New terminal attaches | Future bytes only; no synthetic screen reconstruction. |
| Authentication fails | OpenSSH remains authoritative; no fallback trust. |
| Bootstrap client absent | Association server exits after its initial lease. |
| Shutdown direction fails | Request -> Drain -> Finalize completes within configured deadlines and reports the first cause. |

## 8. Testing and qualification

A feature is incomplete until its failure and ownership boundaries are exercised. Tests use deterministic arbitrary-byte fixtures, controlled clocks, process fault injection, and Linux integration environments; measured gates record their environment rather than asserting universal performance.

- everpty: byte-for-byte forwarding of NUL, invalid UTF-8, CSI/OSC/DCS, Kitty keyboard and graphics, bracketed paste, alternate-screen bytes, CR/LF/CRLF, and partial sequences split across reads; no synthetic bytes on attach stdout; detached output absent after reattach; attach, create, takeover, disconnect, and exit races; independent queue fills and stall deadlines; writer-only resize with real SIGWINCH; termios restoration on every path; lifecycle, permissions, peer-UID checks, malformed frames, and resource pressure.
- everssh: exact bidirectional bytes for interactive SSH, binary streams, EOF, half-close, SFTP, SCP, and local/remote forwarding; only the pinned certificate, valid token, and authorized target are accepted; no target TCP connection before QUIC authentication; Retry, handshake limits, flow control, close deadlines; path rebinding and standard migration; loss, duplication, reordering, and fragmentation with ordered delivery and finite memory; total path loss with bounded resume, duplicate suppression, terminal expiry, and Request -> Drain -> Finalize cleanup leaving no owned task.
- eversh: fake ssh, everssh, and Kitty binaries capture exact argv, environment allowlists, inherited descriptors, stdout/stderr separation, and exit mapping; recursive bootstrap avoidance; live-broker reattach after transport failure; a missing or exited broker is not restarted; Busy/NotFound/auth failures stay visible; resume-all reports partial launch failure.
- everudp: contract gates, fuzz targets, and evidence per [plans/everudp-v1.md](../plans/everudp-v1.md).

CI (`.github/workflows/ci.yml`) runs fmt, clippy with `-D warnings`, workspace tests, a no-default-features lib check, MSRV 1.88 and aarch64 cross checks, and cargo-deny. Release qualification additionally runs `fuzz/qualify-m3.sh` through `qualify-m6.sh` (deterministic gates, netns migration and loss, resource bounds, fuzz campaigns, real-OpenSSH end-to-end, packaging) and records immutable receipts under `docs/release-evidence/`; every qualify script requires a clean committed tree and binds its receipt to exact head and tree SHAs. No release claim is made from fakes alone: at least one Linux release test runs real OpenSSH through everssh into everpty.

## 9. Limits and tuning

Every configurable limit is finite, tested, and defined in code as normative: `crates/everpty/src/limits.rs`, `crates/everssh/src/limits.rs`, `crates/eversh/src/limits.rs`, and `crates/everudp/src/limits.rs`. Limits are either contract values (wire-format bounds such as `frame_max_body` 64 KiB, `auth_frame_len` 35, `max_bi_streams` 1) or runtime values (behavioral bounds such as the 360 s association lease, the roughly 350 s per-outage reconnect budget, the 4 MiB / 1,024-frame replay queues, the 20 s stall deadlines, the 60 s retry deadline, and the episode-restart cap of 3).

A contract value changes only with a recorded revision here. A runtime value may change only with its named qualification gates green — the deterministic workspace gates plus, for transport values, the everssh netns gates; a release-qualified change additionally requires the full m5 gate. The new value lands in the same change as its limits definition and selection evidence. Selection evidence and measured environments live in the qualification receipts under `docs/release-evidence/`.

## 10. Permanent non-goals

Remote scrollback, terminal parsing or state restoration, local prediction, semantic output replay, per-observer virtual terminal viewports, resumption after association expiry, server-side rendering, terminal snapshots, and application-level exactly-once reconnect are permanent non-goals. They are not deferred features and MUST NOT be introduced under another name. The bounded opaque-frame retransmission in everssh and everudp — retained only until cumulative acknowledgement, always bounded, never interpreted — is the reviewed exception, and it never becomes terminal state or SSH semantics.

## References and licence

Reviewed reference projects, source snapshots, and licence decisions are recorded in [plans/reference.md](../plans/reference.md); the vendored noq provenance is under `vendor/noq/EVERSH-PATCH.md` and `vendor/noq-proto/EVERSH-PROVENANCE.md`. eversh is dual-licensed under the MIT licence or the Apache License 2.0, at the user's option; dependencies and incorporated code must be distributable under both choices.
