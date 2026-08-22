# M2 Implementation Plan — transparent everpty broker (eversh-chl.3)

Decision-complete. Normative sources: plans/design.md §1–§5, §9–§11.1–11.2,
§13 (Milestone 2); plans/reference.md (Keepty = permissive structural
reference, adapt-with-attribution only; dtach/atch/zmx/zmosh = behavior/test
references only); plans/m1-plan.md §2–§3 (pinned dependencies); implemented
M1 APIs (`everpty::{frame, lifecycle, limits, error}`).

## 0. Hard invariants (checked per commit)

- No terminal parsing, screen model, scrollback, retained/replay/log buffer,
  redraw, synthetic SIGWINCH, newline conversion, detach key, or input
  interception. Raw PTY bytes flow as `Vec<u8>`/`OsString` end to end.
- everpty core never depends on Tokio or noq; the cargo-metadata graph test
  admits nix+libc into everpty's closure and nothing else new.
- Output is delivered only live; detached output is drained and discarded; a
  healthy writer is lossless within finite backpressure.
- Libraries never print, read global arguments, or exit; stderr and exit
  codes stay at the `everpty` binary edge.
- Wire encoding is unchanged from M1 (13 kinds). M2 defines additional
  connection-state semantics on top of it; no new frame kinds.

## 1. Module layout (crates/everpty/src/)

| Module | Responsibility |
|---|---|
| `sys.rs` | Tiny audited nix/libc wrappers: openpty, TIOCGWINSZ/TIOCSWINSZ/TIOCSCTTY ioctls, poll, Unix socket bind/accept + SO_PEERCRED (send with MSG_NOSIGNAL), signalfd, waitpid(WNOHANG), killpg, PDEATHSIG + getppid re-check, flock, exclusive-create + rename, no-follow opens, allocation-free `execve`. Direct libc only where nix is insufficient; each wrapper documents the syscall. |
| `state.rs` | Poll-event reducer over the M1 pure `BrokerState` transitions. |
| `broker.rs` | Broker: bind, readiness pipe, accept (≤8 per iteration), per-client state, the single poll loop, output fan-out, exit handling. |
| `client.rs` | ClientConn: header-gated framing reader, bounded encoded-frame output queues with write offsets, POLLOUT drain, writer input queue. |
| `child.rs` | openpty, session/pgid setup, disciplined fork/exec, reaping, SIGTERM→grace→SIGKILL, exit-status capture. |
| `session.rs` | State-root discovery, 0700/0600 paths, per-session lock, atomic metadata, stale-socket recovery, discovery. |
| `attach.rs` | Attach-client library half: connect, Hello, termios lifecycle, stdin→Input, Output→stdout, SIGWINCH resize. |
| `run.rs` | Typed command API (start/attach/observe/list/current/detach/kill); typed errors, no printing. |
| `main.rs` | clap edge: real flags (`-- COMMAND...`, `--take-over`, `--json`), Error → diagnostics/exit mapping. |
| `tests/` | `broker_linux.rs`, `bytes.rs`, `ownership_race.rs`, `security.rs`, `resources.rs`, `cli.rs`. |

## 2. Dependencies (pinned per M1 plan and Cargo.lock)

- `nix = "=0.31.3"`, features `fs, poll, process, signal, socket, term, user`
  — everpty only.
- `libc = "=0.2.189"` — everpty only, behind `sys.rs` wrappers.
- No other new production dependencies. No async runtime, no terminal crate.
- Verified against the pinned sources: `nix 0.31.3` exposes all seven named
  features and `pty::openpty` (`term`), `poll`, `signalfd::SignalFd`,
  `waitpid(WNOHANG)`, `kill`/`killpg`, `fcntl::flock`, `sockopt::
  PeerCredentials` (`socket`), `prctl::set_pdeathsig` (`process`, Linux),
  `pipe2(O_CLOEXEC)`, `open/openat` with `O_EXCL`/`O_NOFOLLOW`, `setsid`,
  `setpgid`, `dup2`, `umask`, `getppid`; its MSRV is 1.69. nix's
  `execvp`/`execvpe` are NOT used — `to_exec_array()` allocates after
  fork, violating async-signal safety. Direct libc is required for the
  `TIOCGWINSZ`/`TIOCSWINSZ`/`TIOCSCTTY` ioctl calls and the
  allocation-free `execve` wrapper taking prebuilt pointer arrays;
  `/proc/<pid>/stat` start-time reads use plain `std::fs`.
- Graph test extended: everpty's transitive closure may contain nix+libc and
  still must not contain tokio/noq/ring/rcgen/clap (without the `cli`
  feature).

## 3. Poll-based broker loop (single-threaded)

One thread; one `poll(2)` per iteration over:

- PTY master: POLLIN → read chunk (≤16 KiB) → output fan-out (§6);
  POLLOUT → drain queued writer input; POLLHUP/POLLERR → enter the
  child-exit drain path (§7) regardless of reap order — SIGCHLD may
  arrive before or after the last readable byte.
- Every client socket: POLLIN → frame dispatch by role/connection state;
  POLLOUT → drain that client's output queue; POLLHUP → role-appropriate
  disconnect.
- signalfd: SIGCHLD → waitpid(WNOHANG); SIGTERM/SIGINT/SIGQUIT/SIGHUP →
  kill path.
- **SIGPIPE safety**: the broker ignores SIGPIPE (`SIG_IGN`) so
  readiness-pipe and socket writes observe EPIPE/errno instead of dying;
  every broker/client Unix-socket write uses `send(MSG_NOSIGNAL)` (or an
  equivalently explicit no-SIGPIPE wrapper). The child resets SIGPIPE to
  default before exec. Attach-stdout EPIPE/SIGPIPE follows the ordinary
  terminal-restoration/error path.
- At most 8 accepts per poll iteration.

All fds are `O_NONBLOCK`. Poll timeout = earliest of: startup deadline,
incomplete-frame deadlines, writer-stall deadline, kill grace, PTY-child-exit
drain deadline. Time comes from an injected `trait Clock` (monotonic in
production, mock in tests) so all deadlines are deterministically testable.
No worker threads. Only a healthy current writer may backpressure the PTY;
observer pressure never pauses master reads (§6). There is no periodic
keepalive: Ping/Pong is probe/request-response only, and Unix-socket HUP plus
bounded output queues detect dead or stalled clients.

## 4. Startup ordering (bind → readiness → writer with dimensions → PTY+child)

`everpty start NAME [-- COMMAND...]`:

1. Validate the name (`frame::validate_name`). The command is a
   `Vec<OsString>`, non-empty, no NUL bytes; `$SHELL` (else `/bin/sh`) is
   only the default executable path. Direct exec only; never shell
   evaluation.
2. State root = the first usable of `EVERSH_STATE_DIR`,
   `XDG_RUNTIME_DIR/eversh`, `XDG_STATE_HOME/eversh`,
   `$HOME/.local/state/eversh`. All state paths must be absolute, owned by
   the effective UID, non-symlink, mode-safe, and opened no-follow. Root and
   session directories are 0700. The final socket path must be ≤107 bytes
   else typed `PathTooLong`.
3. Acquire the per-session lock non-blocking (`flock` on `<dir>/lock`,
   0600). Lock held by a live owner → `AlreadyExists`.
4. Stale-socket recovery: unlink only after a connect attempt fails
   (ECONNREFUSED/ENOENT) AND the exclusive lock is held. Filesystem recovery
   uses exactly these two gates. PID/start-time proof (§8) is additionally
   required only before signalling a recorded process; missing or corrupt
   metadata never prevents a safe unlink under the two gates.
5. **One fork.** The child broker calls `setsid`, sets umask 0077, redirects
   fd 0/1/2 to `/dev/null`, installs signalfd, binds the socket (0600),
   writes initial metadata (§8), then writes a fixed-size readiness record
   to the CLOEXEC readiness pipe (readiness = socket bound) and begins
   accepting → `WaitingForWriter`. Pre-readiness failure is reported through
   the same pipe as a fixed-size error record. The broker never retains or
   writes to the starter's terminal. The foreground parent remains the
   initial attach client: it reads readiness and immediately connects. If
   the starter dies before readiness (pipe peer closed → readiness write
   fails with EPIPE), the broker aborts on the startup-failure path — no
   child is spawned and an orphaned broker is reaped by init.
6. The start client sends `Hello{Writer, take_over=false, name, rows, cols}`
   with real `TIOCGWINSZ` dimensions. Writer start requires real initial
   dimensions: `(rows,cols)==(0,0)` means "preserve existing size" and is
   forbidden for the initial writer; mixed-zero dimensions are a protocol
   error. A non-TTY client attaching to an existing session may send (0,0),
   preserves the session's size, and does not enter raw mode.
7. Hello before the 10 s provisional startup deadline →
   `initial_writer(id)` → `Running`. **Before fork**: resolve a bare
   executable through the captured `PATH`; build argv/environment
   `CString`s and null-terminated pointer arrays (environment =
   creator environment + explicit overrides + `EVERPTY_SESSION=<name>`);
   prepare the fd-close plan; run `openpty` with the winsize from Hello
   (it returns already-open master and slave fds; master set
   `O_NONBLOCK`) — the slave is never reopened. **Child after fork**,
   async-signal-safe calls only, in this exact order: (1) set PDEATHSIG
   and verify `getppid()` against the recorded broker PID (closing the
   parent-death race); (2) restore the signal mask and default
   dispositions (SIGPIPE to default); (3) `setsid`; (4)
   `ioctl(TIOCSCTTY)` on the inherited openpty slave fd; (5) `dup2` the
   slave onto fd 0/1/2; (6) close inherited broker descriptors; (7)
   `libc::execve` with the prebuilt path/argv/env pointer arrays — no
   `execvp`/`execvpe` (their `to_exec_array()` allocates after fork).
   On failure at any stage: write the fixed stage+errno record to the
   CLOEXEC exec-error pipe and `_exit(127)`. The broker begins reading
   the master immediately.
8. No initial writer before the deadline → `startup_deadline()`: no child
   was ever spawned; unlink socket, remove the session directory, exit
   `Failed` with typed `StartupDeadline`.

## 5. Roles, control connections, ownership semantics

- `Hello` fixes the role (Writer or Observer); the Hello name must match the
  socket's session; Observer requires `take_over=false`. `HelloAck` grants a
  monotonic `client_id`. Any incomplete frame — first or later — must
  complete within 5 s (provisional) of its first byte, and the deadline is
  not reset by drip-fed bytes.
- **Control connection**: a same-UID peer (SO_PEERCRED) whose first frame is
  `Ping`, `DetachWriter`, or `Kill`, sent without Hello. Ping → `Pong`,
  close. DetachWriter → revoke the current writer; discard its pending
  output, input, and resize; send `Ownership(Revoked)` to the old writer and
  close it; acknowledge the control client with `Ownership(Revoked)`; close.
  No writer → bounded typed `Error` (NoWriter), close. Kill → SIGTERM to the
  group, grace, SIGKILL if required, reap, `Exit{...}` to the control
  client, close. Control connections count toward the 16-connection bound
  and never become observers. Post-Hello observers cannot control anything:
  a control frame from an observer is a protocol error → disconnect.
- A second writer without takeover → `Busy{current_writer_id}`, state
  unchanged. With explicit takeover, in one loop iteration: discard the old
  writer's undelivered output queue and queued Input/Resize; send
  `Ownership(Revoked)` to the old writer before any subsequent Output;
  apply the new writer's dimensions (TIOCSWINSZ only if actually changed);
  grant at the output boundary (`HelloAck` + `Ownership(Granted)`). The old
  writer remains attached output-only if an observer slot is available;
  otherwise it receives Revoked and is closed. Explicit `detach NAME` always
  closes the old writer after Revoked.
- Writer Input: written to the master in the same iteration. If the master
  would block, the input is retained in a bounded 64 KiB writer-input queue
  and the master is polled for POLLOUT until it drains. A full input queue
  disables the writer's POLLIN (socket backpressure; re-enable below half)
  and does NOT invoke the output-stall eviction policy. The master is polled
  for POLLOUT whenever writer input is queued.
- `DetachWriter` from the current writer → `revoke_writer()`, no terminal
  byte sent, child continues.
- Error frames carry codes: Protocol=1, Forbidden=2, NoWriter=3,
  ResourceLimit=4, Internal=5. `Error` is sent only for semantic errors
  after a valid v1 frame; malformed, oversized, unsupported-version, or
  truncated framing closes the connection silently. Error text is bounded
  UTF-8 containing no payload bytes.
- Partial frame at EOF → silent close.
- **First-frame taxonomy**: the only legal first frames are `Hello`,
  `Ping`, `DetachWriter`, and `Kill`. Any other first frame (`Input`,
  `Output`, `Resize`, `Pong`, `HelloAck`, `Exit`, `Error`, `Ownership`,
  `Busy`) is a protocol error → `Error(Protocol=1)` then close. A second
  `Hello` on a connection that already completed one is likewise
  `Error(Protocol=1)` then close — Hello fixes the role once; roles are
  never mutated or re-negotiated on a live connection.
- **Hello name mismatch** with the socket's session: semantic error after
  a valid frame → `Error(Protocol=1)` then close.
- **Connection-cap rejection**: accept #17 only far enough to run
  `SO_PEERCRED`, then send `Error(ResourceLimit=4)` and close; it is never
  granted a slot, a client id, or frame dispatch.
- **client-id exhaustion** (u32 wrap): refuse the grant with
  `Error(ResourceLimit=4)`, close; existing clients are unaffected.
- **Exec failure after the initial Hello**: the CLOEXEC error pipe
  reports failure after `initial_writer()` already entered `Running`;
  the broker runs `terminal(InternalError)` (→ `Failed`), sends
  `Error(Internal=5)` to the writer, closes clients, unlinks state, and
  exits 1. No child was successfully spawned, so no kill path runs.
- **Control replies** (Pong / Ownership(Revoked) / Error / Exit) get one
  bounded frame and a `control_reply_deadline_ms` (5 s provisional)
  deadline; an EAGAIN'd write is retried on that connection's POLLOUT
  until it drains or the deadline expires, then the connection is closed
  — EAGAIN can never retain a control connection indefinitely and a
  control client can never backpressure the loop or the PTY.
- **DetachWriter from the current writer**: the detaching writer receives
  `Ownership(Revoked)` and the connection closes ("no terminal byte"
  means no PTY byte is sent; the ownership frame is protocol, not
  terminal data).
- **Busy aftermath**: the rejected writer receives `Busy` and the
  connection is closed immediately; no re-Hello on the same connection.
- **Pre-spawn control**: `DetachWriter` in `WaitingForWriter` →
  `Error(NoWriter=3)`, close, no mutation. `Kill` in
  `WaitingForWriter` (no child exists) → `Error(NoWriter=3)`, close the
  control connection, and the broker REMAINS in `WaitingForWriter` —
  failure is reported, never a secret termination.
- **Observers vs lifecycle**: an observer may attach any time after
  readiness (in `WaitingForWriter` it simply receives nothing until
  output exists); on `Exited`/`Failed` all clients are closed. Observer
  membership is tracked in the broker's connection table, not in the M1
  `Ownership` enum — `state.rs` extends the M1 pure transitions with an
  orthogonal observer set rather than mutating `Ownership`; M1 tests stay
  green and commit 5 adds the observer-set reducer tests.

## 6. Output fan-out, queues, backpressure

Outbound data is represented as bounded encoded-frame queues with write
offsets. A freshly-read PTY chunk is encoded into ≤64 KiB `Output` frames
appended, in order, to the current writer's queue and each live observer's
queue; identical live bytes may be shared as immutable chunks referenced by
consumers, and chunk references die with their consumer — no history or
replay buffer exists. Aggregate accounting is the sum of remaining logical
queued bytes; Arc sharing must not hide bytes from limits.

**Decoder buffers are separately and finitely bounded**: per-connection
in-progress frame buffers never exceed `frame_max_body` (header validated
before allocation, M1 `validate_header`). With the current M1 decoder,
peak protocol memory per connection can hold BOTH the in-progress frame
buffer and the decoded payload `Vec`, so the conservative stated bound is
`max_connections × 2 × frame_max_body` (~2 MiB at 16×64 KiB) plus fixed
headers and one 16 KiB read chunk. This bound is stated, tested
(partial-frame slot exhaustion), and NOT charged to the output-queue
aggregate cap, which covers queued outbound bytes only.

**Capacity before read**: the encoded size of one read is
`read_chunk_bytes` plus the six-byte M1 frame header — capacity checks
reserve that full encoded size, not payload bytes alone. Within an
iteration, the master is read only if the writer queue has that much
headroom below its cap; otherwise the read is skipped and master POLLIN
stays disabled until the queue drains below the low-water mark. Observer
and aggregate enqueue effects are precomputed before the enqueue: evict
observers BEFORE appending so the configured hard caps are never
transiently exceeded — no append-then-evict overshoot.

- Writer queue (256 KiB provisional): drained on POLLOUT. Overflow → stop
  polling the master for POLLIN until below the low-water mark (half) —
  kernel backpressure, never byte loss. **Stall timer with hysteresis**:
  the 20 s provisional stall timer STARTS when the writer queue reaches
  high-water and PTY reading is blocked; small trickle writes do NOT
  reset it; it is cleared only when the queue drains below the
  low-water mark. Expiry → revoke, disconnect, discard the queue, resume
  reading — the child can never remain backpressured forever through
  one-byte progress.
- Observer queues (64 KiB provisional each, ≤8 observers): a full observer
  is disconnected immediately — never blocks the writer or child.
- Aggregate live queue bytes (1 MiB provisional): on exhaustion, evict
  observers (most-full first) until under the cap; never pause PTY reading
  for observer or aggregate pressure.
- When no attached client can accept output: continue draining the PTY and
  discard. A live observer remains eligible for future output while no
  writer is attached. A new attachment starts at the next output boundary.

## 7. Resize, signals, reaping

- `Resize` only from the current writer; a zero-valued Resize is a protocol
  error; TIOCSWINSZ applied only when the dimensions actually changed — the
  kernel delivers a real SIGWINCH to the child's group; the broker never
  synthesizes one. Observer resize → protocol error → disconnect.
- signalfd for SIGCHLD/SIGTERM/SIGINT/SIGQUIT/SIGHUP (all broker signals blocked;
  signals become pollable fds — no handler races). Reaping uses
  `waitpid(WNOHANG)` only on recorded pids; the broker never reaps what it
  did not spawn.
- Child exit: after the leader is reaped, drain the master to EOF with a 5 s
  deadline; if the slave side remains open at the deadline, perform bounded
  group TERM/grace/KILL cleanup, then close the master. Queued Output is
  delivered before `Exit`; client flushing is bounded by the existing
  writer-stall policy. Then `terminal(ChildExit)`, close clients, unlink
  socket, remove the session directory, exit 0.
- `Kill`: SIGTERM to the child's process group, 5 s provisional grace, then
  SIGKILL to the group; reap; report `Exit{...}`. Idempotent; first cause
  wins.
- The broker's own catchable termination runs the same kill path — the child
  is never orphaned. There is NO guaranteed descendant cleanup after broker
  SIGKILL: PDEATHSIG covers the direct child; catchable exits use
  process-group cleanup; stale recovery identifies processes by
  PID/PGID + `/proc` start-time and never signals a possibly reused PID.
- Attach client: raw mode on entry. INT/TERM/HUP/QUIT → restore termios,
  reset the signal to default, re-raise it; fallback exit status is
  128+signal. TSTP → restore termios then stop. CONT → re-enter raw mode
  and send a fresh `Resize`. SIGWINCH → send `Resize` only when the
  dimensions changed. Termios restoration is impossible after SIGKILL and
  is never claimed. Restoration is provided by a drop guard plus explicit
  paths and tested per signal.

## 8. State, security, metadata

- umask 0077 at broker start; root/session dirs 0700; socket, lock, and
  metadata 0600.
- After accept, `SO_PEERCRED`: UID must equal the broker's effective UID or
  the connection closes before any frame is read. Cross-UID rejection is
  capability-gated: unit-test the policy function; integration-test real
  same-UID credentials; never claim an unprivileged cross-UID test ran.
- Metadata file `<dir>/meta` (0600), exact v1 record, all integers
  big-endian, no trailing bytes:
  `magic[8] = "EVPTYM1\0"` | `u16 name_len` + validated UTF-8 name |
  `u32 broker_pid` | `u64 broker_start_ticks` | `u8 child_present` |
  (when present: `u32 child_pid`, `u32 child_pgid`, `u64
  child_start_ticks`) | `u64 created_unix_ms` | `u16 exec_label_len` +
  UTF-8 display label | `u8 exec_truncated` | `u8 origin_count` |
  repeated `u8 origin_len` + validated UTF-8 origin.
  Rules: argv[0] is converted to a display label with
  `OsStr::to_string_lossy` BEFORE fork; the UTF-8 label is capped at 256
  bytes on a character boundary with `exec_truncated=true` when cut.
  Origins are validated UTF-8, at most four entries and 64 bytes each;
  an invalid or oversized origin returns typed `MetadataInvalid` — never
  truncation. A complete record above 4096 bytes returns typed
  `MetadataTooLarge`. Parsing validates magic, every length, the option
  byte, the count, UTF-8 fields, the total cap, and trailing EOF before
  any allocation (total parser). Written once before readiness with
  `child_present=0`; atomically rewritten after spawn via exclusive temp
  creation + rename. No output, token, arguments, environment, or
  keystrokes ever touch disk (byte-scan tests).
- `list [--json]` prints exactly the metadata fields, filtered by a live
  probe (connect + Ping, 500 ms provisional deadline). Stable JSON shape
  (u64 values as decimal strings):
  `{"version":1,"sessions":[{"name":"…","broker":{"pid":123,
  "start_ticks":"…"},"child":null|{"pid":456,"pgid":456,
  "start_ticks":"…"},"created_unix_ms":"…","executable":"…",
  "executable_truncated":false,"origins":["…"]}]}` — the text listing
  may use the same display label. A session whose `meta` is corrupt or
  over-cap is skipped from `list` output (discovery-only, never fatal)
  and remains eligible for the two-gate stale recovery. `current` takes
  no argument: it reads `$EVERPTY_SESSION`, validates the name, and
  prints it only after the live probe confirms that broker;
  absent/unset env var or a dead broker → no output, typed `NotLive`,
  exit 1.
- Stale recovery: filesystem unlink per the two gates (failed connect +
  exclusive lock). Signalling a recorded process additionally requires
  PID/PGID + `/proc` start-time identity match against the metadata.
  Deliberately stale metadata with a start-time mismatch is the
  deterministic negative test (no "real reused PID" test is claimed).
- Session names are only path components and wire fields, validated before
  construction; never shell fragments.

## 9. Public interface and exit mapping

`everpty start NAME [-- COMMAND...]`, `everpty attach NAME [--take-over]`,
`everpty observe NAME`, `everpty list [--json]`, `everpty current`,
`everpty detach NAME`, `everpty kill NAME`.

Exit codes: clap usage error 2; operational/protocol failure 1; Busy 3;
deliberate detach/control success 0; attached child exit/signal propagated
(restore termios, reset signal to default, re-raise; fallback 128+signal).
Deliberate `kill` command success exits 0.

Internal `attach_or_create(name, cmd)` runs atomically under the per-session
lock and is exposed as a typed library API for eversh M4.

## 10. Tests (real Linux PTY; CI ubuntu-24.04)

- **bytes.rs**: child fixtures emit NUL, 0xFF bytes, invalid-UTF-8 splits,
  CSI/OSC/DCS, Kitty keyboard+graphics sequences, bracketed paste,
  alternate-screen bytes, CR, LF, CRLF, partial escapes split across reads,
  and multi-megabyte streams; assert attach stdout is byte-identical with no
  synthetic prefix/suffix bytes.
- **ownership_race.rs**: simultaneous attachers → exactly one writer + Busy;
  takeover ordering (Revoked → new dimensions → grant at the output
  boundary), queue/input discard, old-writer slot-or-close rule; observer
  future-only; writer disconnect → observers continue; child exit during
  races; control-connection Ping/DetachWriter/Kill including the no-writer
  error path.
- **resources.rs**: writer-queue fill → PTY backpressure with no loss;
  stall-deadline eviction via mock Clock; writer input-queue fill → socket
  backpressure without eviction; observer-queue fill and aggregate
  exhaustion → eviction while the PTY never pauses; total-connection-cap
  exhaustion → connection #17 receives `Error(ResourceLimit)` and closes
  without a slot; N connections parked mid-partial-frame → decoder memory
  plateaus at max_connections × 2 × frame_max_body + fixed headers and
  one read chunk; control-reply deadline eviction (a stalling control
  client is closed at `control_reply_deadline_ms`); readiness-pipe
  EPIPE observed without SIGPIPE death; Unix-socket write behavior under
  MSG_NOSIGNAL (peer-closed socket → EPIPE, no signal); descriptor,
  process, and RSS plateau gates via `/proc/<pid>/fd`,
  `/proc/<pid>/status`, and process-tree scans after catchable exits.
- **security.rs**: 0700/0600 stats; absolute/euid/non-symlink/no-follow
  path policy; peer-UID policy unit tests plus real same-UID integration;
  PathTooLong; over-cap header rejected before allocation (panicking-reader
  assertion); malformed/unsupported/truncated framing closes silently;
  state-directory byte-scan proving payload bytes and secrets never touch
  disk; exclusive-temp+rename atomicity under concurrent readers.
- **broker_linux.rs**: full lifecycle (start/attach/observe/detach/reattach/
  list/current/kill); exit code+signal propagation; process-group cleanup
  for catchable exits; PDEATHSIG direct-child coverage on broker SIGKILL;
  stale recovery including the deterministic start-time-mismatch test;
  startup deadline spawns nothing; initial dimensions precede spawn (child
  prints TIOCGWINSZ first); non-TTY attach preserves size and skips raw
  mode; termios restoration after INT/TERM/HUP/QUIT/TSTP/CONT paths;
  attach stdout EPIPE/SIGPIPE follows the termios-restoration error
  path; broker SIGQUIT runs the catchable cleanup path; after openpty
  the broker itself has NO controlling terminal (its session-leader
  setsid does not acquire one) while the spawned child acquires the
  intended slave via TIOCSCTTY (child proves it by reading
  /proc/self/stat or `tcgetpgrp`).
- **cli.rs**: exit mapping incl. Busy=3 and child-status propagation.
- Fuzz: M2 introduces two new pure parsers, so the isolated fuzz
  workspace gains `fuzz_metadata` (the §8 v1 metadata record) and
  `fuzz_proc_stat` (`/proc/<pid>/stat` start-time extraction). They build
  in CI on stable like the M1 targets; actual bounded fuzz runs remain
  ask-first, and M2 cannot close until they are authorized, executed,
  and recorded on eversh-chl.3.

## 11. Limits remeasurement (local, unprivileged)

Deterministic throttled Unix-socket readers (polled read budgets — no tc,
network namespaces, root, or external hosts) plus PTY workloads
(vim-in-loop, 10 MB `cat`). Results recorded in `plans/m2-limits.md`
(method, environment, rationale); values recorded in `Limits::default()`:
startup deadline 10 s, kill grace 5 s, writer queue 256 KiB, observer
queue 64 KiB, observers 8, aggregate 1 MiB — and **new fields added in
commit 5** with the provisional-limit inventory test extended to name
them: `max_connections` 16, `writer_input_queue_bytes` 64 KiB,
`incomplete_frame_deadline_ms` 5 s, `accepts_per_iteration` 8,
`read_chunk_bytes` 16 KiB, `stall_deadline_ms` 20 s,
`pty_exit_drain_ms` 5 s, `control_reply_deadline_ms` 5 s,
`list_probe_deadline_ms` 500 ms, `metadata_max_bytes` 4096,
`exec_label_max_bytes` 256, plus `origin_label_max_bytes` 64 and
`origin_count_max` 4.
Boundary tests must stay green after any change.

## 12. Atomic commit sequence

Pre-step (no commit): claim `eversh-chl.3` AND run
`bd heartbeat eversh-chl.3` — `bd update --claim` alone does not refresh
the lease reliably; heartbeat again after claim, at every commit and
checkpoint, and before every long gate run. Each commit is green (fmt,
clippy `-D warnings` incl. `unwrap_used`, tests) before the next; message
format `Added: everpty: …` with a `Refs: eversh-chl.3` trailer and no AI
attribution. The tracked `.claude/settings.json` isolation change gets
its own separate commit. This plan file is included in commit 2.

1. `Changed: agents: Allow direct background edits in this repository` —
   only `.claude/settings.json`, `Refs: eversh-chl.3`.
2. `Added: everpty: Add sys wrappers for pty, poll, sockets, signals` —
   sys.rs (+PDEATHSIG, flock, no-follow open) and wrapper unit tests; nix
   and libc pinned; **plus plans/m2-plan.md**.
3. `Added: everpty: Add session state root, locking, and atomic metadata` —
   session.rs and security unit tests.
4. `Added: everpty: Add child process and PTY lifecycle` — disciplined
   fork/exec, CLOEXEC error pipe, reap, TERM→grace→KILL.
5. `Added: everpty: Add client connections, control connections, and
   bounded frame queues` — Hello/Busy/takeover wired to the M1 state
   machine plus the orthogonal observer set (reducer tests); new §11
   `Limits` fields + inventory test; readiness pipe; loop skeleton.
6. `Added: everpty: Add output fan-out, backpressure, and stall eviction` —
   writer-only PTY pause; observer/aggregate eviction; input-queue drain.
7. `Added: everpty: Add resize, signals, exit delivery, and cleanup`.
8. `Added: everpty: Add attach client library and real CLI commands` —
   termios INT/TERM/HUP/QUIT/TSTP/CONT; exit mapping.
9. `Added: tests: Add arbitrary-byte transparency and resource gates` —
   bytes.rs, `fuzz_metadata`/`fuzz_proc_stat` targets (build-only in CI),
   final gates, measurements in `plans/m2-limits.md`.

## 13. Gates before close

`cargo +1.95.0 fmt --all -- --check`; `cargo +1.95.0 clippy --workspace
--all-targets --all-features -- -D warnings` (with `unwrap_used` enabled
via the workspace lints, as in M1); `cargo +1.95.0 test --workspace
--all-features --locked`; `cargo +1.88.0 check --workspace --all-targets
--locked`; `cargo +1.95.0 check --target aarch64-unknown-linux-gnu
--locked`; `cargo +1.95.0 check --workspace --no-default-features --lib
--locked`; fuzz workspace exactly as M1 CI: `cargo +1.95.0 fmt
--manifest-path fuzz/Cargo.toml -- --check`, `cargo +1.95.0 check
--manifest-path fuzz/Cargo.toml --all-targets --locked`, then
`cargo-deny --manifest-path fuzz/Cargo.toml --all-features --locked
check`; `cargo-deny --all-features --locked check`; extended
cargo-metadata graph test (everpty closure: nix+libc allowed, still no
tokio/noq/clap).

## 14. Guardrails

No M3/M4 work; no `main` branch; no commit, push, or `bd dolt push` without
fresh authority; design.md/reference.md untouched unless an M2 fact
contradicts them (recorded, then ask); no ring/log/replay/screen code even
as dead options; Keepty code adapted only with attribution (preferred:
none); commit-discipline skill applies throughout implementation.
