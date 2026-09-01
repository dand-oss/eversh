//! Thin supervision of OpenSSH, everlink, and Kitty processes (design 7).
//!
//! Every function here launches the installed `ssh` binary over the everlink
//! ProxyCommand and supervises it: eversh never relays or parses terminal
//! data, never builds a runtime, and preserves inherited stdin/stdout for the
//! live terminal path. Effective OpenSSH configuration resolution is
//! delegated to OpenSSH itself: ProxyCommand `%n`/`%p` carry the original
//! destination token and effective port into everlink, whose own `ssh -G`
//! verification rejects recursive proxying (design 6.4, 8).
//!
//! ## The remote status channel (design 3, 7)
//!
//! Design 3 designates stderr for "diagnostics, state changes, retries, and
//! errors"; stdin/stdout stay fully inherited and untouched, carrying only
//! the live terminal path. For the three session-carrying remote operations
//! (attach-or-create, attach, observe) the remote `__everpty` role edge uses
//! that stderr channel as a small versioned protocol on top of ordinary
//! diagnostics: it writes `eversh-status-v1 established` immediately before
//! the blocking `everpty::run` call, and writes an `eversh-status-v1 exit
//! code N` / `eversh-status-v1 exit signal N` record on every exit path,
//! flushed before the process actually exits (before the reraise, for a
//! signal). Batch operations (list/probe/detach/kill) never emit either
//! line. Raw `eversh ssh` never runs the remote role at all and stays fully
//! inherited on every descriptor, status channel included.
//!
//! Locally, an interactive spawn pipes stderr through a relay thread that
//! intercepts complete `eversh-status-v1 ` lines (an established flag, an
//! exit record, or a swallowed unknown-v1 line for forward compatibility)
//! and forwards everything else byte-faithfully to the real stderr — so
//! ordinary remote diagnostics (a Busy message, for instance) still reach
//! the user unchanged. This gives the supervisor two independent facts an
//! ssh exit code alone cannot: the establishment gate and an authoritative
//! exit record.
//!
//! The **establishment gate** (finding 1) fixes a false-positive: OpenSSH
//! reserves exit 255 for its own failures, but a remote command exiting 255
//! also yields 255, so a session that dies before ever reaching the blocking
//! attach call (an auth failure, for instance) must never trigger a probe or
//! a retry — it is an ordinary SSH failure ([`SessionEnd::SshFailed`]).
//! Only a 255 that arrives AFTER `established` was seen enters the
//! probe-gated reconnect below.
//!
//! The **exit record** (finding 2) removes the other ambiguity: when the
//! remote role process itself exits or is signaled, its exit record always
//! wins over the raw local ssh exit classification, so a remote child that
//! happens to exit or be killed with something that looks like transport
//! noise is still reported as the real child outcome, and a remote child
//! killed by a signal is reported as `128 + signal`
//! ([`SessionEnd::RemoteSignaled`]) instead of an ambiguous ssh-255.
//!
//! ## Reconnect contract (design 7)
//!
//! After an established named connect, attach, or observe ends unexpectedly
//! with no exit record and OpenSSH's own exit code 255, a fresh
//! authenticated bootstrap probes whether the same broker is alive. Retries
//! reattach the SAME session with plain `attach` — a missing or exited
//! broker is never restarted, so no application work is duplicated — under
//! finite attempts, bounded exponential backoff with jitter, and an overall
//! `retry_deadline_ms` deadline (finding 3) that bounds the WHOLE episode: a
//! hung probe or a reattach that never re-establishes is killed at the
//! remaining deadline rather than left to run unbounded, while a reattach
//! that DOES re-establish then runs unbounded like any live session — and if
//! that established reattach later dies again with no record, a fresh
//! episode starts with fresh attempt and deadline budgets. Ambiguous
//! concurrent transport/child failure (no exit record, established, ssh
//! 255) is reported as transport failure rather than inventing a child
//! status.
#![cfg(unix)]

use crate::command::{
    kitty_launch_args, outer_ssh_args, proxy_command, raw_ssh_args, remote_words,
    validate_self_exe, RemoteOp,
};
use crate::error::Error;
use crate::limits::Limits;
use crate::remote::{origin_label, validate_host, validate_name, ControlRequest};
use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Child, ChildStderr, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Typed configuration assembled at the binary edge. The library reads no
/// global arguments or environment.
#[derive(Debug, Clone)]
pub struct Config {
    /// The installed OpenSSH client (resolved via PATH when relative).
    pub ssh_program: OsString,
    /// The Kitty launcher used by resume-all.
    pub kitty_program: OsString,
    /// This executable, re-invoked as the local everlink role and by Kitty
    /// tabs.
    pub self_exe: PathBuf,
    /// The remote combined eversh binary: bare PATH word or absolute path.
    pub remote_eversh: String,
    /// `KITTY_LISTEN_ON` when present.
    pub kitty_listen_on: Option<String>,
    /// The local host name used for generated origin metadata.
    pub local_host: String,
    pub limits: Limits,
}

/// How a supervised process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitKind {
    Code(u8),
    Signaled(i32),
}

fn classify(status: ExitStatus) -> ExitKind {
    if let Some(code) = status.code() {
        ExitKind::Code((code & 0xff) as u8)
    } else {
        ExitKind::Signaled(status.signal().unwrap_or(0))
    }
}

/// OpenSSH reserves exit code 255 for its own failures; everything else is
/// the remote command's status.
const SSH_FAILURE: u8 = 255;

/// Why a reconnect sequence stopped without a remote status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportFailure {
    /// The broker no longer answers: the session ended or the child status
    /// was lost with the transport. Never restarted.
    SessionGone,
    /// The finite attempt budget was exhausted.
    AttemptsExhausted,
    /// The overall retry deadline passed.
    DeadlineExceeded,
    /// A probe failed with a non-transport error (broken remote install).
    ProbeFailed(u8),
    /// A probe was terminated locally.
    ProbeSignaled(i32),
    /// Every retry within the episode kept finding the session reported
    /// Busy (a writer is already attached) until the attempt budget or
    /// deadline ran out. Never escalated to `--take-over`: a legitimately
    /// attached new writer must not be stolen.
    Busy,
}

/// The supervised outcome of a session-carrying invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEnd {
    /// The remote command's exit status (child exit, Busy, role errors) —
    /// returned unchanged. When an exit record is present it always wins
    /// over the raw local ssh exit classification (finding 2).
    Remote(u8),
    /// The remote child was terminated by a signal, per its status-channel
    /// exit record. The edge maps this to `128 + signal` (finding 2).
    RemoteSignaled(i32),
    /// The local ssh process itself was terminated by a signal.
    SshSignaled(i32),
    /// SSH exited 255 before the session was ever established: an ordinary
    /// OpenSSH failure (auth, host lookup, ...), reported immediately with
    /// no probe and no retry (finding 1).
    SshFailed,
    /// Transport failure without a recoverable session.
    TransportFailed(TransportFailure),
}

/// Progress events for the binary edge to present on stderr.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event<'a> {
    TransportInterrupted {
        attempt: u32,
    },
    Backoff {
        attempt: u32,
        delay_ms: u64,
    },
    Probing {
        name: &'a str,
        attempt: u32,
    },
    SessionLive {
        attempt: u32,
    },
    SessionGone {
        name: &'a str,
    },
    ProbeUnreachable {
        attempt: u32,
    },
    ProbeFailed {
        exit_code: u8,
    },
    Reattaching {
        name: &'a str,
        attempt: u32,
    },
    RetryExhausted {
        attempts: u32,
    },
    RetryDeadlineExceeded,
    ResumeLaunched {
        name: &'a str,
    },
    ResumeSkipped {
        name: &'a str,
    },
    /// SSH failed before the session was ever established (finding 1).
    SshFailed,
    /// A reattach found the session Busy; retried within the same episode's
    /// budget rather than escalating to `--take-over`.
    ReattachBusy {
        name: &'a str,
        attempt: u32,
    },
}

pub trait Notifier {
    fn notify(&mut self, event: Event<'_>);
}

/// A Notifier that discards events (tests, non-interactive callers).
pub struct SilentNotifier;

impl Notifier for SilentNotifier {
    fn notify(&mut self, _event: Event<'_>) {}
}

fn proxy_for(config: &Config, ssh_options: &[String]) -> Result<String, Error> {
    let self_exe = validate_self_exe(&config.self_exe)?;
    proxy_command(self_exe, &config.remote_eversh, ssh_options)
}

fn spawn_inherited(config: &Config, args: &[OsString]) -> Result<ExitKind, Error> {
    let status = Command::new(&config.ssh_program).args(args).status()?;
    Ok(classify(status))
}

fn spawn_quiet(config: &Config, args: &[OsString]) -> Result<ExitKind, Error> {
    let status = Command::new(&config.ssh_program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .status()?;
    Ok(classify(status))
}

// ---------------------------------------------------------------------------
// Bounded waits and the remote status channel (design 3, 7; findings 1-3).
// ---------------------------------------------------------------------------

/// Poll interval for a deadline-bounded child wait. Fine enough that a
/// bounded wait overshoots its deadline by at most this much.
const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(20);

fn poll_interval(deadline: Instant) -> Duration {
    WAIT_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now()))
}

/// One non-interactive child, waited with a hard deadline: a hung child is
/// killed and reaped rather than left running past `retry_deadline_ms`
/// (finding 3).
enum BoundedExit {
    Exited(ExitKind),
    DeadlineExceeded,
}

fn wait_bounded_child(child: &mut Child, deadline: Instant) -> Result<BoundedExit, Error> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(BoundedExit::Exited(classify(status)));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(BoundedExit::DeadlineExceeded);
        }
        std::thread::sleep(poll_interval(deadline));
    }
}

fn spawn_quiet_bounded(
    config: &Config,
    args: &[OsString],
    deadline: Instant,
) -> Result<BoundedExit, Error> {
    let mut child = Command::new(&config.ssh_program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()?;
    wait_bounded_child(&mut child, deadline)
}

/// One classified line from the remote status channel (design 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemoteStatus {
    Code(u8),
    Signal(i32),
}

/// The versioned status-channel line prefix. Must match
/// `main.rs::STATUS_CHANNEL_PREFIX` on the remote role edge exactly.
const STATUS_PREFIX: &str = "eversh-status-v1 ";
/// A protocol line is always short; anything still unterminated past this
/// length can no longer become one, so it is forwarded as data without
/// waiting indefinitely for a newline (bounds relay memory and latency).
const STATUS_LINE_MAX: usize = 256;

enum StatusLine {
    Established,
    Exit(RemoteStatus),
    /// Starts with the v1 prefix but isn't a line this binary recognizes:
    /// swallowed anyway for forward compatibility, never forwarded.
    UnknownV1,
}

/// Classify one line (with or without a trailing `\n`) against the status
/// protocol. `None` means the line does not carry the prefix at all — it is
/// ordinary data and must be forwarded byte-faithfully.
fn decode_status_line(line: &[u8]) -> Option<StatusLine> {
    let text = std::str::from_utf8(line).ok()?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    let rest = text.strip_prefix(STATUS_PREFIX)?;
    if rest == "established" {
        return Some(StatusLine::Established);
    }
    if let Some(value) = rest.strip_prefix("exit code ") {
        return Some(match value.parse::<u8>() {
            Ok(code) => StatusLine::Exit(RemoteStatus::Code(code)),
            Err(_) => StatusLine::UnknownV1,
        });
    }
    if let Some(value) = rest.strip_prefix("exit signal ") {
        return Some(match value.parse::<i32>() {
            Ok(signal) if (1..=64).contains(&signal) => {
                StatusLine::Exit(RemoteStatus::Signal(signal))
            }
            _ => StatusLine::UnknownV1,
        });
    }
    Some(StatusLine::UnknownV1)
}

fn set_established(established: &AtomicBool) {
    established.store(true, Ordering::Release);
}

fn set_record(record: &Mutex<Option<RemoteStatus>>, value: RemoteStatus) {
    let mut guard = record
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *guard = Some(value);
}

/// Classify one complete (or EOF/overflow-terminated) line and either
/// record its status-channel meaning or forward it byte-faithfully to the
/// real stderr.
fn forward_or_swallow(line: &[u8], established: &AtomicBool, record: &Mutex<Option<RemoteStatus>>) {
    match decode_status_line(line) {
        Some(StatusLine::Established) => set_established(established),
        Some(StatusLine::Exit(value)) => set_record(record, value),
        Some(StatusLine::UnknownV1) => {}
        None => {
            let mut stderr = std::io::stderr();
            let _ = stderr.write_all(line);
            let _ = stderr.flush();
        }
    }
}

fn drain_complete_lines(
    pending: &mut Vec<u8>,
    established: &AtomicBool,
    record: &Mutex<Option<RemoteStatus>>,
) {
    while let Some(position) = pending.iter().position(|&byte| byte == b'\n') {
        let line: Vec<u8> = pending.drain(..=position).collect();
        forward_or_swallow(&line, established, record);
    }
}

/// The relay thread body: reads the piped stderr in chunks, maintains a
/// bounded line buffer, classifies complete lines against the status
/// protocol, and forwards every non-protocol line byte-faithfully. Ends at
/// pipe EOF, forwarding any unterminated tail.
fn relay_stderr(
    mut pipe: ChildStderr,
    established: &AtomicBool,
    record: &Mutex<Option<RemoteStatus>>,
) {
    let mut pending: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => {
                pending.extend_from_slice(&chunk[..count]);
                drain_complete_lines(&mut pending, established, record);
                if pending.len() > STATUS_LINE_MAX {
                    forward_or_swallow(&pending, established, record);
                    pending.clear();
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    if !pending.is_empty() {
        forward_or_swallow(&pending, established, record);
    }
}

/// A running relay thread plus the shared status-channel state it updates.
/// Dropping it joins the thread — always safe to drop once the child that
/// owns the pipe's write end has been reaped, since that is exactly when the
/// relay observes EOF.
struct StderrRelay {
    established: Arc<AtomicBool>,
    record: Arc<Mutex<Option<RemoteStatus>>>,
    handle: Option<JoinHandle<()>>,
}

impl StderrRelay {
    fn spawn(pipe: ChildStderr) -> Self {
        let established = Arc::new(AtomicBool::new(false));
        let record: Arc<Mutex<Option<RemoteStatus>>> = Arc::new(Mutex::new(None));
        let established_thread = Arc::clone(&established);
        let record_thread = Arc::clone(&record);
        let handle = std::thread::spawn(move || {
            relay_stderr(pipe, &established_thread, &record_thread);
        });
        Self {
            established,
            record,
            handle: Some(handle),
        }
    }

    fn established(&self) -> bool {
        self.established.load(Ordering::Acquire)
    }

    fn record(&self) -> Option<RemoteStatus> {
        *self
            .record
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Block until the relay thread has observed pipe EOF and finished
    /// processing every buffered byte. MUST be called (directly, or via
    /// `Drop`) before treating `established()`/`record()` as final: once the
    /// child is confirmed reaped, its last written line may still be
    /// sitting unread in the pipe, and only a join guarantees the relay has
    /// drained it — reading the shared state right after `wait()` without
    /// joining first is a race.
    fn join(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for StderrRelay {
    fn drop(&mut self) {
        self.join();
    }
}

fn captured_termios() -> Option<everpty::sys::TerminalAttributes> {
    let stdin = std::io::stdin();
    if !everpty::sys::is_terminal(stdin.as_fd()) {
        return None;
    }
    everpty::sys::terminal_attributes(stdin.as_fd()).ok()
}

fn restore_termios(termios: &everpty::sys::TerminalAttributes) {
    let stdin = std::io::stdin();
    let _ = everpty::sys::restore_terminal(stdin.as_fd(), termios);
}

/// One interactive/status-channel spawn's local outcome.
enum StatusSpawn {
    Exited {
        exit: ExitKind,
        established: bool,
        record: Option<RemoteStatus>,
    },
    /// Only possible when `deadline` was set and the child never reached
    /// `established` or an exit record before it passed.
    DeadlineExceeded,
}

/// Spawn one interactive/status-channel remote invocation for a
/// session-carrying operation (attach-or-create, attach, observe — never raw
/// ssh, which stays fully inherited). stdin/stdout remain fully inherited
/// for the live terminal path; stderr is piped through [`StderrRelay`].
///
/// `deadline`, when set, bounds the wait ONLY until the remote side reports
/// `established` or an exit record appears: a hung pre-establishment child
/// (a reattach that never reconnects) is killed and reaped at the deadline,
/// with the outer terminal's termios restored first if this process put it
/// mid-transition. Once established — or when `deadline` is `None`, as for
/// the very first spawn of an invocation, which is never part of a bounded
/// reconnect episode — the wait is unbounded: an ongoing session is never
/// killed by the reconnect deadline (design 7, finding 3).
fn spawn_status_channel(
    config: &Config,
    args: &[OsString],
    deadline: Option<Instant>,
) -> Result<StatusSpawn, Error> {
    let termios = if deadline.is_some() {
        captured_termios()
    } else {
        None
    };
    let mut child = Command::new(&config.ssh_program)
        .args(args)
        .stderr(Stdio::piped())
        .spawn()?;
    let pipe = child
        .stderr
        .take()
        .ok_or_else(|| Error::Io(std::io::Error::other("captured stderr pipe missing")))?;
    let mut relay = StderrRelay::spawn(pipe);

    if let Some(deadline) = deadline {
        loop {
            if let Some(status) = child.try_wait()? {
                // The child is reaped, but its last written line may still
                // be sitting unread in the pipe: join before reading the
                // final state (see StderrRelay::join).
                relay.join();
                return Ok(StatusSpawn::Exited {
                    exit: classify(status),
                    established: relay.established(),
                    record: relay.record(),
                });
            }
            if relay.established() || relay.record().is_some() {
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                relay.join();
                if let Some(termios) = &termios {
                    restore_termios(termios);
                }
                return Ok(StatusSpawn::DeadlineExceeded);
            }
            std::thread::sleep(poll_interval(deadline));
        }
    }
    let status = child.wait()?;
    relay.join();
    Ok(StatusSpawn::Exited {
        exit: classify(status),
        established: relay.established(),
        record: relay.record(),
    })
}

/// The terminal meaning of one status-channel spawn (findings 1-3). An exit
/// record — when present — always wins over the local ssh exit
/// classification, because the remote already told us definitively what
/// happened to the session.
enum SpawnOutcome {
    Remote(u8),
    RemoteSignaled(i32),
    SshSignaled(i32),
    /// SSH exited 255 and the session was never established (finding 1).
    SshFailedUnestablished,
    /// SSH exited 255 after establishment with no exit record: a genuine
    /// transport failure (finding 2, 3).
    TransportAfterEstablished,
}

fn classify_status_spawn(
    exit: ExitKind,
    established: bool,
    record: Option<RemoteStatus>,
) -> SpawnOutcome {
    if let Some(record) = record {
        return match record {
            RemoteStatus::Code(code) => SpawnOutcome::Remote(code),
            RemoteStatus::Signal(signal) => SpawnOutcome::RemoteSignaled(signal),
        };
    }
    match exit {
        ExitKind::Signaled(signal) => SpawnOutcome::SshSignaled(signal),
        ExitKind::Code(SSH_FAILURE) if established => SpawnOutcome::TransportAfterEstablished,
        ExitKind::Code(SSH_FAILURE) => SpawnOutcome::SshFailedUnestablished,
        ExitKind::Code(code) => SpawnOutcome::Remote(code),
    }
}

/// Captured non-interactive remote output plus its exit classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Captured {
    pub exit: ExitKind,
    pub stdout: Vec<u8>,
}

fn spawn_captured(config: &Config, args: &[OsString]) -> Result<Captured, Error> {
    let mut child = Command::new(&config.ssh_program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::Io(std::io::Error::other("captured stdout pipe missing")))?;
    let cap = config.limits.list_output_max;
    let mut collected = Vec::new();
    let mut chunk = [0u8; 8192];
    let overflow = loop {
        match stdout.read(&mut chunk) {
            Ok(0) => break false,
            Ok(count) => {
                if collected.len() + count > cap {
                    break true;
                }
                collected.extend_from_slice(&chunk[..count]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Error::Io(error));
            }
        }
    };
    if overflow {
        let _ = child.kill();
        let _ = child.wait();
        return Err(Error::ListOutputTooLarge);
    }
    drop(stdout);
    let status = child.wait()?;
    Ok(Captured {
        exit: classify(status),
        stdout: collected,
    })
}

/// The probe result for one fresh authenticated bootstrap (design 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeStatus {
    Live,
    NotLive,
    Unreachable,
    Failed(u8),
    Signaled(i32),
    /// The probe itself hung past the remaining reconnect deadline and was
    /// killed and reaped (finding 3).
    DeadlineExceeded,
}

/// Remote probe exit code meaning "broker not live" (private role protocol).
pub const PROBE_NOT_LIVE_EXIT: u8 = 5;

/// Remote exit code for `everpty::Error::Busy` (a writer is already
/// attached), mirrored at the role edge in `main.rs::everpty_role_error`.
pub const REMOTE_BUSY_EXIT: u8 = 3;

/// `deadline` bounds the probe's own execution: a hung probe is killed and
/// reaped rather than left running past the reconnect episode's deadline
/// (finding 3).
fn probe(
    config: &Config,
    host: &str,
    name: &str,
    ssh_options: &[String],
    deadline: Instant,
) -> Result<ProbeStatus, Error> {
    let proxy = proxy_for(config, ssh_options)?;
    let words = remote_words(
        &config.remote_eversh,
        &RemoteOp::Probe { name },
        &config.limits,
    )?;
    let args = outer_ssh_args(&proxy, ssh_options, host, &words, false)?;
    Ok(match spawn_quiet_bounded(config, &args, deadline)? {
        BoundedExit::DeadlineExceeded => ProbeStatus::DeadlineExceeded,
        BoundedExit::Exited(ExitKind::Code(0)) => ProbeStatus::Live,
        BoundedExit::Exited(ExitKind::Code(PROBE_NOT_LIVE_EXIT)) => ProbeStatus::NotLive,
        BoundedExit::Exited(ExitKind::Code(SSH_FAILURE)) => ProbeStatus::Unreachable,
        BoundedExit::Exited(ExitKind::Code(code)) => ProbeStatus::Failed(code),
        BoundedExit::Exited(ExitKind::Signaled(signal)) => ProbeStatus::Signaled(signal),
    })
}

fn backoff_delay(attempt: u32, limits: &Limits) -> Duration {
    let shift = attempt.saturating_sub(1).min(20);
    let raw = limits
        .retry_backoff_base_ms
        .saturating_mul(1u64 << shift)
        .min(limits.retry_backoff_cap_ms);
    Duration::from_millis(raw.saturating_add(jitter_below(raw / 2 + 1)))
}

fn jitter_below(bound: u64) -> u64 {
    use std::hash::{BuildHasher, Hasher};
    if bound <= 1 {
        return 0;
    }
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.subsec_nanos() as u64)
            .unwrap_or(0),
    );
    hasher.finish() % bound
}

#[derive(Clone, Copy)]
struct SessionRun<'a> {
    host: &'a str,
    name: &'a str,
    take_over: bool,
    ssh_options: &'a [String],
    /// Observer sessions reattach with observe; writer sessions with attach.
    observer: bool,
}

/// Turn a terminal [`SpawnOutcome`] into the [`SessionEnd`] the caller sees.
/// Returns `None` for `TransportAfterEstablished`, which is never terminal
/// by itself — the caller enters or continues the reconnect episode.
fn spawn_outcome_to_session_end(outcome: SpawnOutcome) -> Option<SessionEnd> {
    match outcome {
        SpawnOutcome::Remote(code) => Some(SessionEnd::Remote(code)),
        SpawnOutcome::RemoteSignaled(signal) => Some(SessionEnd::RemoteSignaled(signal)),
        SpawnOutcome::SshSignaled(signal) => Some(SessionEnd::SshSignaled(signal)),
        SpawnOutcome::SshFailedUnestablished => Some(SessionEnd::SshFailed),
        SpawnOutcome::TransportAfterEstablished => None,
    }
}

/// Run one interactive/streaming remote operation and, on unexpected SSH
/// termination AFTER establishment, reconnect the SAME session through
/// probe-gated retries (design 7). A pre-establishment SSH failure is an
/// ordinary SSH failure with no probe and no retry (finding 1).
fn run_with_reconnect(
    config: &Config,
    run: SessionRun<'_>,
    first_op: RemoteOp<'_>,
    notifier: &mut dyn Notifier,
) -> Result<SessionEnd, Error> {
    config.limits.validate()?;
    validate_host(run.host)?;
    let proxy = proxy_for(config, run.ssh_options)?;
    let words = remote_words(&config.remote_eversh, &first_op, &config.limits)?;
    let interactive = first_op.interactive();
    let args = outer_ssh_args(&proxy, run.ssh_options, run.host, &words, interactive)?;
    // The very first spawn of an invocation is never part of a bounded
    // reconnect episode: it runs unbounded, exactly like an already
    // established session (design 7).
    let (exit, established, record) = match spawn_status_channel(config, &args, None)? {
        StatusSpawn::Exited {
            exit,
            established,
            record,
        } => (exit, established, record),
        StatusSpawn::DeadlineExceeded => {
            // Unreachable: an unbounded spawn never reports this. Fail safe
            // rather than panic if that invariant is ever violated.
            return Ok(SessionEnd::TransportFailed(
                TransportFailure::DeadlineExceeded,
            ));
        }
    };
    let outcome = classify_status_spawn(exit, established, record);
    if let Some(end) = spawn_outcome_to_session_end(outcome) {
        if matches!(end, SessionEnd::SshFailed) {
            notifier.notify(Event::SshFailed);
        }
        return Ok(end);
    }
    // TransportAfterEstablished: enter the reconnect episode. A later
    // established-then-255 reattach starts a FRESH episode with fresh
    // attempt/deadline budgets (finding 3), so this loops rather than
    // recursing.
    loop {
        match reconnect(config, run, notifier)? {
            ReconnectOutcome::Terminal(end) => return Ok(end),
            ReconnectOutcome::RestartEpisode => continue,
        }
    }
}

/// Why [`reconnect`] returned: a terminal outcome for the whole invocation,
/// or a signal to start a fresh episode with fresh attempt/deadline budgets.
enum ReconnectOutcome {
    Terminal(SessionEnd),
    RestartEpisode,
}

/// One bounded reconnect episode: finite attempts, bounded backoff with
/// jitter, and an overall deadline that bounds a hung probe or a
/// not-yet-established reattach (finding 3). Once a reattach establishes it
/// runs unbounded; if THAT later dies again with no exit record, this
/// returns [`ReconnectOutcome::RestartEpisode`] rather than continuing this
/// episode's attempt count.
fn reconnect(
    config: &Config,
    run: SessionRun<'_>,
    notifier: &mut dyn Notifier,
) -> Result<ReconnectOutcome, Error> {
    let limits = &config.limits;
    let deadline = Instant::now() + Duration::from_millis(limits.retry_deadline_ms);
    let mut attempt: u32 = 0;
    // Whether the MOST RECENT retry cause was a reattach reporting Busy: a
    // dead transport's writer slot may not have been revoked yet, so a
    // reattach getting Busy is retried within this same episode's budget
    // (never escalated to take_over). When the budget/deadline then runs
    // out, the busy diagnostic is reported as the reason rather than a
    // generic exhaustion message.
    let mut last_busy = false;
    loop {
        attempt += 1;
        if attempt > limits.retry_attempts_max {
            notifier.notify(Event::RetryExhausted {
                attempts: limits.retry_attempts_max,
            });
            let reason = if last_busy {
                TransportFailure::Busy
            } else {
                TransportFailure::AttemptsExhausted
            };
            return Ok(ReconnectOutcome::Terminal(SessionEnd::TransportFailed(
                reason,
            )));
        }
        let delay = backoff_delay(attempt, limits);
        if Instant::now() + delay >= deadline {
            notifier.notify(Event::RetryDeadlineExceeded);
            let reason = if last_busy {
                TransportFailure::Busy
            } else {
                TransportFailure::DeadlineExceeded
            };
            return Ok(ReconnectOutcome::Terminal(SessionEnd::TransportFailed(
                reason,
            )));
        }
        notifier.notify(Event::Backoff {
            attempt,
            delay_ms: delay.as_millis() as u64,
        });
        std::thread::sleep(delay);
        notifier.notify(Event::Probing {
            name: run.name,
            attempt,
        });
        match probe(config, run.host, run.name, run.ssh_options, deadline)? {
            ProbeStatus::Live => {
                notifier.notify(Event::SessionLive { attempt });
            }
            ProbeStatus::NotLive => {
                notifier.notify(Event::SessionGone { name: run.name });
                return Ok(ReconnectOutcome::Terminal(SessionEnd::TransportFailed(
                    TransportFailure::SessionGone,
                )));
            }
            ProbeStatus::Unreachable => {
                notifier.notify(Event::ProbeUnreachable { attempt });
                last_busy = false;
                continue;
            }
            ProbeStatus::Failed(code) => {
                notifier.notify(Event::ProbeFailed { exit_code: code });
                return Ok(ReconnectOutcome::Terminal(SessionEnd::TransportFailed(
                    TransportFailure::ProbeFailed(code),
                )));
            }
            ProbeStatus::Signaled(signal) => {
                return Ok(ReconnectOutcome::Terminal(SessionEnd::TransportFailed(
                    TransportFailure::ProbeSignaled(signal),
                )));
            }
            ProbeStatus::DeadlineExceeded => {
                notifier.notify(Event::RetryDeadlineExceeded);
                return Ok(ReconnectOutcome::Terminal(SessionEnd::TransportFailed(
                    TransportFailure::DeadlineExceeded,
                )));
            }
        }
        notifier.notify(Event::Reattaching {
            name: run.name,
            attempt,
        });
        let request = ControlRequest {
            take_over: run.take_over,
            origins: Vec::new(),
            child_argv: Vec::new(),
        };
        let (op, interactive) = if run.observer {
            (RemoteOp::Observe { name: run.name }, false)
        } else {
            (
                RemoteOp::Attach {
                    name: run.name,
                    request: &request,
                },
                true,
            )
        };
        let proxy = proxy_for(config, run.ssh_options)?;
        let words = remote_words(&config.remote_eversh, &op, &config.limits)?;
        let args = outer_ssh_args(&proxy, run.ssh_options, run.host, &words, interactive)?;
        // Bounded ONLY until this reattach establishes or reports an exit
        // record; once established, the wait inside becomes unbounded.
        match spawn_status_channel(config, &args, Some(deadline))? {
            StatusSpawn::DeadlineExceeded => {
                notifier.notify(Event::RetryDeadlineExceeded);
                return Ok(ReconnectOutcome::Terminal(SessionEnd::TransportFailed(
                    TransportFailure::DeadlineExceeded,
                )));
            }
            StatusSpawn::Exited {
                exit,
                established,
                record,
            } => match classify_status_spawn(exit, established, record) {
                SpawnOutcome::TransportAfterEstablished => {
                    return Ok(ReconnectOutcome::RestartEpisode);
                }
                SpawnOutcome::SshFailedUnestablished => {
                    notifier.notify(Event::TransportInterrupted { attempt });
                    last_busy = false;
                }
                // A reattach finding the session Busy is retried within
                // THIS episode's existing attempt/backoff/deadline budget:
                // the dead transport's writer slot may not have been
                // revoked yet by the time the retry lands. Never escalated
                // to take_over — a legitimately attached new writer must
                // not be stolen.
                SpawnOutcome::Remote(REMOTE_BUSY_EXIT) if !run.observer => {
                    notifier.notify(Event::ReattachBusy {
                        name: run.name,
                        attempt,
                    });
                    last_busy = true;
                }
                SpawnOutcome::Remote(code) => {
                    return Ok(ReconnectOutcome::Terminal(SessionEnd::Remote(code)));
                }
                SpawnOutcome::RemoteSignaled(signal) => {
                    return Ok(ReconnectOutcome::Terminal(SessionEnd::RemoteSignaled(
                        signal,
                    )));
                }
                SpawnOutcome::SshSignaled(signal) => {
                    return Ok(ReconnectOutcome::Terminal(SessionEnd::SshSignaled(signal)));
                }
            },
        }
    }
}

/// Generate a conservative session name for an unnamed connect.
pub fn generated_session_name(limits: &Limits) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let mut name = format!("s{nanos}");
    name.truncate(limits.name_max);
    name
}

/// `eversh connect`: atomic remote attach-or-create plus reconnect.
pub fn connect(
    config: &Config,
    host: &str,
    name: &str,
    take_over: bool,
    child_argv: Vec<Vec<u8>>,
    ssh_options: &[String],
    notifier: &mut dyn Notifier,
) -> Result<SessionEnd, Error> {
    if !validate_name(name, &config.limits) {
        return Err(Error::NameInvalid);
    }
    let request = ControlRequest {
        take_over,
        origins: vec![origin_label(&config.local_host)],
        child_argv,
    };
    run_with_reconnect(
        config,
        SessionRun {
            host,
            name,
            take_over,
            ssh_options,
            observer: false,
        },
        RemoteOp::AttachOrCreate {
            name,
            request: &request,
        },
        notifier,
    )
}

/// `eversh attach`: writer attach to an existing named session.
pub fn attach(
    config: &Config,
    host: &str,
    name: &str,
    take_over: bool,
    ssh_options: &[String],
    notifier: &mut dyn Notifier,
) -> Result<SessionEnd, Error> {
    let request = ControlRequest {
        take_over,
        origins: Vec::new(),
        child_argv: Vec::new(),
    };
    run_with_reconnect(
        config,
        SessionRun {
            host,
            name,
            take_over,
            ssh_options,
            observer: false,
        },
        RemoteOp::Attach {
            name,
            request: &request,
        },
        notifier,
    )
}

/// `eversh observe`: future-output-only observer with reconnect.
pub fn observe(
    config: &Config,
    host: &str,
    name: &str,
    ssh_options: &[String],
    notifier: &mut dyn Notifier,
) -> Result<SessionEnd, Error> {
    run_with_reconnect(
        config,
        SessionRun {
            host,
            name,
            take_over: false,
            ssh_options,
            observer: true,
        },
        RemoteOp::Observe { name },
        notifier,
    )
}

/// `eversh list`: captured, bounded remote discovery output (passed through
/// verbatim by the edge).
pub fn list(
    config: &Config,
    host: &str,
    local_host: Option<&str>,
    json: bool,
    ssh_options: &[String],
) -> Result<Captured, Error> {
    config.limits.validate()?;
    let label = local_host.map(origin_label);
    let proxy = proxy_for(config, ssh_options)?;
    let words = remote_words(
        &config.remote_eversh,
        &RemoteOp::List {
            json,
            filter_origin: label.as_deref(),
        },
        &config.limits,
    )?;
    let args = outer_ssh_args(&proxy, ssh_options, host, &words, false)?;
    spawn_captured(config, &args)
}

/// `eversh detach` / `eversh kill`: exit status passthrough.
pub fn simple_remote(
    config: &Config,
    host: &str,
    op: &RemoteOp<'_>,
    ssh_options: &[String],
) -> Result<ExitKind, Error> {
    config.limits.validate()?;
    let proxy = proxy_for(config, ssh_options)?;
    let words = remote_words(&config.remote_eversh, op, &config.limits)?;
    let args = outer_ssh_args(&proxy, ssh_options, host, &words, false)?;
    spawn_quiet(config, &args)
}

/// `eversh ssh`: raw OpenSSH over everlink. Never restarted (design 7),
/// never touches the status channel (fully inherited on every descriptor).
/// `pre_options` are outer SSH options (placed before the destination,
/// unaudited); `post_command` is an optional remote command (placed after
/// the destination) — see [`crate::command::split_raw_tokens`] (finding 4).
pub fn raw_ssh(
    config: &Config,
    host: &str,
    pre_options: &[String],
    post_command: &[String],
) -> Result<SessionEnd, Error> {
    config.limits.validate()?;
    // Raw options are passed verbatim to the outer ssh (unaudited escape
    // hatch), but only the audited subset is mirrored into the everlink
    // bootstrap's ProxyCommand (design 6.4); a rejected option simply stays
    // outer-ssh-only rather than erroring in raw mode (finding 4).
    let audited = crate::command::audited_subset(pre_options);
    let proxy = proxy_for(config, &audited)?;
    let args = raw_ssh_args(&proxy, pre_options, host, post_command)?;
    Ok(match spawn_inherited(config, &args)? {
        ExitKind::Code(code) => SessionEnd::Remote(code),
        ExitKind::Signaled(signal) => SessionEnd::SshSignaled(signal),
    })
}

/// The live session names this supervisor would resume (list text format,
/// filtered remotely by the local-host origin label).
pub fn session_names(
    config: &Config,
    host: &str,
    local_host: &str,
    ssh_options: &[String],
) -> Result<Vec<String>, Error> {
    config.limits.validate()?;
    let label = origin_label(local_host);
    let proxy = proxy_for(config, ssh_options)?;
    let words = remote_words(
        &config.remote_eversh,
        &RemoteOp::List {
            json: false,
            filter_origin: Some(&label),
        },
        &config.limits,
    )?;
    let args = outer_ssh_args(&proxy, ssh_options, host, &words, false)?;
    let captured = spawn_captured(config, &args)?;
    match captured.exit {
        ExitKind::Code(0) => {}
        ExitKind::Code(code) => return Err(Error::RemoteCommandFailed(code)),
        ExitKind::Signaled(signal) => return Err(Error::RemoteCommandSignaled(signal)),
    }
    let text = std::str::from_utf8(&captured.stdout).map_err(|_| Error::ListOutputInvalid)?;
    let mut names = Vec::new();
    for line in text.lines() {
        let name = line.split('\t').next().unwrap_or("");
        if !validate_name(name, &config.limits) {
            return Err(Error::ListOutputInvalid);
        }
        names.push(name.to_owned());
    }
    Ok(names)
}

/// Why one resume-all launch failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumeFailure {
    Spawn(std::io::ErrorKind),
    Exit(u8),
    Signaled(i32),
}

/// The complete resume-all outcome: every partial failure stays visible.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResumeReport {
    pub launched: Vec<String>,
    pub failures: Vec<(String, ResumeFailure)>,
    pub skipped: Vec<String>,
}

/// `eversh resume-all`: one Kitty tab per matching live session, targeting
/// `KITTY_LISTEN_ON` when available. Failed launches are reported, never
/// silently dropped; sessions beyond the configured cap are reported as
/// skipped.
pub fn resume_all(
    config: &Config,
    host: &str,
    local_host: &str,
    ssh_options: &[String],
    notifier: &mut dyn Notifier,
) -> Result<ResumeReport, Error> {
    config.limits.validate()?;
    let self_exe = validate_self_exe(&config.self_exe)?.to_owned();
    let names = session_names(config, host, local_host, ssh_options)?;
    let mut report = ResumeReport::default();
    for (index, name) in names.iter().enumerate() {
        if index >= config.limits.resume_sessions_max {
            notifier.notify(Event::ResumeSkipped { name });
            report.skipped.push(name.clone());
            continue;
        }
        let args = kitty_launch_args(
            config.kitty_listen_on.as_deref(),
            &self_exe,
            host,
            name,
            ssh_options,
            &config.limits,
        )?;
        let launched = Command::new(&config.kitty_program)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .status();
        match launched {
            Ok(status) => match classify(status) {
                ExitKind::Code(0) => {
                    notifier.notify(Event::ResumeLaunched { name });
                    report.launched.push(name.clone());
                }
                ExitKind::Code(code) => {
                    report
                        .failures
                        .push((name.clone(), ResumeFailure::Exit(code)));
                }
                ExitKind::Signaled(signal) => {
                    report
                        .failures
                        .push((name.clone(), ResumeFailure::Signaled(signal)));
                }
            },
            Err(error) => {
                report
                    .failures
                    .push((name.clone(), ResumeFailure::Spawn(error.kind())));
            }
        }
    }
    Ok(report)
}
