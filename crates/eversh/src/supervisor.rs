//! Thin supervision of OpenSSH, everlink, and Kitty processes (design 7).
//!
//! Every function here launches the installed `ssh` binary over the everlink
//! ProxyCommand and supervises it: eversh never relays or parses terminal
//! data, never builds a runtime, and preserves inherited stdin/stdout/stderr
//! for the live terminal path. Effective OpenSSH configuration resolution is
//! delegated to OpenSSH itself: ProxyCommand `%n`/`%p` carry the original
//! destination token and effective port into everlink, whose own `ssh -G`
//! verification rejects recursive proxying (design 6.4, 8).
//!
//! ## The local everlink link-status file (design 3, 7)
//!
//! OpenSSH reserves exit 255 for its own failures, but that single code is
//! produced identically whether the SSH session never established anything
//! (an auth failure, for instance), the transport died mid-session, or a
//! remote command happened to exit 255 itself. Resolving that ambiguity
//! does not need a remote-side channel: for every structured interactive
//! operation and every probe, eversh creates a private per-spawn file under
//! its own state root (a `0700` directory, `0600` files) and passes its
//! path to the local everlink `ssh-proxy` edge as a `--status-file`
//! ProxyCommand ARGUMENT. OpenSSH executes the ProxyCommand line through
//! the user's local shell, so the path arrives in everlink's own argv: no
//! environment variable exists, no `SendEnv`/`AcceptEnv` policy can forward
//! one remotely, and no ambient value can instrument a spawn that was not
//! given the argument. The channel is mandatory, never best-effort: if the
//! file cannot be allocated — no state root resolved at all, an unwritable
//! or unallocatable root, or a root whose path cannot travel as the
//! argument (a percent token OpenSSH would expand inside the quoted word,
//! a quote, a control byte, or non-UTF-8) — the operation fails with a
//! clear local error BEFORE any ssh child exists, because an
//! uninstrumented spawn's missing record would classify an ordinary 255
//! (an auth or policy failure) as a transport failure and wrongly enter
//! the reconnect path (design 7). Batch operations that never classify
//! (`list`, `detach`/`kill`, raw `ssh`) pass no status file and are
//! unaffected. Raw `eversh ssh` never passes it and stays fully
//! inherited and uninstrumented (design 7: it is never retried, so there is
//! nothing to classify).
//!
//! everlink appends two kinds of versioned line to that file: `carrying`,
//! written once as soon as the QUIC stream first delivers a byte
//! originating from the remote peer (a genuine round trip — the remote
//! sshd's own banner proves it), and a terminal `cause <word>
//! carried=<0|1>` line on every exit path, mapping its own terminal
//! evidence to exactly two classes — `clean-close` only for a graceful
//! `SourceEof` whose Drain AND Finalize both completed cleanly (plus every
//! pre-bridge failure: an ordinary failure with nothing carried), and
//! `transport-failure` for everything else — recording whether application
//! bytes ever flowed in both directions.
//!
//! ## Classification (findings 1, 2)
//!
//! stdin/stdout/stderr stay fully inherited throughout every spawn here —
//! nothing is piped or parsed locally. A non-255 exit passes through
//! exactly as always (Busy stays exit code 3, an ordinary remote exit stays
//! itself). A locally signaled `ssh` process is reported as such. An exit
//! code of 255 reads, then removes, the status file: `clean-close` is an
//! ordinary SSH failure, reported immediately as [`SessionEnd::SshFailed`]
//! with no probe and no retry — this deterministically covers both an auth
//! failure and a remote command that itself exited 255, and design 7
//! accepts that collapsed diagnostic, since the exit code is 255 either
//! way. `transport-failure`, or a missing or unparseable file, enters or
//! continues the probe-gated reconnect episode below — failing toward a
//! bounded probe is always safer than silently skipping a retry a live
//! session still needed.
//!
//! ## Reconnect contract (design 7, findings 3)
//!
//! After an established named connect, attach, or observe ends unexpectedly
//! with a transport-failure (or unparseable) 255, a fresh authenticated
//! bootstrap probes whether the same broker is alive. Retries reattach the
//! SAME session with plain `attach` — a missing or exited broker is never
//! restarted, so no application work is duplicated — under bounded
//! exponential backoff with jitter and an overall `retry_deadline_ms`
//! deadline that bounds the WHOLE episode: a reattach spawn is
//! deadline-bounded only until its status file shows `carrying` (or any
//! terminal record has already arrived) — a hung probe or a
//! not-yet-carrying reattach is killed and reaped at the remaining
//! deadline, with termios restored first — after which the wait is
//! unbounded, exactly like any live session.
//!
//! A reattach reporting Busy (a writer is already attached) is retried
//! against the episode's OWN deadline, never the attempt budget and never
//! `--take-over`: after a path death the remote writer slot can stay
//! legitimately held for up to everlink's idle timeout (~30s), because the
//! remote bridge only learns of the loss when its QUIC endpoint expires —
//! a small attempt count would give up long before the broker could
//! possibly revoke the slot. Other in-episode failures (an unreachable
//! host, a reattach that dies again without carrying) keep the finite
//! attempt budget: they give up fast by design rather than hammering a
//! down host.
//!
//! A later reattach whose OWN status file shows `carried=1` before it dies
//! again starts a FRESH episode with fresh attempt/deadline budgets, and
//! `carried=0` deaths continue the same episode's budget — but episode
//! restarts are capped invocation-wide (`episode_restarts_max`): a
//! topology that repeatedly delivers a carrying session and then kills it
//! ends as a visible ordinary failure once the cap is reached, never a
//! silent infinite loop.
//!
//! Because every spawn stays fully inherited (no piped descriptor to await
//! EOF on), a deadline-triggered kill of the direct `ssh` child is always
//! bounded regardless of any surviving descendant (notably everlink's own
//! `ssh-proxy` ProxyCommand child, if it is mid-handshake): eversh never
//! waits on it. Residual documented limitation: once a reattach is
//! carrying, a wedge on that now-live transport is bounded by everlink's
//! own contractual timeouts (idle/stall/handshake/lease deadlines are all
//! finite and measured in single-digit to low tens of seconds — design 4,
//! 6.3), not by `retry_deadline_ms`. A user who needs a tighter bound on
//! THAT window can layer
//! `ServerAliveCountMax`/`ServerAliveInterval`/`ConnectTimeout` via
//! `--ssh-option`.
#![cfg(unix)]

use crate::command::{
    kitty_launch_args, outer_ssh_args, proxy_command, raw_ssh_args, remote_words, status_word_safe,
    validate_self_exe, RemoteOp,
};
use crate::error::{Error, LinkStatusFault};
use crate::limits::Limits;
use crate::remote::{origin_label, validate_host, validate_name, ControlRequest};
use everlink::link_status;
use std::ffi::OsString;
use std::io::Read;
use std::os::fd::AsFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
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
    /// The private local root eversh's own per-spawn everlink link-status
    /// files are created under (design 3, 7); `None` when no state-root
    /// candidate resolves at all, in which case every classification-
    /// carrying spawn (structured interactive operations and probes) fails
    /// closed with a clear local error before any ssh child exists —
    /// never an uninstrumented spawn whose missing record would
    /// misclassify an ordinary 255 as transport failure.
    pub link_status_root: Option<PathBuf>,
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
    /// Busy (a writer is already attached) until the episode deadline ran
    /// out. Never escalated to `--take-over`: a legitimately attached new
    /// writer must not be stolen.
    Busy,
    /// The invocation-wide episode-restart cap was exhausted: transports
    /// kept dying after genuinely carrying the session. A visible, ordinary
    /// failure — the episode loop never continues silently past the cap.
    RestartsExhausted,
}

/// The supervised outcome of a session-carrying invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEnd {
    /// The remote command's exit status (child exit, Busy, role errors) —
    /// returned unchanged.
    Remote(u8),
    /// The local ssh process itself was terminated by a signal.
    SshSignaled(i32),
    /// SSH exited 255 with the local link-status file reporting
    /// `clean-close`: an ordinary OpenSSH failure (auth, host lookup, or a
    /// remote command that itself exited 255 — deterministically
    /// indistinguishable from OpenSSH's own perspective), reported
    /// immediately with no probe and no retry (finding 1).
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
    /// SSH failed with the transport intact (finding 1).
    SshFailed,
    /// A reattach found the session Busy; retried within the same episode's
    /// deadline budget rather than escalating to `--take-over`.
    ReattachBusy {
        name: &'a str,
        attempt: u32,
    },
    /// The invocation-wide episode-restart cap was reached: carried-death
    /// restarts stop here as a visible, ordinary failure.
    EpisodeRestartsExhausted {
        restarts: u32,
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

/// Build the ProxyCommand for one spawn. `status_file`, when set, is the
/// same per-spawn link-status file the spawn's ssh child is classified
/// through: the path travels to the local everlink edge as a ProxyCommand
/// argument (never an environment variable — see the module header).
fn proxy_for(
    config: &Config,
    ssh_options: &[String],
    status_file: Option<&Path>,
) -> Result<String, Error> {
    let self_exe = validate_self_exe(&config.self_exe)?;
    proxy_command(self_exe, &config.remote_eversh, ssh_options, status_file)
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
// Bounded waits and the local everlink link-status file (design 3, 7;
// findings 1-3).
// ---------------------------------------------------------------------------

/// Poll interval for a deadline-bounded child wait. Fine enough that a
/// bounded wait overshoots its deadline by at most this much.
const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(20);

fn poll_interval(deadline: Instant) -> Duration {
    WAIT_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now()))
}

/// One non-interactive child, waited with a hard deadline: a hung child is
/// killed and reaped rather than left running past `retry_deadline_ms`
/// (finding 3). Safe regardless of any surviving descendant: nothing here
/// is piped, so nothing can hold an inherited descriptor open against us.
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

/// One non-interactive child for the probe spawn, waited with a hard
/// deadline (see [`probe`], which owns the probe's allocated status file
/// and its removal guard). Probe classification is exit-code-only; the
/// status file exists purely for parity/diagnostic value with structured
/// interactive spawns.
fn spawn_quiet_bounded(
    config: &Config,
    args: &[OsString],
    deadline: Instant,
) -> Result<BoundedExit, Error> {
    let mut command = Command::new(&config.ssh_program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    let mut child = command.spawn()?;
    let outcome = wait_bounded_child(&mut child, deadline)?;
    Ok(outcome)
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

/// Bounded grace period for the final status-file read after the direct
/// child is confirmed reaped: covers the everlink `ssh-proxy` ProxyCommand
/// descendant's own terminal write landing a few scheduler ticks after its
/// parent `ssh` process exits. A reliability improvement only — reading a
/// local file never blocks the way a pipe read can, so this grace period
/// never risks a hang; it only reduces spurious "unparseable" fallbacks
/// from a legitimate race between the two processes' exits.
const LINK_STATUS_GRACE: Duration = Duration::from_millis(300);

/// The classified outcome of reading the link-status file after a spawn
/// exits, or its absence (design 3, 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinkOutcome {
    /// `cause=clean-close`: the transport ended after a completed, graceful
    /// exchange — an ordinary SSH failure, never retried (finding 1).
    CleanClose,
    /// `cause=transport-failure`, or the file is missing/unparseable: fails
    /// toward a bounded probe rather than silently skipping a retry a live
    /// session still needed. `carried` is `false` whenever it is not
    /// positively known.
    TransportFailure { carried: bool },
}

fn parse_link_status(content: &str) -> Option<LinkOutcome> {
    for line in content.lines() {
        if let Some(link_status::StatusRecord::Cause { cause, carried }) =
            link_status::parse_line(line)
        {
            return Some(match cause {
                link_status::StatusCause::CleanClose => LinkOutcome::CleanClose,
                link_status::StatusCause::TransportFailure => {
                    LinkOutcome::TransportFailure { carried }
                }
            });
        }
    }
    None
}

/// Read the final classification, retrying within [`LINK_STATUS_GRACE`]
/// while the file exists but has no terminal record yet. A missing or
/// unreadable file, or an unparseable one, resolves to the safe default —
/// the same defense in depth that covers a record lost after the spawn.
fn link_status_final(path: &Path) -> LinkOutcome {
    let deadline = Instant::now() + LINK_STATUS_GRACE;
    loop {
        let Ok(content) = std::fs::read_to_string(path) else {
            return LinkOutcome::TransportFailure { carried: false };
        };
        if let Some(outcome) = parse_link_status(&content) {
            return outcome;
        }
        if Instant::now() >= deadline {
            return LinkOutcome::TransportFailure { carried: false };
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Whether the status file already has ANY recognized record (`carrying`
/// or a terminal `cause`) — used only to end the bounded phase of a
/// reattach spawn early; the final classification always uses
/// [`link_status_final`], never this.
fn link_status_settled(path: &Path) -> bool {
    let Ok(content) = std::fs::read_to_string(path) else {
        return false;
    };
    content
        .lines()
        .any(|line| link_status::parse_line(line).is_some())
}

/// One allocated per-spawn link-status file, with its
/// allocation-to-removal guard: the file is removed exactly once when the
/// allocating scope exits, on EVERY return path — normal completion, an
/// error before or after the spawn, or a deadline kill — so repeated
/// failed invocations cannot accumulate private files under the state
/// root. The `0700`/`0600`/exclusive-create lifecycle is unchanged; only
/// removal became scoped (the guard, not scattered removals).
struct AllocatedStatus {
    path: PathBuf,
}

impl AllocatedStatus {
    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for AllocatedStatus {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Allocate one fresh per-spawn link-status file (design 3, 7): a `0700`
/// directory under [`Config::link_status_root`] and one `0600` file with a
/// process-id/timestamp/counter name, created exclusively so a collision is
/// a hard failure rather than a silently reused stale file. The path must
/// also embed as the single-quoted `--status-file` ProxyCommand word, so a
/// state root that cannot (non-UTF-8, quotes, control bytes, or a percent
/// token OpenSSH would expand inside the quoted word) is rejected before
/// anything is created on disk.
///
/// Fail-closed (round 4): every failure — no root resolved at all, an
/// unwritable or unallocatable root, or an unembeddable path — is a clear
/// local error. A spawn that classifies through this file NEVER proceeds
/// uninstrumented: a missing record would classify an ordinary 255 (an
/// auth or policy failure) as transport failure and wrongly enter the
/// reconnect path (design 7).
fn allocate_status_file(config: &Config) -> Result<AllocatedStatus, Error> {
    let root = config
        .link_status_root
        .as_deref()
        .ok_or(Error::LinkStatusChannel {
            root: None,
            fault: LinkStatusFault::NoRoot,
        })?;
    let dir = root.join("link-status");
    let path = dir.join(unique_status_name());
    if !status_word_safe(&path) {
        return Err(Error::LinkStatusChannel {
            root: Some(root.to_owned()),
            fault: LinkStatusFault::UnsafePath,
        });
    }
    // `DirBuilder::mode` applies to EVERY directory this call creates, the
    // state root included if it does not exist yet — unlike
    // `create_dir_all` followed by a single `set_permissions` on the leaf,
    // which would leave a freshly created root at the process umask's
    // default (not private), failing everpty's own 0700 state-root check
    // (design 5.4) for the remote role sharing that same root.
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder
        .create(&dir)
        .map_err(|error| Error::LinkStatusChannel {
            root: Some(root.to_owned()),
            fault: LinkStatusFault::RootUnusable(error),
        })?;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|error| Error::LinkStatusChannel {
            root: Some(root.to_owned()),
            fault: LinkStatusFault::FileCreate(error),
        })?;
    Ok(AllocatedStatus { path })
}

fn unique_status_name() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{}-{nanos}-{sequence}.status", std::process::id())
}

/// One interactive/link-tracked spawn's local outcome.
enum StatusSpawn {
    Exited {
        exit: ExitKind,
        status: LinkOutcome,
    },
    /// Only possible when `deadline` was set and the status file never
    /// showed `carrying` (or any terminal record) before it passed.
    DeadlineExceeded,
}

/// Spawn one interactive remote invocation for a session-carrying operation
/// (attach-or-create, attach, observe — never raw ssh, which stays fully
/// inherited and uninstrumented). stdin/stdout/stderr remain FULLY
/// inherited for the live terminal path (design 7) — classification comes
/// entirely from the local out-of-band link-status file (whose path is
/// already embedded in the ProxyCommand argument inside `args`), never a
/// piped descriptor, so a deadline-triggered kill of the direct child is
/// always bounded regardless of any surviving descendant. The CALLER owns
/// the status file's [`AllocatedStatus`] guard: removal happens on every
/// return path from the allocating scope, including the error paths below.
///
/// `deadline`, when set, bounds the wait ONLY until the status file shows
/// `carrying` (or a terminal record has already arrived): a hung
/// pre-`carrying` child (a reattach that never reconnects) is killed and
/// reaped at the deadline, with the outer terminal's termios restored
/// first if this process's ssh child put it mid-transition. Once
/// carrying — or when `deadline` is `None`, as for the very first spawn of
/// an invocation, which is never part of a bounded reconnect episode — the
/// wait is unbounded: an ongoing session is never killed by the reconnect
/// deadline (design 7, finding 3).
fn spawn_link_tracked(
    config: &Config,
    args: &[OsString],
    status_path: &Path,
    deadline: Option<Instant>,
) -> Result<StatusSpawn, Error> {
    let termios = if deadline.is_some() {
        captured_termios()
    } else {
        None
    };
    let mut command = Command::new(&config.ssh_program);
    command.args(args);
    let mut child = command.spawn()?;

    if let Some(deadline) = deadline {
        loop {
            if let Some(status) = child.try_wait()? {
                let outcome = link_status_final(status_path);
                return Ok(StatusSpawn::Exited {
                    exit: classify(status),
                    status: outcome,
                });
            }
            if link_status_settled(status_path) {
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                // Restore termios BEFORE any further work (finding 3): the
                // killed ssh child never got the chance to restore it
                // itself, and nothing after this point may block.
                if let Some(termios) = &termios {
                    restore_termios(termios);
                }
                return Ok(StatusSpawn::DeadlineExceeded);
            }
            std::thread::sleep(poll_interval(deadline));
        }
    }
    let status = child.wait()?;
    let outcome = link_status_final(status_path);
    Ok(StatusSpawn::Exited {
        exit: classify(status),
        status: outcome,
    })
}

/// The terminal meaning of one link-tracked spawn (findings 1-3).
enum SpawnOutcome {
    Remote(u8),
    SshSignaled(i32),
    /// ssh exited 255 and the status file says `clean-close` (finding 1).
    SshFailedCleanClose,
    /// ssh exited 255 and the transport genuinely died underneath a peer,
    /// or the status file was missing/unparseable (finding 1, 3). `carried`
    /// drives episode-restart when this happens to an already-carrying
    /// reattach.
    TransportAfterFailure {
        carried: bool,
    },
}

fn classify_status_spawn(exit: ExitKind, status: LinkOutcome) -> SpawnOutcome {
    match exit {
        ExitKind::Signaled(signal) => SpawnOutcome::SshSignaled(signal),
        ExitKind::Code(SSH_FAILURE) => match status {
            LinkOutcome::CleanClose => SpawnOutcome::SshFailedCleanClose,
            LinkOutcome::TransportFailure { carried } => {
                SpawnOutcome::TransportAfterFailure { carried }
            }
        },
        ExitKind::Code(code) => SpawnOutcome::Remote(code),
    }
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
/// (finding 3). The probe classifies through its own allocated status file
/// like every structured spawn (design 3, 7): allocation is fail-closed —
/// an unusable state root aborts the invocation with a local error rather
/// than probing uninstrumented.
fn probe(
    config: &Config,
    host: &str,
    name: &str,
    ssh_options: &[String],
    deadline: Instant,
) -> Result<ProbeStatus, Error> {
    let status = allocate_status_file(config)?;
    let proxy = proxy_for(config, ssh_options, Some(status.path()))?;
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
/// Returns `None` for `TransportAfterFailure`, which is never terminal by
/// itself — the caller enters or continues the reconnect episode.
fn spawn_outcome_to_session_end(outcome: SpawnOutcome) -> Option<SessionEnd> {
    match outcome {
        SpawnOutcome::Remote(code) => Some(SessionEnd::Remote(code)),
        SpawnOutcome::SshSignaled(signal) => Some(SessionEnd::SshSignaled(signal)),
        SpawnOutcome::SshFailedCleanClose => Some(SessionEnd::SshFailed),
        SpawnOutcome::TransportAfterFailure { .. } => None,
    }
}

/// Run one interactive/streaming remote operation and, on unexpected SSH
/// termination with a transport-failure status, reconnect the SAME session
/// through probe-gated retries (design 7). A clean-close SSH failure is an
/// ordinary SSH failure with no probe and no retry (finding 1).
fn run_with_reconnect(
    config: &Config,
    run: SessionRun<'_>,
    first_op: RemoteOp<'_>,
    notifier: &mut dyn Notifier,
) -> Result<SessionEnd, Error> {
    config.limits.validate()?;
    validate_host(run.host)?;
    // Fail-closed (round 4): the classification channel must exist before
    // the ssh child does — an unusable state root is a local error, never
    // an uninstrumented spawn. The guard's scope ends with the first
    // spawn's classification: the file is removed on every path out of
    // this block, including every `?` error below.
    let (exit, status) = {
        let status = allocate_status_file(config)?;
        let proxy = proxy_for(config, run.ssh_options, Some(status.path()))?;
        let words = remote_words(&config.remote_eversh, &first_op, &config.limits)?;
        let interactive = first_op.interactive();
        let args = outer_ssh_args(&proxy, run.ssh_options, run.host, &words, interactive)?;
        // The very first spawn of an invocation is never part of a bounded
        // reconnect episode: it runs unbounded, exactly like an
        // already-carrying session (design 7).
        match spawn_link_tracked(config, &args, status.path(), None)? {
            StatusSpawn::Exited { exit, status } => (exit, status),
            StatusSpawn::DeadlineExceeded => {
                // Unreachable: an unbounded spawn never reports this. Fail
                // safe rather than panic if that invariant is ever
                // violated.
                return Ok(SessionEnd::TransportFailed(
                    TransportFailure::DeadlineExceeded,
                ));
            }
        }
    };
    if let Some(end) = spawn_outcome_to_session_end(classify_status_spawn(exit, status)) {
        if matches!(end, SessionEnd::SshFailed) {
            notifier.notify(Event::SshFailed);
        }
        return Ok(end);
    }
    // TransportAfterFailure: enter the reconnect episode. A later
    // carried-then-255 reattach starts a FRESH episode with fresh
    // attempt/deadline budgets (finding 3), so this loops rather than
    // recursing — but restarts are capped invocation-wide: a topology that
    // keeps delivering a carrying session and then killing it ends as a
    // visible ordinary failure once `episode_restarts_max` is reached,
    // never a silent infinite loop.
    let mut restarts: u32 = 0;
    loop {
        match reconnect(config, run, notifier)? {
            ReconnectOutcome::Terminal(end) => return Ok(end),
            ReconnectOutcome::RestartEpisode => {
                restarts += 1;
                if restarts > config.limits.episode_restarts_max {
                    notifier.notify(Event::EpisodeRestartsExhausted {
                        restarts: config.limits.episode_restarts_max,
                    });
                    return Ok(SessionEnd::TransportFailed(
                        TransportFailure::RestartsExhausted,
                    ));
                }
            }
        }
    }
}

/// Why [`reconnect`] returned: a terminal outcome for the whole invocation,
/// or a signal to start a fresh episode with fresh attempt/deadline budgets.
enum ReconnectOutcome {
    Terminal(SessionEnd),
    RestartEpisode,
}

/// One bounded reconnect episode: finite attempts for ordinary in-episode
/// failures, bounded backoff with jitter, and an overall deadline that
/// bounds a hung probe, a not-yet-carrying reattach, AND the Busy-retry
/// path (finding 3). Busy reattach responses never consume the attempt
/// budget — the episode deadline alone governs them, because the remote
/// writer slot can stay legitimately held for up to everlink's idle timeout
/// after a path death, far longer than a small attempt budget could span.
/// Once a reattach starts carrying it runs unbounded; if THAT later dies
/// again with `carried=1`, this returns [`ReconnectOutcome::RestartEpisode`]
/// rather than continuing this episode's attempt count.
fn reconnect(
    config: &Config,
    run: SessionRun<'_>,
    notifier: &mut dyn Notifier,
) -> Result<ReconnectOutcome, Error> {
    let limits = &config.limits;
    let deadline = Instant::now() + Duration::from_millis(limits.retry_deadline_ms);
    let mut attempt: u32 = 0;
    // Whether the most recent retry cause was a reattach reporting Busy,
    // and how many Busy responses have stacked up consecutively. A Busy
    // reattach continues without charging the attempt budget (the deadline
    // alone bounds it); the streak grows the backoff so a long hold is
    // polled gently rather than hammered, and when the deadline then runs
    // out the busy diagnostic is reported as the reason rather than a
    // generic exhaustion message.
    let mut last_busy = false;
    let mut busy_streak: u32 = 0;
    loop {
        if !last_busy {
            attempt += 1;
            if attempt > limits.retry_attempts_max {
                notifier.notify(Event::RetryExhausted {
                    attempts: limits.retry_attempts_max,
                });
                return Ok(ReconnectOutcome::Terminal(SessionEnd::TransportFailed(
                    TransportFailure::AttemptsExhausted,
                )));
            }
        }
        let delay = backoff_delay(attempt.saturating_add(busy_streak), limits);
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
                busy_streak = 0;
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
        // Fail-closed (round 4) with the same allocation-to-removal guard:
        // the reattach's own status file must exist before its ssh child
        // does, and is removed on every path out of this iteration —
        // Busy retries, carried deaths, terminal outcomes, and every `?`
        // error below.
        let status = allocate_status_file(config)?;
        let proxy = proxy_for(config, run.ssh_options, Some(status.path()))?;
        let words = remote_words(&config.remote_eversh, &op, &config.limits)?;
        let args = outer_ssh_args(&proxy, run.ssh_options, run.host, &words, interactive)?;
        // Bounded ONLY until this reattach starts carrying or reports a
        // terminal record; once carrying, the wait inside becomes unbounded.
        match spawn_link_tracked(config, &args, status.path(), Some(deadline))? {
            StatusSpawn::DeadlineExceeded => {
                notifier.notify(Event::RetryDeadlineExceeded);
                return Ok(ReconnectOutcome::Terminal(SessionEnd::TransportFailed(
                    TransportFailure::DeadlineExceeded,
                )));
            }
            StatusSpawn::Exited { exit, status } => match classify_status_spawn(exit, status) {
                SpawnOutcome::TransportAfterFailure { carried: true } => {
                    return Ok(ReconnectOutcome::RestartEpisode);
                }
                SpawnOutcome::TransportAfterFailure { carried: false } => {
                    notifier.notify(Event::TransportInterrupted { attempt });
                    last_busy = false;
                    busy_streak = 0;
                }
                SpawnOutcome::SshFailedCleanClose => {
                    notifier.notify(Event::SshFailed);
                    return Ok(ReconnectOutcome::Terminal(SessionEnd::SshFailed));
                }
                // A reattach finding the session Busy is retried within
                // THIS episode's deadline budget without charging its
                // attempt budget: the dead transport's writer slot may not
                // be revoked for up to everlink's idle timeout after the
                // path death. Never escalated to take_over — a
                // legitimately attached new writer must not be stolen.
                SpawnOutcome::Remote(REMOTE_BUSY_EXIT) if !run.observer => {
                    notifier.notify(Event::ReattachBusy {
                        name: run.name,
                        attempt,
                    });
                    last_busy = true;
                    busy_streak += 1;
                }
                SpawnOutcome::Remote(code) => {
                    return Ok(ReconnectOutcome::Terminal(SessionEnd::Remote(code)));
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
    let proxy = proxy_for(config, ssh_options, None)?;
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
    let proxy = proxy_for(config, ssh_options, None)?;
    let words = remote_words(&config.remote_eversh, op, &config.limits)?;
    let args = outer_ssh_args(&proxy, ssh_options, host, &words, false)?;
    spawn_quiet(config, &args)
}

/// `eversh ssh`: raw OpenSSH over everlink. Never restarted (design 7),
/// never passes a link-status file to its ProxyCommand — stays fully
/// inherited and uninstrumented on every descriptor (and since the handoff
/// is an argument, not an environment variable, no ambient value can
/// instrument it either). `pre_options` are outer SSH options (placed
/// before the destination, unaudited); `post_command` is an optional
/// remote command (placed after the destination) — see
/// [`crate::command::split_raw_tokens`] (finding 4).
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
    let proxy = proxy_for(config, &audited, None)?;
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
    let proxy = proxy_for(config, ssh_options, None)?;
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
