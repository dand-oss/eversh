//! Child process and PTY lifecycle (plans/m2-plan.md §4, §7; commit 4).
//!
//! [`spawn`] prepares EVERYTHING before its single fork: executable
//! resolution through the captured `PATH`, argv/environment validation
//! plus `EVERPTY_SESSION`, the CString/pointer arrays, the validated
//! descriptor close plan, the PTY pair, a CLOEXEC exec-error pipe, and
//! one CLOEXEC `AF_UNIX` sync socketpair. The post-fork child performs
//! one fixed async-signal-safe sequence, then PARKS at a barrier
//! (ready byte written, go byte awaited on the sync socket) so the
//! parent can capture the child's PGID and `/proc` start ticks
//! race-free before the child is released into `execve`. The parent's
//! release write goes through `send(MSG_NOSIGNAL)` — no parent-side
//! synchronization write can ever raise `SIGPIPE`. Every parent-side
//! failure after fork runs a cleanup that ends and blocking-reaps
//! exactly the forked child: before release, dropping the sync socket
//! makes the parked child `_exit(127)` on its own — no signal is ever
//! sent to an unproven identity — and after release the fully verified
//! [`ChildProc`] capability terminates it. A cleanup whose reap or
//! terminate cannot be CONFIRMED surfaces that failure instead of the
//! original error; an external reaper in this process or an
//! unrecoverable OS error can still defeat cleanup, and is then
//! reported, never hidden. Post-fork child code never allocates,
//! formats, logs, reads the environment, locks, unwinds, or constructs
//! `std::io::Error`; failures travel as a fixed stage+errno record
//! before `_exit(127)`.

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nix::sys::signal::Signal;

use crate::error::Error;
use crate::frame;
use crate::limits::Limits;
use crate::sys;

/// Exact byte length of the exec-error record: one stage byte plus a
/// big-endian errno.
const EXEC_RECORD_LEN: usize = 5;

/// How long the TERM→KILL grace loop sleeps between exit polls.
const GRACE_POLL: Duration = Duration::from_millis(10);

/// The environment key that names the session inside the child.
const SESSION_ENV_KEY: &[u8] = b"EVERPTY_SESSION";

/// Where the post-fork child failed. Reported through the CLOEXEC
/// exec-error pipe as one fixed record; never allocated after fork.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SpawnStage {
    /// `prctl(PR_SET_PDEATHSIG)` failed.
    Pdeathsig = 1,
    /// The recorded parent died before PDEATHSIG could cover the gap.
    ParentGone = 2,
    /// Restoring the signal mask / default dispositions failed.
    ResetSignals = 3,
    /// `setsid(2)` failed.
    Setsid = 4,
    /// `ioctl(TIOCSCTTY)` on the inherited slave failed.
    ControllingTty = 5,
    /// `dup2(2)` of the slave onto fd 0/1/2 failed.
    DupStdio = 6,
    /// `execve(2)` returned.
    Exec = 7,
    /// The ready/go synchronization barrier failed or the parent
    /// abandoned the spawn while the child was parked.
    Sync = 8,
}

impl SpawnStage {
    fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            1 => Self::Pdeathsig,
            2 => Self::ParentGone,
            3 => Self::ResetSignals,
            4 => Self::Setsid,
            5 => Self::ControllingTty,
            6 => Self::DupStdio,
            7 => Self::Exec,
            8 => Self::Sync,
            _ => return None,
        })
    }
}

impl std::fmt::Display for SpawnStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Pdeathsig => "pdeathsig",
            Self::ParentGone => "parent-gone",
            Self::ResetSignals => "signal-reset",
            Self::Setsid => "setsid",
            Self::ControllingTty => "controlling-tty",
            Self::DupStdio => "stdio-dup",
            Self::Exec => "exec",
            Self::Sync => "sync",
        };
        f.write_str(s)
    }
}

/// How the recorded child ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitOutcome {
    /// Normal exit with the given status code.
    Exited(u32),
    /// Terminated by the given signal number.
    Signaled(u32),
}

fn outcome_from_wait(signaled: bool, code: u32) -> ExitOutcome {
    if signaled {
        ExitOutcome::Signaled(code)
    } else {
        ExitOutcome::Exited(code)
    }
}

/// Everything [`spawn`] needs, prepared by the caller before any fork.
/// The environment is the CREATOR's captured environment plus explicit
/// overrides — this library never reads the global environment.
pub struct SpawnSpec<'a> {
    /// Validated session name; exported to the child as
    /// `EVERPTY_SESSION`.
    pub session_name: &'a str,
    /// argv; `argv[0]` names the executable, resolved through
    /// `path_var` when it contains no `/`.
    pub argv: &'a [OsString],
    /// `KEY=VALUE` environment entries.
    pub env: &'a [OsString],
    /// The captured `PATH` value for bare-name resolution.
    pub path_var: Option<&'a OsStr>,
    /// Initial PTY rows; zero is rejected — the initial writer must
    /// supply real dimensions.
    pub rows: u16,
    /// Initial PTY columns; zero is rejected.
    pub cols: u16,
    /// Additional inherited descriptors the child must close before
    /// exec (broker-side fds). Stdio slots (0..=2) and numbers that
    /// collide with the spawn's own freshly allocated descriptors are
    /// refused.
    pub close_in_child: &'a [RawFd],
}

/// A successfully spawned session child: the recorded identity plus
/// the nonblocking PTY master.
pub struct Spawned {
    /// The reap/terminate capability over exactly this child.
    pub child: ChildProc,
    /// The PTY master, already `O_NONBLOCK`.
    pub master: OwnedFd,
}

/// The one process this broker spawned. Every signal and reap goes
/// through this capability at the recorded, re-proven identity; there
/// is no Drop-time signalling — cleanup is always an explicit
/// [`ChildProc::terminate`], the only operation that finalizes the
/// group and consumes the identity anchor. [`ChildProc::observe_exit`]
/// watches the leader without consuming anything.
#[derive(Debug)]
pub struct ChildProc {
    pid: libc::pid_t,
    pgid: libc::pid_t,
    start_ticks: u64,
    /// Leader exit OBSERVED non-consumingly (`waitid(WNOWAIT)`); the
    /// leader is still unreaped and the identity anchor still holds.
    observed: Option<ExitOutcome>,
    /// The group was finalized and the leader REAPED; only this state
    /// may answer [`ChildProc::terminate`] from cache.
    outcome: Option<ExitOutcome>,
}

/// Prepares everything, forks exactly once, and returns the recorded
/// child plus the PTY master. Once fork returns a positive PID, every
/// possible return either yields a fully verified [`ChildProc`] or has
/// run a cleanup that ends and blocking-reaps exactly that child; a
/// cleanup whose reap or terminate fails surfaces THAT failure instead
/// of the original error, so an unconfirmed cleanup is never reported
/// as a clean spawn failure.
pub fn spawn(spec: &SpawnSpec<'_>, limits: &Limits) -> Result<Spawned, Error> {
    let pre = prepare_fork(spec, limits)?;
    let slave_fd = pre.slave.as_raw_fd();
    let err_fd = pre.err_write.as_raw_fd();
    let sync_fd = pre.sync_child.as_raw_fd();

    // SAFETY: exactly one fork; the child branch runs only the
    // async-signal-safe sequence in `run_child` and never returns.
    let forked = unsafe { sys::fork() }.map_err(Error::Io)?;
    let pid = match forked {
        sys::Forked::Child => run_child(
            &pre.plan,
            slave_fd,
            &pre.close_plan,
            err_fd,
            sync_fd,
            pre.parent_pid,
        ),
        sys::Forked::Parent(pid) => pid,
    };
    if pid <= 0 {
        // fork only reports positive child PIDs; refuse to record a
        // broken identity rather than guess. Returning drops every
        // descriptor including the sync socket, so a child that
        // somehow exists parks at the barrier, reads EOF, and
        // `_exit(127)`s itself.
        return Err(invalid("fork returned a non-positive pid"));
    }

    // Parent: release the child-side ends, then run the handshake.
    // Every failure inside `parent_after_fork` ends and reaps exactly
    // this child before returning (or truthfully reports that the
    // cleanup itself failed).
    drop(pre.slave);
    drop(pre.err_write);
    drop(pre.sync_child);
    let child = parent_after_fork(pid, pre.err_read, pre.sync_parent)?;
    Ok(Spawned {
        child,
        master: pre.master,
    })
}

/// Everything allocated and validated before the fork.
struct Prefork {
    plan: sys::ExecPlan,
    master: OwnedFd,
    slave: OwnedFd,
    err_read: OwnedFd,
    err_write: OwnedFd,
    sync_parent: OwnedFd,
    sync_child: OwnedFd,
    close_plan: Vec<RawFd>,
    parent_pid: libc::pid_t,
}

/// Pre-fork allocation: exec plan, PTY, pipes, close plan. All working
/// descriptors are re-homed above the stdio slots so the child's
/// dup2(slave, 0/1/2) can never clobber an internal descriptor even
/// when the broker inherited closed stdio.
fn prepare_fork(spec: &SpawnSpec<'_>, limits: &Limits) -> Result<Prefork, Error> {
    let prepared = prepare_spec(spec, limits)?;
    let exec_path = prepared.executable.as_os_str();
    let plan = sys::ExecPlan::new(exec_path, spec.argv, &prepared.env).map_err(Error::Io)?;
    let (master, slave) = sys::openpty(spec.rows, spec.cols).map_err(Error::Io)?;
    let master = sys::ensure_fd_above_stdio(master).map_err(Error::Io)?;
    let slave = sys::ensure_fd_above_stdio(slave).map_err(Error::Io)?;
    sys::set_nonblocking(master.as_fd()).map_err(Error::Io)?;
    let (err_read, err_write) = pipe_above_stdio()?;
    let (sync_parent, sync_child) = socketpair_above_stdio()?;
    let parent_pid = std::process::id() as libc::pid_t;
    if parent_pid <= 0 {
        return Err(invalid("broker pid out of pid_t range"));
    }
    let internal_close = [
        master.as_raw_fd(),
        err_read.as_raw_fd(),
        sync_parent.as_raw_fd(),
    ];
    let protected = [
        slave.as_raw_fd(),
        err_write.as_raw_fd(),
        sync_child.as_raw_fd(),
    ];
    let extras = spec.close_in_child;
    let close_plan = build_close_plan(internal_close, protected, extras)?;
    Ok(Prefork {
        plan,
        master,
        slave,
        err_read,
        err_write,
        sync_parent,
        sync_child,
        close_plan,
        parent_pid,
    })
}

fn pipe_above_stdio() -> Result<(OwnedFd, OwnedFd), Error> {
    let (r, w) = sys::pipe_cloexec().map_err(Error::Io)?;
    let r = sys::ensure_fd_above_stdio(r).map_err(Error::Io)?;
    let w = sys::ensure_fd_above_stdio(w).map_err(Error::Io)?;
    Ok((r, w))
}

fn socketpair_above_stdio() -> Result<(OwnedFd, OwnedFd), Error> {
    let (a, b) = sys::socketpair_cloexec().map_err(Error::Io)?;
    let a = sys::ensure_fd_above_stdio(a).map_err(Error::Io)?;
    let b = sys::ensure_fd_above_stdio(b).map_err(Error::Io)?;
    Ok((a, b))
}

struct Prepared {
    executable: PathBuf,
    env: Vec<OsString>,
}

/// Pure pre-fork validation and resolution; forks nothing.
fn prepare_spec(spec: &SpawnSpec<'_>, limits: &Limits) -> Result<Prepared, Error> {
    if !frame::validate_name(spec.session_name, limits) {
        return Err(Error::NameInvalid);
    }
    if spec.rows == 0 || spec.cols == 0 {
        return Err(invalid("initial PTY dimensions must be nonzero"));
    }
    let argv0 = match spec.argv.first() {
        Some(a) => a,
        None => return Err(invalid("argv must not be empty")),
    };
    let executable = resolve_executable(argv0, spec.path_var)?;
    let env = build_child_env(spec.env, spec.session_name)?;
    Ok(Prepared { executable, env })
}

/// Resolves `argv[0]` to the path handed to `execve`. A name containing
/// `/` is used as given — exec is always direct, never shell
/// evaluation. A bare name is searched through the captured `path_var`,
/// taking only absolute entries; the first candidate that is an
/// executable regular file wins. The check is advisory — `execve`
/// remains the authority at exec time.
fn resolve_executable(argv0: &OsStr, path_var: Option<&OsStr>) -> Result<PathBuf, Error> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = argv0.as_bytes();
    if bytes.is_empty() {
        return Err(invalid("empty executable name"));
    }
    if bytes.contains(&0) {
        return Err(invalid("NUL byte in executable name"));
    }
    if bytes.contains(&b'/') {
        return Ok(PathBuf::from(argv0));
    }
    let path_var = match path_var {
        Some(p) => p,
        None => return Err(Error::Io(io::Error::from(io::ErrorKind::NotFound))),
    };
    for dir in path_var.as_bytes().split(|&b| b == b':') {
        if dir.first() != Some(&b'/') {
            // Empty or relative PATH entries never resolve a broker
            // exec: the working directory is not a trusted search root.
            continue;
        }
        let candidate = Path::new(OsStr::from_bytes(dir)).join(argv0);
        if is_executable_file(&candidate) {
            return Ok(candidate);
        }
    }
    Err(Error::Io(io::Error::from(io::ErrorKind::NotFound)))
}

fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(m) => m.is_file() && m.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

/// Validates `KEY=VALUE` entries (non-empty key, an `=`, no NUL) and
/// returns them with exactly one `EVERPTY_SESSION=<name>` entry —
/// replacing any caller-supplied value, appending otherwise.
fn build_child_env(env: &[OsString], session_name: &str) -> Result<Vec<OsString>, Error> {
    use std::os::unix::ffi::OsStrExt;
    let mut out = Vec::with_capacity(env.len() + 1);
    for entry in env {
        let bytes = entry.as_bytes();
        if bytes.contains(&0) {
            return Err(invalid("NUL byte in environment entry"));
        }
        let eq = match bytes.iter().position(|&b| b == b'=') {
            Some(i) => i,
            None => return Err(invalid("environment entry without '='")),
        };
        if eq == 0 {
            return Err(invalid("environment entry with empty key"));
        }
        if &bytes[..eq] == SESSION_ENV_KEY {
            // Replaced below with the validated session name.
            continue;
        }
        out.push(entry.clone());
    }
    let mut session = OsString::from("EVERPTY_SESSION=");
    session.push(session_name);
    out.push(session);
    Ok(out)
}

/// Builds the child's deduplicated close plan from the internal
/// parent-side ends plus caller extras. Caller entries in the stdio
/// slots are refused, and a caller number colliding with ANY freshly
/// allocated internal descriptor — protected child-side ends included
/// — is refused outright: a wild caller number must never close a
/// descriptor it does not own.
fn build_close_plan(
    internal_close: [RawFd; 3],
    protected: [RawFd; 3],
    extras: &[RawFd],
) -> Result<Vec<RawFd>, Error> {
    let mut plan: Vec<RawFd> = internal_close.to_vec();
    for &fd in extras {
        if fd <= 2 {
            return Err(invalid("close_in_child must not contain stdio descriptors"));
        }
        if protected.contains(&fd) || internal_close.contains(&fd) {
            return Err(invalid("close_in_child collides with an internal descriptor"));
        }
        if !plan.contains(&fd) {
            plan.push(fd);
        }
    }
    Ok(plan)
}

fn invalid(msg: &'static str) -> Error {
    Error::Io(io::Error::new(io::ErrorKind::InvalidInput, msg))
}

/// The post-fork child. Async-signal-safe only — raw errno end to end,
/// no `std::io::Error` — every step either succeeds or reports a fixed
/// stage+errno record and `_exit(127)`s. Order per plans/m2-plan.md §4
/// step 7, plus the identity barrier before exec.
fn run_child(
    plan: &sys::ExecPlan,
    slave: RawFd,
    close_plan: &[RawFd],
    err_fd: RawFd,
    sync_fd: RawFd,
    parent_pid: libc::pid_t,
) -> ! {
    // (1) PDEATHSIG, then close the parent-death race via getppid.
    // SAFETY: post-fork child context.
    match unsafe { sys::child_set_pdeathsig_checked(parent_pid) } {
        Ok(true) => {}
        Ok(false) => child_fail(err_fd, SpawnStage::ParentGone, 0),
        Err(errno) => child_fail(err_fd, SpawnStage::Pdeathsig, errno),
    }
    // (2) Restore the signal mask and default dispositions.
    // SAFETY: post-fork child context.
    if let Err(errno) = unsafe { sys::child_reset_signals() } {
        child_fail(err_fd, SpawnStage::ResetSignals, errno);
    }
    // (3) New session.
    // SAFETY: post-fork child context.
    if let Err(errno) = unsafe { sys::child_setsid() } {
        child_fail(err_fd, SpawnStage::Setsid, errno);
    }
    // (4) Acquire the inherited slave as the controlling terminal.
    // SAFETY: post-fork child context, freshly a session leader.
    if let Err(errno) = unsafe { sys::set_controlling_tty(slave) } {
        child_fail(err_fd, SpawnStage::ControllingTty, errno);
    }
    // (5) Slave onto stdin/stdout/stderr, then drop the original fd —
    // always above the stdio slots (`ensure_fd_above_stdio`), so this
    // never closes a freshly made copy.
    for target in 0..=2 {
        // SAFETY: post-fork child context.
        if let Err(errno) = unsafe { sys::child_dup2(slave, target) } {
            child_fail(err_fd, SpawnStage::DupStdio, errno);
        }
    }
    // SAFETY: post-fork child context.
    unsafe { sys::child_close(slave) };
    // (6) Close inherited broker descriptors per the validated plan.
    // The error-pipe and sync-socket child-side ends are protected
    // from the plan and stay open.
    for &fd in close_plan {
        // SAFETY: post-fork child context.
        unsafe { sys::child_close(fd) };
    }
    // (6a) Announce the barrier over the sync socket: everything
    // before exec succeeded.
    // SAFETY: post-fork child context.
    if let Err(errno) = unsafe { sys::child_write_exact(sync_fd, &[1]) } {
        child_fail(err_fd, SpawnStage::Sync, errno);
    }
    // (6b) Park until the parent captures the identity. EOF means the
    // parent abandoned the spawn: exit WITHOUT exec — this is how a
    // parent-side failure ends a pending child without any signal.
    // SAFETY: post-fork child context.
    match unsafe { sys::child_read_byte(sync_fd) } {
        Ok(true) => {}
        Ok(false) => child_fail(err_fd, SpawnStage::Sync, 0),
        Err(errno) => child_fail(err_fd, SpawnStage::Sync, errno),
    }
    // (7) Direct execve over the prebuilt arrays; returns only errno.
    // SAFETY: post-fork child context; on success the image is
    // replaced.
    let errno = unsafe { plan.execve() };
    child_fail(err_fd, SpawnStage::Exec, errno)
}

/// Writes the fixed record and exits 127. Never returns, never
/// allocates.
fn child_fail(err_fd: RawFd, stage: SpawnStage, errno: i32) -> ! {
    let record = encode_exec_record(stage, errno);
    // SAFETY: post-fork child context; best-effort report before exit.
    let _ = unsafe { sys::child_write_exact(err_fd, &record) };
    // SAFETY: `_exit` never unwinds or runs atexit handlers.
    unsafe { sys::child_exit(127) }
}

fn encode_exec_record(stage: SpawnStage, errno: i32) -> [u8; EXEC_RECORD_LEN] {
    let e = errno.to_be_bytes();
    [stage as u8, e[0], e[1], e[2], e[3]]
}

fn parse_exec_record(buf: &[u8]) -> Option<(SpawnStage, i32)> {
    if buf.len() != EXEC_RECORD_LEN {
        return None;
    }
    let stage = SpawnStage::from_u8(buf[0])?;
    let errno = i32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    Some((stage, errno))
}

/// Post-release failure classification — the input to the pure
/// cleanup decision in [`released_failure_needs_terminate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReleasedFailure {
    /// A well-formed stage+errno record arrived: the child reported
    /// its failure and has already `_exit(127)`-ed.
    ReportedFailure,
    /// Malformed bytes arrived. Only a failing child writes to the
    /// exec-error pipe, so the child died — but untrustworthily.
    MalformedRecord,
    /// Reading the exec-error pipe itself failed: nothing proves the
    /// child exited, so it may be RUNNING.
    PipeReadFailed,
}

/// The normative post-release cleanup decision, pinned by unit tests:
/// only a failure that can leave the released child running routes to
/// the verified terminate; a child that provably `_exit`-ed needs only
/// the confirmed reap.
fn released_failure_needs_terminate(failure: ReleasedFailure) -> bool {
    match failure {
        ReleasedFailure::ReportedFailure | ReleasedFailure::MalformedRecord => false,
        ReleasedFailure::PipeReadFailed => true,
    }
}

/// Combines the primary spawn error with the cleanup's reap result.
/// A CONFIRMED reap of the exact child keeps the primary error; a
/// failed reap means the child may be leaked, and that cleanup
/// failure WINS — it is never discarded behind a clean-looking spawn
/// error.
fn cleanup_result(primary: Error, reap: io::Result<(bool, u32)>) -> Error {
    match reap {
        Ok(_) => primary,
        Err(e) => Error::Io(e),
    }
}

/// Classifies what the exec-error pipe said about a child that died
/// before the barrier. Pure over the drained read result.
fn barrier_death_error(report: io::Result<Option<(SpawnStage, i32)>>) -> Error {
    match report {
        Ok(Some((stage, errno))) => Error::SpawnFailed { stage, errno },
        Ok(None) => invalid("child died before the sync barrier"),
        Err(e) => Error::Io(e),
    }
}

/// The parked child must lead its own positive process group — the
/// pure predicate behind the pre-release identity gate.
fn group_is_child_own(pid: libc::pid_t, pgid: libc::pid_t) -> bool {
    pgid > 0 && pgid == pid
}

/// Parent half of the spawn handshake over the sync socket. EVERY
/// failure return runs its cleanup and CONFIRMS it: a child parked at
/// the barrier is aborted by sync-socket EOF (it exits itself — no
/// unproven signal) and then reaped, a child that already `_exit`-ed
/// is reaped, and a released child that may be running is terminated
/// through the verified capability. No cleanup result is discarded —
/// [`cleanup_result`] makes an unconfirmed reap the surfaced error.
fn parent_after_fork(
    pid: libc::pid_t,
    err_read: OwnedFd,
    sync: OwnedFd,
) -> Result<ChildProc, Error> {
    // Wait for the child to reach the barrier (setsid and stdio wiring
    // done) or die trying.
    match sys::read_byte_blocking(sync.as_fd()) {
        Ok(true) => {}
        Ok(false) => {
            // The child died before the barrier: collect its record,
            // then reap the exact PID.
            let primary = barrier_death_error(read_exec_result(err_read));
            return Err(fail_pending(primary, sync, pid));
        }
        Err(e) => return Err(fail_pending(Error::Io(e), sync, pid)),
    }
    // The child is parked: capture its identity race-free. setsid has
    // already run, so the group must be the child's own.
    let pgid = match sys::getpgid_of(pid) {
        Ok(p) => p,
        Err(e) => return Err(fail_pending(Error::Io(e), sync, pid)),
    };
    let start_ticks = match sys::proc_start_ticks(pid) {
        Ok(t) => t,
        Err(e) => return Err(fail_pending(Error::Io(e), sync, pid)),
    };
    if !group_is_child_own(pid, pgid) {
        let primary = invalid("child is not its own process-group leader");
        return Err(fail_pending(primary, sync, pid));
    }
    // Release the verified child into exec: exactly one byte through
    // the SIGPIPE-proof sender. A vanished child surfaces as EPIPE.
    if let Err(e) = send_release_byte(sync.as_fd()) {
        return Err(fail_pending(Error::Io(e), sync, pid));
    }
    drop(sync);
    let mut child = ChildProc {
        pid,
        pgid,
        start_ticks,
        observed: None,
        outcome: None,
    };
    match read_exec_result(err_read) {
        Ok(None) => Ok(child),
        Ok(Some((stage, errno))) => {
            let primary = Error::SpawnFailed { stage, errno };
            let failure = ReleasedFailure::ReportedFailure;
            Err(fail_released(failure, primary, &mut child))
        }
        Err(e) if e.kind() == io::ErrorKind::InvalidData => {
            let failure = ReleasedFailure::MalformedRecord;
            Err(fail_released(failure, Error::Io(e), &mut child))
        }
        Err(e) => {
            let failure = ReleasedFailure::PipeReadFailed;
            Err(fail_released(failure, Error::Io(e), &mut child))
        }
    }
}

/// Cleanup for every failure while the parent still holds the sync
/// socket: dropping it aborts a parked child — its blocking read
/// returns EOF and it `_exit(127)`s on its own, no signal to an
/// unproven identity — and is a no-op for a child that already died.
/// The blocking reap of the exact PID is the confirmation either way.
fn fail_pending(primary: Error, sync: OwnedFd, pid: libc::pid_t) -> Error {
    drop(sync);
    cleanup_result(primary, sys::waitpid_blocking(pid))
}

/// Cleanup after the verified child was released into exec, routed by
/// the pure [`released_failure_needs_terminate`] decision.
fn fail_released(failure: ReleasedFailure, primary: Error, child: &mut ChildProc) -> Error {
    if released_failure_needs_terminate(failure) {
        // The child may be running; its identity is proven, so end it
        // through the checked capability (which finalizes the group
        // and reaps). A failed terminate is surfaced, not discarded.
        match child.terminate(Duration::ZERO) {
            Ok(_) => primary,
            Err(cleanup) => cleanup,
        }
    } else {
        // The child `_exit`-ed itself; the confirmed reap is the
        // whole cleanup.
        cleanup_result(primary, sys::waitpid_blocking(child.pid))
    }
}

/// Releases the parked child: exactly one byte through
/// `send(MSG_NOSIGNAL)` on the sync socket, so no parent-side
/// synchronization write can ever raise SIGPIPE — a vanished child
/// surfaces as `EPIPE`. Retries `EINTR`; anything but a complete
/// one-byte send is an error.
fn send_release_byte(fd: BorrowedFd<'_>) -> io::Result<()> {
    loop {
        match sys::send_no_sigpipe(fd, &[1]) {
            Ok(1) => return Ok(()),
            Ok(_) => return Err(io::Error::other("release byte not sent whole")),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Parent half of the exec-error pipe: drains to EOF. `None` means the
/// pipe closed empty — execve succeeded and CLOEXEC revoked the write
/// end. A record means the child failed and has already `_exit`-ed.
/// Anything else on the pipe is `InvalidData`.
fn read_exec_result(fd: OwnedFd) -> io::Result<Option<(SpawnStage, i32)>> {
    use std::io::Read;
    let mut file = std::fs::File::from(fd);
    let mut buf = [0u8; EXEC_RECORD_LEN + 1];
    let mut len = 0usize;
    loop {
        match file.read(&mut buf[len..]) {
            Ok(0) => break,
            Ok(n) => {
                len += n;
                if len == buf.len() {
                    // Longer than any legal record.
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    if len == 0 {
        return Ok(None);
    }
    match parse_exec_record(&buf[..len]) {
        Some(r) => Ok(Some(r)),
        None => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed exec-error record",
        )),
    }
}

impl ChildProc {
    /// Recorded child PID (always positive).
    pub fn pid(&self) -> libc::pid_t {
        self.pid
    }

    /// Recorded process-group id (always positive and equal to the
    /// PID; the child's own setsid group).
    pub fn pgid(&self) -> libc::pid_t {
        self.pgid
    }

    /// Recorded `/proc/<pid>/stat` start ticks.
    pub fn start_ticks(&self) -> u64 {
        self.start_ticks
    }

    /// The stored exit outcome once the group was finalized and the
    /// leader reaped (by [`ChildProc::terminate`]).
    pub fn outcome(&self) -> Option<ExitOutcome> {
        self.outcome
    }

    /// Re-proves the recorded identity: the process still exists
    /// (live or unreaped zombie), sits in the recorded process group,
    /// and carries the recorded start ticks. `Ok(false)` when it is
    /// gone or no longer matches.
    pub fn identity_matches(&self) -> io::Result<bool> {
        if self.pid <= 0 || self.pgid <= 0 {
            return Ok(false);
        }
        let pgid = match sys::getpgid_of(self.pid) {
            Ok(p) => p,
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => return Ok(false),
            Err(e) => return Err(e),
        };
        let ticks = match sys::proc_start_ticks(self.pid) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e),
        };
        Ok(pgid == self.pgid && ticks == self.start_ticks)
    }

    /// Non-consuming exit observation (`waitid(WNOWAIT)`): the exact
    /// outcome once the leader has exited, `None` while it runs. The
    /// leader stays UNREAPED, so the PID/PGID/start-ticks identity
    /// anchor remains valid — descendant cleanup can still be decided
    /// afterwards. Finalization and the one reap happen only in
    /// [`ChildProc::terminate`].
    pub fn observe_exit(&mut self) -> io::Result<Option<ExitOutcome>> {
        if let Some(o) = self.outcome {
            return Ok(Some(o));
        }
        if let Some(o) = self.observed {
            return Ok(Some(o));
        }
        match sys::observe_exit_nowait(self.pid)? {
            None => Ok(None),
            Some((signaled, code)) => {
                let o = outcome_from_wait(signaled, code);
                self.observed = Some(o);
                Ok(Some(o))
            }
        }
    }

    /// The ONE anchor-consuming reap — private, called only by
    /// [`ChildProc::terminate`] after group finalization. (A narrowly
    /// scoped post-quiescence reap for the broker loop is commit-7
    /// work.)
    fn reap_blocking(&mut self) -> io::Result<ExitOutcome> {
        if let Some(o) = self.outcome {
            return Ok(o);
        }
        let (signaled, code) = sys::waitpid_blocking(self.pid)?;
        let o = outcome_from_wait(signaled, code);
        self.outcome = Some(o);
        Ok(o)
    }

    /// TERM→bounded-grace→KILL group cleanup that never abandons the
    /// identity anchor:
    ///
    /// 1. The leader's exit is observed WITHOUT reaping
    ///    (`waitid(WNOWAIT)`), so the PID/PGID/start-ticks proof stays
    ///    valid throughout — a leader that exits on TERM while a
    ///    TERM-ignoring descendant remains in the group does NOT end
    ///    the cleanup early, and a merely OBSERVED exit never takes
    ///    the cached-return path.
    /// 2. The group is ALWAYS finalized with a proof-gated SIGKILL
    ///    before anything is consumed. An identity that cannot be
    ///    proven — before TERM or before the KILL finalization — is
    ///    [`Error::NotLive`]: nothing is signalled, nothing is reaped,
    ///    and finalization is never claimed.
    /// 3. The leader is reaped exactly once, after finalization; only
    ///    that finalized-and-reaped outcome is answered from cache.
    pub fn terminate(&mut self, grace: Duration) -> Result<ExitOutcome, Error> {
        if let Some(o) = self.outcome {
            // Cached ONLY once the group was finalized and the leader
            // reaped — an observed-but-unreaped exit falls through.
            return Ok(o);
        }
        // Phase 1: TERM the proven group, unless the leader already
        // exited (then go straight to finalization).
        if self.observe_exit().map_err(Error::Io)?.is_none() {
            if !self.identity_matches().map_err(Error::Io)? {
                return Err(Error::NotLive);
            }
            self.signal_group(Signal::SIGTERM)?;
            // Overflowed deadlines escalate immediately rather than
            // waiting forever.
            let deadline = Instant::now().checked_add(grace);
            loop {
                if self.observe_exit().map_err(Error::Io)?.is_some() {
                    break;
                }
                match deadline {
                    Some(d) if Instant::now() < d => std::thread::sleep(GRACE_POLL),
                    _ => break,
                }
            }
        }
        // Phase 2: finalize the group. The leader is still unreaped
        // (live or zombie), so the anchor normally holds; if it cannot
        // be re-proven (an external reaper consumed the leader), that
        // is NotLive — never a silently skipped SIGKILL passed off as
        // finalization.
        if !self.identity_matches().map_err(Error::Io)? {
            return Err(Error::NotLive);
        }
        self.signal_group(Signal::SIGKILL)?;
        // Phase 3: reap exactly once, after finalization.
        self.reap_blocking().map_err(Error::Io)
    }

    /// Checked group signal. A group that vanished between the proof
    /// and the signal (`ESRCH`) is benign — the reap that follows is
    /// the authority.
    fn signal_group(&self, sig: Signal) -> Result<(), Error> {
        match sys::killpg(self.pgid, sig) {
            Ok(()) => Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => Ok(()),
            Err(e) => Err(Error::Io(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn os(s: &str) -> OsString {
        OsString::from(s)
    }

    fn spec<'a>(name: &'a str, argv: &'a [OsString], rows: u16, cols: u16) -> SpawnSpec<'a> {
        SpawnSpec {
            session_name: name,
            argv,
            env: &[],
            path_var: None,
            rows,
            cols,
            close_in_child: &[],
        }
    }

    #[test]
    fn spawn_stage_and_exec_record_round_trip() {
        let stages = [
            SpawnStage::Pdeathsig,
            SpawnStage::ParentGone,
            SpawnStage::ResetSignals,
            SpawnStage::Setsid,
            SpawnStage::ControllingTty,
            SpawnStage::DupStdio,
            SpawnStage::Exec,
            SpawnStage::Sync,
        ];
        for stage in stages {
            for errno in [0, libc::ENOENT, i32::MAX, -1] {
                let rec = encode_exec_record(stage, errno);
                assert_eq!(parse_exec_record(&rec), Some((stage, errno)));
            }
        }
        assert_eq!(parse_exec_record(&[]), None);
        assert_eq!(parse_exec_record(&[1, 0, 0, 0]), None);
        assert_eq!(parse_exec_record(&[1, 0, 0, 0, 0, 0]), None);
        assert_eq!(parse_exec_record(&[0, 0, 0, 0, 2]), None);
        assert_eq!(parse_exec_record(&[9, 0, 0, 0, 2]), None);
        assert_eq!(outcome_from_wait(false, 7), ExitOutcome::Exited(7));
        assert_eq!(outcome_from_wait(true, 9), ExitOutcome::Signaled(9));
    }

    #[test]
    fn resolve_executable_uses_only_absolute_path_entries() {
        let fx = Fixture::new();
        let bin = fx.base.join("bin");
        std::fs::create_dir(&bin).expect("bin dir");
        let exec = bin.join("tool");
        std::fs::write(&exec, b"#!/bin/sh\n").expect("write tool");
        let mode = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(&exec, mode).expect("chmod");
        let plain = bin.join("plain");
        std::fs::write(&plain, b"x").expect("write plain");

        // Relative and empty PATH entries are skipped; the absolute
        // entry resolves the executable candidate.
        let mut pv = OsString::from("rel/dir::");
        pv.push(bin.as_os_str());
        let got = resolve_executable(OsStr::new("tool"), Some(&pv)).expect("resolve");
        assert_eq!(got, exec);
        // A non-executable candidate never matches.
        assert!(matches!(
            resolve_executable(OsStr::new("plain"), Some(&pv)),
            Err(Error::Io(e)) if e.kind() == io::ErrorKind::NotFound
        ));
        // A name with '/' is used as given, without consulting PATH.
        let abs = resolve_executable(OsStr::new("/bin/sh"), None).expect("absolute");
        assert_eq!(abs, PathBuf::from("/bin/sh"));
        let rel = resolve_executable(OsStr::new("./x"), None).expect("relative");
        assert_eq!(rel, PathBuf::from("./x"));
        // Empty and NUL names fail before any fork could happen.
        assert!(matches!(
            resolve_executable(OsStr::new(""), Some(&pv)),
            Err(Error::Io(e)) if e.kind() == io::ErrorKind::InvalidInput
        ));
        let nul = OsStr::from_bytes(b"a\0b");
        assert!(matches!(
            resolve_executable(nul, Some(&pv)),
            Err(Error::Io(e)) if e.kind() == io::ErrorKind::InvalidInput
        ));
        // A bare name with no captured PATH is NotFound.
        assert!(matches!(
            resolve_executable(OsStr::new("tool"), None),
            Err(Error::Io(e)) if e.kind() == io::ErrorKind::NotFound
        ));
    }

    #[test]
    fn child_env_replaces_session_and_rejects_malformed() {
        let base = [os("A=1"), os("EVERPTY_SESSION=old"), os("B=x=y")];
        let out = build_child_env(&base, "work").expect("env");
        let expected = vec![os("A=1"), os("B=x=y"), os("EVERPTY_SESSION=work")];
        assert_eq!(out, expected);
        let none = build_child_env(&[], "work").expect("env");
        assert_eq!(none, vec![os("EVERPTY_SESSION=work")]);
        let missing_eq = [os("NOEQ")];
        assert!(matches!(
            build_child_env(&missing_eq, "w"),
            Err(Error::Io(e)) if e.kind() == io::ErrorKind::InvalidInput
        ));
        let empty_key = [os("=v")];
        assert!(matches!(
            build_child_env(&empty_key, "w"),
            Err(Error::Io(e)) if e.kind() == io::ErrorKind::InvalidInput
        ));
        let nul = [OsStr::from_bytes(b"A=\0x").to_os_string()];
        assert!(matches!(
            build_child_env(&nul, "w"),
            Err(Error::Io(e)) if e.kind() == io::ErrorKind::InvalidInput
        ));
    }

    #[test]
    fn prepare_spec_rejects_bad_name_empty_argv_and_zero_dims() {
        let limits = Limits::default();
        let argv = [os("/bin/sh")];
        assert!(matches!(
            prepare_spec(&spec("bad/name", &argv, 24, 80), &limits),
            Err(Error::NameInvalid)
        ));
        assert!(matches!(
            prepare_spec(&spec("work", &[], 24, 80), &limits),
            Err(Error::Io(e)) if e.kind() == io::ErrorKind::InvalidInput
        ));
        // Zero and mixed-zero initial dimensions are refused before
        // any PTY is opened.
        for (rows, cols) in [(0, 0), (0, 80), (24, 0)] {
            assert!(matches!(
                prepare_spec(&spec("work", &argv, rows, cols), &limits),
                Err(Error::Io(e)) if e.kind() == io::ErrorKind::InvalidInput
            ));
        }
        let ok = prepare_spec(&spec("work", &argv, 24, 80), &limits).expect("valid spec");
        assert_eq!(ok.executable, PathBuf::from("/bin/sh"));
        assert_eq!(ok.env, vec![os("EVERPTY_SESSION=work")]);
    }

    #[test]
    fn close_plan_rejects_stdio_and_collisions_and_dedups() {
        let internal = [10, 11, 12];
        let protected = [20, 21, 22];
        // No extras: the plan is exactly the internal close set.
        let plan = build_close_plan(internal, protected, &[]).expect("plan");
        assert_eq!(plan, vec![10, 11, 12]);
        // Extras are appended deduplicated.
        let plan = build_close_plan(internal, protected, &[30, 30, 31]).expect("plan");
        assert_eq!(plan, vec![10, 11, 12, 30, 31]);
        // Stdio slots are refused.
        for fd in [0, 1, 2] {
            assert!(matches!(
                build_close_plan(internal, protected, &[fd]),
                Err(Error::Io(e)) if e.kind() == io::ErrorKind::InvalidInput
            ));
        }
        // Collisions with protected child-side ends are refused: a
        // wild caller number must never close a fresh descriptor.
        for fd in protected {
            assert!(matches!(
                build_close_plan(internal, protected, &[fd]),
                Err(Error::Io(e)) if e.kind() == io::ErrorKind::InvalidInput
            ));
        }
        // Collisions with the internal close targets are refused too.
        for fd in internal {
            assert!(matches!(
                build_close_plan(internal, protected, &[fd]),
                Err(Error::Io(e)) if e.kind() == io::ErrorKind::InvalidInput
            ));
        }
    }

    #[test]
    fn released_cleanup_decision_is_pinned() {
        // Only the failure that can leave the released child RUNNING
        // routes to the verified terminate; a child that provably
        // `_exit`-ed (any bytes on the exec-error pipe come only from
        // a failing child) needs only the confirmed reap.
        assert!(!released_failure_needs_terminate(
            ReleasedFailure::ReportedFailure
        ));
        assert!(!released_failure_needs_terminate(
            ReleasedFailure::MalformedRecord
        ));
        assert!(released_failure_needs_terminate(
            ReleasedFailure::PipeReadFailed
        ));
    }

    #[test]
    fn cleanup_result_surfaces_unconfirmed_reaps() {
        // A confirmed reap keeps the primary spawn error, for both
        // exit shapes.
        let primary = Error::SpawnFailed {
            stage: SpawnStage::Exec,
            errno: libc::ENOENT,
        };
        assert!(matches!(
            cleanup_result(primary, Ok((false, 127))),
            Error::SpawnFailed {
                stage: SpawnStage::Exec,
                errno: libc::ENOENT
            }
        ));
        let primary = invalid("child died before the sync barrier");
        assert!(matches!(
            cleanup_result(primary, Ok((true, 9))),
            Error::Io(e) if e.kind() == io::ErrorKind::InvalidInput
        ));
        // An UNCONFIRMED reap (a possible leak) wins over the primary
        // error — it must never be discarded behind a clean-looking
        // spawn failure.
        let primary = Error::SpawnFailed {
            stage: SpawnStage::Exec,
            errno: libc::ENOENT,
        };
        let reap_err = io::Error::from_raw_os_error(libc::ECHILD);
        assert!(matches!(
            cleanup_result(primary, Err(reap_err)),
            Error::Io(e) if e.raw_os_error() == Some(libc::ECHILD)
        ));
    }

    #[test]
    fn barrier_death_classifies_records_and_read_errors() {
        // A record maps to the exact stage+errno.
        let report = Ok(Some((SpawnStage::Setsid, libc::EPERM)));
        assert!(matches!(
            barrier_death_error(report),
            Error::SpawnFailed {
                stage: SpawnStage::Setsid,
                errno: libc::EPERM
            }
        ));
        // An empty pipe means the child died silently.
        assert!(matches!(
            barrier_death_error(Ok(None)),
            Error::Io(e) if e.kind() == io::ErrorKind::InvalidInput
        ));
        // A pipe read failure propagates as-is.
        let read_err = io::Error::from_raw_os_error(libc::EIO);
        assert!(matches!(
            barrier_death_error(Err(read_err)),
            Error::Io(e) if e.raw_os_error() == Some(libc::EIO)
        ));
    }

    #[test]
    fn group_gate_requires_the_childs_own_positive_group() {
        assert!(group_is_child_own(100, 100));
        // A mismatched, zero, or negative captured group is refused.
        assert!(!group_is_child_own(100, 101));
        assert!(!group_is_child_own(100, 1));
        assert!(!group_is_child_own(100, 0));
        assert!(!group_is_child_own(100, -100));
        assert!(!group_is_child_own(-100, -100));
        assert!(!group_is_child_own(0, 0));
    }

    static FIXTURE: AtomicUsize = AtomicUsize::new(0);

    /// Exclusively created 0700 fixture base; Drop removes only what
    /// this fixture itself created.
    struct Fixture {
        base: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let mut private_dir = std::fs::DirBuilder::new();
            private_dir.mode(0o700);
            for _ in 0..64 {
                let n = FIXTURE.fetch_add(1, Ordering::Relaxed);
                let unique = format!("everpty-child-{}-{}", std::process::id(), n);
                let base = std::env::temp_dir().join(unique);
                match private_dir.create(&base) {
                    Ok(()) => return Self { base },
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(e) => panic!("fixture base: {e}"),
                }
            }
            panic!("no unique fixture base");
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }
}
