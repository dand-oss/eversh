//! Typed command orchestration for everpty.
//!
//! All configuration is injected. This module neither reads arguments or the
//! process environment, nor prints, nor exits. After the single daemonizing
//! fork both processes return a typed outcome to their respective binary edge.

use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nix::sys::signal::Signal;

use crate::attach::{self, AttachConfig, AttachOutcome, SizeMode};
use crate::broker::{
    self, Broker, BrokerExit, MonotonicClock, ReadyStatus, SpawnPlan, READY_RECORD_LEN,
};
use crate::child::SpawnSpec;
use crate::error::Error;
use crate::frame::{self, Frame, OwnershipEvent, Role};
use crate::limits::Limits;
use crate::session::{
    resolve_state_root_existing_from, resolve_state_root_from, LockedSession, SessionMeta,
    StateRoot,
};
use crate::sys::{self, Forked, PollFd, PollFlags};

#[derive(Debug, Clone)]
pub struct Context {
    pub state_candidates: Vec<PathBuf>,
    pub limits: Limits,
}

#[derive(Debug)]
pub enum Outcome {
    Success,
    Detached,
    ChildExited(u8),
    ChildSignaled(i32),
    LocalSignaled(i32),
    Broker(BrokerExit),
}

impl From<AttachOutcome> for Outcome {
    fn from(outcome: AttachOutcome) -> Self {
        match outcome {
            AttachOutcome::Detached => Self::Detached,
            AttachOutcome::ChildExited(value) => Self::ChildExited(value),
            AttachOutcome::ChildSignaled(signal) => Self::ChildSignaled(signal),
            AttachOutcome::LocalSignaled(signal) => Self::LocalSignaled(signal),
        }
    }
}

pub struct AttachRequest<'a> {
    pub context: &'a Context,
    pub name: &'a str,
    pub role: Role,
    pub take_over: bool,
    pub stdin: BorrowedFd<'a>,
    pub stdout: BorrowedFd<'a>,
}

pub struct StartRequest<'a> {
    pub context: Context,
    pub name: String,
    pub command: Vec<OsString>,
    pub default_shell: Option<OsString>,
    pub environment: Vec<OsString>,
    pub path: Option<OsString>,
    pub origins: Vec<OsString>,
    pub stdin: BorrowedFd<'a>,
    pub stdout: BorrowedFd<'a>,
}

fn existing_root(context: &Context) -> Result<StateRoot, Error> {
    resolve_state_root_existing_from(&context.state_candidates).map_err(|error| match error {
        Error::StateRootUnavailable => Error::NotLive,
        other => other,
    })
}

#[allow(clippy::too_many_arguments)]
fn attach_from_session(
    session: &crate::session::SessionDir,
    context: &Context,
    name: &str,
    role: Role,
    take_over: bool,
    stdin: BorrowedFd<'_>,
    stdout: BorrowedFd<'_>,
    size: SizeMode,
) -> Result<Outcome, Error> {
    attach::attach(AttachConfig {
        session,
        name,
        role,
        take_over,
        size,
        stdin,
        stdout,
        limits: context.limits,
    })
    .map(Outcome::from)
}

#[allow(clippy::too_many_arguments)]
fn attach_from_root(
    root: &StateRoot,
    context: &Context,
    name: &str,
    role: Role,
    take_over: bool,
    stdin: BorrowedFd<'_>,
    stdout: BorrowedFd<'_>,
    size: SizeMode,
) -> Result<Outcome, Error> {
    let session = root.open_session(name, &context.limits)?;
    attach_from_session(
        &session, context, name, role, take_over, stdin, stdout, size,
    )
}

pub fn attach(request: AttachRequest<'_>) -> Result<Outcome, Error> {
    let root = existing_root(request.context)?;
    attach_from_root(
        &root,
        request.context,
        request.name,
        request.role,
        request.take_over,
        request.stdin,
        request.stdout,
        SizeMode::Existing,
    )
}

/// Observer-specific typed entry point. It cannot request ownership or
/// takeover and otherwise shares the exact attach lifecycle.
pub fn observe(request: AttachRequest<'_>) -> Result<Outcome, Error> {
    if request.role != Role::Observer || request.take_over {
        return Err(Error::Protocol("invalid observe request"));
    }
    attach(request)
}

fn contains_nul(value: &OsStr) -> bool {
    value.as_bytes().contains(&0)
}

fn validate_request_name(request: &StartRequest<'_>) -> Result<(), Error> {
    if !frame::validate_name(&request.name, &request.context.limits) {
        return Err(Error::NameInvalid);
    }
    Ok(())
}

fn prepare_command(request: &mut StartRequest<'_>) -> Result<(), Error> {
    if request.command.is_empty() {
        request.command.push(
            request
                .default_shell
                .take()
                .filter(|shell| !shell.is_empty() && !contains_nul(shell))
                .unwrap_or_else(|| OsString::from("/bin/sh")),
        );
    }
    if request.command.is_empty()
        || request.command.iter().any(|part| contains_nul(part))
        || request.environment.iter().any(|part| contains_nul(part))
        || request.path.as_deref().is_some_and(contains_nul)
    {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "command, environment, or PATH contains NUL",
        )));
    }
    validate_request_name(request)
}

fn validate_origins(request: &StartRequest<'_>) -> Result<(), Error> {
    if request.origins.len() > request.context.limits.origin_count_max
        || request.origins.len() > u8::MAX as usize
    {
        return Err(Error::MetadataInvalid);
    }
    for origin in &request.origins {
        let origin = origin.to_str().ok_or(Error::MetadataInvalid)?;
        if origin.len() > request.context.limits.origin_label_max_bytes
            || origin.len() > u8::MAX as usize
        {
            return Err(Error::MetadataInvalid);
        }
    }
    Ok(())
}

fn validate_spawn_inputs(request: &StartRequest<'_>, dimensions: (u16, u16)) -> Result<(), Error> {
    validate_origins(request)?;
    crate::child::validate_spawn_spec(
        &SpawnSpec {
            session_name: &request.name,
            argv: &request.command,
            env: &request.environment,
            path_var: request.path.as_deref(),
            rows: dimensions.0,
            cols: dimensions.1,
            close_in_child: &[],
        },
        &request.context.limits,
    )?;
    let argv0 = request
        .command
        .first()
        .ok_or_else(|| Error::Io(io::Error::new(io::ErrorKind::InvalidInput, "empty argv")))?;
    let origins = request
        .origins
        .iter()
        .map(|origin| {
            origin
                .to_str()
                .map(str::to_owned)
                .ok_or(Error::MetadataInvalid)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let metadata = SessionMeta::new(&request.name, &request.context.limits, argv0, 1, 0, 0)?
        .with_origins(&request.context.limits, origins)?;
    metadata.encode_into(&request.context.limits, &mut Vec::new())
}

fn initial_dimensions(request: &StartRequest<'_>) -> Result<(u16, u16), Error> {
    sys::validate_fd(request.stdin)?;
    sys::validate_fd(request.stdout)?;
    if !sys::is_terminal(request.stdin) {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "start requires a terminal on stdin",
        )));
    }
    let (rows, cols) = sys::get_winsize(request.stdin)?;
    if rows == 0 || cols == 0 {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "start requires nonzero terminal dimensions",
        )));
    }
    Ok((rows, cols))
}

fn unix_millis() -> Result<u64, Error> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Io(io::Error::other("system time precedes Unix epoch")))?
        .as_millis();
    u64::try_from(millis)
        .map_err(|_| Error::Io(io::Error::other("Unix timestamp does not fit metadata")))
}

fn readiness_errno(error: &Error) -> i32 {
    match error {
        Error::Io(error) => error.raw_os_error().unwrap_or(libc::EIO),
        _ => libc::EINVAL,
    }
}

fn report_readiness_failure(fd: OwnedFd, error: &Error) {
    let mut file = std::fs::File::from(fd);
    let _ = file.write_all(
        &ReadyStatus::Failed {
            errno: readiness_errno(error),
        }
        .encode(),
    );
}

fn broker_branch(
    mut request: StartRequest<'_>,
    locked: LockedSession,
    readiness_write: OwnedFd,
    created_unix_ms: u64,
) -> Result<Outcome, Error> {
    let mut readiness_write = Some(readiness_write);
    let built = (|| -> Result<Broker, Error> {
        sys::ignore_sigpipe()?;
        sys::daemon_broker_setup()?;
        let stdin_fd = request.stdin.as_raw_fd();
        let stdout_fd = request.stdout.as_raw_fd();
        sys::replace_daemon_inherited_fd(stdin_fd)?;
        if stdout_fd != stdin_fd {
            sys::replace_daemon_inherited_fd(stdout_fd)?;
        }
        let mut bound = locked.bind_broker_socket(&request.context.limits)?;
        let prepared = (|| -> Result<(SessionMeta, OwnedFd), Error> {
            let pid = std::process::id() as libc::pid_t;
            let argv0 = request
                .command
                .first()
                .map(OsString::as_os_str)
                .ok_or_else(|| {
                    Error::Io(io::Error::new(io::ErrorKind::InvalidInput, "empty argv"))
                })?;
            let metadata = SessionMeta::new(
                &request.name,
                &request.context.limits,
                argv0,
                pid,
                sys::proc_start_ticks(pid)?,
                created_unix_ms,
            )?
            .with_origins(
                &request.context.limits,
                std::mem::take(&mut request.origins)
                    .into_iter()
                    .map(|origin| origin.into_string().map_err(|_| Error::MetadataInvalid))
                    .collect::<Result<Vec<_>, _>>()?,
            )?;
            // Retain one duplicate until every fallible construction step
            // has completed. If Broker::new/set_spawn_plan fails, the
            // original still carries the fixed failure record to the starter.
            let broker_readiness = readiness_write
                .as_ref()
                .ok_or_else(|| Error::Io(io::Error::other("readiness fd missing")))?
                .try_clone()?;
            Ok((metadata, broker_readiness))
        })();
        let (metadata, broker_readiness) = match prepared {
            Ok(prepared) => prepared,
            Err(primary) => {
                return Err(match bound.retire_state() {
                    Ok(()) => primary,
                    Err(cleanup) => cleanup,
                })
            }
        };
        let mut broker = Broker::new(
            bound,
            &request.context.limits,
            Rc::new(MonotonicClock),
            Some(broker_readiness),
        )?;
        let plan = SpawnPlan::new(
            std::mem::take(&mut request.command),
            std::mem::take(&mut request.environment),
            request.path.take(),
            metadata,
        );
        if let Err(primary) = broker.set_spawn_plan(plan) {
            return Err(match broker.retire_unstarted() {
                Ok(()) => primary,
                Err(cleanup) => cleanup,
            });
        }
        drop(readiness_write.take());
        Ok(broker)
    })();

    match built {
        Ok(mut broker) => Ok(Outcome::Broker(broker.serve())),
        Err(error) => {
            if let Some(fd) = readiness_write.take() {
                report_readiness_failure(fd, &error);
            }
            Err(error)
        }
    }
}

fn wait_readiness(fd: BorrowedFd<'_>, timeout_ms: u64) -> Result<ReadyStatus, Error> {
    sys::set_nonblocking(fd)?;
    let deadline = sys::clock_monotonic_ms()?.saturating_add(timeout_ms);
    let mut record = [0u8; READY_RECORD_LEN];
    let mut filled = 0usize;
    loop {
        let now = sys::clock_monotonic_ms()?;
        if now >= deadline {
            return Err(Error::StartupDeadline);
        }
        let remaining = u32::try_from(deadline - now).unwrap_or(u32::MAX);
        let mut pfd = [PollFd::new(
            fd,
            PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR,
        )];
        match sys::poll(&mut pfd, Some(remaining)) {
            Ok(0) => return Err(Error::StartupDeadline),
            Ok(_) => loop {
                match sys::read_fd(fd, &mut record[filled..]) {
                    Ok(0) => return Err(Error::Io(io::Error::from(io::ErrorKind::UnexpectedEof))),
                    Ok(count) => {
                        filled += count;
                        if filled == record.len() {
                            return ReadyStatus::decode(&record).map_err(Error::Io);
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(Error::Io(error)),
                }
            },
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(Error::Io(error)),
        }
    }
}

fn reap_failed_broker(pid: libc::pid_t, grace_ms: u64) -> Result<(), Error> {
    match sys::kill(pid, Signal::SIGTERM) {
        Ok(()) => {}
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {}
        Err(error) => return Err(Error::Io(error)),
    }
    let now = Instant::now();
    let deadline = now
        .checked_add(Duration::from_millis(grace_ms.max(1)))
        .unwrap_or(now);
    loop {
        match sys::waitpid_nohang(pid) {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => {}
            Err(error) if error.raw_os_error() == Some(libc::ECHILD) => return Ok(()),
            Err(error) => return Err(Error::Io(error)),
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    match sys::kill(pid, Signal::SIGKILL) {
        Ok(()) => {}
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {}
        Err(error) => return Err(Error::Io(error)),
    }
    match sys::waitpid_blocking(pid) {
        Ok(_) => Ok(()),
        Err(error) if error.raw_os_error() == Some(libc::ECHILD) => Ok(()),
        Err(error) => Err(Error::Io(error)),
    }
}

fn start_locked(
    request: StartRequest<'_>,
    root: StateRoot,
    locked: LockedSession,
    dimensions: (u16, u16),
    created_unix_ms: u64,
) -> Result<Outcome, Error> {
    let readiness = broker::ReadinessChannel::new()?;
    // SAFETY: the everpty process edge is single-threaded before this one
    // daemon fork and owns every duplicated capability in this function.
    let forked = unsafe { sys::fork_broker()? };
    match forked {
        Forked::Child => {
            drop(readiness.read);
            drop(root);
            broker_branch(request, locked, readiness.write, created_unix_ms)
        }
        Forked::Parent(pid) => {
            locked.close_parent_fork_duplicate();
            drop(readiness.write);
            match wait_readiness(
                readiness.read.as_fd(),
                request.context.limits.startup_deadline_ms,
            ) {
                Ok(ReadyStatus::Ready) => attach_from_root(
                    &root,
                    &request.context,
                    &request.name,
                    Role::Writer,
                    false,
                    request.stdin,
                    request.stdout,
                    SizeMode::Initial {
                        rows: dimensions.0,
                        cols: dimensions.1,
                    },
                ),
                Ok(ReadyStatus::Failed { errno }) => {
                    reap_failed_broker(pid, request.context.limits.control_reply_deadline_ms)?;
                    Err(Error::Io(io::Error::from_raw_os_error(errno)))
                }
                Err(error) => {
                    reap_failed_broker(pid, request.context.limits.control_reply_deadline_ms)?;
                    Err(error)
                }
            }
        }
    }
}

pub fn start(mut request: StartRequest<'_>) -> Result<Outcome, Error> {
    prepare_command(&mut request)?;
    let dimensions = initial_dimensions(&request)?;
    validate_spawn_inputs(&request, dimensions)?;
    let created_unix_ms = unix_millis()?;
    let root = resolve_state_root_from(&request.context.state_candidates)?;
    let locked = root
        .session(&request.name, &request.context.limits)?
        .lock()?;
    locked.recover_stale_socket()?;
    start_locked(request, root, locked, dimensions, created_unix_ms)
}

pub fn attach_or_create(mut request: StartRequest<'_>) -> Result<Outcome, Error> {
    validate_request_name(&request)?;
    let deadline =
        sys::clock_monotonic_ms()?.saturating_add(request.context.limits.startup_deadline_ms);

    loop {
        match existing_root(&request.context) {
            Ok(root) => {
                match attach_from_root(
                    &root,
                    &request.context,
                    &request.name,
                    Role::Writer,
                    false,
                    request.stdin,
                    request.stdout,
                    SizeMode::Existing,
                ) {
                    Err(Error::NotLive) => {}
                    result => return result,
                }
            }
            Err(Error::NotLive) => {}
            Err(error) => return Err(error),
        }
        if sys::clock_monotonic_ms()? >= deadline {
            return Err(Error::StartupDeadline);
        }
        let root = resolve_state_root_from(&request.context.state_candidates)?;
        let session = root.session(&request.name, &request.context.limits)?;
        match session.lock() {
            Ok(locked) => {
                match attach_from_session(
                    locked.dir(),
                    &request.context,
                    &request.name,
                    Role::Writer,
                    false,
                    request.stdin,
                    request.stdout,
                    SizeMode::Existing,
                ) {
                    Err(Error::NotLive) => {
                        locked.recover_stale_socket()?;
                    }
                    result => return result,
                }
                if sys::clock_monotonic_ms()? >= deadline {
                    return Err(Error::StartupDeadline);
                }
                prepare_command(&mut request)?;
                let dimensions = initial_dimensions(&request)?;
                validate_spawn_inputs(&request, dimensions)?;
                let created_unix_ms = unix_millis()?;
                return start_locked(request, root, locked, dimensions, created_unix_ms);
            }
            Err(Error::AlreadyExists) => {
                if sys::clock_monotonic_ms()? >= deadline {
                    return Err(Error::StartupDeadline);
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}

fn ping_session(session: &crate::session::SessionDir, limits: &Limits) -> Result<(), Error> {
    match attach::control(session, &Frame::Ping, limits, limits.list_probe_deadline_ms)? {
        Frame::Pong => Ok(()),
        _ => Err(Error::NotLive),
    }
}

fn dead_probe_error(error: &Error) -> bool {
    match error {
        Error::NotLive | Error::Protocol(_) | Error::StatePathUnsafe => true,
        Error::Io(error) => {
            matches!(
                error.kind(),
                io::ErrorKind::TimedOut
                    | io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::NotConnected
            )
        }
        _ => false,
    }
}

pub fn list(context: &Context) -> Result<Vec<SessionMeta>, Error> {
    let root = match existing_root(context) {
        Ok(root) => root,
        Err(Error::NotLive) => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut live = Vec::new();
    for discovered in root.discover_sessions(&context.limits)? {
        match ping_session(&discovered.dir, &context.limits) {
            Ok(()) => live.push(discovered.meta),
            Err(error) if dead_probe_error(&error) => {}
            Err(error) => return Err(error),
        }
    }
    live.sort_by(|left, right| left.name().cmp(right.name()));
    Ok(live)
}

pub fn current(context: &Context, session_env: Option<&OsStr>) -> Result<String, Error> {
    let name = session_env.and_then(OsStr::to_str).ok_or(Error::NotLive)?;
    if !frame::validate_name(name, &context.limits) {
        return Err(Error::NotLive);
    }
    let root = existing_root(context)?;
    let session = root.open_session(name, &context.limits)?;
    let meta = match session.load_metadata(&context.limits) {
        Ok(meta) => meta,
        Err(Error::MetadataInvalid | Error::MetadataTooLarge) => return Err(Error::NotLive),
        Err(Error::Io(error)) if error.raw_os_error() == Some(libc::ENOENT) => {
            return Err(Error::NotLive)
        }
        Err(error) => return Err(error),
    };
    if meta.name() != name {
        return Err(Error::NotLive);
    }
    match sys::proc_start_ticks(meta.broker_pid()) {
        Ok(ticks) if ticks == meta.broker_start_ticks() => {}
        Ok(_) => return Err(Error::NotLive),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Err(Error::NotLive),
        Err(error) => return Err(Error::Io(error)),
    }
    match ping_session(&session, &context.limits) {
        Ok(()) => {}
        Err(error) if dead_probe_error(&error) => return Err(Error::NotLive),
        Err(error) => return Err(error),
    }
    Ok(name.to_owned())
}

fn open_named(context: &Context, name: &str) -> Result<crate::session::SessionDir, Error> {
    let root = existing_root(context)?;
    root.open_session(name, &context.limits)
}

pub fn detach(context: &Context, name: &str) -> Result<Outcome, Error> {
    let session = open_named(context, name)?;
    match attach::control(
        &session,
        &Frame::DetachWriter,
        &context.limits,
        context.limits.control_reply_deadline_ms,
    )? {
        Frame::Ownership(OwnershipEvent::Revoked) => Ok(Outcome::Success),
        Frame::Error { .. } => Err(Error::Protocol("detach rejected by broker")),
        _ => Err(Error::Protocol("unexpected detach reply")),
    }
}

pub fn kill(context: &Context, name: &str) -> Result<Outcome, Error> {
    let session = open_named(context, name)?;
    let reply_wait = context
        .limits
        .kill_grace_ms
        .saturating_add(context.limits.pty_exit_drain_ms)
        .saturating_add(context.limits.control_reply_deadline_ms);
    match attach::control(&session, &Frame::Kill, &context.limits, reply_wait)? {
        Frame::Exit {
            signal: false,
            value,
        } if value <= u8::MAX as u32 => {}
        Frame::Exit {
            signal: true,
            value,
        } if (1..=64).contains(&value) => {}
        Frame::Error { .. } => return Err(Error::Protocol("kill rejected by broker")),
        _ => return Err(Error::Protocol("unexpected kill reply")),
    }

    let deadline =
        sys::clock_monotonic_ms()?.saturating_add(context.limits.control_reply_deadline_ms);
    loop {
        if !session.parent_entry_matches()? {
            return Ok(Outcome::Success);
        }
        if sys::clock_monotonic_ms()? >= deadline {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "broker state cleanup did not complete",
            )));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::DirBuilderExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            loop {
                let id = FIXTURE.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "everpty-run-validation-{}-{id}",
                    std::process::id()
                ));
                match builder.create(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("temporary directory: {error}"),
                }
            }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn daemon_broker_setup_succeeds_in_the_one_fork_child() {
        let (read, write) = sys::pipe_cloexec().expect("pipe");
        // SAFETY: the child executes only syscall wrappers and _exit.
        match unsafe { sys::fork_broker().expect("fork") } {
            Forked::Child => {
                drop(read);
                let errno = sys::daemon_broker_setup()
                    .err()
                    .and_then(|error| error.raw_os_error())
                    .unwrap_or(0);
                let bytes = errno.to_be_bytes();
                // SAFETY: write is live and the child exits immediately.
                let _ = unsafe { sys::child_write_exact(write.as_raw_fd(), &bytes) };
                // SAFETY: this is the post-fork child branch.
                unsafe { sys::child_exit(i32::from(errno != 0)) }
            }
            Forked::Parent(pid) => {
                drop(write);
                let mut bytes = [0u8; 4];
                sys::read_exact_blocking(read.as_fd(), &mut bytes).expect("record");
                let errno = i32::from_be_bytes(bytes);
                let _ = sys::waitpid_blocking(pid).expect("reap");
                assert_eq!(
                    errno,
                    0,
                    "daemon setup failed: {}",
                    io::Error::from_raw_os_error(errno)
                );
            }
        }
    }

    #[test]
    fn partial_readiness_record_obeys_the_startup_deadline() {
        let (read, write) = sys::pipe_cloexec().expect("pipe");
        let ready = ReadyStatus::Ready.encode();
        assert_eq!(
            sys::write_fd(write.as_fd(), &ready[..3]).expect("partial write"),
            3
        );
        let started = Instant::now();
        assert!(matches!(
            wait_readiness(read.as_fd(), 30),
            Err(Error::StartupDeadline)
        ));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "partial readiness read blocked past its deadline"
        );
        drop(write);
    }

    #[test]
    fn malformed_spawn_inputs_fail_before_creating_state() {
        let base = TempDir::new();
        let state = base.0.join("state");
        let (_master, slave) = sys::openpty(24, 80).expect("pty");
        let stdout = slave.try_clone().expect("stdout");

        let make_request = |environment: Vec<OsString>, origins: Vec<OsString>| StartRequest {
            context: Context {
                state_candidates: vec![state.clone()],
                limits: Limits::default(),
            },
            name: "validation".into(),
            command: vec![OsString::from("/bin/true")],
            default_shell: None,
            environment,
            path: Some(OsString::from("/bin")),
            origins,
            stdin: slave.as_fd(),
            stdout: stdout.as_fd(),
        };

        assert!(start(make_request(vec![OsString::from("BROKEN")], Vec::new())).is_err());
        assert!(!state.exists(), "invalid environment created state");

        let invalid_utf8 = OsString::from_vec(vec![0xff]);
        assert!(start(make_request(Vec::new(), vec![invalid_utf8])).is_err());
        assert!(!state.exists(), "invalid origin created state");

        let mut request = make_request(Vec::new(), Vec::new());
        request.command = vec![OsString::from("missing-everpty-command")];
        assert!(start(request).is_err());
        assert!(!state.exists(), "unresolvable command created state");
    }

    #[test]
    fn current_maps_an_absent_metadata_record_to_not_live() {
        let base = TempDir::new();
        let state = base.0.join("state");
        let limits = Limits::default();
        let root = resolve_state_root_from(std::slice::from_ref(&state)).expect("root");
        let _session = root.session("missing-meta", &limits).expect("session");
        let context = Context {
            state_candidates: vec![state],
            limits,
        };
        assert!(matches!(
            current(&context, Some(OsStr::new("missing-meta"))),
            Err(Error::NotLive)
        ));
    }

    #[test]
    fn attach_or_create_propagates_unexpected_existing_root_io() {
        let base = TempDir::new();
        let candidate = base.0.join("x".repeat(300));
        let (stdin, _stdin_write) = sys::pipe_cloexec().expect("stdin");
        let (stdout_read, stdout) = sys::pipe_cloexec().expect("stdout");
        let result = attach_or_create(StartRequest {
            context: Context {
                state_candidates: vec![candidate.clone()],
                limits: Limits::default(),
            },
            name: "fail-closed".into(),
            command: vec![OsString::from("/bin/true")],
            default_shell: None,
            environment: Vec::new(),
            path: Some(OsString::from("/bin")),
            origins: Vec::new(),
            stdin: stdin.as_fd(),
            stdout: stdout.as_fd(),
        });
        assert!(matches!(
            result,
            Err(Error::Io(ref error)) if error.raw_os_error() == Some(libc::ENAMETOOLONG)
        ));
        assert!(
            !candidate.exists(),
            "unexpected I/O must not fall into creation"
        );
        drop((stdout_read, stdout));
    }

    #[test]
    fn attach_or_create_waits_through_publication_and_reaches_busy() {
        let base = TempDir::new();
        let state = base.0.join("state");
        let limits = Limits {
            startup_deadline_ms: 2_000,
            ..Limits::default()
        };
        let root = resolve_state_root_from(std::slice::from_ref(&state)).expect("root");
        let locked = root
            .session("publication-race", &limits)
            .expect("session")
            .lock()
            .expect("creator lock");
        let (master, slave) = sys::openpty(24, 80).expect("pty");
        let stdout = slave.try_clone().expect("stdout");
        let state_for_client = state.clone();

        let client = std::thread::spawn(move || {
            let before_termios = sys::terminal_attributes(slave.as_fd()).expect("termios");
            let before_mask = sys::current_signal_mask().expect("mask");
            let before_stdin = nix::fcntl::fcntl(slave.as_fd(), nix::fcntl::FcntlArg::F_GETFL)
                .expect("stdin flags");
            let before_stdout = nix::fcntl::fcntl(stdout.as_fd(), nix::fcntl::FcntlArg::F_GETFL)
                .expect("stdout flags");
            let result = attach_or_create(StartRequest {
                context: Context {
                    state_candidates: vec![state_for_client],
                    limits,
                },
                name: "publication-race".into(),
                command: vec![OsString::from_vec(b"/bin/true\0".to_vec())],
                default_shell: None,
                environment: Vec::new(),
                path: Some(OsString::from("/bin")),
                origins: Vec::new(),
                stdin: slave.as_fd(),
                stdout: stdout.as_fd(),
            });
            assert!(
                sys::terminal_attributes(slave.as_fd()).expect("termios") == before_termios,
                "Busy path changed termios"
            );
            assert_eq!(sys::current_signal_mask().expect("mask"), before_mask);
            assert_eq!(
                nix::fcntl::fcntl(slave.as_fd(), nix::fcntl::FcntlArg::F_GETFL)
                    .expect("stdin flags"),
                before_stdin
            );
            assert_eq!(
                nix::fcntl::fcntl(stdout.as_fd(), nix::fcntl::FcntlArg::F_GETFL)
                    .expect("stdout flags"),
                before_stdout
            );
            result
        });

        // Keep the lock held with no socket long enough for the competing
        // caller to exercise the pre-publication retry path.
        std::thread::sleep(Duration::from_millis(30));
        let mut bound = locked.bind_broker_socket(&limits).expect("publish socket");
        let deadline = Instant::now() + Duration::from_secs(2);
        let accepted = loop {
            match sys::accept_nonblock(bound.listener()).expect("accept") {
                Some(accepted) => break accepted,
                None => {
                    assert!(Instant::now() < deadline, "client did not reconnect");
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        };
        let hello = attach::read_frame(accepted.as_fd(), &limits, 1_000).expect("Hello");
        assert!(matches!(
            hello,
            Frame::Hello {
                role: Role::Writer,
                take_over: false,
                ref name,
                ..
            } if name == "publication-race"
        ));
        attach::send_frame(
            accepted.as_fd(),
            &Frame::Busy {
                current_writer_id: 41,
            },
            1_000,
        )
        .expect("Busy");
        drop(accepted);

        assert!(matches!(
            client.join().expect("client thread"),
            Err(Error::Busy {
                current_writer_id: 41
            })
        ));
        drop(master);
        bound.retire_state().expect("retire fixture state");
    }
}
