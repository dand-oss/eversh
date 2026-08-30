//! Typed attach-client half for the everpty v1 local protocol.
//!
//! This module owns no arguments, diagnostics, environment lookup, or process
//! exit. It connects through a validated session directory capability, keeps
//! all protocol storage bounded, and restores every caller-owned terminal,
//! signal-mask, and descriptor flag it changes.

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use crate::client::{FrameReader, OutQueue};
use crate::error::Error;
use crate::frame::{AttachStatus, Frame, OwnershipEvent, Role, PROTOCOL_VERSION};
use crate::limits::Limits;
use crate::session::SessionDir;
use crate::sys::{self, PollFd, PollFlags};

/// How a writer chooses the dimensions carried in Hello.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeMode {
    /// Existing-session attach: a TTY supplies its current size and a non-TTY
    /// supplies `(0,0)` to preserve the broker's size.
    Existing,
    /// Initial writer: the already-captured real dimensions are mandatory.
    Initial { rows: u16, cols: u16 },
}

/// Fully injected attach inputs.
pub struct AttachConfig<'a> {
    pub session: &'a SessionDir,
    pub name: &'a str,
    pub role: Role,
    pub take_over: bool,
    pub size: SizeMode,
    pub stdin: BorrowedFd<'a>,
    pub stdout: BorrowedFd<'a>,
    pub limits: Limits,
}

/// Terminal outcome returned to the binary edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachOutcome {
    Detached,
    ChildExited(u8),
    ChildSignaled(i32),
    LocalSignaled(i32),
}

struct TerminalGuard<'fd> {
    fd: BorrowedFd<'fd>,
    original: sys::TerminalAttributes,
    raw: bool,
}

impl<'fd> TerminalGuard<'fd> {
    fn new(fd: BorrowedFd<'fd>) -> Result<Self, Error> {
        let original = sys::terminal_attributes(fd)?;
        sys::set_terminal_raw(fd, &original)?;
        Ok(Self {
            fd,
            original,
            raw: true,
        })
    }

    fn enter_raw(&mut self) -> Result<(), Error> {
        if !self.raw {
            sys::set_terminal_raw(self.fd, &self.original)?;
            self.raw = true;
        }
        Ok(())
    }

    fn restore(&mut self) -> Result<(), Error> {
        if self.raw {
            sys::restore_terminal(self.fd, &self.original)?;
            self.raw = false;
        }
        Ok(())
    }
}

impl Drop for TerminalGuard<'_> {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

fn protocol(message: &'static str) -> Error {
    Error::Protocol(message)
}

fn timeout(message: &'static str) -> Error {
    Error::Io(io::Error::new(io::ErrorKind::TimedOut, message))
}

fn deadline_after(ms: u64) -> Result<u64, Error> {
    Ok(sys::clock_monotonic_ms()?.saturating_add(ms))
}

fn remaining_ms(deadline: u64) -> Result<u32, Error> {
    let now = sys::clock_monotonic_ms()?;
    if now >= deadline {
        return Ok(0);
    }
    Ok(u32::try_from(deadline - now).unwrap_or(u32::MAX))
}

fn wait_fd(fd: BorrowedFd<'_>, events: PollFlags, deadline: u64) -> Result<PollFlags, Error> {
    loop {
        let remaining = remaining_ms(deadline)?;
        if remaining == 0 {
            return Err(timeout("protocol deadline expired"));
        }
        let mut pfd = [PollFd::new(
            fd,
            events | PollFlags::POLLERR | PollFlags::POLLHUP,
        )];
        match sys::poll(&mut pfd, Some(remaining)) {
            Ok(0) => return Err(timeout("protocol deadline expired")),
            Ok(_) => return Ok(pfd[0].revents().unwrap_or(PollFlags::empty())),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(Error::Io(error)),
        }
    }
}

fn classify_connect_error(errno: i32) -> Error {
    if matches!(errno, libc::ENOENT | libc::ECONNREFUSED) {
        Error::NotLive
    } else {
        Error::Io(io::Error::from_raw_os_error(errno))
    }
}

pub(crate) fn connect(session: &SessionDir, timeout_ms: u64) -> Result<OwnedFd, Error> {
    let fd = session.connect_socket()?;
    let deadline = deadline_after(timeout_ms)?;
    let revents = wait_fd(fd.as_fd(), PollFlags::POLLOUT, deadline)?;
    if let Some(errno) = sys::socket_error(fd.as_fd())? {
        return Err(classify_connect_error(errno));
    }
    if revents.intersects(PollFlags::POLLERR | PollFlags::POLLHUP)
        && !revents.contains(PollFlags::POLLOUT)
    {
        return Err(Error::NotLive);
    }
    if sys::peer_uid(fd.as_fd())? != sys::effective_uid() {
        return Err(Error::StatePathUnsafe);
    }
    Ok(fd)
}

pub(crate) fn send_frame(fd: BorrowedFd<'_>, frame: &Frame, timeout_ms: u64) -> Result<(), Error> {
    let encoded = frame.encode();
    let deadline = deadline_after(timeout_ms)?;
    let mut offset = 0usize;
    while offset < encoded.len() {
        match sys::send_no_sigpipe(fd, &encoded[offset..]) {
            Ok(0) => return Err(Error::Io(io::Error::from(io::ErrorKind::WriteZero))),
            Ok(n) => offset += n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                wait_fd(fd, PollFlags::POLLOUT, deadline)?;
            }
            Err(error) => return Err(Error::Io(error)),
        }
    }
    Ok(())
}

pub(crate) fn read_frame(
    fd: BorrowedFd<'_>,
    limits: &Limits,
    timeout_ms: u64,
) -> Result<Frame, Error> {
    let deadline = deadline_after(timeout_ms)?;
    let mut reader = FrameReader::new();
    let mut chunk = vec![0u8; limits.read_chunk_bytes.max(1)];
    loop {
        let want = reader.bytes_needed().min(chunk.len());
        match sys::recv(fd, &mut chunk[..want]) {
            Ok(Some(0)) => return Err(protocol("connection closed before reply")),
            Ok(Some(n)) => {
                let now = sys::clock_monotonic_ms()?;
                let used = reader.append(&chunk[..n], now, limits);
                if used != n {
                    return Err(protocol("frame reader rejected socket bytes"));
                }
                if reader.has_fatal() {
                    return Err(protocol("malformed frame header"));
                }
                if reader.frame_ready() {
                    return reader
                        .take_frame(limits)
                        .map_err(|_| protocol("malformed frame body"))?
                        .ok_or_else(|| protocol("complete frame disappeared"));
                }
            }
            Ok(None) => {
                wait_fd(fd, PollFlags::POLLIN, deadline)?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                wait_fd(fd, PollFlags::POLLIN, deadline)?;
            }
            Err(error) => return Err(Error::Io(error)),
        }
    }
}

pub(crate) fn control(
    session: &SessionDir,
    request: &Frame,
    limits: &Limits,
    timeout_ms: u64,
) -> Result<Frame, Error> {
    let fd = connect(session, timeout_ms)?;
    send_frame(fd.as_fd(), request, timeout_ms)?;
    read_frame(fd.as_fd(), limits, timeout_ms)
}

fn hello_dimensions(config: &AttachConfig<'_>) -> Result<(u16, u16, bool), Error> {
    if config.role == Role::Observer {
        if config.take_over {
            return Err(protocol("observer cannot request takeover"));
        }
        return Ok((0, 0, false));
    }
    let tty = sys::is_terminal(config.stdin);
    match config.size {
        SizeMode::Initial { rows, cols } => {
            if !tty || rows == 0 || cols == 0 {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "initial writer requires a real nonzero TTY size",
                )));
            }
            Ok((rows, cols, true))
        }
        SizeMode::Existing if tty => {
            let (rows, cols) = sys::get_winsize(config.stdin)?;
            if rows == 0 || cols == 0 {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "TTY dimensions must be nonzero",
                )));
            }
            Ok((rows, cols, true))
        }
        SizeMode::Existing => Ok((0, 0, false)),
    }
}

fn validate_hello_reply(frame: Frame, role: Role) -> Result<(), Error> {
    match frame {
        Frame::HelloAck {
            client_id,
            broker_protocol_version,
            status,
        } if client_id != 0
            && broker_protocol_version == PROTOCOL_VERSION
            && matches!(
                (role, status),
                (Role::Writer, AttachStatus::WriterGranted)
                    | (Role::Observer, AttachStatus::ObserverAccepted)
            ) =>
        {
            Ok(())
        }
        Frame::Busy { current_writer_id } if role == Role::Writer => {
            if current_writer_id == 0 {
                Err(protocol("Busy named an invalid writer"))
            } else {
                Err(Error::Busy { current_writer_id })
            }
        }
        Frame::Error { .. } => Err(protocol("broker rejected Hello")),
        Frame::HelloAck { .. } => Err(protocol("invalid HelloAck")),
        _ => Err(protocol("unexpected Hello reply")),
    }
}

enum LoopResult {
    Outcome(AttachOutcome),
    FatalSignal(i32),
}

#[derive(Clone, Copy)]
enum PollOwner {
    Socket,
    Signals,
    Stdin,
    Stdout,
}

fn queue_resize(queue: &mut OutQueue, rows: u16, cols: u16) -> Result<(), Error> {
    if rows == 0 || cols == 0 {
        return Err(protocol("zero terminal resize"));
    }
    if !queue.push_frame(&Frame::Resize { rows, cols }) {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "attach socket queue limit reached",
        )));
    }
    Ok(())
}

fn handle_frame(
    frame: Frame,
    writer: &mut bool,
    revoked: &mut bool,
    terminal: &mut Option<TerminalGuard<'_>>,
    stdin_flags: &mut Option<sys::NonblockingGuard<'_>>,
    socket_out: &mut OutQueue,
    stdout_pending: &mut Option<(Vec<u8>, usize)>,
) -> Result<Option<AttachOutcome>, Error> {
    match frame {
        Frame::Output(bytes) => {
            if stdout_pending.is_some() {
                return Err(protocol("Output arrived before prior Output drained"));
            }
            if !bytes.is_empty() {
                *stdout_pending = Some((bytes, 0));
            }
            Ok(None)
        }
        Frame::Ownership(OwnershipEvent::Granted) if *writer => Ok(None),
        Frame::Ownership(OwnershipEvent::Revoked) if *writer => {
            socket_out.clear();
            *writer = false;
            *revoked = true;
            if let Some(terminal) = terminal.as_mut() {
                terminal.restore()?;
            }
            if let Some(flags) = stdin_flags.as_mut() {
                flags.restore()?;
            }
            Ok(None)
        }
        Frame::Exit {
            signal: false,
            value,
        } if value <= u8::MAX as u32 => Ok(Some(AttachOutcome::ChildExited(value as u8))),
        Frame::Exit {
            signal: true,
            value,
        } if (1..=64).contains(&value) => Ok(Some(AttachOutcome::ChildSignaled(value as i32))),
        Frame::Error { .. } => Err(protocol("broker reported a protocol error")),
        Frame::Exit { .. } => Err(protocol("invalid Exit value")),
        _ => Err(protocol("unexpected attached-session frame")),
    }
}

#[allow(clippy::too_many_arguments)]
fn run_loop(
    socket: BorrowedFd<'_>,
    config: &AttachConfig<'_>,
    signals: &sys::AttachSignals,
    terminal: &mut Option<TerminalGuard<'_>>,
    stdin_flags: &mut Option<sys::NonblockingGuard<'_>>,
    mut writer: bool,
    tty_writer: bool,
    mut last_size: Option<(u16, u16)>,
) -> Result<LoopResult, Error> {
    let max_input = config
        .limits
        .read_chunk_bytes
        .min(config.limits.frame_max_body.saturating_sub(2))
        .min(
            config
                .limits
                .writer_input_queue_bytes
                .saturating_sub(crate::frame::HEADER_LEN),
        )
        .max(1);
    let mut stdin_buf = vec![0u8; max_input];
    let mut socket_buf = vec![0u8; config.limits.read_chunk_bytes.max(1)];
    let mut reader = FrameReader::new();
    let mut socket_out = OutQueue::new(config.limits.writer_input_queue_bytes);
    let mut stdout_pending: Option<(Vec<u8>, usize)> = None;
    let mut revoked = false;

    loop {
        let mut pfds = Vec::with_capacity(4);
        let mut owners = Vec::with_capacity(4);
        let mut socket_events = PollFlags::empty();
        if stdout_pending.is_none() {
            socket_events |= PollFlags::POLLIN;
        }
        if !socket_out.is_empty() {
            socket_events |= PollFlags::POLLOUT;
        }
        pfds.push(PollFd::new(socket, socket_events));
        owners.push(PollOwner::Socket);
        pfds.push(PollFd::new(signals.fd(), PollFlags::POLLIN));
        owners.push(PollOwner::Signals);
        if writer
            && socket_out
                .live_bytes()
                .saturating_add(max_input + crate::frame::HEADER_LEN)
                <= socket_out.cap_bytes()
        {
            pfds.push(PollFd::new(config.stdin, PollFlags::POLLIN));
            owners.push(PollOwner::Stdin);
        }
        if stdout_pending.is_some() {
            pfds.push(PollFd::new(config.stdout, PollFlags::POLLOUT));
            owners.push(PollOwner::Stdout);
        }
        let poll_timeout = if let Some(started) = reader.started_ms() {
            let deadline = started.saturating_add(config.limits.incomplete_frame_deadline_ms);
            let remaining = remaining_ms(deadline)?;
            if remaining == 0 {
                return Err(timeout("attached-session frame deadline expired"));
            }
            Some(remaining)
        } else {
            None
        };
        match sys::poll(&mut pfds, poll_timeout) {
            Ok(0) => return Err(timeout("attached-session frame deadline expired")),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Error::Io(error)),
        }
        let events: Vec<(PollOwner, PollFlags)> = pfds
            .iter()
            .zip(&owners)
            .map(|(pfd, owner)| (*owner, pfd.revents().unwrap_or(PollFlags::empty())))
            .collect();
        drop(pfds);
        drop(owners);

        // Socket frames are handled before CONT so a queued Revoked event can
        // demote the old writer before any raw-mode re-entry or Resize.
        if let Some((_, revents)) = events
            .iter()
            .find(|(owner, _)| matches!(owner, PollOwner::Socket))
        {
            // Read ownership/terminal frames before attempting a queued
            // writer send. If takeover Revoked is already readable, the old
            // writer discards every unsent Input/Resize byte first.
            if revents.intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR)
                && stdout_pending.is_none()
            {
                let want = reader.bytes_needed().min(socket_buf.len());
                match sys::recv(socket, &mut socket_buf[..want]) {
                    Ok(Some(0)) => {
                        if reader.has_partial_frame() {
                            return Err(protocol("truncated frame at socket EOF"));
                        }
                        return Err(Error::NotLive);
                    }
                    Ok(Some(n)) => {
                        let now = sys::clock_monotonic_ms()?;
                        if reader.append(&socket_buf[..n], now, &config.limits) != n
                            || reader.has_fatal()
                        {
                            return Err(protocol("malformed attached-session frame"));
                        }
                        if reader.frame_ready() {
                            let frame = reader
                                .take_frame(&config.limits)
                                .map_err(|_| protocol("malformed attached-session frame"))?
                                .ok_or_else(|| protocol("complete frame disappeared"))?;
                            if let Some(outcome) = handle_frame(
                                frame,
                                &mut writer,
                                &mut revoked,
                                terminal,
                                stdin_flags,
                                &mut socket_out,
                                &mut stdout_pending,
                            )? {
                                return Ok(LoopResult::Outcome(outcome));
                            }
                        }
                    }
                    Ok(None) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(Error::Io(error)),
                }
            }
            if revents.contains(PollFlags::POLLOUT) && !socket_out.is_empty() {
                match socket_out.flush_with(|bytes| sys::send_no_sigpipe(socket, bytes)) {
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(Error::Io(error)),
                }
            }
        }

        if let Some((_, revents)) = events
            .iter()
            .find(|(owner, _)| matches!(owner, PollOwner::Stdout))
        {
            if revents.contains(PollFlags::POLLOUT) {
                if let Some((bytes, offset)) = stdout_pending.as_mut() {
                    match sys::write_fd(config.stdout, &bytes[*offset..]) {
                        Ok(0) => return Err(Error::Io(io::Error::from(io::ErrorKind::WriteZero))),
                        Ok(n) => {
                            *offset += n;
                            if *offset == bytes.len() {
                                stdout_pending = None;
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                        Err(error) => return Err(Error::Io(error)),
                    }
                }
            } else if revents.intersects(PollFlags::POLLERR | PollFlags::POLLHUP) {
                return Err(Error::Io(io::Error::from_raw_os_error(libc::EPIPE)));
            }
        }

        if let Some((_, revents)) = events
            .iter()
            .find(|(owner, _)| matches!(owner, PollOwner::Signals))
        {
            if revents.contains(PollFlags::POLLIN) {
                while let Some(signal) = sys::read_signalfd(signals.fd())? {
                    match signal {
                        libc::SIGINT | libc::SIGTERM | libc::SIGHUP | libc::SIGQUIT => {
                            return Ok(LoopResult::FatalSignal(signal));
                        }
                        libc::SIGTSTP => {
                            if let Some(terminal) = terminal.as_mut() {
                                terminal.restore()?;
                            }
                            signals.suspend()?;
                        }
                        libc::SIGCONT if writer && tty_writer => {
                            if let Some(terminal) = terminal.as_mut() {
                                terminal.enter_raw()?;
                            }
                            let (rows, cols) = sys::get_winsize(config.stdin)?;
                            queue_resize(&mut socket_out, rows, cols)?;
                            last_size = Some((rows, cols));
                        }
                        libc::SIGWINCH if writer && tty_writer => {
                            let (rows, cols) = sys::get_winsize(config.stdin)?;
                            if last_size != Some((rows, cols)) {
                                queue_resize(&mut socket_out, rows, cols)?;
                                last_size = Some((rows, cols));
                            }
                        }
                        libc::SIGCONT | libc::SIGWINCH => {}
                        _ => return Err(protocol("unexpected attach signal")),
                    }
                }
            }
        }

        if writer {
            if let Some((_, revents)) = events
                .iter()
                .find(|(owner, _)| matches!(owner, PollOwner::Stdin))
            {
                if revents.contains(PollFlags::POLLIN) {
                    match sys::read_fd(config.stdin, &mut stdin_buf) {
                        Ok(0) => return Ok(LoopResult::Outcome(AttachOutcome::Detached)),
                        Ok(n) => {
                            if !socket_out.push_frame(&Frame::Input(stdin_buf[..n].to_vec())) {
                                return Err(Error::Io(io::Error::new(
                                    io::ErrorKind::OutOfMemory,
                                    "attach input queue limit reached",
                                )));
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                        Err(error) => return Err(Error::Io(error)),
                    }
                } else if revents.intersects(PollFlags::POLLERR | PollFlags::POLLHUP) {
                    return Ok(LoopResult::Outcome(AttachOutcome::Detached));
                }
            }
        }
    }
}

fn prepare_attach(config: &AttachConfig<'_>) -> Result<(u16, u16, bool), Error> {
    sys::validate_fd(config.stdout)?;
    if config.role == Role::Writer {
        sys::validate_fd(config.stdin)?;
    }
    if config.session.name() != config.name {
        return Err(protocol("session capability/name mismatch"));
    }
    if config.limits.read_chunk_bytes == 0
        || config.limits.frame_max_body < 3
        || config.limits.writer_input_queue_bytes <= crate::frame::HEADER_LEN
    {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "attach limits cannot carry one input byte",
        )));
    }
    hello_dimensions(config)
}

fn attach_connected_with_reraise(
    config: AttachConfig<'_>,
    socket: OwnedFd,
    dimensions: (u16, u16, bool),
    reraise: impl FnOnce(i32) -> io::Result<()>,
) -> Result<AttachOutcome, Error> {
    let (rows, cols, tty_writer) = dimensions;
    let hello = Frame::Hello {
        role: config.role,
        take_over: config.take_over,
        name: config.name.to_owned(),
        rows,
        cols,
    };
    send_frame(
        socket.as_fd(),
        &hello,
        config.limits.incomplete_frame_deadline_ms,
    )?;
    let reply = read_frame(
        socket.as_fd(),
        &config.limits,
        config.limits.incomplete_frame_deadline_ms,
    )?;
    validate_hello_reply(reply, config.role)?;

    let signals = sys::attach_signals()?;
    let shared_io_object = if config.role == Role::Writer {
        let stdin_stat = sys::fstat_fd(config.stdin)?;
        let stdout_stat = sys::fstat_fd(config.stdout)?;
        config.stdin.as_raw_fd() == config.stdout.as_raw_fd()
            || (stdin_stat.st_dev == stdout_stat.st_dev && stdin_stat.st_ino == stdout_stat.st_ino)
    } else {
        false
    };
    // A blocking stdin is safe behind this single-threaded poll loop. When
    // stdin/stdout are duplicate terminal descriptions, keep one stdout-side
    // guard so immediate revocation restoration cannot accidentally make
    // observer output blocking or restore a stale duplicate snapshot.
    let mut stdin_flags = if config.role == Role::Writer && !shared_io_object {
        Some(sys::NonblockingGuard::new(config.stdin)?)
    } else {
        None
    };
    let mut stdout_flags = Some(sys::NonblockingGuard::new(config.stdout)?);
    let mut terminal = if tty_writer {
        Some(TerminalGuard::new(config.stdin)?)
    } else {
        None
    };

    let result = run_loop(
        socket.as_fd(),
        &config,
        &signals,
        &mut terminal,
        &mut stdin_flags,
        config.role == Role::Writer,
        tty_writer,
        (rows != 0 && cols != 0).then_some((rows, cols)),
    );

    // Restoration order is deliberate: termios and fd flags precede signal
    // unmasking. The socket closes before any local fatal signal is re-raised.
    let terminal_result = terminal.as_mut().map(TerminalGuard::restore).transpose();
    let stdin_result = stdin_flags
        .as_mut()
        .map(sys::NonblockingGuard::restore)
        .transpose();
    let stdout_result = stdout_flags
        .as_mut()
        .map(sys::NonblockingGuard::restore)
        .transpose();
    drop(socket);
    terminal_result?;
    stdin_result?;
    stdout_result?;

    match result? {
        LoopResult::Outcome(outcome) => Ok(outcome),
        LoopResult::FatalSignal(signal) => {
            drop(signals);
            let _ = reraise(signal);
            Ok(AttachOutcome::LocalSignaled(signal))
        }
    }
}

fn attach_connected(
    config: AttachConfig<'_>,
    socket: OwnedFd,
    dimensions: (u16, u16, bool),
) -> Result<AttachOutcome, Error> {
    attach_connected_with_reraise(config, socket, dimensions, sys::reraise_default)
}

/// Connects, performs Hello, and runs one typed attachment to completion.
pub fn attach(config: AttachConfig<'_>) -> Result<AttachOutcome, Error> {
    let dimensions = prepare_attach(&config)?;
    let socket = connect(config.session, config.limits.incomplete_frame_deadline_ms)?;
    attach_connected(config, socket, dimensions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::unix::fs::DirBuilderExt;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use crate::session::resolve_state_root_from;

    static FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct SessionFixture {
        base: std::path::PathBuf,
        session: SessionDir,
    }

    impl SessionFixture {
        fn new(name: &str) -> Self {
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            let base = loop {
                let n = FIXTURE.fetch_add(1, Ordering::Relaxed);
                let base =
                    std::env::temp_dir().join(format!("everpty-attach-{}-{n}", std::process::id()));
                match builder.create(&base) {
                    Ok(()) => break base,
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("fixture: {error}"),
                }
            };
            let root_path = base.join("state");
            let root = resolve_state_root_from(std::slice::from_ref(&root_path)).expect("root");
            let session = root.session(name, &Limits::default()).expect("session");
            Self { base, session }
        }
    }

    impl Drop for SessionFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    fn recv_test_frame(stream: &mut File, limits: &Limits) -> Frame {
        let mut header = [0u8; crate::frame::HEADER_LEN];
        stream.read_exact(&mut header).expect("frame header");
        let total = Frame::validate_header(&header, limits).expect("valid header");
        let mut encoded = header.to_vec();
        encoded.resize(total, 0);
        stream
            .read_exact(&mut encoded[crate::frame::HEADER_LEN..])
            .expect("frame body");
        Frame::decode(&encoded, limits).expect("decode").0
    }

    fn send_test_frame(stream: &mut File, frame: &Frame) {
        stream.write_all(&frame.encode()).expect("send frame");
    }

    fn status_flags(fd: BorrowedFd<'_>) -> i32 {
        nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFL).expect("status flags")
    }

    #[test]
    fn writer_forwards_arbitrary_bytes_and_restores_fd_flags_and_mask() {
        let _signal_serial = sys::SIGNAL_TEST_LOCK.lock().expect("signal test lock");
        let fixture = SessionFixture::new("bytes");
        let limits = Limits::default();
        let (client, server) = sys::socketpair_cloexec().expect("socketpair");
        sys::set_nonblocking(client.as_fd()).expect("client nonblocking");
        let (stdin_read, stdin_write) = sys::pipe_cloexec().expect("stdin pipe");
        let (stdout_read, stdout_write) = sys::pipe_cloexec().expect("stdout pipe");
        let input = vec![0, 0xff, b'\r', b'\n', 0x1b, b'[', b'3'];
        let output = vec![0xff, 0, b'\n', b'\r', 0x1b, b']', b'x'];
        let mut input_writer = File::from(stdin_write);
        input_writer.write_all(&input).expect("input");
        let stdin_before = status_flags(stdin_read.as_fd());
        let stdout_before = status_flags(stdout_write.as_fd());
        let mask_before = sys::current_signal_mask().expect("signal mask");

        let expected_input = input.clone();
        let expected_output = output.clone();
        let server_thread = std::thread::spawn(move || {
            let mut stream = File::from(server);
            assert!(matches!(
                recv_test_frame(&mut stream, &limits),
                Frame::Hello {
                    role: Role::Writer,
                    rows: 0,
                    cols: 0,
                    ..
                }
            ));
            send_test_frame(
                &mut stream,
                &Frame::HelloAck {
                    client_id: 1,
                    broker_protocol_version: PROTOCOL_VERSION,
                    status: AttachStatus::WriterGranted,
                },
            );
            assert_eq!(
                recv_test_frame(&mut stream, &limits),
                Frame::Input(expected_input)
            );
            send_test_frame(&mut stream, &Frame::Output(expected_output));
            send_test_frame(
                &mut stream,
                &Frame::Exit {
                    signal: false,
                    value: 23,
                },
            );
        });

        let config = AttachConfig {
            session: &fixture.session,
            name: "bytes",
            role: Role::Writer,
            take_over: false,
            size: SizeMode::Existing,
            stdin: stdin_read.as_fd(),
            stdout: stdout_write.as_fd(),
            limits,
        };
        let dimensions = prepare_attach(&config).expect("prepare");
        let outcome = attach_connected(config, client, dimensions).expect("attach");
        assert_eq!(outcome, AttachOutcome::ChildExited(23));
        server_thread.join().expect("server");
        assert_eq!(status_flags(stdin_read.as_fd()), stdin_before);
        assert_eq!(status_flags(stdout_write.as_fd()), stdout_before);
        assert_eq!(
            sys::current_signal_mask().expect("signal mask"),
            mask_before
        );
        drop(stdout_write);
        let mut got = Vec::new();
        File::from(stdout_read)
            .read_to_end(&mut got)
            .expect("stdout");
        assert_eq!(got, output);
    }

    #[test]
    fn tty_writer_restores_termios_after_child_exit() {
        let _signal_serial = sys::SIGNAL_TEST_LOCK.lock().expect("signal test lock");
        let fixture = SessionFixture::new("tty");
        let limits = Limits::default();
        let (client, server) = sys::socketpair_cloexec().expect("socketpair");
        sys::set_nonblocking(client.as_fd()).expect("client nonblocking");
        let (_master, slave) = sys::openpty(31, 97).expect("pty");
        let stdout = slave.try_clone().expect("stdout duplicate");
        let before = sys::terminal_attributes(slave.as_fd()).expect("termios");
        let flags_before = status_flags(slave.as_fd());
        let stdout_flags_before = status_flags(stdout.as_fd());
        let server_thread = std::thread::spawn(move || {
            let mut stream = File::from(server);
            assert!(matches!(
                recv_test_frame(&mut stream, &limits),
                Frame::Hello {
                    role: Role::Writer,
                    rows: 31,
                    cols: 97,
                    ..
                }
            ));
            send_test_frame(
                &mut stream,
                &Frame::HelloAck {
                    client_id: 2,
                    broker_protocol_version: PROTOCOL_VERSION,
                    status: AttachStatus::WriterGranted,
                },
            );
            send_test_frame(
                &mut stream,
                &Frame::Exit {
                    signal: false,
                    value: 0,
                },
            );
        });
        let config = AttachConfig {
            session: &fixture.session,
            name: "tty",
            role: Role::Writer,
            take_over: false,
            size: SizeMode::Existing,
            stdin: slave.as_fd(),
            stdout: stdout.as_fd(),
            limits,
        };
        let dimensions = prepare_attach(&config).expect("prepare");
        assert_eq!(
            attach_connected(config, client, dimensions).expect("attach"),
            AttachOutcome::ChildExited(0)
        );
        server_thread.join().expect("server");
        let after = sys::terminal_attributes(slave.as_fd()).expect("termios restored");
        assert!(before == after, "termios changed across attach");
        assert_eq!(status_flags(slave.as_fd()), flags_before);
        assert_eq!(status_flags(stdout.as_fd()), stdout_flags_before);
    }

    #[test]
    fn winch_is_changed_only_and_cont_sends_a_fresh_resize() {
        let _signal_serial = sys::SIGNAL_TEST_LOCK.lock().expect("signal test lock");
        let fixture = SessionFixture::new("resize");
        let limits = Limits::default();
        let (client, server) = sys::socketpair_cloexec().expect("socketpair");
        sys::set_nonblocking(client.as_fd()).expect("client nonblocking");
        let (_master, slave) = sys::openpty(24, 80).expect("pty");
        let slave_probe = slave.try_clone().expect("probe fd");
        let (stdout_read, stdout_write) = sys::pipe_cloexec().expect("stdout pipe");
        let original = sys::terminal_attributes(slave.as_fd()).expect("termios");
        let probe_original = original.clone();
        let target = sys::current_thread_id();
        let server_thread = std::thread::spawn(move || {
            let mut stream = File::from(server);
            let hello = recv_test_frame(&mut stream, &limits);
            assert!(matches!(
                hello,
                Frame::Hello {
                    rows: 24,
                    cols: 80,
                    ..
                }
            ));
            send_test_frame(
                &mut stream,
                &Frame::HelloAck {
                    client_id: 3,
                    broker_protocol_version: PROTOCOL_VERSION,
                    status: AttachStatus::WriterGranted,
                },
            );
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let now = sys::terminal_attributes(slave_probe.as_fd()).expect("probe termios");
                if now != probe_original {
                    break;
                }
                assert!(Instant::now() < deadline, "client did not enter raw mode");
                std::thread::sleep(Duration::from_millis(1));
            }
            sys::set_winsize(slave_probe.as_fd(), 40, 100).expect("winsize");
            sys::signal_thread(target, libc::SIGWINCH).expect("WINCH");
            assert_eq!(
                recv_test_frame(&mut stream, &limits),
                Frame::Resize {
                    rows: 40,
                    cols: 100
                }
            );

            sys::signal_thread(target, libc::SIGWINCH).expect("duplicate WINCH");
            let mut poll = [PollFd::new(stream.as_fd(), PollFlags::POLLIN)];
            assert_eq!(sys::poll(&mut poll, Some(40)).expect("dedupe poll"), 0);

            sys::signal_thread(target, libc::SIGCONT).expect("CONT");
            assert_eq!(
                recv_test_frame(&mut stream, &limits),
                Frame::Resize {
                    rows: 40,
                    cols: 100
                }
            );
            send_test_frame(
                &mut stream,
                &Frame::Exit {
                    signal: false,
                    value: 0,
                },
            );
        });
        let config = AttachConfig {
            session: &fixture.session,
            name: "resize",
            role: Role::Writer,
            take_over: false,
            size: SizeMode::Existing,
            stdin: slave.as_fd(),
            stdout: stdout_write.as_fd(),
            limits,
        };
        let dimensions = prepare_attach(&config).expect("prepare");
        assert_eq!(
            attach_connected(config, client, dimensions).expect("attach"),
            AttachOutcome::ChildExited(0)
        );
        server_thread.join().expect("server");
        assert!(
            sys::terminal_attributes(slave.as_fd()).expect("restored") == original,
            "CONT/WINCH path did not restore termios"
        );
        drop(stdout_write);
        drop(stdout_read);
    }

    #[test]
    fn truncated_post_hello_frame_is_protocol_failure_with_flags_restored() {
        let _signal_serial = sys::SIGNAL_TEST_LOCK.lock().expect("signal test lock");
        let fixture = SessionFixture::new("truncated");
        let limits = Limits {
            incomplete_frame_deadline_ms: 50,
            ..Limits::default()
        };
        let (client, server) = sys::socketpair_cloexec().expect("socketpair");
        sys::set_nonblocking(client.as_fd()).expect("client nonblocking");
        let (stdin_read, _stdin_write) = sys::pipe_cloexec().expect("stdin pipe");
        let (stdout_read, stdout_write) = sys::pipe_cloexec().expect("stdout pipe");
        let stdin_before = status_flags(stdin_read.as_fd());
        let stdout_before = status_flags(stdout_write.as_fd());
        let mask_before = sys::current_signal_mask().expect("mask");
        let server_thread = std::thread::spawn(move || {
            let mut stream = File::from(server);
            let _ = recv_test_frame(&mut stream, &limits);
            send_test_frame(
                &mut stream,
                &Frame::HelloAck {
                    client_id: 4,
                    broker_protocol_version: PROTOCOL_VERSION,
                    status: AttachStatus::WriterGranted,
                },
            );
            stream.write_all(&[0, 0, 0]).expect("partial header");
            std::thread::sleep(Duration::from_millis(100));
        });
        let config = AttachConfig {
            session: &fixture.session,
            name: "truncated",
            role: Role::Writer,
            take_over: false,
            size: SizeMode::Existing,
            stdin: stdin_read.as_fd(),
            stdout: stdout_write.as_fd(),
            limits,
        };
        let dimensions = prepare_attach(&config).expect("prepare");
        assert!(matches!(
            attach_connected(config, client, dimensions),
            Err(Error::Io(ref error)) if error.kind() == io::ErrorKind::TimedOut
        ));
        server_thread.join().expect("server");
        assert_eq!(status_flags(stdin_read.as_fd()), stdin_before);
        assert_eq!(status_flags(stdout_write.as_fd()), stdout_before);
        assert_eq!(sys::current_signal_mask().expect("mask"), mask_before);
        drop(stdout_write);
        drop(stdout_read);
    }

    #[test]
    fn semantic_post_hello_failure_restores_termios_mask_and_flags() {
        let _signal_serial = sys::SIGNAL_TEST_LOCK.lock().expect("signal test lock");
        let fixture = SessionFixture::new("semantic");
        let limits = Limits::default();
        let (client, server) = sys::socketpair_cloexec().expect("socketpair");
        sys::set_nonblocking(client.as_fd()).expect("client nonblocking");
        let (_master, slave) = sys::openpty(32, 101).expect("pty");
        let stdout = slave.try_clone().expect("stdout");
        let termios_before = sys::terminal_attributes(slave.as_fd()).expect("termios");
        let stdin_before = status_flags(slave.as_fd());
        let stdout_before = status_flags(stdout.as_fd());
        let mask_before = sys::current_signal_mask().expect("mask");
        let server_thread = std::thread::spawn(move || {
            let mut stream = File::from(server);
            let _ = recv_test_frame(&mut stream, &limits);
            send_test_frame(
                &mut stream,
                &Frame::HelloAck {
                    client_id: 5,
                    broker_protocol_version: PROTOCOL_VERSION,
                    status: AttachStatus::WriterGranted,
                },
            );
            send_test_frame(&mut stream, &Frame::Pong);
        });
        let config = AttachConfig {
            session: &fixture.session,
            name: "semantic",
            role: Role::Writer,
            take_over: false,
            size: SizeMode::Existing,
            stdin: slave.as_fd(),
            stdout: stdout.as_fd(),
            limits,
        };
        let dimensions = prepare_attach(&config).expect("prepare");
        assert!(matches!(
            attach_connected(config, client, dimensions),
            Err(Error::Protocol(_))
        ));
        server_thread.join().expect("server");
        assert!(
            sys::terminal_attributes(slave.as_fd()).expect("termios") == termios_before,
            "semantic error did not restore termios"
        );
        assert_eq!(status_flags(slave.as_fd()), stdin_before);
        assert_eq!(status_flags(stdout.as_fd()), stdout_before);
        assert_eq!(sys::current_signal_mask().expect("mask"), mask_before);
    }

    #[test]
    fn exit_value_validation_is_strict() {
        let mut writer = true;
        let mut revoked = false;
        let mut terminal = None;
        let mut stdin_flags = None;
        let mut queue = OutQueue::new(1024);
        let mut stdout = None;
        assert!(matches!(
            handle_frame(
                Frame::Exit {
                    signal: false,
                    value: 255,
                },
                &mut writer,
                &mut revoked,
                &mut terminal,
                &mut stdin_flags,
                &mut queue,
                &mut stdout,
            ),
            Ok(Some(AttachOutcome::ChildExited(255)))
        ));
        assert!(handle_frame(
            Frame::Exit {
                signal: false,
                value: 256,
            },
            &mut writer,
            &mut revoked,
            &mut terminal,
            &mut stdin_flags,
            &mut queue,
            &mut stdout,
        )
        .is_err());
    }

    #[test]
    fn hello_semantics_fail_closed_and_busy_remains_typed() {
        assert!(matches!(
            validate_hello_reply(
                Frame::Busy {
                    current_writer_id: 9
                },
                Role::Writer,
            ),
            Err(Error::Busy {
                current_writer_id: 9
            })
        ));
        assert!(matches!(
            validate_hello_reply(
                Frame::HelloAck {
                    client_id: 1,
                    broker_protocol_version: PROTOCOL_VERSION + 1,
                    status: AttachStatus::WriterGranted,
                },
                Role::Writer,
            ),
            Err(Error::Protocol(_))
        ));
        assert!(matches!(
            validate_hello_reply(
                Frame::HelloAck {
                    client_id: 1,
                    broker_protocol_version: PROTOCOL_VERSION,
                    status: AttachStatus::ObserverAccepted,
                },
                Role::Writer,
            ),
            Err(Error::Protocol(_))
        ));
        assert!(matches!(
            validate_hello_reply(
                Frame::Busy {
                    current_writer_id: 0
                },
                Role::Writer,
            ),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn revocation_discards_every_queued_writer_frame() {
        let mut writer = true;
        let mut revoked = false;
        let mut terminal = None;
        let mut stdin_flags = None;
        let mut queue = OutQueue::new(1024);
        assert!(queue.push_frame(&Frame::Input(vec![1, 2, 3])));
        assert!(queue.push_frame(&Frame::Resize { rows: 2, cols: 3 }));
        let mut stdout = None;
        assert!(handle_frame(
            Frame::Ownership(OwnershipEvent::Revoked),
            &mut writer,
            &mut revoked,
            &mut terminal,
            &mut stdin_flags,
            &mut queue,
            &mut stdout,
        )
        .expect("revoke")
        .is_none());
        assert!(!writer);
        assert!(revoked);
        assert!(queue.is_empty());
    }

    #[test]
    fn revocation_preempts_stdin_from_the_same_poll_result() {
        let _signal_serial = sys::SIGNAL_TEST_LOCK.lock().expect("signal test lock");
        let fixture = SessionFixture::new("same-poll-revoke");
        let limits = Limits::default();
        let (client, server) = sys::socketpair_cloexec().expect("socketpair");
        sys::set_nonblocking(client.as_fd()).expect("client nonblocking");
        let (stdin_read, stdin_write) = sys::pipe_cloexec().expect("stdin pipe");
        let (stdout_read, stdout_write) = sys::pipe_cloexec().expect("stdout pipe");
        let mut input_writer = File::from(stdin_write);
        input_writer
            .write_all(b"must-not-send")
            .expect("queued stdin");
        let stdin_before = status_flags(stdin_read.as_fd());
        let stdout_before = status_flags(stdout_write.as_fd());
        let mask_before = sys::current_signal_mask().expect("mask");

        let server_thread = std::thread::spawn(move || {
            let mut stream = File::from(server);
            let _ = recv_test_frame(&mut stream, &limits);
            let wire = [
                Frame::HelloAck {
                    client_id: 7,
                    broker_protocol_version: PROTOCOL_VERSION,
                    status: AttachStatus::WriterGranted,
                }
                .encode(),
                Frame::Ownership(OwnershipEvent::Revoked).encode(),
            ]
            .concat();
            stream.write_all(&wire).expect("ack plus revoke");

            let mut poll = [PollFd::new(stream.as_fd(), PollFlags::POLLIN)];
            assert_eq!(
                sys::poll(&mut poll, Some(250)).expect("stale-input poll"),
                0,
                "a stdin event captured with Revoked sent old-writer input"
            );
            send_test_frame(&mut stream, &Frame::Output(b"future".to_vec()));
            send_test_frame(
                &mut stream,
                &Frame::Exit {
                    signal: false,
                    value: 0,
                },
            );
            let mut closed = [PollFd::new(
                stream.as_fd(),
                PollFlags::POLLIN | PollFlags::POLLHUP,
            )];
            assert_ne!(
                sys::poll(&mut closed, Some(2_000)).expect("client-close poll"),
                0,
                "revoked client did not close after Exit"
            );
            let mut stale = [0u8; 1];
            assert_eq!(
                stream.read(&mut stale).expect("post-Exit read"),
                0,
                "revoked client sent stale input after the no-input window"
            );
        });

        let config = AttachConfig {
            session: &fixture.session,
            name: "same-poll-revoke",
            role: Role::Writer,
            take_over: false,
            size: SizeMode::Existing,
            stdin: stdin_read.as_fd(),
            stdout: stdout_write.as_fd(),
            limits,
        };
        let dimensions = prepare_attach(&config).expect("prepare");
        assert_eq!(
            attach_connected(config, client, dimensions).expect("attach"),
            AttachOutcome::ChildExited(0)
        );
        server_thread.join().expect("server");
        assert_eq!(status_flags(stdin_read.as_fd()), stdin_before);
        assert_eq!(status_flags(stdout_write.as_fd()), stdout_before);
        assert_eq!(sys::current_signal_mask().expect("mask"), mask_before);
        drop((input_writer, stdout_write));
        let mut output = Vec::new();
        File::from(stdout_read)
            .read_to_end(&mut output)
            .expect("stdout");
        assert_eq!(output, b"future");
    }

    #[test]
    fn takeover_revocation_restores_immediately_and_cont_cannot_resize() {
        let _signal_serial = sys::SIGNAL_TEST_LOCK.lock().expect("signal test lock");
        let fixture = SessionFixture::new("takeover");
        let limits = Limits::default();
        let (client, server) = sys::socketpair_cloexec().expect("socketpair");
        sys::set_nonblocking(client.as_fd()).expect("client nonblocking");
        let (_master, slave) = sys::openpty(28, 93).expect("pty");
        let slave_probe = slave.try_clone().expect("probe");
        let stdout = slave.try_clone().expect("stdout");
        let original = sys::terminal_attributes(slave.as_fd()).expect("termios");
        let stdin_flags = status_flags(slave.as_fd());
        let stdout_flags = status_flags(stdout.as_fd());
        let mask = sys::current_signal_mask().expect("mask");
        let target = sys::current_thread_id();
        let expected_original = original.clone();

        let server_thread = std::thread::spawn(move || {
            let mut stream = File::from(server);
            assert!(matches!(
                recv_test_frame(&mut stream, &limits),
                Frame::Hello {
                    role: Role::Writer,
                    ..
                }
            ));
            send_test_frame(
                &mut stream,
                &Frame::HelloAck {
                    client_id: 8,
                    broker_protocol_version: PROTOCOL_VERSION,
                    status: AttachStatus::WriterGranted,
                },
            );
            let deadline = Instant::now() + Duration::from_secs(2);
            while sys::terminal_attributes(slave_probe.as_fd()).expect("raw probe")
                == expected_original
            {
                assert!(Instant::now() < deadline, "client did not enter raw mode");
                std::thread::sleep(Duration::from_millis(1));
            }

            send_test_frame(&mut stream, &Frame::Ownership(OwnershipEvent::Revoked));
            let deadline = Instant::now() + Duration::from_secs(2);
            while sys::terminal_attributes(slave_probe.as_fd()).expect("restore probe")
                != expected_original
            {
                assert!(
                    Instant::now() < deadline,
                    "revoked writer did not restore termios"
                );
                std::thread::sleep(Duration::from_millis(1));
            }

            sys::signal_thread(target, libc::SIGCONT).expect("CONT");
            let mut poll = [PollFd::new(stream.as_fd(), PollFlags::POLLIN)];
            assert_eq!(
                sys::poll(&mut poll, Some(50)).expect("post-CONT poll"),
                0,
                "revoked writer sent Input or Resize after CONT"
            );
            send_test_frame(&mut stream, &Frame::Output(b"future-only".to_vec()));
            send_test_frame(
                &mut stream,
                &Frame::Exit {
                    signal: false,
                    value: 0,
                },
            );
        });

        let config = AttachConfig {
            session: &fixture.session,
            name: "takeover",
            role: Role::Writer,
            take_over: false,
            size: SizeMode::Existing,
            stdin: slave.as_fd(),
            stdout: stdout.as_fd(),
            limits,
        };
        let dimensions = prepare_attach(&config).expect("prepare");
        assert_eq!(
            attach_connected(config, client, dimensions).expect("attach"),
            AttachOutcome::ChildExited(0)
        );
        server_thread.join().expect("server");
        assert!(
            sys::terminal_attributes(slave.as_fd()).expect("termios") == original,
            "takeover path did not restore exact termios"
        );
        assert_eq!(status_flags(slave.as_fd()), stdin_flags);
        assert_eq!(status_flags(stdout.as_fd()), stdout_flags);
        assert_eq!(sys::current_signal_mask().expect("mask"), mask);
    }

    #[test]
    fn post_revocation_socket_eof_is_operational_and_restores_exact_state() {
        let _signal_serial = sys::SIGNAL_TEST_LOCK.lock().expect("signal test lock");
        let fixture = SessionFixture::new("revoked-eof");
        let limits = Limits::default();
        let (client, server) = sys::socketpair_cloexec().expect("socketpair");
        sys::set_nonblocking(client.as_fd()).expect("client nonblocking");
        let (_master, slave) = sys::openpty(29, 94).expect("pty");
        let slave_probe = slave.try_clone().expect("termios probe");
        let (stdout_read, stdout_write) = sys::pipe_cloexec().expect("stdout pipe");
        let termios_before = sys::terminal_attributes(slave.as_fd()).expect("termios");
        let probe_before = termios_before.clone();
        let stdin_before = status_flags(slave.as_fd());
        let stdout_before = status_flags(stdout_write.as_fd());
        let mask_before = sys::current_signal_mask().expect("mask");

        let server_thread = std::thread::spawn(move || {
            let mut stream = File::from(server);
            let _ = recv_test_frame(&mut stream, &limits);
            send_test_frame(
                &mut stream,
                &Frame::HelloAck {
                    client_id: 9,
                    broker_protocol_version: PROTOCOL_VERSION,
                    status: AttachStatus::WriterGranted,
                },
            );
            let deadline = Instant::now() + Duration::from_secs(2);
            while sys::terminal_attributes(slave_probe.as_fd()).expect("raw probe") == probe_before
            {
                assert!(Instant::now() < deadline, "client did not enter raw mode");
                std::thread::sleep(Duration::from_millis(1));
            }
            send_test_frame(&mut stream, &Frame::Ownership(OwnershipEvent::Revoked));
            let deadline = Instant::now() + Duration::from_secs(2);
            while sys::terminal_attributes(slave_probe.as_fd()).expect("restore probe")
                != probe_before
            {
                assert!(
                    Instant::now() < deadline,
                    "revocation did not restore termios before EOF"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            // A clean close produces EOF/HUP without the required Exit frame.
        });

        let config = AttachConfig {
            session: &fixture.session,
            name: "revoked-eof",
            role: Role::Writer,
            take_over: false,
            size: SizeMode::Existing,
            stdin: slave.as_fd(),
            stdout: stdout_write.as_fd(),
            limits,
        };
        let dimensions = prepare_attach(&config).expect("prepare");
        assert!(matches!(
            attach_connected(config, client, dimensions),
            Err(Error::NotLive)
        ));
        server_thread.join().expect("server");
        assert!(
            sys::terminal_attributes(slave.as_fd()).expect("termios") == termios_before,
            "post-revocation EOF did not restore exact termios"
        );
        assert_eq!(status_flags(slave.as_fd()), stdin_before);
        assert_eq!(status_flags(stdout_write.as_fd()), stdout_before);
        assert_eq!(sys::current_signal_mask().expect("mask"), mask_before);
        drop((stdout_read, stdout_write));
    }

    #[test]
    fn stdout_epipe_restores_termios_mask_and_both_fd_statuses() {
        let _signal_serial = sys::SIGNAL_TEST_LOCK.lock().expect("signal test lock");
        let fixture = SessionFixture::new("epipe");
        let limits = Limits::default();
        let (client, server) = sys::socketpair_cloexec().expect("socketpair");
        sys::set_nonblocking(client.as_fd()).expect("client nonblocking");
        let (_master, slave) = sys::openpty(30, 95).expect("pty");
        let slave_probe = slave.try_clone().expect("termios probe");
        let (stdout_read, stdout_write) = sys::pipe_cloexec().expect("stdout pipe");
        drop(stdout_read);
        let termios_before = sys::terminal_attributes(slave.as_fd()).expect("termios");
        let probe_before = termios_before.clone();
        let stdin_before = status_flags(slave.as_fd());
        let stdout_before = status_flags(stdout_write.as_fd());
        let mask_before = sys::current_signal_mask().expect("mask");

        let server_thread = std::thread::spawn(move || {
            let mut stream = File::from(server);
            let _ = recv_test_frame(&mut stream, &limits);
            send_test_frame(
                &mut stream,
                &Frame::HelloAck {
                    client_id: 10,
                    broker_protocol_version: PROTOCOL_VERSION,
                    status: AttachStatus::WriterGranted,
                },
            );
            let deadline = Instant::now() + Duration::from_secs(2);
            while sys::terminal_attributes(slave_probe.as_fd()).expect("raw probe") == probe_before
            {
                assert!(Instant::now() < deadline, "client did not enter raw mode");
                std::thread::sleep(Duration::from_millis(1));
            }
            send_test_frame(&mut stream, &Frame::Output(b"broken stdout".to_vec()));
        });

        let config = AttachConfig {
            session: &fixture.session,
            name: "epipe",
            role: Role::Writer,
            take_over: false,
            size: SizeMode::Existing,
            stdin: slave.as_fd(),
            stdout: stdout_write.as_fd(),
            limits,
        };
        let dimensions = prepare_attach(&config).expect("prepare");
        assert!(matches!(
            attach_connected(config, client, dimensions),
            Err(Error::Io(ref error)) if error.raw_os_error() == Some(libc::EPIPE)
        ));
        server_thread.join().expect("server");
        assert!(
            sys::terminal_attributes(slave.as_fd()).expect("termios") == termios_before,
            "stdout EPIPE did not restore exact termios"
        );
        assert_eq!(status_flags(slave.as_fd()), stdin_before);
        assert_eq!(status_flags(stdout_write.as_fd()), stdout_before);
        assert_eq!(sys::current_signal_mask().expect("mask"), mask_before);
    }

    #[test]
    fn fatal_signal_cleanup_precedes_reraise_and_restores_exact_state() {
        let _signal_serial = sys::SIGNAL_TEST_LOCK.lock().expect("signal test lock");
        for (index, signal) in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT]
            .into_iter()
            .enumerate()
        {
            let name = format!("fatal-cleanup-{index}");
            let fixture = SessionFixture::new(&name);
            let limits = Limits::default();
            let (client, server) = sys::socketpair_cloexec().expect("socketpair");
            sys::set_nonblocking(client.as_fd()).expect("client nonblocking");
            let (_master, slave) = sys::openpty(31, 96).expect("pty");
            let slave_probe = slave.try_clone().expect("termios probe");
            let (stdout_read, stdout_write) = sys::pipe_cloexec().expect("stdout pipe");
            let termios_before = sys::terminal_attributes(slave.as_fd()).expect("termios");
            let probe_before = termios_before.clone();
            let stdin_before = status_flags(slave.as_fd());
            let stdout_before = status_flags(stdout_write.as_fd());
            let mask_before = sys::current_signal_mask().expect("mask");
            let target = sys::current_thread_id();

            let server_thread = std::thread::spawn(move || {
                let mut stream = File::from(server);
                let _ = recv_test_frame(&mut stream, &limits);
                send_test_frame(
                    &mut stream,
                    &Frame::HelloAck {
                        client_id: 20 + index as u32,
                        broker_protocol_version: PROTOCOL_VERSION,
                        status: AttachStatus::WriterGranted,
                    },
                );
                let deadline = Instant::now() + Duration::from_secs(2);
                while sys::terminal_attributes(slave_probe.as_fd()).expect("raw probe")
                    == probe_before
                {
                    assert!(Instant::now() < deadline, "client did not enter raw mode");
                    std::thread::sleep(Duration::from_millis(1));
                }
                sys::signal_thread(target, signal).expect("fatal attach signal");
                let mut byte = [0u8; 1];
                assert_eq!(stream.read(&mut byte).expect("socket close"), 0);
            });

            let config = AttachConfig {
                session: &fixture.session,
                name: &name,
                role: Role::Writer,
                take_over: false,
                size: SizeMode::Existing,
                stdin: slave.as_fd(),
                stdout: stdout_write.as_fd(),
                limits,
            };
            let dimensions = prepare_attach(&config).expect("prepare");
            let outcome = attach_connected_with_reraise(config, client, dimensions, |seen| {
                assert_eq!(seen, signal);
                assert!(
                    sys::terminal_attributes(slave.as_fd()).expect("termios") == termios_before
                );
                assert_eq!(status_flags(slave.as_fd()), stdin_before);
                assert_eq!(status_flags(stdout_write.as_fd()), stdout_before);
                assert_eq!(sys::current_signal_mask().expect("mask"), mask_before);
                Ok(())
            })
            .expect("fatal fallback outcome");
            assert_eq!(outcome, AttachOutcome::LocalSignaled(signal));
            server_thread.join().expect("server");
            assert!(sys::terminal_attributes(slave.as_fd()).expect("termios") == termios_before);
            assert_eq!(status_flags(slave.as_fd()), stdin_before);
            assert_eq!(status_flags(stdout_write.as_fd()), stdout_before);
            assert_eq!(sys::current_signal_mask().expect("mask"), mask_before);
            drop((stdout_read, stdout_write));
        }
    }

    #[test]
    fn tstp_cont_return_restores_termios_mask_and_both_fd_statuses() {
        let mut isolated = Command::new(std::env::current_exe().expect("unit-test executable"))
            .arg("--exact")
            .arg("attach::tests::tstp_cont_isolated_helper")
            .arg("--ignored")
            .arg("--test-threads=1")
            .spawn()
            .expect("spawn isolated TSTP/CONT test");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = isolated.try_wait().expect("isolated test status") {
                assert!(status.success(), "isolated TSTP/CONT test failed: {status}");
                break;
            }
            if Instant::now() >= deadline {
                let _ = isolated.kill();
                let _ = isolated.wait();
                panic!("isolated TSTP/CONT test exceeded its deadline");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    #[ignore = "executed in an isolated subprocess by tstp_cont_return_restores_termios_mask_and_both_fd_statuses"]
    fn tstp_cont_isolated_helper() {
        let _signal_serial = sys::SIGNAL_TEST_LOCK.lock().expect("signal test lock");
        let fixture = SessionFixture::new("tstp-cont-state");
        let limits = Limits::default();
        let (client, server) = sys::socketpair_cloexec().expect("socketpair");
        sys::set_nonblocking(client.as_fd()).expect("client nonblocking");
        let (_master, slave) = sys::openpty(32, 97).expect("pty");
        let slave_probe = slave.try_clone().expect("termios probe");
        let (stdout_read, stdout_write) = sys::pipe_cloexec().expect("stdout pipe");
        let termios_before = sys::terminal_attributes(slave.as_fd()).expect("termios");
        let probe_before = termios_before.clone();
        let stdin_before = status_flags(slave.as_fd());
        let stdout_before = status_flags(stdout_write.as_fd());
        let mask_before = sys::current_signal_mask().expect("mask");
        let target = sys::current_thread_id();

        let mut continuer = Command::new("/bin/sh")
            .arg("-c")
            .arg("IFS= read -r _; sleep 0.05; kill -CONT \"$1\"")
            .arg("everpty-cont")
            .arg(std::process::id().to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("CONT helper");
        let mut continue_gate = continuer.stdin.take().expect("CONT helper stdin");

        let server_thread = std::thread::spawn(move || {
            let mut job_control = nix::sys::signal::SigSet::empty();
            job_control.add(nix::sys::signal::Signal::SIGTSTP);
            job_control.add(nix::sys::signal::Signal::SIGCONT);
            nix::sys::signal::pthread_sigmask(
                nix::sys::signal::SigmaskHow::SIG_BLOCK,
                Some(&job_control),
                None,
            )
            .expect("block job-control signals in mock server");
            let mut stream = File::from(server);
            let _ = recv_test_frame(&mut stream, &limits);
            send_test_frame(
                &mut stream,
                &Frame::HelloAck {
                    client_id: 30,
                    broker_protocol_version: PROTOCOL_VERSION,
                    status: AttachStatus::WriterGranted,
                },
            );
            let deadline = Instant::now() + Duration::from_secs(2);
            while sys::terminal_attributes(slave_probe.as_fd()).expect("raw probe") == probe_before
            {
                assert!(Instant::now() < deadline, "client did not enter raw mode");
                std::thread::sleep(Duration::from_millis(1));
            }
            continue_gate.write_all(b"continue\n").expect("arm CONT");
            sys::signal_thread(target, libc::SIGTSTP).expect("TSTP");

            // The Rust test harness retains an unmasked coordinator thread.
            // The external process-wide CONT therefore guarantees resume but
            // is not guaranteed to reach this attach thread's signalfd. Once
            // TSTP restoration is observable, target CONT at the attach
            // thread unless the external CONT already produced its Resize.
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let mut ready = [PollFd::new(stream.as_fd(), PollFlags::POLLIN)];
                if sys::poll(&mut ready, Some(0)).expect("early CONT Resize poll") != 0 {
                    break;
                }
                if sys::terminal_attributes(slave_probe.as_fd()).expect("TSTP restore probe")
                    == probe_before
                {
                    sys::signal_thread(target, libc::SIGCONT).expect("targeted CONT");
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "TSTP did not restore termios before CONT"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            let mut poll = [PollFd::new(stream.as_fd(), PollFlags::POLLIN)];
            assert_eq!(
                sys::poll(&mut poll, Some(2_000)).expect("CONT Resize poll"),
                1,
                "CONT did not produce a fresh Resize"
            );
            assert_eq!(
                recv_test_frame(&mut stream, &limits),
                Frame::Resize { rows: 32, cols: 97 }
            );
            send_test_frame(
                &mut stream,
                &Frame::Exit {
                    signal: false,
                    value: 0,
                },
            );
        });

        let config = AttachConfig {
            session: &fixture.session,
            name: "tstp-cont-state",
            role: Role::Writer,
            take_over: false,
            size: SizeMode::Existing,
            stdin: slave.as_fd(),
            stdout: stdout_write.as_fd(),
            limits,
        };
        let dimensions = prepare_attach(&config).expect("prepare");
        assert_eq!(
            attach_connected(config, client, dimensions).expect("attach"),
            AttachOutcome::ChildExited(0)
        );
        server_thread.join().expect("server");
        assert!(continuer.wait().expect("CONT helper wait").success());
        assert!(
            sys::terminal_attributes(slave.as_fd()).expect("termios") == termios_before,
            "TSTP/CONT return did not restore exact termios"
        );
        assert_eq!(status_flags(slave.as_fd()), stdin_before);
        assert_eq!(status_flags(stdout_write.as_fd()), stdout_before);
        assert_eq!(sys::current_signal_mask().expect("mask"), mask_before);
        drop((stdout_read, stdout_write));
    }
}
