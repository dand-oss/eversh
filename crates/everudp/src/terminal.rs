//! Restorable local terminal edge activated only after QUIC authentication.

use crate::wire::{ConnectionRole, Resize};
use everpty::sys::{self, AttachSignal};
use std::fmt;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use tokio::io::unix::AsyncFd;

pub const GAP_NOTICE: &[u8] = b"everudp: output skipped during network outage\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalEvent {
    Resize(Resize),
    Suspended,
    Continued,
    Cancel(AttachSignal),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalEvent {
    Stdin { bytes: usize },
    StdinClosed,
    Signal(TerminalEvent),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalWriteEvent {
    Written { bytes: usize },
    Signal(TerminalEvent),
}

#[derive(Debug)]
pub enum TerminalError {
    Io(io::Error),
    AlreadyActive,
    NotActive,
    WriterRequiresDimensions,
}

impl fmt::Display for TerminalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::AlreadyActive => formatter.write_str("everudp terminal edge is already active"),
            Self::NotActive => formatter.write_str("everudp terminal edge is not active"),
            Self::WriterRequiresDimensions => {
                formatter.write_str("everudp writer terminal has zero dimensions")
            }
        }
    }
}

impl std::error::Error for TerminalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for TerminalError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

struct RawTerminal<'fd> {
    fd: BorrowedFd<'fd>,
    original: sys::TerminalAttributes,
    active: bool,
}

impl<'fd> RawTerminal<'fd> {
    fn enter(fd: BorrowedFd<'fd>) -> io::Result<Self> {
        let original = sys::terminal_attributes(fd)?;
        sys::set_terminal_raw(fd, &original)?;
        Ok(Self {
            fd,
            original,
            active: true,
        })
    }

    fn reenter(&mut self) -> io::Result<()> {
        if !self.active {
            sys::set_terminal_raw(self.fd, &self.original)?;
            self.active = true;
        }
        Ok(())
    }

    fn restore(&mut self) -> io::Result<()> {
        if self.active {
            sys::restore_terminal(self.fd, &self.original)?;
            self.active = false;
        }
        Ok(())
    }
}

impl Drop for RawTerminal<'_> {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

/// Owns caller terminal state only after [`TerminalEdge::activate`] is called.
/// Staging validates descriptors but changes no termios, flags, or signal mask.
pub struct TerminalEdge<'fd> {
    stdin: BorrowedFd<'fd>,
    stdout: BorrowedFd<'fd>,
    stderr: BorrowedFd<'fd>,
    role: Option<ConnectionRole>,
    raw: Option<RawTerminal<'fd>>,
    stdin_flags: Option<sys::NonblockingGuard<'fd>>,
    stdout_flags: Option<sys::NonblockingGuard<'fd>>,
    stderr_flags: Option<sys::NonblockingGuard<'fd>>,
    signals: Option<sys::AttachSignals>,
    stdin_async: Option<AsyncDescriptor>,
    stdout_async: Option<AsyncDescriptor>,
    stderr_async: Option<AsyncDescriptor>,
    signal_async: Option<AsyncFd<OwnedFd>>,
    last_size: Option<(u16, u16)>,
}

impl<'fd> TerminalEdge<'fd> {
    pub fn stage(
        stdin: BorrowedFd<'fd>,
        stdout: BorrowedFd<'fd>,
        stderr: BorrowedFd<'fd>,
    ) -> Result<Self, TerminalError> {
        sys::validate_fd(stdin)?;
        sys::validate_fd(stdout)?;
        sys::validate_fd(stderr)?;
        Ok(Self {
            stdin,
            stdout,
            stderr,
            role: None,
            raw: None,
            stdin_flags: None,
            stdout_flags: None,
            stderr_flags: None,
            signals: None,
            stdin_async: None,
            stdout_async: None,
            stderr_async: None,
            signal_async: None,
            last_size: None,
        })
    }

    /// Activates only after the caller has validated `SERVER_HELLO`. Every
    /// partial setup failure restores changes through local guards.
    pub fn activate(&mut self, role: ConnectionRole) -> Result<(), TerminalError> {
        if self.role.is_some() {
            return Err(TerminalError::AlreadyActive);
        }
        let tty_writer = role == ConnectionRole::Writer && sys::is_terminal(self.stdin);
        let (raw, last_size) = if tty_writer {
            let size = sys::get_winsize(self.stdin)?;
            if size.0 == 0 || size.1 == 0 {
                return Err(TerminalError::WriterRequiresDimensions);
            }
            (Some(RawTerminal::enter(self.stdin)?), Some(size))
        } else {
            (None, None)
        };
        let signals = sys::attach_signals()?;
        let stdin_is_stdout =
            role == ConnectionRole::Writer && same_open_object(self.stdin, self.stdout)?;
        let stderr_is_stdout = same_open_object(self.stderr, self.stdout)?;
        let stderr_is_stdin = role == ConnectionRole::Writer
            && !stdin_is_stdout
            && same_open_object(self.stderr, self.stdin)?;
        let stdin_flags = if role == ConnectionRole::Writer && !stdin_is_stdout {
            Some(sys::NonblockingGuard::new(self.stdin)?)
        } else {
            None
        };
        let stdout_flags = Some(sys::NonblockingGuard::new(self.stdout)?);
        let stderr_flags = if stderr_is_stdout || stderr_is_stdin {
            None
        } else {
            Some(sys::NonblockingGuard::new(self.stderr)?)
        };

        self.raw = raw;
        self.stdin_flags = stdin_flags;
        self.stdout_flags = stdout_flags;
        self.stderr_flags = stderr_flags;
        self.signals = Some(signals);
        self.last_size = last_size;
        self.role = Some(role);
        Ok(())
    }

    /// Registers duplicated descriptors with the active Tokio reactor.
    /// Registration is deliberately separate from terminal activation.
    pub fn enable_async_io(&mut self) -> Result<(), TerminalError> {
        if self.role.is_none() {
            return Err(TerminalError::NotActive);
        }
        if self.signal_async.is_some() {
            return Ok(());
        }
        let stdin_async = if self.role == Some(ConnectionRole::Writer) {
            Some(AsyncDescriptor::register(self.stdin)?)
        } else {
            None
        };
        let stdout_async = AsyncDescriptor::register(self.stdout)?;
        let stderr_async = AsyncDescriptor::register(self.stderr)?;
        let signal_async = AsyncFd::new(sys::duplicate_cloexec(
            self.signals.as_ref().ok_or(TerminalError::NotActive)?.fd(),
        )?)?;
        self.stdin_async = stdin_async;
        self.stdout_async = Some(stdout_async);
        self.stderr_async = Some(stderr_async);
        self.signal_async = Some(signal_async);
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.role.is_some()
    }

    pub fn role(&self) -> Option<ConnectionRole> {
        self.role
    }

    pub fn signal_fd(&self) -> Result<BorrowedFd<'_>, TerminalError> {
        self.signals
            .as_ref()
            .map(sys::AttachSignals::fd)
            .ok_or(TerminalError::NotActive)
    }

    pub fn next_signal_event(&mut self) -> Result<Option<TerminalEvent>, TerminalError> {
        let signal = self
            .signals
            .as_ref()
            .ok_or(TerminalError::NotActive)
            .and_then(|signals| sys::read_attach_signal(signals).map_err(Into::into))?;
        let Some(signal) = signal else {
            return Ok(None);
        };
        self.handle_signal(signal)
    }

    /// Waits for either one stdin read or one meaningful terminal signal.
    /// `poll_stdin=false` is the queue-full backpressure state: stdin is not
    /// registered in the select at all, while cancellation remains live.
    pub async fn next_local_event(
        &mut self,
        stdin_buffer: &mut [u8],
        poll_stdin: bool,
    ) -> Result<LocalEvent, TerminalError> {
        let signal = self.signal_async.as_ref().ok_or(TerminalError::NotActive)?;
        enum Ready {
            Stdin(usize),
            Signal(AttachSignal),
        }
        let ready = if poll_stdin {
            let stdin = self.stdin_async.as_ref().ok_or(TerminalError::NotActive)?;
            tokio::select! {
                read = read_ready(stdin, stdin_buffer) => Ready::Stdin(read?),
                signal = read_signal_ready(signal) => Ready::Signal(signal?),
            }
        } else {
            Ready::Signal(read_signal_ready(signal).await?)
        };
        match ready {
            Ready::Stdin(0) => Ok(LocalEvent::StdinClosed),
            Ready::Stdin(bytes) => Ok(LocalEvent::Stdin { bytes }),
            Ready::Signal(mut signal) => loop {
                if let Some(event) = self.handle_signal(signal)? {
                    return Ok(LocalEvent::Signal(event));
                }
                signal =
                    read_signal_ready(self.signal_async.as_ref().ok_or(TerminalError::NotActive)?)
                        .await?;
            },
        }
    }

    pub async fn write_stdout_all(&self, bytes: &[u8]) -> Result<(), TerminalError> {
        let output = self.stdout_async.as_ref().ok_or(TerminalError::NotActive)?;
        write_all_ready(output, bytes).await.map_err(Into::into)
    }

    /// Waits for one stdout write or one meaningful signal. This keeps local
    /// cancellation and resize handling responsive while a slow stdout sink
    /// backpressures output delivery.
    pub async fn write_stdout_or_signal(
        &mut self,
        bytes: &[u8],
    ) -> Result<TerminalWriteEvent, TerminalError> {
        if bytes.is_empty() {
            return Err(io::Error::from(io::ErrorKind::WriteZero).into());
        }
        loop {
            let output = self.stdout_async.as_ref().ok_or(TerminalError::NotActive)?;
            let signal = self.signal_async.as_ref().ok_or(TerminalError::NotActive)?;
            enum Ready {
                Written(usize),
                Signal(AttachSignal),
            }
            let ready = tokio::select! {
                written = write_ready(output, bytes) => Ready::Written(written?),
                signal = read_signal_ready(signal) => Ready::Signal(signal?),
            };
            match ready {
                Ready::Written(0) => return Err(io::Error::from(io::ErrorKind::WriteZero).into()),
                Ready::Written(bytes) => {
                    return Ok(TerminalWriteEvent::Written { bytes });
                }
                Ready::Signal(signal) => {
                    if let Some(event) = self.handle_signal(signal)? {
                        return Ok(TerminalWriteEvent::Signal(event));
                    }
                }
            }
        }
    }

    pub async fn write_gap_notice_async(&self) -> Result<(), TerminalError> {
        let error = self.stderr_async.as_ref().ok_or(TerminalError::NotActive)?;
        write_all_ready(error, GAP_NOTICE).await.map_err(Into::into)
    }

    pub async fn write_stderr_all_async(&self, bytes: &[u8]) -> Result<(), TerminalError> {
        let error = self.stderr_async.as_ref().ok_or(TerminalError::NotActive)?;
        write_all_ready(error, bytes).await.map_err(Into::into)
    }

    fn handle_signal(
        &mut self,
        signal: AttachSignal,
    ) -> Result<Option<TerminalEvent>, TerminalError> {
        match signal {
            AttachSignal::WindowChange if self.raw.is_some() => self.changed_size(),
            AttachSignal::Continue if self.raw.is_some() => {
                self.raw.as_mut().expect("checked raw").reenter()?;
                Ok(self.changed_size()?.or(Some(TerminalEvent::Continued)))
            }
            AttachSignal::Suspend => {
                if let Some(raw) = self.raw.as_mut() {
                    raw.restore()?;
                }
                self.signals
                    .as_ref()
                    .expect("active signal guard")
                    .suspend()?;
                Ok(Some(TerminalEvent::Suspended))
            }
            AttachSignal::Interrupt
            | AttachSignal::Terminate
            | AttachSignal::Hangup
            | AttachSignal::Quit => Ok(Some(TerminalEvent::Cancel(signal))),
            AttachSignal::Continue | AttachSignal::WindowChange => Ok(None),
        }
    }

    pub fn read_stdin(&self, buffer: &mut [u8]) -> Result<usize, TerminalError> {
        if self.role != Some(ConnectionRole::Writer) {
            return Err(TerminalError::NotActive);
        }
        sys::read_fd(self.stdin, buffer).map_err(Into::into)
    }

    pub fn write_stdout(&self, bytes: &[u8]) -> Result<usize, TerminalError> {
        if self.role.is_none() {
            return Err(TerminalError::NotActive);
        }
        sys::write_fd(self.stdout, bytes).map_err(Into::into)
    }

    pub fn write_gap_notice(&self) -> Result<(), TerminalError> {
        if self.role.is_none() {
            return Err(TerminalError::NotActive);
        }
        let mut written = 0usize;
        while written < GAP_NOTICE.len() {
            match sys::write_fd(self.stderr, &GAP_NOTICE[written..]) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero).into()),
                Ok(count) => written += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    pub fn deactivate(&mut self) -> Result<(), TerminalError> {
        let mut first = None;
        self.stdin_async = None;
        self.stdout_async = None;
        self.stderr_async = None;
        self.signal_async = None;
        if let Some(raw) = self.raw.as_mut() {
            retain_first(&mut first, raw.restore());
        }
        if let Some(flags) = self.stdin_flags.as_mut() {
            retain_first(&mut first, flags.restore());
        }
        if let Some(flags) = self.stdout_flags.as_mut() {
            retain_first(&mut first, flags.restore());
        }
        if let Some(flags) = self.stderr_flags.as_mut() {
            retain_first(&mut first, flags.restore());
        }
        self.raw = None;
        self.stdin_flags = None;
        self.stdout_flags = None;
        self.stderr_flags = None;
        self.signals = None;
        self.last_size = None;
        self.role = None;
        first.map_or(Ok(()), |error| Err(error.into()))
    }

    fn changed_size(&mut self) -> Result<Option<TerminalEvent>, TerminalError> {
        let size = sys::get_winsize(self.stdin)?;
        if size.0 == 0 || size.1 == 0 || self.last_size == Some(size) {
            return Ok(None);
        }
        self.last_size = Some(size);
        Ok(Some(TerminalEvent::Resize(Resize {
            rows: size.0,
            columns: size.1,
            pixel_width: 0,
            pixel_height: 0,
        })))
    }
}

impl Drop for TerminalEdge<'_> {
    fn drop(&mut self) {
        let _ = self.deactivate();
    }
}

impl fmt::Debug for TerminalEdge<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TerminalEdge")
            .field("role", &self.role)
            .field("raw", &self.raw.is_some())
            .field("signals", &self.signals.is_some())
            .finish_non_exhaustive()
    }
}

enum AsyncDescriptor {
    Evented(AsyncFd<OwnedFd>),
    Immediate(OwnedFd),
}

impl AsyncDescriptor {
    fn register(source: BorrowedFd<'_>) -> io::Result<Self> {
        match AsyncFd::new(sys::duplicate_cloexec(source)?) {
            Ok(descriptor) => Ok(Self::Evented(descriptor)),
            // epoll rejects regular files with EPERM. They are always ready,
            // so a retained descriptor can perform the operation directly
            // without a blocking helper thread.
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                Ok(Self::Immediate(sys::duplicate_cloexec(source)?))
            }
            Err(error) => Err(error),
        }
    }
}

async fn read_ready(fd: &AsyncDescriptor, buffer: &mut [u8]) -> io::Result<usize> {
    match fd {
        AsyncDescriptor::Evented(fd) => loop {
            let mut ready = fd.readable().await?;
            #[cfg(feature = "path-io-diagnostics")]
            crate::io_trace::record_terminal(crate::io_trace::TerminalStage::Ready);
            if let Ok(result) =
                ready.try_io(|inner| traced_stdin_read(inner.get_ref().as_fd(), buffer))
            {
                return result;
            }
        },
        AsyncDescriptor::Immediate(fd) => loop {
            #[cfg(feature = "path-io-diagnostics")]
            crate::io_trace::record_terminal(crate::io_trace::TerminalStage::Ready);
            match traced_stdin_read(fd.as_fd(), buffer) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    tokio::task::yield_now().await;
                }
                result => return result,
            }
        },
    }
}

fn traced_stdin_read(fd: BorrowedFd<'_>, buffer: &mut [u8]) -> io::Result<usize> {
    #[cfg(feature = "path-io-diagnostics")]
    crate::io_trace::record_terminal(crate::io_trace::TerminalStage::ReadStart);
    let result = sys::read_fd(fd, buffer);
    #[cfg(feature = "path-io-diagnostics")]
    {
        crate::io_trace::record_terminal(crate::io_trace::TerminalStage::ReadEnd);
        if matches!(result, Ok(bytes) if bytes > 0) {
            crate::io_trace::record_terminal(crate::io_trace::TerminalStage::Data);
        }
    }
    result
}

async fn read_signal_ready(fd: &AsyncFd<OwnedFd>) -> io::Result<AttachSignal> {
    loop {
        let mut ready = fd.readable().await?;
        if let Ok(result) = ready.try_io(|inner| read_one_signal(inner.get_ref().as_fd())) {
            return result;
        }
    }
}

fn read_one_signal(fd: BorrowedFd<'_>) -> io::Result<AttachSignal> {
    let signal =
        sys::read_signalfd(fd)?.ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))?;
    AttachSignal::from_number(signal)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unexpected attach signal"))
}

async fn write_all_ready(fd: &AsyncDescriptor, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        match write_ready(fd, bytes).await {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            Ok(written) => bytes = &bytes[written..],
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

async fn write_ready(fd: &AsyncDescriptor, bytes: &[u8]) -> io::Result<usize> {
    match fd {
        AsyncDescriptor::Evented(fd) => loop {
            let mut ready = fd.writable().await?;
            if let Ok(result) = ready.try_io(|inner| sys::write_fd(inner.get_ref().as_fd(), bytes))
            {
                return result;
            }
        },
        AsyncDescriptor::Immediate(fd) => loop {
            match sys::write_fd(fd.as_fd(), bytes) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    tokio::task::yield_now().await;
                }
                result => return result,
            }
        },
    }
}

fn same_open_object(left: BorrowedFd<'_>, right: BorrowedFd<'_>) -> io::Result<bool> {
    if left.as_raw_fd() == right.as_raw_fd() {
        return Ok(true);
    }
    let left = sys::fstat_fd(left)?;
    let right = sys::fstat_fd(right)?;
    Ok(left.st_dev == right.st_dev && left.st_ino == right.st_ino)
}

fn retain_first(first: &mut Option<io::Error>, result: io::Result<()>) {
    if let Err(error) = result {
        if first.is_none() {
            *first = Some(error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::read_one_signal;
    use everpty::sys;
    use std::io;
    use std::os::fd::AsFd;

    #[test]
    fn empty_async_signal_read_preserves_would_block() {
        let (read, _write) = sys::pipe_cloexec().expect("signal pipe");
        sys::set_nonblocking(read.as_fd()).expect("nonblocking signal pipe");

        let error = read_one_signal(read.as_fd()).expect_err("empty signal pipe");
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    }
}
