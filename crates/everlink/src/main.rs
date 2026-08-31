//! Production everlink binary edge.
#![cfg_attr(not(test), allow(clippy::print_stderr))]

use clap::{error::ErrorKind as ClapErrorKind, ArgAction, Parser, Subcommand};
use everlink::admission::AuthenticatedConnection;
use everlink::role_protocol::parse_ssh_connection;
use everlink::ssh_policy::SshPlan;
use everlink::{Error, Limits};
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::ExitCode;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug, Parser)]
#[command(
    name = "everlink",
    version,
    about = "One-stream authenticated QUIC ProxyCommand for OpenSSH"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Bootstrap a one-shot server over system OpenSSH and proxy stdin/stdout.
    SshProxy {
        /// Original OpenSSH destination token, normally ProxyCommand `%n`.
        destination: String,
        /// Effective OpenSSH port, normally ProxyCommand `%p`.
        port: String,
        /// One audited, self-contained OpenSSH option.
        #[arg(
            long = "ssh-option",
            value_name = "OPTION",
            action = ArgAction::Append,
            allow_hyphen_values = true
        )]
        ssh_option: Vec<String>,
    },
    #[command(name = "__bootstrap-parent-v1", hide = true)]
    BootstrapParentV1,
    #[command(name = "__server-v1", hide = true)]
    ServerV1,
}

enum PreparedRole {
    Proxy(SshPlan),
    BootstrapParent {
        authenticated: AuthenticatedConnection,
        self_exe: PathBuf,
    },
    Server,
}

fn prepare(command: Command) -> Result<PreparedRole, Error> {
    match command {
        Command::SshProxy {
            destination,
            port,
            ssh_option,
        } => Ok(PreparedRole::Proxy(SshPlan::new(
            destination,
            port,
            ssh_option,
        )?)),
        Command::BootstrapParentV1 => {
            let value = std::env::var_os("SSH_CONNECTION")
                .and_then(|value| value.into_string().ok())
                .ok_or(Error::SshConnectionMalformed)?;
            let authenticated = parse_ssh_connection(&value)?;
            let self_exe = std::env::current_exe().map_err(Error::Io)?;
            Ok(PreparedRole::BootstrapParent {
                authenticated,
                self_exe,
            })
        }
        Command::ServerV1 => Ok(PreparedRole::Server),
    }
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                ClapErrorKind::DisplayHelp | ClapErrorKind::DisplayVersion
            ) =>
        {
            return if error.print().is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            };
        }
        Err(_) => {
            eprintln!("everlink: invalid arguments");
            return ExitCode::from(2);
        }
    };
    let prepared = match prepare(cli.command) {
        Ok(prepared) => prepared,
        Err(error) => {
            eprintln!("everlink: {error}");
            return ExitCode::from(2);
        }
    };
    let runtime = match everlink::runtime::build() {
        Ok(runtime) => runtime,
        Err(_) => {
            eprintln!("everlink: runtime unavailable");
            return ExitCode::from(3);
        }
    };
    let limits = Limits::default();
    let result = runtime.block_on(async move {
        match prepared {
            PreparedRole::Proxy(plan) => {
                let stdin = DirectPipeReader::stdin().map_err(Error::Io)?;
                let stdout = DirectPipeWriter::stdout().map_err(Error::Io)?;
                everlink::roles::run_ssh_proxy(plan, limits, stdin, stdout).await
            }
            PreparedRole::BootstrapParent {
                authenticated,
                self_exe,
            } => {
                let output = DirectPipeWriter::stdout().map_err(Error::Io)?;
                everlink::roles::run_bootstrap_parent(authenticated, self_exe, output, limits).await
            }
            PreparedRole::Server => {
                let input = DirectPipeReader::stdin().map_err(Error::Io)?;
                let readiness = DirectPipeWriter::stdout().map_err(Error::Io)?;
                everlink::roles::run_server(input, readiness, limits).await
            }
        }
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("everlink: {error}");
            ExitCode::from(3)
        }
    }
}

/// Unbuffered, edge-owned standard descriptor. Evented pipes preserve direct
/// backpressure and can be closed independently without uncancellable blocking
/// stdio tasks. Protected records never enter a global stdout allocation.
#[cfg(target_os = "linux")]
enum DirectDescriptor {
    Evented {
        registered: tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>,
        _original: std::os::fd::OwnedFd,
    },
    Immediate(std::os::fd::OwnedFd),
    Closed,
}

#[cfg(target_os = "linux")]
impl DirectDescriptor {
    fn from_raw(descriptor_number: i32) -> io::Result<Self> {
        use std::os::fd::FromRawFd;

        // SAFETY: prepared-role dispatch creates at most one owner for each
        // inherited standard descriptor, before constructing a standard handle.
        let descriptor = unsafe { std::os::fd::OwnedFd::from_raw_fd(descriptor_number) };
        set_nonblocking(&descriptor)?;
        let registration = descriptor.try_clone()?;
        match tokio::io::unix::AsyncFd::new(registration) {
            Ok(registered) => Ok(Self::Evented {
                registered,
                _original: descriptor,
            }),
            // epoll deliberately rejects regular files and devices such as
            // /dev/null. Their direct operations complete synchronously.
            Err(error) if error.raw_os_error() == Some(1) => Ok(Self::Immediate(descriptor)),
            Err(error) => Err(error),
        }
    }

    fn close(&mut self) -> io::Result<()> {
        let owned = std::mem::replace(self, Self::Closed);
        match owned {
            Self::Evented {
                registered,
                _original: original,
            } => {
                let first = close_owned(registered.into_inner()).err();
                let second = close_owned(original).err();
                match first.or(second) {
                    Some(error) => Err(error),
                    None => Ok(()),
                }
            }
            Self::Immediate(descriptor) => close_owned(descriptor),
            Self::Closed => Ok(()),
        }
    }
}

#[cfg(target_os = "linux")]
struct DirectPipeReader {
    inner: DirectDescriptor,
}

#[cfg(target_os = "linux")]
impl DirectPipeReader {
    fn stdin() -> io::Result<Self> {
        Ok(Self {
            inner: DirectDescriptor::from_raw(0)?,
        })
    }
}

#[cfg(target_os = "linux")]
impl AsyncRead for DirectPipeReader {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            let result = match &self.inner {
                DirectDescriptor::Evented { registered, .. } => {
                    let mut readiness = std::task::ready!(registered.poll_read_ready(context))?;
                    let destination = output.initialize_unfilled();
                    match readiness.try_io(|registered| raw_read(registered.get_ref(), destination))
                    {
                        Ok(result) => result,
                        Err(_would_block) => continue,
                    }
                }
                DirectDescriptor::Immediate(descriptor) => {
                    let destination = output.initialize_unfilled();
                    raw_read(descriptor, destination)
                }
                DirectDescriptor::Closed => return Poll::Ready(Ok(())),
            };
            match result {
                Ok(count) => {
                    output.advance(count);
                    return Poll::Ready(Ok(()));
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    context.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
    }
}

#[cfg(target_os = "linux")]
struct DirectPipeWriter {
    inner: DirectDescriptor,
}

#[cfg(target_os = "linux")]
impl DirectPipeWriter {
    fn stdout() -> io::Result<Self> {
        Ok(Self {
            inner: DirectDescriptor::from_raw(1)?,
        })
    }
}

#[cfg(target_os = "linux")]
impl AsyncWrite for DirectPipeWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let result = match &self.inner {
                DirectDescriptor::Evented { registered, .. } => {
                    let mut readiness = std::task::ready!(registered.poll_write_ready(context))?;
                    match readiness.try_io(|registered| raw_write(registered.get_ref(), bytes)) {
                        Ok(result) => result,
                        Err(_would_block) => continue,
                    }
                }
                DirectDescriptor::Immediate(descriptor) => raw_write(descriptor, bytes),
                DirectDescriptor::Closed => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "direct output is closed",
                    )));
                }
            };
            match result {
                Ok(count) => return Poll::Ready(Ok(count)),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    context.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.inner.close())
    }
}

#[cfg(target_os = "linux")]
fn close_owned(descriptor: std::os::fd::OwnedFd) -> io::Result<()> {
    use std::os::fd::IntoRawFd;
    use std::os::raw::c_int;

    extern "C" {
        fn close(descriptor: c_int) -> c_int;
    }

    let raw = descriptor.into_raw_fd();
    // SAFETY: `into_raw_fd` transfers the only close ownership to this call.
    let result = unsafe { close(raw) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn set_nonblocking(descriptor: &std::os::fd::OwnedFd) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::raw::c_int;

    const F_GETFL: c_int = 3;
    const F_SETFL: c_int = 4;
    const O_NONBLOCK: c_int = 0x800;
    extern "C" {
        fn fcntl(descriptor: c_int, command: c_int, ...) -> c_int;
    }

    // SAFETY: both calls use the live exclusively owned descriptor and Linux's
    // documented F_GETFL/F_SETFL variadic ABI.
    let flags = unsafe { fcntl(descriptor.as_raw_fd(), F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let result = unsafe { fcntl(descriptor.as_raw_fd(), F_SETFL, flags | O_NONBLOCK) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn raw_read(descriptor: &std::os::fd::OwnedFd, bytes: &mut [u8]) -> io::Result<usize> {
    use std::ffi::c_void;
    use std::os::fd::AsRawFd;
    use std::os::raw::c_int;

    extern "C" {
        fn read(descriptor: c_int, bytes: *mut c_void, length: usize) -> isize;
    }

    // SAFETY: the mutable slice is valid for `length` and the descriptor stays
    // owned for the call.
    let result = unsafe {
        read(
            descriptor.as_raw_fd(),
            bytes.as_mut_ptr().cast::<c_void>(),
            bytes.len(),
        )
    };
    if result >= 0 {
        Ok(result as usize)
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn raw_write(descriptor: &std::os::fd::OwnedFd, bytes: &[u8]) -> io::Result<usize> {
    use std::ffi::c_void;
    use std::os::fd::AsRawFd;
    use std::os::raw::c_int;

    extern "C" {
        fn write(descriptor: c_int, bytes: *const c_void, length: usize) -> isize;
    }

    // SAFETY: the slice is valid for `length` and the descriptor stays owned
    // for the call.
    let result = unsafe {
        write(
            descriptor.as_raw_fd(),
            bytes.as_ptr().cast::<c_void>(),
            bytes.len(),
        )
    };
    if result >= 0 {
        Ok(result as usize)
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
struct DirectPipeReader;

#[cfg(not(target_os = "linux"))]
impl DirectPipeReader {
    fn stdin() -> io::Result<Self> {
        Err(unsupported_direct_io())
    }
}

#[cfg(not(target_os = "linux"))]
impl AsyncRead for DirectPipeReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        _output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(unsupported_direct_io()))
    }
}

#[cfg(not(target_os = "linux"))]
struct DirectPipeWriter;

#[cfg(not(target_os = "linux"))]
impl DirectPipeWriter {
    fn stdout() -> io::Result<Self> {
        Err(unsupported_direct_io())
    }
}

#[cfg(not(target_os = "linux"))]
impl AsyncWrite for DirectPipeWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        _bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(unsupported_direct_io()))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(not(target_os = "linux"))]
fn unsupported_direct_io() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "direct standard-descriptor ownership is unsupported",
    )
}
