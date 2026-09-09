//! Shared process edge for standalone and combined-binary everudp roles.
//!
//! Argument and environment access belongs here. In particular, PTY session
//! creation happens before the single-threaded Tokio runtime is constructed,
//! because `everpty` daemonizes at that boundary.
#![allow(clippy::print_stderr)]

use crate::request::BootstrapRequest;
use crate::roles::{
    prepare_bootstrap_parent, run_bootstrap_parent, run_gateway_role, BootstrapPreparation,
    COMBINED_EVERUDP_ROLE,
};
use crate::{
    run_client, BootstrapOperation, ClientConfig, ClientExit, ClientRunError, Limits, RoleError,
    TerminalEdge,
};
use clap::{error::ErrorKind as ClapErrorKind, ArgAction, Parser, Subcommand};
use everssh::role_protocol::parse_ssh_connection;
use std::ffi::OsString;
use std::net::IpAddr;
use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

/// How this role was reached. Combined re-execs must preserve the private
/// `__everudp` marker; standalone re-execs use the executable directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invocation {
    Standalone,
    CombinedEversh,
}

impl Invocation {
    fn gateway_role_prefix(self) -> &'static [&'static str] {
        match self {
            Self::Standalone => &[],
            Self::CombinedEversh => &[COMBINED_EVERUDP_ROLE],
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "everudp",
    version,
    about = "Persistent direct-QUIC terminal transport"
)]
struct Cli {
    /// Remote program that provides the corresponding everudp role.
    #[arg(
        long = "remote-program",
        value_name = "WORD_OR_ABSOLUTE_PATH",
        global = true
    )]
    remote_program: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Attach or create a named persistent terminal session.
    Connect {
        destination: String,
        #[arg(long)]
        session: String,
        #[arg(long = "take-over")]
        take_over: bool,
        #[arg(
            long = "ssh-option",
            value_name = "OPTION",
            action = ArgAction::Append,
            allow_hyphen_values = true
        )]
        ssh_option: Vec<String>,
        #[arg(long = "status-file", value_name = "PATH", hide = true)]
        status_file: Option<PathBuf>,
        #[arg(last = true, value_name = "COMMAND")]
        child: Vec<OsString>,
    },
    /// Attach to an existing named session as its writer.
    Attach {
        destination: String,
        session: String,
        #[arg(long = "take-over")]
        take_over: bool,
        #[arg(
            long = "ssh-option",
            value_name = "OPTION",
            action = ArgAction::Append,
            allow_hyphen_values = true
        )]
        ssh_option: Vec<String>,
        #[arg(long = "status-file", value_name = "PATH", hide = true)]
        status_file: Option<PathBuf>,
    },
    /// Observe future output from an existing session without an input stream.
    Observe {
        destination: String,
        session: String,
        #[arg(
            long = "ssh-option",
            value_name = "OPTION",
            action = ArgAction::Append,
            allow_hyphen_values = true
        )]
        ssh_option: Vec<String>,
        #[arg(long = "status-file", value_name = "PATH", hide = true)]
        status_file: Option<PathBuf>,
    },
    /// Authenticated SSH parent that prepares the PTY and detaches a gateway.
    #[command(name = "__bootstrap-parent-v1", hide = true)]
    BootstrapParentV1 { request: String },
    /// Detached persistent gateway process.
    #[command(name = "__gateway-v1", hide = true)]
    GatewayV1 {
        #[arg(long = "state-root", value_name = "ABSOLUTE_PATH")]
        state_root: PathBuf,
        #[arg(long = "bind-ip", value_name = "IP")]
        bind_ip: IpAddr,
        #[arg(long = "request", value_name = "TOKEN")]
        request: String,
    },
}

enum PreparedRole {
    Client(ClientConfig),
    BootstrapParent {
        request: BootstrapRequest,
        state_root: PathBuf,
        bind_ip: IpAddr,
        self_exe: PathBuf,
    },
    Gateway {
        request: BootstrapRequest,
        state_root: PathBuf,
        bind_ip: IpAddr,
    },
    Broker(everpty::broker::BrokerExit),
}

fn state_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::with_capacity(4);
    if let Some(path) = std::env::var_os("EVERSH_STATE_DIR") {
        candidates.push(PathBuf::from(path));
    }
    if let Some(path) = std::env::var_os("XDG_RUNTIME_DIR") {
        candidates.push(PathBuf::from(path).join("eversh"));
    }
    if let Some(path) = std::env::var_os("XDG_STATE_HOME") {
        candidates.push(PathBuf::from(path).join("eversh"));
    }
    if let Some(path) = std::env::var_os("HOME") {
        candidates.push(PathBuf::from(path).join(".local/state/eversh"));
    }
    candidates
}

fn captured_environment() -> Vec<OsString> {
    std::env::vars_os()
        .map(|(mut key, value)| {
            key.push("=");
            key.push(value);
            key
        })
        .collect()
}

fn prepare(
    invocation: Invocation,
    remote_program: Option<String>,
    command: Command,
) -> Result<PreparedRole, RoleError> {
    match command {
        Command::Connect {
            destination,
            session,
            take_over,
            ssh_option,
            status_file,
            child,
        } => {
            let (rows, columns) = writer_dimensions()?;
            Ok(PreparedRole::Client(ClientConfig {
                destination,
                remote_role_words: remote_role_words(invocation, remote_program),
                ssh_options: ssh_option,
                operation: BootstrapOperation::Connect,
                session,
                take_over,
                rows,
                columns,
                origin: local_host_name(),
                command: child.into_iter().map(|word| word.into_vec()).collect(),
                status_path: status_file,
            }))
        }
        Command::Attach {
            destination,
            session,
            take_over,
            ssh_option,
            status_file,
        } => {
            let (rows, columns) = writer_dimensions()?;
            Ok(PreparedRole::Client(ClientConfig {
                destination,
                remote_role_words: remote_role_words(invocation, remote_program),
                ssh_options: ssh_option,
                operation: BootstrapOperation::Attach,
                session,
                take_over,
                rows,
                columns,
                origin: local_host_name(),
                command: Vec::new(),
                status_path: status_file,
            }))
        }
        Command::Observe {
            destination,
            session,
            ssh_option,
            status_file,
        } => Ok(PreparedRole::Client(ClientConfig {
            destination,
            remote_role_words: remote_role_words(invocation, remote_program),
            ssh_options: ssh_option,
            operation: BootstrapOperation::Observe,
            session,
            take_over: false,
            rows: 0,
            columns: 0,
            origin: local_host_name(),
            command: Vec::new(),
            status_path: status_file,
        })),
        Command::BootstrapParentV1 { request } => {
            let request = BootstrapRequest::decode_token(&request)?;
            let ssh_connection = std::env::var_os("SSH_CONNECTION")
                .and_then(|value| value.into_string().ok())
                .ok_or(everssh::Error::SshConnectionMalformed)?;
            let authenticated = parse_ssh_connection(&ssh_connection)?;
            let context = everpty::run::Context {
                state_candidates: state_candidates(),
                limits: everpty::Limits::default(),
            };
            match prepare_bootstrap_parent(
                request,
                context,
                captured_environment(),
                std::env::var_os("SHELL"),
                std::env::var_os("PATH"),
            )? {
                BootstrapPreparation::Ready {
                    request,
                    state_root,
                } => Ok(PreparedRole::BootstrapParent {
                    request,
                    state_root,
                    bind_ip: authenticated.local().ip(),
                    self_exe: std::env::current_exe()?,
                }),
                BootstrapPreparation::Broker(exit) => Ok(PreparedRole::Broker(exit)),
            }
        }
        Command::GatewayV1 {
            state_root,
            bind_ip,
            request,
        } => {
            if !state_root.is_absolute() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "everudp state root must be absolute",
                )
                .into());
            }
            Ok(PreparedRole::Gateway {
                request: BootstrapRequest::decode_token(&request)?,
                state_root,
                bind_ip,
            })
        }
    }
}

fn remote_role_words(invocation: Invocation, remote_program: Option<String>) -> Vec<String> {
    match invocation {
        Invocation::Standalone => vec![remote_program.unwrap_or_else(|| "everudp".to_owned())],
        Invocation::CombinedEversh => vec![
            remote_program.unwrap_or_else(|| "eversh".to_owned()),
            COMBINED_EVERUDP_ROLE.to_owned(),
        ],
    }
}

fn writer_dimensions() -> Result<(u16, u16), RoleError> {
    let stdin = std::io::stdin();
    Ok(everpty::sys::get_winsize(stdin.as_fd())?)
}

fn local_host_name() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "local".to_owned())
}

/// Runs one process role and returns its stable edge exit code.
pub fn run(invocation: Invocation, args: Vec<OsString>) -> u8 {
    let argv = std::iter::once(OsString::from("everudp")).chain(args);
    let cli = match Cli::try_parse_from(argv) {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                ClapErrorKind::DisplayHelp | ClapErrorKind::DisplayVersion
            ) =>
        {
            return if error.print().is_ok() { 0 } else { 2 };
        }
        Err(_) => {
            eprintln!("everudp: invalid arguments");
            return 2;
        }
    };
    let prepared = match prepare(invocation, cli.remote_program, cli.command) {
        Ok(prepared) => prepared,
        Err(error) => {
            eprintln!("everudp: {error}");
            return 2;
        }
    };
    if let PreparedRole::Broker(exit) = prepared {
        return exit.suggested_exit_code;
    }
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            eprintln!("everudp: runtime unavailable");
            return 3;
        }
    };
    let limits = Limits::default();
    let result: Result<Option<ClientExit>, RoleError> = runtime.block_on(async move {
        match prepared {
            PreparedRole::Client(config) => {
                run_application(async move {
                    let stdin = std::io::stdin();
                    let stdout = std::io::stdout();
                    let stderr = std::io::stderr();
                    let terminal =
                        TerminalEdge::stage(stdin.as_fd(), stdout.as_fd(), stderr.as_fd())
                            .map_err(ClientRunError::from)?;
                    Ok(Some(run_client(config, terminal, limits).await?))
                })
                .await
            }
            PreparedRole::BootstrapParent {
                request,
                state_root,
                bind_ip,
                self_exe,
            } => {
                let output = std::io::stdout().lock();
                run_bootstrap_parent(
                    self_exe,
                    invocation.gateway_role_prefix(),
                    state_root,
                    bind_ip,
                    request,
                    output,
                    limits,
                )
                .await?;
                Ok(None)
            }
            PreparedRole::Gateway {
                request,
                state_root,
                bind_ip,
            } => {
                run_application(async move {
                    // The gateway survives for the PTY lifetime, but its parent
                    // reads this one bootstrap record to EOF. Own fd 1 directly
                    // so dropping `output` after the record really closes the
                    // pipe; dropping `StdoutLock` would leave the global stdout
                    // descriptor open and deadlock the parent until timeout.
                    // SAFETY: role dispatch creates exactly one stdout owner in
                    // this process and never constructs a `Stdout` handle.
                    let output = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(1) });
                    run_gateway_role(&state_root, bind_ip, request, output, limits).await?;
                    Ok(None)
                })
                .await
            }
            PreparedRole::Broker(_) => unreachable!("handled before runtime"),
        }
    });
    match result {
        Ok(Some(exit)) => exit.exit_code(),
        Ok(None) => 0,
        Err(RoleError::ClientRun(error)) if error.is_initial_udp_unavailable() => {
            eprintln!("everudp: {error}");
            crate::UDP_UNREACHABLE_EXIT
        }
        Err(error) => {
            eprintln!("everudp: {error}");
            3
        }
    }
}

/// Keep the role owned until completion; only experimental builds change its queue.
async fn run_application<F>(future: F) -> Result<Option<ClientExit>, RoleError>
where
    F: std::future::Future<Output = Result<Option<ClientExit>, RoleError>> + Send + 'static,
{
    #[cfg(feature = "application-task-spike")]
    {
        match tokio::spawn(future).await {
            Ok(result) => result,
            Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
            Err(_) => Err(RoleError::Io(std::io::Error::other(
                "application task cancelled",
            ))),
        }
    }
    #[cfg(not(feature = "application-task-spike"))]
    future.await
}

#[cfg(test)]
mod tests {
    use super::{remote_role_words, Cli, Command, Invocation};
    use clap::Parser;

    struct DropNotice(std::sync::Arc<std::sync::atomic::AtomicBool>);

    impl Drop for DropNotice {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn application_owner_awaits_completion_and_preserves_errors() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        let dropped = Arc::new(AtomicBool::new(false));
        let notice = DropNotice(Arc::clone(&dropped));
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let release = tokio::spawn(async move { sender.send(()).expect("application alive") });
        let result = super::run_application(async move {
            let _notice = notice;
            receiver.await.expect("release task alive");
            Err(crate::RoleError::AssociationMismatch)
        })
        .await;
        assert!(matches!(result, Err(crate::RoleError::AssociationMismatch)));
        assert!(dropped.load(Ordering::SeqCst));
        release.await.expect("release task");
        assert!(matches!(
            super::run_application(async { Ok(None) }).await,
            Ok(None)
        ));
    }

    #[test]
    fn application_owner_preserves_panic_and_drops_owned_state() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        let dropped = Arc::new(AtomicBool::new(false));
        let notice = DropNotice(Arc::clone(&dropped));
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runtime.block_on(super::run_application(async move {
                let _notice = notice;
                std::panic::panic_any(73_u32);
            }))
        }))
        .expect_err("application panic must propagate");
        assert_eq!(panic.downcast_ref::<u32>(), Some(&73));
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn private_roles_have_exact_versioned_grammar() {
        let parsed = Cli::try_parse_from([
            "everudp",
            "__gateway-v1",
            "--state-root",
            "/tmp/state",
            "--bind-ip",
            "127.0.0.1",
            "--request",
            "00",
        ])
        .expect("gateway grammar");
        assert!(matches!(parsed.command, Command::GatewayV1 { .. }));
        assert!(Cli::try_parse_from(["everudp", "__gateway-v2"]).is_err());
        assert!(Cli::try_parse_from(["everudp", "__bootstrap-parent-v1"]).is_err());
    }

    #[test]
    fn standalone_and_combined_remote_roles_cannot_be_confused() {
        assert_eq!(remote_role_words(Invocation::Standalone, None), ["everudp"]);
        assert_eq!(
            remote_role_words(Invocation::CombinedEversh, None),
            ["eversh", "__everudp"]
        );
    }
}
