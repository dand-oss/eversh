//! Disposable authenticated reliable-stream comparison entry point.
//! Explicit ordinary/native roles; this is not qualification.
#![allow(clippy::print_stderr)]

#[path = "support/stream_native.rs"]
mod stream_native;

#[path = "support/stream_profile.rs"]
mod stream_profile;

use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use everssh::association::AssociationId;
use everssh::role_protocol::parse_ssh_connection;
use everssh::ssh_bootstrap::{acquire_bootstrap_bytes, verify_effective_config};
use everssh::ssh_policy::SshPlan;
use everudp::stream_floor_fd::AsyncDescriptor;
use everudp::stream_floor_ordinary::{client_handshake, serve_echo, server_handshake_until};
use everudp::transport::{stream_floor_client_config, stream_floor_server_config};
use everudp::wire::ConnectionRole;
use everudp::{
    BootstrapOperation, BootstrapRecord, BootstrapRequest, ClientHello, ClientIdentity,
    GatewayGeneration, GatewayIdentity, InvitationStore, Limits, ResumePosition, TerminalEdge,
    TerminalEvent,
};
use noq::Runtime as _;
use std::error::Error;
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use std::process::{ExitCode, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{unix::AsyncFd, AsyncReadExt};
use tokio::process::Command;

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
const BOOTSTRAP: &str = "__stream-bootstrap-v1";
const SERVER: &str = "__stream-server-v1";
const SESSION_LIMIT: Duration = Duration::from_secs(3600);

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Runtime {
    Ordinary,
    Native,
}

impl Runtime {
    fn name(self) -> &'static str {
        match self {
            Self::Ordinary => "ordinary",
            Self::Native => "native",
        }
    }
}

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Role,
}

#[derive(Subcommand)]
enum Role {
    Client {
        destination: String,
        #[arg(long, value_enum)]
        runtime: Runtime,
        #[arg(long, default_value = "stream-floor")]
        session: String,
        #[arg(long, default_value = "everudp-stream-floor")]
        remote_program: String,
        #[arg(long, action = ArgAction::Append)]
        ssh_option: Vec<String>,
    },
    #[command(name = "__stream-bootstrap-v1", hide = true)]
    Bootstrap {
        #[arg(value_enum)]
        runtime: Runtime,
        request: String,
    },
    #[command(name = "__stream-server-v1", hide = true)]
    Server {
        #[arg(long, value_enum)]
        runtime: Runtime,
        #[arg(long)]
        bind_ip: IpAddr,
        request: String,
    },
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn validate(request: &BootstrapRequest) -> Result<()> {
    if request.operation() != BootstrapOperation::Connect
        || request.role() != ConnectionRole::Writer
        || request.take_over()
    {
        return Err(invalid("stream floor requires a fresh writer invitation").into());
    }
    Ok(())
}

async fn acquire(
    destination: String,
    session: String,
    remote: String,
    options: Vec<String>,
    runtime: Runtime,
) -> Result<(BootstrapRecord, ClientIdentity, ClientHello)> {
    let limits = Limits::default();
    let identity = ClientIdentity::generate()?;
    let association = AssociationId::generate()?;
    let request = BootstrapRequest::new(
        BootstrapOperation::Connect,
        session,
        ConnectionRole::Writer,
        false,
        24,
        80,
        association,
        identity.spki_sha256(),
        "stream-floor".to_owned(),
        vec![b"stream-floor".to_vec()],
    )?;
    let plan = SshPlan::using_config(destination, options)?.with_remote_role_invocation(
        vec![remote],
        BOOTSTRAP,
        &[runtime.name().to_owned(), request.encode_token()?],
    )?;
    let ssh_limits = everssh::Limits::default();
    verify_effective_config(&plan, &ssh_limits).await?;
    let wire = acquire_bootstrap_bytes(&plan, limits.bootstrap_record_max, &ssh_limits).await?;
    if wire.overflowed() {
        return Err(invalid("stream bootstrap overflow").into());
    }
    let record = BootstrapRecord::parse_line(std::str::from_utf8(wire.as_slice())?, &limits)?;
    if record.association_id() != association {
        return Err(invalid("stream bootstrap association mismatch").into());
    }
    let hello = ClientHello::initial(
        association,
        record.generation(),
        ConnectionRole::Writer,
        ResumePosition {
            input_epoch: 0,
            next_input: 0,
            output_epoch: 0,
            next_output: 0,
            delivered_output_ack: 0,
        },
        record.token().clone(),
    )?;
    Ok((record, identity, hello))
}

async fn bootstrap(runtime: Runtime, token: String) -> Result<()> {
    let limits = Limits::default();
    let request = BootstrapRequest::decode_token(&token)?;
    validate(&request)?;
    let authenticated = parse_ssh_connection(&std::env::var("SSH_CONNECTION")?)?;
    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg(SERVER)
        .arg("--runtime")
        .arg(runtime.name())
        .arg("--bind-ip")
        .arg(authenticated.local().ip().to_string())
        .arg(token)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(false);
    if let Some(directory) = std::env::var_os(stream_profile::DIRECTORY_ENV) {
        command.env(stream_profile::DIRECTORY_ENV, directory);
    }
    // SAFETY: setsid is the only operation in the post-fork child callback.
    unsafe {
        command.pre_exec(|| everpty::sys::child_setsid().map_err(io::Error::from_raw_os_error));
    }
    let mut child = command.spawn()?;
    // Every fallible post-spawn operation stays inside this result boundary so
    // malformed UTF-8/records and parent stdout errors also terminate the child.
    let result: Result<()> = async {
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| invalid("missing bootstrap pipe"))?;
        let mut wire = Vec::with_capacity(512);
        tokio::time::timeout(
            limits.initial_udp_budget(),
            stdout
                .take((limits.bootstrap_record_max + 1) as u64)
                .read_to_end(&mut wire),
        )
        .await??;
        let record = BootstrapRecord::parse_line(std::str::from_utf8(&wire)?, &limits)?;
        if record.association_id() != request.association_id()
            || record.endpoint().ip() != authenticated.local().ip()
            || Some(record.pid()) != child.id()
        {
            return Err(invalid("child bootstrap identity mismatch").into());
        }
        let stdout = io::stdout();
        let mut output = stdout.lock();
        output.write_all(&wire)?;
        output.flush()?;
        Ok(())
    }
    .await;
    if result.is_err() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    // On success, the bounded detached server owns its lifetime; dropping the
    // child handle does not kill it or retain an unused bootstrap pipe.
    result
}

async fn server(bind_ip: IpAddr, token: String, mut output: std::fs::File) -> Result<()> {
    let limits = Limits::default();
    let request = BootstrapRequest::decode_token(&token)?;
    validate(&request)?;
    let generation = GatewayGeneration::generate()?;
    let identity = GatewayIdentity::generate()?;
    let config = stream_floor_server_config(&identity, &limits)?;
    let runtime = Arc::new(noq::TokioRuntime);
    let socket =
        runtime.wrap_udp_socket(std::net::UdpSocket::bind(SocketAddr::new(bind_ip, 0))?)?;
    // The ordinary driver clamps its sender capability to ten (pinned noQ).
    let initial_gso_cap = socket.create_sender().max_transmit_segments().get().min(10);
    stream_profile::server(Runtime::Ordinary, &config, initial_gso_cap)?;
    let endpoint = noq::Endpoint::new_with_abstract_socket(
        noq::EndpointConfig::default(),
        Some(config),
        socket,
        runtime,
    )?;
    let mut invitations = InvitationStore::new(request.session(), generation, &limits)?;
    let ticket = invitations.issue(
        request.association_id(),
        request.role(),
        request.client_spki_sha256(),
        everpty::sys::clock_monotonic_ms()?,
    )?;
    let record = BootstrapRecord::new(
        endpoint.local_addr()?,
        identity.spki_sha256(),
        ticket.token().clone(),
        request.association_id(),
        generation,
        std::process::id(),
    )?;
    output.write_all(record.encode().as_str().as_bytes())?;
    output.flush()?;
    drop(output);
    let connection = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let incoming = endpoint
                .accept()
                .await
                .ok_or_else(|| invalid("endpoint closed"))?;
            if !incoming.remote_address_validated() {
                incoming.retry()?;
                continue;
            }
            // Waiting for an invitation to be used and completing one accepted
            // TLS handshake have different budgets. A peer that rejects our
            // certificate must not retain the server for the full invitation TTL.
            return tokio::time::timeout(limits.initial_udp_budget(), incoming)
                .await?
                .map_err(Box::<dyn Error + Send + Sync>::from);
        }
    })
    .await??;
    let control = server_handshake_until(
        connection,
        &mut invitations,
        limits,
        limits.initial_udp_budget(),
    )
    .await?;
    let connection = control.connection.clone();
    let closed = tokio::time::timeout(SESSION_LIMIT, async {
        tokio::select! {
            biased;
            closed = connection.closed() => Ok::<_, Box<dyn Error + Send + Sync>>(closed),
            served = serve_echo(control, limits) => {
                // Retain control while the client finishes local sink delivery.
                // Never send an early control FIN across independently ordered streams.
                let owner = served?;
                Ok(owner.connection.closed().await)
            }
        }
    })
    .await??;
    // A normal peer close ends this disposable server's lifetime. This is not
    // proof of delivery: qualification uses the client's exact transcript.
    if !matches!(closed, noq::ConnectionError::ApplicationClosed(ref close) if close.error_code == noq::VarInt::from_u32(0))
    {
        return Err(closed.into());
    }
    endpoint.wait_idle().await;
    Ok(())
}

async fn ordinary_client(
    record: BootstrapRecord,
    identity: ClientIdentity,
    hello: ClientHello,
) -> Result<()> {
    let limits = Limits::default();
    let socket = everssh::transport::bind_udp(
        record.endpoint(),
        everssh::transport::UdpBindPolicy::RouteSelected,
        &everssh::Limits::default(),
    )?
    .into_socket();
    let runtime = Arc::new(noq::TokioRuntime);
    let socket = runtime.wrap_udp_socket(socket)?;
    let initial_gso_cap = socket.create_sender().max_transmit_segments().get().min(10);
    let endpoint = noq::Endpoint::new_with_abstract_socket(
        noq::EndpointConfig::default(),
        None,
        socket,
        runtime,
    )?;
    let (config, mismatch) =
        stream_floor_client_config(&identity, record.server_spki_sha256(), &limits)?;
    stream_profile::client(Runtime::Ordinary, &config, initial_gso_cap)?;
    endpoint.set_default_client_config(config);
    let connection = tokio::time::timeout(
        limits.initial_udp_budget(),
        endpoint.connect(record.endpoint(), "localhost")?,
    )
    .await??;
    if mismatch.observed() {
        return Err(invalid("SPKI mismatch").into());
    }
    let control = client_handshake(connection, hello, limits).await?;
    let connection = control.connection.clone();
    let stdin = io::stdin();
    let stdout = io::stdout();
    let stderr = io::stderr();
    let mut terminal = TerminalEdge::stage(stdin.as_fd(), stdout.as_fd(), stderr.as_fd())?;
    terminal.activate(ConnectionRole::Writer)?;
    let result: Result<()> = async {
        let mut input = AsyncDescriptor::new(stdin.as_fd())?;
        let mut output = AsyncDescriptor::new(stdout.as_fd())?;
        let signals = AsyncFd::new(everpty::sys::duplicate_cloexec(terminal.signal_fd()?)?)?;
        let cancelled = async {
            loop {
                let mut readiness = signals.readable().await?;
                while let Some(event) = terminal.next_signal_event()? {
                    if matches!(event, TerminalEvent::Cancel(_)) {
                        return Err::<(), Box<dyn Error + Send + Sync>>(
                            io::Error::from(io::ErrorKind::Interrupted).into(),
                        );
                    }
                    // Echo floor has no remote PTY; resize changes no wire bytes.
                }
                readiness.clear_ready();
            }
        };
        let delivery = async {
            let (_owner, _) = everudp::stream_floor_ordinary_client::run(
                control,
                &mut input,
                &mut output,
                limits,
            )
            .await?;
            Ok(())
        };
        tokio::select! {
            biased;
            result = cancelled => result,
            result = delivery => result,
        }
    }
    .await;
    connection.close(noq::VarInt::from_u32(0), b"stream-floor client finished");
    let restored = terminal.deactivate();
    endpoint.wait_idle().await;
    result?;
    restored?;
    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result: Result<()> = (|| {
        let make_runtime = || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
        };
        match cli.command {
            Role::Client {
                destination,
                runtime,
                session,
                remote_program,
                ssh_option,
            } => {
                // Bootstrap's runtime is dropped before native data-plane entry.
                let (record, identity, hello) = make_runtime()?.block_on(acquire(
                    destination,
                    session,
                    remote_program,
                    ssh_option,
                    runtime,
                ))?;
                match runtime {
                    Runtime::Ordinary => {
                        make_runtime()?.block_on(ordinary_client(record, identity, hello))
                    }
                    Runtime::Native => stream_native::client(record, identity, hello),
                }
            }
            Role::Bootstrap { runtime, request } => {
                make_runtime()?.block_on(bootstrap(runtime, request))
            }
            Role::Server {
                runtime,
                bind_ip,
                request,
            } => {
                // SAFETY: this role alone owns descriptor 1, and dropping it
                // closes the bootstrap pipe without leaving a Stdout handle.
                let output = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(1) });
                match runtime {
                    Runtime::Ordinary => make_runtime()?.block_on(server(bind_ip, request, output)),
                    Runtime::Native => stream_native::server(bind_ip, request, output),
                }
            }
        }
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("everudp-stream-floor: {error}");
            ExitCode::from(3)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn cli_requires_explicit_runtime_and_accepts_both_modes() {
        assert!(Cli::try_parse_from(["floor", "client", "host"]).is_err());
        assert!(Cli::try_parse_from(["floor", "client", "host", "--runtime", "ordinary"]).is_ok());
        assert!(Cli::try_parse_from(["floor", "client", "host", "--runtime", "native"]).is_ok());
    }

    #[test]
    fn bootstrap_runtime_is_a_policy_approved_positional_word() {
        for mode in [Runtime::Ordinary, Runtime::Native] {
            let arguments = [mode.name().to_owned(), "ab12".to_owned()];
            let plan = SshPlan::using_config("target".to_owned(), vec![])
                .expect("SSH plan")
                .with_remote_role_invocation(
                    vec!["everudp-stream-floor".to_owned()],
                    BOOTSTRAP,
                    &arguments,
                )
                .expect("conservative remote words");
            assert_eq!(
                plan.bootstrap_args().last().expect("remote command"),
                &format!("everudp-stream-floor {BOOTSTRAP} {} ab12", mode.name())
            );
            assert!(Cli::try_parse_from(["floor", BOOTSTRAP, mode.name(), "ab12"]).is_ok());
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn server_record_eof_precedes_authenticated_echo_and_peer_close() {
        for server_mode in [Runtime::Ordinary, Runtime::Native] {
            for client_mode in [Runtime::Ordinary, Runtime::Native] {
                role_case(server_mode, client_mode).await;
            }
        }
    }

    async fn role_case(server_mode: Runtime, client_mode: Runtime) {
        tokio::time::timeout(Duration::from_secs(10), async {
            let limits = Limits::default();
            let identity = ClientIdentity::generate().expect("identity");
            let association = AssociationId::generate().expect("association");
            let request = BootstrapRequest::new(
                BootstrapOperation::Connect,
                "test".to_owned(),
                ConnectionRole::Writer,
                false,
                24,
                80,
                association,
                identity.spki_sha256(),
                "test".to_owned(),
                vec![b"echo".to_vec()],
            )
            .expect("request");
            let (record_writer, record_reader) = UnixStream::pair().expect("record pipe");
            record_reader.set_nonblocking(true).expect("reader flags");
            let mut reader =
                tokio::net::UnixStream::from_std(record_reader).expect("record reader");
            let output = std::fs::File::from(OwnedFd::from(record_writer));
            let token = request.encode_token().expect("token");
            let bind_ip = "127.0.0.1".parse().expect("bind IP");
            let serve = async move {
                match server_mode {
                    Runtime::Ordinary => server(bind_ip, token, output).await,
                    Runtime::Native => tokio::task::spawn_blocking(move || {
                        stream_native::server(bind_ip, token, output)
                    })
                    .await
                    .expect("native server thread"),
                }
            };
            let connect = async {
                let mut wire = Vec::new();
                (&mut reader)
                    .take((limits.bootstrap_record_max + 1) as u64)
                    .read_to_end(&mut wire)
                    .await
                    .expect("record and EOF before connection");
                let record =
                    BootstrapRecord::parse_line(std::str::from_utf8(&wire).expect("UTF8"), &limits)
                        .expect("canonical record");
                assert_eq!(record.association_id(), association);
                let expected = b"opaque\x1b[31m\x00\xff";
                if matches!(client_mode, Runtime::Native) {
                    let hello = ClientHello::initial(
                        association,
                        record.generation(),
                        ConnectionRole::Writer,
                        ResumePosition {
                            input_epoch: 0,
                            next_input: 0,
                            output_epoch: 0,
                            next_output: 0,
                            delivered_output_ack: 0,
                        },
                        record.token().clone(),
                    )
                    .expect("hello");
                    let (input, mut feeder) = UnixStream::pair().expect("input pair");
                    let (output, drain) = UnixStream::pair().expect("output pair");
                    let (stderr, _stderr_peer) = UnixStream::pair().expect("stderr pair");
                    std::io::Write::write_all(&mut feeder, expected).expect("feed");
                    feeder.shutdown(std::net::Shutdown::Write).expect("EOF");
                    drain.set_nonblocking(true).expect("drain flags");
                    let drain = tokio::net::UnixStream::from_std(drain).expect("drain");
                    let native = tokio::task::spawn_blocking(move || {
                        stream_native::client_on_fds(
                            record,
                            identity,
                            hello,
                            input.as_fd(),
                            output.as_fd(),
                            stderr.as_fd(),
                            std::net::UdpSocket::bind("127.0.0.1:0").expect("fixture-owned socket"),
                        )
                    });
                    let receive = async {
                        let mut actual = Vec::new();
                        drain
                            .take(65)
                            .read_to_end(&mut actual)
                            .await
                            .expect("native output EOF");
                        actual
                    };
                    let (result, actual) = tokio::join!(native, receive);
                    result
                        .expect("native client thread")
                        .expect("native client role");
                    assert_eq!(actual, expected);
                    return;
                }
                let endpoint = noq::Endpoint::client("127.0.0.1:0".parse().expect("address"))
                    .expect("endpoint");
                let (config, mismatch) =
                    stream_floor_client_config(&identity, record.server_spki_sha256(), &limits)
                        .expect("config");
                endpoint.set_default_client_config(config);
                let connection = endpoint
                    .connect(record.endpoint(), "localhost")
                    .expect("connect")
                    .await
                    .expect("TLS");
                assert!(!mismatch.observed());
                let hello = ClientHello::initial(
                    association,
                    record.generation(),
                    ConnectionRole::Writer,
                    ResumePosition {
                        input_epoch: 0,
                        next_input: 0,
                        output_epoch: 0,
                        next_output: 0,
                        delivered_output_ack: 0,
                    },
                    record.token().clone(),
                )
                .expect("hello");
                let control = client_handshake(connection, hello, limits)
                    .await
                    .expect("admission");
                let (mut feeder, mut input) = tokio::io::duplex(64);
                let (mut output, mut drain) = tokio::io::duplex(64);
                feeder.write_all(expected).await.expect("feed");
                feeder.shutdown().await.expect("EOF");
                let (owner, count) = everudp::stream_floor_ordinary_client::run(
                    control,
                    &mut input,
                    &mut output,
                    limits,
                )
                .await
                .expect("echo");
                assert_eq!(count, expected.len() as u64);
                let mut actual = vec![0; expected.len()];
                drain.read_exact(&mut actual).await.expect("local output");
                assert_eq!(actual, expected);
                owner
                    .connection
                    .close(noq::VarInt::from_u32(0), b"verified local delivery");
                endpoint.wait_idle().await;
            };
            let (served, ()) = tokio::join!(serve, connect);
            served.expect("server completed");
        })
        .await
        .expect("bounded server role test");
    }
}
