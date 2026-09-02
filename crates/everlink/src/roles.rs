//! Typed orchestration for the public proxy and private process roles.

use crate::bootstrap::BootstrapRecord;
use crate::bridge::{DrainStatus, FinalizeStatus, StdioBridge, TargetBridge};
use crate::error::Error;
use crate::identity::EphemeralIdentity;
use crate::limits::Limits;
use crate::link_status::{self, StatusCause, TrackedReader, TrackedWriter};
use crate::role_protocol::{
    validate_release, ServerStartRecord, StartUdpPolicy, RELEASE_RECORD, SERVER_START_MAX,
};
use crate::shutdown::Shutdown;
use crate::ssh_bootstrap::{
    acquire_bootstrap, read_capped_line, read_capped_to_eof, require_eof, verify_effective_config,
    ChildOwner, SecretBytes,
};
use crate::ssh_policy::SshPlan;
use crate::transport::{ClientEndpoint, ServerEndpoint, UdpBindPolicy};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::process::{ChildStdin, Command};
use tokio::time::Instant;

/// Run the SSH-launched parent. Its only global inputs are supplied by the
/// process edge. `server_role_args` is the argv prefix required to reach the
/// everlink role when re-invoking `self_exe` (empty for the standalone
/// binary; the combined binary's role marker otherwise).
pub async fn run_bootstrap_parent<W>(
    authenticated: crate::admission::AuthenticatedConnection,
    self_exe: PathBuf,
    server_role_args: &[&str],
    mut output: W,
    limits: Limits,
) -> Result<(), Error>
where
    W: AsyncWrite + Unpin,
{
    limits.validate()?;
    let deadline = Instant::now()
        .checked_add(std::time::Duration::from_millis(
            limits.bootstrap_timeout_ms,
        ))
        .ok_or(Error::BootstrapTimedOut)?;
    let start =
        ServerStartRecord::try_new(authenticated, StartUdpPolicy::RouteSelected, &limits)?.encode();
    let mut command = Command::new(self_exe);
    command
        .args(server_role_args)
        .arg("__server-v1")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut owner = ChildOwner::spawn_transferable(&mut command, limits.finalize_timeout())?;
    let mut control = Some(owner.take_stdin()?);
    let mut readiness = owner.take_stdout()?;

    let operation = async {
        let writer = control.as_mut().ok_or(Error::SshProcessFailed)?;
        write_at(writer, start.as_bytes(), deadline).await?;
        let writer = control.as_mut().ok_or(Error::SshProcessFailed)?;
        flush_at(writer, deadline).await?;

        let wire = tokio::time::timeout_at(
            deadline,
            read_capped_to_eof(&mut readiness, limits.bootstrap_record_max),
        )
        .await
        .map_err(|_| Error::BootstrapTimedOut)??;
        if owner.try_wait()?.is_some() {
            return Err(Error::SshProcessFailed);
        }
        let record = parse_canonical_bootstrap_line(&wire, &limits)?;
        drop(record);
        write_at(&mut output, wire.as_slice(), deadline).await?;
        flush_at(&mut output, deadline).await?;
        if owner.try_wait()?.is_some() {
            return Err(Error::SshProcessFailed);
        }

        let writer = control.as_mut().ok_or(Error::SshProcessFailed)?;
        write_at(writer, RELEASE_RECORD, deadline).await?;
        let writer = control.as_mut().ok_or(Error::SshProcessFailed)?;
        flush_at(writer, deadline).await?;
        close_control(control.take().ok_or(Error::SshProcessFailed)?)?;
        Ok(())
    }
    .await;

    match operation {
        Ok(()) => {
            drop(readiness);
            owner.release()?;
            Ok(())
        }
        Err(first) => {
            let _ = owner.kill_and_reap().await;
            Err(first)
        }
    }
}

/// Run the detached one-shot server using only protected inherited IO.
pub async fn run_server<R, W>(mut input: R, mut readiness: W, limits: Limits) -> Result<(), Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    limits.validate()?;
    let startup_deadline = Instant::now()
        .checked_add(std::time::Duration::from_millis(
            limits.bootstrap_timeout_ms,
        ))
        .ok_or(Error::BootstrapTimedOut)?;
    let start_wire = read_capped_line(&mut input, SERVER_START_MAX, startup_deadline).await?;
    let start = parse_canonical_start(&start_wire, &limits)?;
    let policy = convert_policy(start.policy());

    let identity = EphemeralIdentity::generate()?;
    let endpoint = ServerEndpoint::bind(start.authenticated(), policy, &identity, limits)?;
    let lease_deadline = endpoint.lease_deadline();
    let record = BootstrapRecord::new(
        endpoint.local_addr().ip(),
        endpoint.local_addr().port(),
        identity.spki_sha256(),
        identity.take_bootstrap_token()?,
        std::process::id(),
    )?;
    let line = record.encode();
    if let Err(first) = write_at(&mut readiness, line.as_str().as_bytes(), lease_deadline).await {
        drop(line);
        drop(record);
        let _ = endpoint.close().await;
        return Err(first);
    }
    if let Err(first) = flush_at(&mut readiness, lease_deadline).await {
        drop(line);
        drop(record);
        let _ = endpoint.close().await;
        return Err(first);
    }
    if let Err(first) = shutdown_at(&mut readiness, lease_deadline).await {
        drop(line);
        drop(record);
        let _ = endpoint.close().await;
        return Err(first);
    }
    drop(readiness);
    drop(line);
    drop(record);
    drop(identity);

    let released = async {
        let release = read_capped_line(&mut input, RELEASE_RECORD.len(), lease_deadline).await?;
        validate_release(release.as_slice())?;
        require_eof(&mut input, lease_deadline).await
    }
    .await;
    if let Err(first) = released {
        let _ = endpoint.close().await;
        return Err(first);
    }
    drop(input);

    let admitted = endpoint.accept_for_role().await?;
    let connected = admitted.connect_target().await?;
    let shutdown = Shutdown::new();
    let bridge = TargetBridge::try_new(connected, limits, shutdown).await?;
    require_clean_bridge(bridge.run().await)
}

/// Run the public ProxyCommand edge after clap has produced typed values.
/// `status_path`, when set (design 3, 7 — the caller reads it from this
/// process's own argv at the edge; this typed library function never reads
/// global environment itself), receives the local out-of-band status record
/// on every exit path: a `carrying` line as soon as the QUIC stream first
/// delivers a byte from the remote peer, and a terminal `cause ...
/// carried=...` line no matter how this function returns — including a
/// failure before any bridge ever started, which is always reported as an
/// ORDINARY failure (`clean-close`, nothing carried) so the supervisor
/// reports the resulting 255 immediately with no probe and no reconnect
/// episode (design 7: bootstrap and authentication failures remain ordinary
/// OpenSSH failures; nothing was ever carried, so a retry could only
/// duplicate work).
pub async fn run_ssh_proxy<R, W>(
    plan: SshPlan,
    limits: Limits,
    stdin: R,
    stdout: W,
    status_path: Option<PathBuf>,
) -> Result<(), Error>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    let established = async {
        verify_effective_config(&plan, &limits).await?;
        let record = acquire_bootstrap(&plan, &limits).await?;
        let server = SocketAddr::new(record.udp_endpoint, record.udp_port);
        let client = ClientEndpoint::bind(
            server,
            UdpBindPolicy::RouteSelected,
            record.spki_sha256,
            limits,
        )?;
        let session = client
            .connect_and_authenticate(record.token(), plan.port())
            .await?;
        drop(record);
        Ok::<_, Error>(session)
    }
    .await;
    let session = match established {
        Ok(session) => session,
        Err(error) => {
            // Everything before bridge construction — effective-config
            // policy, the SSH bootstrap (including its authentication), the
            // client UDP bind, and QUIC connect/authenticate — never carried
            // a byte and left no live session behind: an ordinary failure.
            if let Some(path) = &status_path {
                link_status::write_cause(path, StatusCause::CleanClose, false);
            }
            return Err(error);
        }
    };

    let shutdown = Shutdown::new();
    let quic_to_peer_delivered = Arc::new(AtomicBool::new(false));
    let peer_to_quic_delivered = Arc::new(AtomicBool::new(false));
    let tracked_stdin = TrackedReader::new(stdin, Arc::clone(&peer_to_quic_delivered));
    let tracked_stdout = TrackedWriter::new(
        stdout,
        Arc::clone(&quic_to_peer_delivered),
        status_path.clone(),
    );

    let bridge = match StdioBridge::try_new(
        session,
        tracked_stdin,
        tracked_stdout,
        limits,
        shutdown,
    )
    .await
    {
        Ok(bridge) => bridge,
        Err(error) => {
            if let Some(path) = &status_path {
                link_status::write_cause(path, StatusCause::TransportFailure, false);
            }
            return Err(error);
        }
    };

    let completion = bridge.run().await;
    if let Some(path) = &status_path {
        // clean-close requires a completely drained AND finalized bridge
        // (design 6.3, 9): a graceful SourceEof alone does not prove the
        // exchange completed, so the terminal record classifies the WHOLE
        // completion — the same evidence `require_clean_bridge` re-checks
        // below for this process's own result.
        let cause = link_status::classify_completion(&completion);
        let carried = quic_to_peer_delivered.load(Ordering::Acquire)
            && peer_to_quic_delivered.load(Ordering::Acquire);
        link_status::write_cause(path, cause, carried);
    }
    require_clean_bridge(completion)
}

fn convert_policy(policy: StartUdpPolicy) -> UdpBindPolicy {
    match policy {
        StartUdpPolicy::RouteSelected => UdpBindPolicy::RouteSelected,
        StartUdpPolicy::RouteSelectedPortRange { start, end } => {
            UdpBindPolicy::RouteSelectedPortRange { start, end }
        }
        StartUdpPolicy::Explicit(address) => UdpBindPolicy::Explicit(address),
    }
}

fn parse_canonical_start(wire: &SecretBytes, limits: &Limits) -> Result<ServerStartRecord, Error> {
    let bytes = wire.as_slice();
    if wire.overflowed()
        || bytes.last() != Some(&b'\n')
        || bytes.contains(&b'\r')
        || bytes[..bytes.len() - 1].contains(&b'\n')
    {
        return Err(Error::ServerStartMalformed);
    }
    let line =
        std::str::from_utf8(&bytes[..bytes.len() - 1]).map_err(|_| Error::ServerStartMalformed)?;
    let record = ServerStartRecord::parse(line, limits)?;
    if record.encode().as_bytes() != bytes {
        return Err(Error::ServerStartMalformed);
    }
    Ok(record)
}

fn parse_canonical_bootstrap_line(
    wire: &SecretBytes,
    limits: &Limits,
) -> Result<BootstrapRecord, Error> {
    let bytes = wire.as_slice();
    if wire.overflowed()
        || bytes.last() != Some(&b'\n')
        || bytes.contains(&b'\r')
        || bytes[..bytes.len() - 1].contains(&b'\n')
    {
        return Err(Error::BootstrapMalformed);
    }
    let line =
        std::str::from_utf8(&bytes[..bytes.len() - 1]).map_err(|_| Error::BootstrapMalformed)?;
    let record = BootstrapRecord::parse(line, limits)?;
    if record.encode().as_str().as_bytes() != bytes {
        return Err(Error::BootstrapMalformed);
    }
    Ok(record)
}

fn require_clean_bridge(completion: crate::bridge::BridgeCompletion) -> Result<(), Error> {
    if completion.drain == DrainStatus::Completed
        && completion.finalize == FinalizeStatus::Completed
    {
        Ok(())
    } else {
        Err(Error::BridgeIncomplete)
    }
}

#[cfg(unix)]
fn close_control(control: ChildStdin) -> Result<(), Error> {
    use std::os::fd::IntoRawFd;
    use std::os::raw::c_int;

    extern "C" {
        fn close(descriptor: c_int) -> c_int;
    }

    let descriptor = control.into_owned_fd().map_err(Error::Io)?.into_raw_fd();
    // SAFETY: `into_raw_fd` transfers the only close ownership to this call.
    let result = unsafe { close(descriptor) };
    if result == 0 {
        Ok(())
    } else {
        Err(Error::Io(std::io::Error::last_os_error()))
    }
}

#[cfg(not(unix))]
fn close_control(control: ChildStdin) -> Result<(), Error> {
    drop(control);
    Err(Error::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "control-pipe close confirmation is unsupported",
    )))
}

async fn write_at<W>(writer: &mut W, bytes: &[u8], deadline: Instant) -> Result<(), Error>
where
    W: AsyncWrite + Unpin,
{
    tokio::time::timeout_at(deadline, writer.write_all(bytes))
        .await
        .map_err(|_| Error::BootstrapTimedOut)?
        .map_err(Error::Io)
}

async fn flush_at<W>(writer: &mut W, deadline: Instant) -> Result<(), Error>
where
    W: AsyncWrite + Unpin,
{
    tokio::time::timeout_at(deadline, writer.flush())
        .await
        .map_err(|_| Error::BootstrapTimedOut)?
        .map_err(Error::Io)
}

async fn shutdown_at<W>(writer: &mut W, deadline: Instant) -> Result<(), Error>
where
    W: AsyncWrite + Unpin,
{
    tokio::time::timeout_at(deadline, writer.shutdown())
        .await
        .map_err(|_| Error::BootstrapTimedOut)?
        .map_err(Error::Io)
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::role_protocol::parse_ssh_connection;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tokio::io::AsyncReadExt;

    /// Serializes script creation and spawning across test threads: a script
    /// file open for writing in one thread can be inherited across another
    /// thread's fork window and make exec fail with ETXTBSY.
    static SCRIPT_GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct Script {
        executable: PathBuf,
        pid_file: PathBuf,
        argv_file: PathBuf,
    }

    impl Script {
        fn new(mode: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "everlink-role-{mode}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&root).unwrap();
            let executable = root.join("server");
            let pid_file = root.join("pid");
            let argv_file = root.join("argv");
            let line = format!(
                "everlink v1 192.0.2.2 4444 {} {} 123\\n",
                "00".repeat(32),
                "11".repeat(32)
            );
            let behavior = match mode {
                "success" => format!(
                    "printf '{line}'; exec 1>&-; IFS= read -r release || exit 31; [ \"$release\" = 'everlink-release v1' ] || exit 32; exit 0"
                ),
                "chatter" => format!("printf '{line}junk\\n'; exec 1>&-; sleep 30"),
                "missing-eof" => format!("printf '{line}'; sleep 30"),
                "early" => format!("printf '{line}'; exec 1>&-; exit 7"),
                "release-fail" => {
                    format!("exec 0<&-; printf '{line}'; exec 1>&-; sleep 30")
                }
                _ => unreachable!(),
            };
            let body = format!(
                "#!/bin/sh\nprintf '%s' \"$$\" > '{}'\nprintf '%s' \"$*\" > '{}'\nIFS= read -r start || exit 30\n{behavior}\n",
                pid_file.display(),
                argv_file.display()
            );
            fs::write(&executable, body).unwrap();
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
            Self {
                executable,
                pid_file,
                argv_file,
            }
        }

        async fn pid(&self) -> u32 {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                if let Ok(value) = fs::read_to_string(&self.pid_file) {
                    return value.parse().unwrap();
                }
                assert!(Instant::now() < deadline, "fake child did not publish pid");
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    }

    impl Drop for Script {
        fn drop(&mut self) {
            if let Some(root) = self.executable.parent() {
                let _ = fs::remove_dir_all(root);
            }
        }
    }

    fn test_limits() -> Limits {
        Limits {
            bootstrap_timeout_ms: 200,
            finalize_timeout_ms: 1_000,
            ..Limits::default()
        }
    }

    #[allow(clippy::await_holding_lock)]
    async fn run_mode(mode: &str) -> (Result<(), Error>, Vec<u8>, u32) {
        let gate = SCRIPT_GATE
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let script = Script::new(mode);
        let (writer, mut reader) = tokio::io::duplex(1024);
        let authenticated = parse_ssh_connection("192.0.2.1 50000 192.0.2.2 22").unwrap();
        let future = run_bootstrap_parent(
            authenticated,
            script.executable.clone(),
            &[],
            writer,
            test_limits(),
        );
        let capture = async {
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).await.unwrap();
            bytes
        };
        let (result, bytes) = tokio::join!(future, capture);
        drop(gate);
        let pid = script.pid().await;
        let deadline = Instant::now() + Duration::from_secs(2);
        while std::path::Path::new(&format!("/proc/{pid}")).exists() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "owned child {pid} survived {mode}"
        );
        (result, bytes, pid)
    }

    #[tokio::test]
    async fn parent_requires_readiness_eof_and_reaps_every_pretransfer_failure() {
        let (success, output, _) = run_mode("success").await;
        assert!(success.is_ok());
        assert_eq!(output.iter().filter(|byte| **byte == b'\n').count(), 1);

        for mode in ["chatter", "missing-eof", "early", "release-fail"] {
            let (result, output, _) = run_mode(mode).await;
            assert!(result.is_err(), "{mode} unexpectedly transferred");
            assert!(output.is_empty() || output.iter().filter(|byte| **byte == b'\n').count() == 1);
        }
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn combined_role_prefix_precedes_the_server_role_word() {
        let gate = SCRIPT_GATE
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let script = Script::new("success");
        let (writer, mut reader) = tokio::io::duplex(1024);
        let authenticated = parse_ssh_connection("192.0.2.1 50000 192.0.2.2 22").unwrap();
        let future = run_bootstrap_parent(
            authenticated,
            script.executable.clone(),
            &["__everlink"],
            writer,
            test_limits(),
        );
        let capture = async {
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).await.unwrap();
            bytes
        };
        let (result, _bytes) = tokio::join!(future, capture);
        drop(gate);
        assert!(result.is_ok());
        assert_eq!(
            fs::read_to_string(&script.argv_file).unwrap(),
            "__everlink __server-v1",
            "combined dispatch must re-invoke through the everlink role marker"
        );
    }

    struct FailingRelay;

    impl AsyncWrite for FailingRelay {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
            _bytes: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "injected relay failure",
            )))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn relay_failure_kills_child_before_release() {
        let gate = SCRIPT_GATE
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let script = Script::new("success");
        let authenticated = parse_ssh_connection("192.0.2.1 50000 192.0.2.2 22").unwrap();
        // The full suite launches several real processes concurrently. Give
        // this test's child enough time to reach the injected relay seam; the
        // relay failure itself remains immediate and is still required to reap
        // the child before release.
        let limits = Limits {
            bootstrap_timeout_ms: 5_000,
            ..test_limits()
        };
        let result = run_bootstrap_parent(
            authenticated,
            script.executable.clone(),
            &[],
            FailingRelay,
            limits,
        )
        .await;
        drop(gate);
        assert!(
            matches!(
                &result,
                Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::BrokenPipe
            ),
            "unexpected relay result: {result:?}"
        );
        let pid = script.pid().await;
        assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
    }

    #[tokio::test]
    async fn readiness_write_failure_closes_bound_endpoint_before_release() {
        let target = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        target.set_nonblocking(true).unwrap();
        let udp = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let udp_address = udp.local_addr().unwrap();
        drop(udp);
        let authenticated = crate::admission::AuthenticatedConnection::new(
            std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 50_000)),
            target.local_addr().unwrap(),
        )
        .unwrap();
        let limits = test_limits();
        let start = ServerStartRecord::try_new(
            authenticated,
            StartUdpPolicy::Explicit(udp_address),
            &limits,
        )
        .unwrap()
        .encode();
        let mut input = start.as_bytes();
        let result = run_server(&mut input, FailingRelay, limits).await;
        assert!(result.is_err());
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match std::net::UdpSocket::bind(udp_address) {
                Ok(socket) => {
                    drop(socket);
                    break;
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::AddrInUse
                        && Instant::now() < deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Err(error) => panic!("readiness endpoint survived cleanup: {error}"),
            }
        }
        assert!(matches!(
            target.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }
}
