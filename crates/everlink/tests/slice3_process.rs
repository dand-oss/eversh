//! Production-binary Slice 3 process and byte-path coverage.
#![cfg(feature = "cli")]
#![allow(clippy::unwrap_used)]

use everlink::admission::AuthenticatedConnection;
use everlink::bootstrap::{BootstrapRecord, SecretToken};
use everlink::role_protocol::{ServerStartRecord, StartUdpPolicy};
use everlink::transport::{ClientEndpoint, UdpBindPolicy};
use everlink::Limits;
use std::fs;
use std::io::{BufRead, ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const BIN: &str = env!("CARGO_BIN_EXE_everlink");

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("everlink-{label}-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn selected_non_loopback_v4() -> Ipv4Addr {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    socket.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).unwrap();
    match socket.local_addr().unwrap().ip() {
        std::net::IpAddr::V4(ip) if !ip.is_loopback() && !ip.is_unspecified() => ip,
        other => panic!("route did not select a usable non-loopback IPv4 address: {other}"),
    }
}

fn write_fake_ssh(directory: &TempDir, body: &str) -> std::path::PathBuf {
    let path = directory.0.join("ssh");
    fs::write(&path, body).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

fn fake_path(directory: &TempDir) -> std::ffi::OsString {
    let mut value = directory.0.as_os_str().to_os_string();
    value.push(":");
    value.push(std::env::var_os("PATH").unwrap_or_default());
    value
}

fn wait_child(mut child: Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("child {} exceeded cleanup deadline", child.id());
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn wait_pid_gone(pid: u32, timeout: Duration) {
    let path = std::path::PathBuf::from(format!("/proc/{pid}"));
    let deadline = Instant::now() + timeout;
    while path.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        !path.exists(),
        "process {pid} survived its cleanup deadline"
    );
}

fn assert_udp_released(address: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match UdpSocket::bind(address) {
            Ok(socket) => {
                drop(socket);
                return;
            }
            Err(error) if error.kind() == ErrorKind::AddrInUse && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("UDP endpoint {address} survived cleanup: {error}"),
        }
    }
}

fn bind_client_endpoint_retrying_ephemeral_addr_in_use(
    server: SocketAddr,
    pin: [u8; 32],
    limits: Limits,
) -> (ClientEndpoint, SocketAddr) {
    const MAX_ATTEMPTS: usize = 16;

    for attempt in 1..=MAX_ATTEMPTS {
        let reservation = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap_or_else(|error| {
            panic!(
                "failed to reserve client UDP address on attempt {attempt}/{MAX_ATTEMPTS}: {error}"
            )
        });
        let address = reservation.local_addr().unwrap_or_else(|error| {
            panic!(
                "failed to inspect reserved client UDP address on attempt {attempt}/{MAX_ATTEMPTS}: {error}"
            )
        });
        drop(reservation);

        match ClientEndpoint::bind(server, UdpBindPolicy::Explicit(address), pin, limits) {
            Ok(endpoint) => {
                let actual = endpoint.local_addr().unwrap_or_else(|error| {
                    panic!(
                        "client endpoint local address failed on attempt {attempt}/{MAX_ATTEMPTS} for {address}: {error:?}"
                    )
                });
                assert_eq!(
                    actual, address,
                    "client endpoint changed its explicit address on attempt {attempt}/{MAX_ATTEMPTS}"
                );
                return (endpoint, address);
            }
            Err(everlink::Error::UdpBind(source))
                if source.kind() == ErrorKind::AddrInUse && attempt < MAX_ATTEMPTS =>
            {
                thread::sleep(Duration::from_millis(5));
            }
            Err(everlink::Error::UdpBind(source)) if source.kind() == ErrorKind::AddrInUse => {
                panic!(
                    "client UDP bind remained in use after {MAX_ATTEMPTS} attempts; last reserved address {address}: {source}"
                )
            }
            Err(error) => {
                panic!(
                    "client UDP bind failed without retry on attempt {attempt}/{MAX_ATTEMPTS} for reserved address {address}: {error:?}"
                )
            }
        }
    }

    unreachable!("client UDP bind retry loop exhausted without a result")
}

fn spawn_explicit_server(
    target_address: SocketAddr,
) -> (Child, ChildStdin, BootstrapRecord, SocketAddr) {
    let reserved = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let udp_address = reserved.local_addr().unwrap();
    drop(reserved);
    let authenticated = AuthenticatedConnection::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 50_000)),
        target_address,
    )
    .unwrap();
    let start = ServerStartRecord::try_new(
        authenticated,
        StartUdpPolicy::Explicit(udp_address),
        &Limits::default(),
    )
    .unwrap();
    let mut child = Command::new(BIN)
        .arg("__server-v1")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    input.write_all(start.encode().as_bytes()).unwrap();
    input.flush().unwrap();

    let mut reader = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut wire = String::new();
    reader.read_line(&mut wire).unwrap();
    let mut trailing = Vec::new();
    reader.read_to_end(&mut trailing).unwrap();
    assert!(
        trailing.is_empty(),
        "private readiness contained trailing bytes"
    );
    assert!(
        child.try_wait().unwrap().is_none(),
        "server died before release"
    );
    let record = BootstrapRecord::parse(wire.trim_end_matches('\n'), &Limits::default()).unwrap();
    assert_eq!(record.pid, child.id());
    assert_eq!(record.udp_endpoint, udp_address.ip());
    assert_eq!(record.udp_port, udp_address.port());
    (child, input, record, udp_address)
}

fn direct_children(parent: u32) -> Vec<u32> {
    let mut children = Vec::new();
    let tasks = match fs::read_dir(format!("/proc/{parent}/task")) {
        Ok(tasks) => tasks,
        Err(_) => return children,
    };
    for task in tasks.flatten() {
        let path = task.path().join("children");
        if let Ok(value) = fs::read_to_string(path) {
            children.extend(
                value
                    .split_ascii_whitespace()
                    .filter_map(|pid| pid.parse::<u32>().ok()),
            );
        }
    }
    children.sort_unstable();
    children.dedup();
    children
}

#[test]
fn production_proxy_uses_real_roles_and_preserves_both_half_closes() {
    let temp = TempDir::new("proxy-success");
    let capture = temp.0.join("argv");
    write_fake_ssh(
        &temp,
        r#"#!/bin/sh
printf 'BEGIN\n' >> "$FAKE_CAPTURE"
is_query=no
for arg in "$@"; do
    printf '%s\n' "$arg" >> "$FAKE_CAPTURE"
    [ "$arg" = "-G" ] && is_query=yes
done
printf 'ENV:%s\n' "$PRESERVED_SENTINEL" >> "$FAKE_CAPTURE"
printf 'END\n' >> "$FAKE_CAPTURE"
[ "$PRESERVED_SENTINEL" = kept ] || exit 89
if IFS= read -r unexpected; then exit 90; fi
if [ "$is_query" = yes ]; then
    printf 'hostname fake\n'
    exit 0
fi
SSH_CONNECTION="$FAKE_CONN"
export SSH_CONNECTION
exec "$EVERLINK_BIN" __bootstrap-parent-v1
"#,
    );

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let target_port = listener.local_addr().unwrap().port();
    let route_ip = selected_non_loopback_v4();
    let uplink: Vec<u8> = (0..512_777)
        .map(|index| ((index * 193 + 17) & 0xff) as u8)
        .collect();
    let downlink: Vec<u8> = (0..450_123)
        .map(|index| ((index * 131 + 251) & 0xff) as u8)
        .collect();
    let expected_uplink = uplink.clone();
    let expected_downlink = downlink.clone();
    let target = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut received = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let count = stream.read(&mut chunk).unwrap();
            if count == 0 {
                break;
            }
            received.extend_from_slice(&chunk[..count]);
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(received, expected_uplink);
        for chunk in expected_downlink.chunks(4096) {
            stream.write_all(chunk).unwrap();
            thread::sleep(Duration::from_millis(1));
        }
        stream.shutdown(std::net::Shutdown::Write).unwrap();
    });

    let mut child = Command::new(BIN)
        .args([
            "ssh-proxy",
            "user@alias",
            &target_port.to_string(),
            "--ssh-option",
            "-oConnectTimeout=4",
        ])
        .env("PATH", fake_path(&temp))
        .env("EVERLINK_BIN", BIN)
        .env("FAKE_CAPTURE", &capture)
        .env("PRESERVED_SENTINEL", "kept")
        .env(
            "FAKE_CONN",
            format!("{route_ip} 50000 {route_ip} {target_port}"),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&uplink).unwrap();
    let output = child.wait_with_output().unwrap();
    target.join().unwrap();

    assert!(output.status.success(), "stderr={:?}", output.stderr);
    assert_eq!(output.stdout, downlink);
    assert!(output.stderr.is_empty());
    let argv = fs::read_to_string(capture).unwrap();
    assert_eq!(argv.matches("BEGIN\n").count(), 2);
    assert_eq!(argv.matches("ENV:kept\n").count(), 2);
    assert!(argv.contains("ProxyCommand=none\n"));
    assert!(argv.contains("ControlMaster=no\n"));
    assert!(argv.contains("ForkAfterAuthentication=no\n"));
    assert!(argv.contains("StdinNull=yes\n"));
    assert!(argv.contains("everlink __bootstrap-parent-v1\n"));
    assert!(!argv.contains("BatchMode"));
}

#[test]
fn server_requires_release_and_exposes_no_token_in_process_state() {
    let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    target.set_nonblocking(true).unwrap();
    let target_address = target.local_addr().unwrap();
    let (child, input, record, udp_address) = spawn_explicit_server(target_address);
    let token_hex: String = record
        .token()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let cmdline = fs::read(format!("/proc/{}/cmdline", record.pid)).unwrap();
    let environ = fs::read(format!("/proc/{}/environ", record.pid)).unwrap();
    assert!(environ.is_empty());
    assert!(!std::path::Path::new(&format!("/proc/{}/fd/1", record.pid)).exists());
    assert!(std::path::Path::new(&format!("/proc/{}/fd/0", record.pid)).exists());
    assert!(!cmdline
        .windows(token_hex.len())
        .any(|part| part == token_hex.as_bytes()));
    assert!(!environ
        .windows(token_hex.len())
        .any(|part| part == token_hex.as_bytes()));

    // EOF without the exact release is a parent-death signal.
    drop(input);
    let status = wait_child(child, Duration::from_secs(3));
    assert!(!status.success());
    assert_udp_released(udp_address);
    assert!(matches!(
        target.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
}

#[test]
fn server_rejects_every_release_shape_and_does_not_accept_before_eof() {
    for bad in [
        b"".as_slice(),
        b"everlink-release v1",
        b"everlink-release v2\n",
        b"everlink-release v1\nextra",
        b"everlink-release v1\r\n",
    ] {
        let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        target.set_nonblocking(true).unwrap();
        let (child, mut input, _record, udp_address) =
            spawn_explicit_server(target.local_addr().unwrap());
        input.write_all(bad).unwrap();
        input.flush().unwrap();
        drop(input);
        let status = wait_child(child, Duration::from_secs(3));
        assert!(!status.success(), "release {bad:?} unexpectedly succeeded");
        assert_udp_released(udp_address);
        assert!(matches!(
            target.accept(),
            Err(error) if error.kind() == ErrorKind::WouldBlock
        ));
    }

    let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    target.set_nonblocking(true).unwrap();
    let (mut child, mut input, _record, udp_address) =
        spawn_explicit_server(target.local_addr().unwrap());
    input.write_all(b"everlink-release v1\n").unwrap();
    input.flush().unwrap();
    thread::sleep(Duration::from_millis(150));
    assert!(child.try_wait().unwrap().is_none());
    assert!(matches!(
        target.accept(),
        Err(error) if error.kind() == ErrorKind::WouldBlock
    ));
    child.kill().unwrap();
    assert!(!child.wait().unwrap().success());
    drop(input);
    assert_udp_released(udp_address);
}

#[test]
fn production_server_bind_and_lease_fail_without_target_access() {
    let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    target.set_nonblocking(true).unwrap();
    let occupied = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let authenticated = AuthenticatedConnection::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 50_000)),
        target.local_addr().unwrap(),
    )
    .unwrap();
    let start = ServerStartRecord::try_new(
        authenticated,
        StartUdpPolicy::Explicit(occupied.local_addr().unwrap()),
        &Limits::default(),
    )
    .unwrap()
    .encode();
    let mut child = Command::new(BIN)
        .arg("__server-v1")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(start.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.len() < 256);
    assert!(matches!(
        target.accept(),
        Err(error) if error.kind() == ErrorKind::WouldBlock
    ));
    drop(occupied);

    let (child, input, _record, udp_address) = spawn_explicit_server(target.local_addr().unwrap());
    let started = Instant::now();
    let status = wait_child(child, Duration::from_secs(38));
    let elapsed = started.elapsed();
    assert!(!status.success());
    assert!(elapsed >= Duration::from_secs(25));
    assert!(elapsed < Duration::from_secs(38));
    // The held-open lifeline proves expiry, not parent EOF, ended the role.
    drop(input);
    assert_udp_released(udp_address);
    assert!(matches!(
        target.accept(),
        Err(error) if error.kind() == ErrorKind::WouldBlock
    ));
}

#[test]
fn killing_bootstrap_parent_closes_lifeline_and_leaves_no_server_or_target() {
    let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    target.set_nonblocking(true).unwrap();
    let target_port = target.local_addr().unwrap().port();
    let route_ip = selected_non_loopback_v4();

    let (mut blocked_reader, mut blocked_writer) = UnixStream::pair().unwrap();
    blocked_writer.set_nonblocking(true).unwrap();
    let fill = [0xa5; 8192];
    loop {
        match blocked_writer.write(&fill) {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock => break,
            Err(error) => panic!("cannot fill relay pipe: {error}"),
        }
    }
    blocked_writer.set_nonblocking(false).unwrap();
    blocked_reader.set_nonblocking(true).unwrap();

    let mut parent = Command::new(BIN)
        .arg("__bootstrap-parent-v1")
        .env_clear()
        .env(
            "SSH_CONNECTION",
            format!("{route_ip} 50000 {route_ip} {target_port}"),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::from(OwnedFd::from(blocked_writer)))
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let parent_pid = parent.id();
    let deadline = Instant::now() + Duration::from_secs(3);
    let server_pid = loop {
        if let Some(pid) = direct_children(parent_pid).into_iter().next() {
            break pid;
        }
        assert!(
            Instant::now() < deadline,
            "parent never spawned private server"
        );
        thread::sleep(Duration::from_millis(5));
    };
    assert!(std::path::Path::new(&format!("/proc/{server_pid}")).exists());
    parent.kill().unwrap();
    let _ = parent.wait().unwrap();
    wait_pid_gone(server_pid, Duration::from_secs(5));
    assert!(matches!(
        target.accept(),
        Err(error) if error.kind() == ErrorKind::WouldBlock
    ));
    let mut byte = [0u8; 1];
    let _ = blocked_reader.read(&mut byte);
}

#[test]
fn production_server_target_failure_closes_quic_and_udp() {
    let closed = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let target_address = closed.local_addr().unwrap();
    drop(closed);
    let (child, mut input, record, udp_address) = spawn_explicit_server(target_address);
    input.write_all(b"everlink-release v1\n").unwrap();
    input.flush().unwrap();
    drop(input);

    let limits = Limits::default();
    let runtime = everlink::runtime::build().unwrap();
    let client_address = runtime.block_on(async {
        let (client, client_address) = bind_client_endpoint_retrying_ephemeral_addr_in_use(
            SocketAddr::new(record.udp_endpoint, record.udp_port),
            record.spki_sha256,
            limits,
        );
        if let Ok(session) = client
            .connect_and_authenticate(record.token(), target_address.port())
            .await
        {
            session.close().await;
        }
        client_address
    });

    let status = wait_child(child, Duration::from_secs(5));
    assert!(!status.success());
    assert_udp_released(udp_address);
    assert_udp_released(client_address);
}

#[test]
fn production_server_rejects_wrong_pin_token_and_selector_before_target() {
    enum Case {
        Pin,
        Token,
        Selector,
    }

    let runtime = everlink::runtime::build().unwrap();
    for case in [Case::Pin, Case::Token, Case::Selector] {
        let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        target.set_nonblocking(true).unwrap();
        let target_address = target.local_addr().unwrap();
        let (child, mut input, record, udp_address) = spawn_explicit_server(target_address);
        input.write_all(b"everlink-release v1\n").unwrap();
        input.flush().unwrap();
        drop(input);

        let client_address = runtime.block_on(async {
            let mut pin = record.spki_sha256;
            if matches!(case, Case::Pin) {
                pin[0] ^= 0xff;
            }
            let (client, client_address) = bind_client_endpoint_retrying_ephemeral_addr_in_use(
                SocketAddr::new(record.udp_endpoint, record.udp_port),
                pin,
                Limits::default(),
            );
            let wrong = SecretToken::from_bytes([0x5a; 32]);
            let token = if matches!(case, Case::Token) {
                &wrong
            } else {
                record.token()
            };
            let selector = if matches!(case, Case::Selector) {
                if target_address.port() == u16::MAX {
                    target_address.port() - 1
                } else {
                    target_address.port() + 1
                }
            } else {
                target_address.port()
            };
            if let Ok(session) = client.connect_and_authenticate(token, selector).await {
                session.close().await;
            }
            client_address
        });

        let status = wait_child(child, Duration::from_secs(18));
        assert!(!status.success());
        assert!(matches!(
            target.accept(),
            Err(error) if error.kind() == ErrorKind::WouldBlock
        ));
        assert_udp_released(udp_address);
        assert_udp_released(client_address);
    }
}

#[test]
fn production_proxy_allows_late_stdin_after_target_half_close() {
    let temp = TempDir::new("target-fin-first");
    write_fake_ssh(
        &temp,
        r#"#!/bin/sh
is_query=no
for arg in "$@"; do [ "$arg" = "-G" ] && is_query=yes; done
if [ "$is_query" = yes ]; then printf 'hostname fake\n'; exit 0; fi
SSH_CONNECTION="$FAKE_CONN"; export SSH_CONNECTION
exec "$EVERLINK_BIN" __bootstrap-parent-v1
"#,
    );
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let target_port = listener.local_addr().unwrap().port();
    let route_ip = selected_non_loopback_v4();
    let uplink: Vec<u8> = (0..65_777).map(|index| (index % 251) as u8).collect();
    let downlink: Vec<u8> = (0..33_333)
        .map(|index| ((index * 17) % 256) as u8)
        .collect();
    let expected_uplink = uplink.clone();
    let expected_downlink = downlink.clone();
    let target = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(&expected_downlink).unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        thread::sleep(Duration::from_millis(150));
        let mut received = Vec::new();
        stream.read_to_end(&mut received).unwrap();
        assert_eq!(received, expected_uplink);
    });

    let mut child = Command::new(BIN)
        .args(["ssh-proxy", "alias", &target_port.to_string()])
        .env("PATH", fake_path(&temp))
        .env("EVERLINK_BIN", BIN)
        .env(
            "FAKE_CONN",
            format!("{route_ip} 50000 {route_ip} {target_port}"),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let (finished_output, output_ready) = std::sync::mpsc::sync_channel(1);
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).unwrap();
        finished_output.send(bytes).unwrap();
    });
    let received = match output_ready.recv_timeout(Duration::from_secs(3)) {
        Ok(bytes) => bytes,
        Err(error) => {
            drop(stdin);
            let _ = child.kill();
            let _ = child.wait();
            reader.join().unwrap();
            panic!("stdout did not half-close independently: {error}");
        }
    };
    assert_eq!(received, downlink);
    assert!(child.try_wait().unwrap().is_none());

    stdin.write_all(&uplink).unwrap();
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    reader.join().unwrap();
    target.join().unwrap();
    assert!(output.status.success(), "stderr={:?}", output.stderr);
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn production_proxy_output_failure_cancels_held_stdin_and_target() {
    let temp = TempDir::new("proxy-output-failure");
    write_fake_ssh(
        &temp,
        r#"#!/bin/sh
is_query=no
for arg in "$@"; do [ "$arg" = "-G" ] && is_query=yes; done
if [ "$is_query" = yes ]; then printf 'hostname fake\n'; exit 0; fi
SSH_CONNECTION="$FAKE_CONN"; export SSH_CONNECTION
exec "$EVERLINK_BIN" __bootstrap-parent-v1
"#,
    );
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let target_port = listener.local_addr().unwrap().port();
    let route_ip = selected_non_loopback_v4();
    let (accepted, target_ready) = std::sync::mpsc::sync_channel(1);
    let target = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        accepted.send(()).unwrap();
        let _ = stream.write_all(&[0x5a; 64 * 1024]);
        let _ = stream.shutdown(std::net::Shutdown::Write);
        stream
            .set_read_timeout(Some(Duration::from_secs(12)))
            .unwrap();
        let mut discarded = Vec::new();
        match stream.read_to_end(&mut discarded) {
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::ConnectionReset | ErrorKind::BrokenPipe
                ) => {}
            Err(error) => panic!("target was not cancelled boundedly: {error}"),
        }
    });

    let mut child = Command::new(BIN)
        .args(["ssh-proxy", "alias", &target_port.to_string()])
        .env("PATH", fake_path(&temp))
        .env("EVERLINK_BIN", BIN)
        .env(
            "FAKE_CONN",
            format!("{route_ip} 50000 {route_ip} {target_port}"),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let held_stdin = child.stdin.take().unwrap();
    drop(child.stdout.take());
    target_ready.recv_timeout(Duration::from_secs(5)).unwrap();
    let status = wait_child(child, Duration::from_secs(12));
    assert!(!status.success());
    drop(held_stdin);
    target.join().unwrap();
}

#[test]
fn malformed_binary_edges_are_bounded_and_do_not_echo_arguments() {
    for connection in [
        "",
        "hostname 1 192.0.2.2 22",
        "127.0.0.1 50000 127.0.0.1 22",
        &"1".repeat(92),
    ] {
        let output = Command::new(BIN)
            .arg("__bootstrap-parent-v1")
            .env_clear()
            .env("SSH_CONNECTION", connection)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(output.stderr.len() < 256);
    }

    for start in [
        b"".as_slice(),
        b"everlink-start v2 127.0.0.1 1 127.0.0.1 22 route\n",
        b"everlink-start v1 127.0.0.1 1 127.0.0.1 22 route\nextra",
        &[b'x'; 513],
    ] {
        let mut child = Command::new(BIN)
            .arg("__server-v1")
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(start).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(output.stderr.len() < 256);
    }

    let hostile = "secret-value-".repeat(500);
    for arguments in [
        vec!["ssh-proxy".to_owned(), hostile.clone(), "22".to_owned()],
        vec!["__server-v1".to_owned(), hostile.clone()],
        vec![hostile.clone()],
    ] {
        let output = Command::new(BIN)
            .args(arguments)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(output.stderr.len() < 256);
        assert!(!output
            .stderr
            .windows(hostile.len())
            .any(|part| part == hostile.as_bytes()));
    }
}

#[test]
fn production_bootstrap_rejects_chatter_truncation_nonzero_and_noisy_stderr() {
    let temp = TempDir::new("proxy-failures");
    write_fake_ssh(
        &temp,
        r#"#!/bin/sh
is_query=no
for arg in "$@"; do [ "$arg" = "-G" ] && is_query=yes; done
if [ "$is_query" = yes ]; then
  [ -n "$FAKE_CALLS" ] && printf 'query\n' >> "$FAKE_CALLS"
  case "$FAKE_QUERY_MODE" in
    proxy) printf 'proxyjump jump.example\n'; exit 0 ;;
    nonzero) exit 7 ;;
    malformed) printf 'malformed\n'; exit 0 ;;
    overflow) i=0; while [ "$i" -lt 70000 ]; do printf x; i=$((i + 1)); done; exit 0 ;;
  esac
  printf 'hostname fake\n'; exit 0
fi
[ -n "$FAKE_CALLS" ] && printf 'actual\n' >> "$FAKE_CALLS"
case "$FAKE_MODE" in
  chatter) printf 'junk\njunk\n'; exit 0 ;;
  overflow) i=0; while [ "$i" -lt 5000 ]; do printf x; i=$((i + 1)); done; exit 0 ;;
  truncated) printf 'everlink v1 '; exit 0 ;;
  nonzero) printf 'everlink v1 127.0.0.1 4444 0000000000000000000000000000000000000000000000000000000000000000 0000000000000000000000000000000000000000000000000000000000000000 1\n'; exit 7 ;;
  noisy) i=0; while [ "$i" -lt 20000 ]; do printf x >&2; i=$((i + 1)); done; exit 9 ;;
  empty) exit 0 ;;
  timeout) printf '%s' "$$" > "$FAKE_PID"; exec sleep 30 ;;
esac
exit 10
"#,
    );
    for mode in [
        "chatter",
        "overflow",
        "truncated",
        "nonzero",
        "noisy",
        "empty",
    ] {
        let output = Command::new(BIN)
            .args(["ssh-proxy", "alias", "22"])
            .env("PATH", fake_path(&temp))
            .env("FAKE_MODE", mode)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        assert!(!output.status.success(), "{mode} unexpectedly succeeded");
        assert!(output.stdout.is_empty(), "{mode} contaminated stdout");
        assert!(
            output.stderr.len() < 1024,
            "{mode} diagnostics were not capped"
        );
        if mode == "overflow" {
            assert_eq!(output.stderr, b"everlink: malformed bootstrap record\n");
        }
    }

    for query_mode in ["proxy", "nonzero", "malformed", "overflow"] {
        let calls = temp.0.join(format!("calls-{query_mode}"));
        let output = Command::new(BIN)
            .args(["ssh-proxy", "alias", "22"])
            .env("PATH", fake_path(&temp))
            .env("FAKE_QUERY_MODE", query_mode)
            .env("FAKE_CALLS", &calls)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "query mode {query_mode} succeeded"
        );
        assert!(output.stdout.is_empty());
        assert!(output.stderr.len() < 1024);
        if query_mode == "overflow" {
            assert_eq!(
                output.stderr,
                b"everlink: effective SSH proxy configuration is not permitted\n"
            );
        }
        assert_eq!(fs::read_to_string(calls).unwrap(), "query\n");
    }

    let fake_pid = temp.0.join("timeout-pid");
    let started = Instant::now();
    let output = Command::new(BIN)
        .args(["ssh-proxy", "alias", "22"])
        .env("PATH", fake_path(&temp))
        .env("FAKE_MODE", "timeout")
        .env("FAKE_PID", &fake_pid)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.len() < 1024);
    assert!(started.elapsed() < Duration::from_secs(30));
    let pid: u32 = fs::read_to_string(fake_pid).unwrap().parse().unwrap();
    wait_pid_gone(pid, Duration::from_secs(3));
}
