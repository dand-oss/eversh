//! Real process composition: PTY, broker, detached gateway, and QUIC client.
//! Only OpenSSH is replaced by a localhost shim so no host daemon or account
//! configuration is required by this gate.
#![cfg(all(target_os = "linux", feature = "cli"))]
#![allow(clippy::unwrap_used)]

use everpty::run::{self, Context};
use everpty::sys;
use everssh::association::AssociationId;
use everudp::wire::ConnectionRole;
use everudp::{
    BootstrapOperation, BootstrapRecord, BootstrapRequest, ClientEndpoint, ClientHello,
    ClientIdentity, Limits, ResumePosition,
};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::AsFd;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

#[path = "support/exit_snapshot.rs"]
mod exit_snapshot;

static NEXT: AtomicU64 = AtomicU64::new(0);
static PROCESS_GATE: Mutex<()> = Mutex::new(());

fn process_gate() -> MutexGuard<'static, ()> {
    PROCESS_GATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

const SSH_SHIM: &str = r#"#!/bin/sh
set -eu
for argument in "$@"; do
  if [ "$argument" = "-G" ]; then
    printf 'hostname localhost\nproxycommand none\nproxyjump none\n'
    exit 0
  fi
done
remote=
for argument in "$@"; do remote=$argument; done
[ -n "$remote" ] || exit 255
export SSH_CONNECTION='127.0.0.1 40000 SERVER_IP 22'
exec /bin/sh -c "$remote"
"#;

struct Fixture {
    root: std::path::PathBuf,
    state: std::path::PathBuf,
    bin: std::path::PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        let root = loop {
            let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
            let candidate = std::env::temp_dir()
                .join(format!("everudp-process-{}-{sequence}", std::process::id()));
            match builder.create(&candidate) {
                Ok(()) => break candidate,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("fixture: {error}"),
            }
        };
        let bin = root.join("bin");
        builder.create(&bin).unwrap();
        let ssh = bin.join("ssh");
        fs::write(&ssh, SSH_SHIM.replace("SERVER_IP", &route_selected_ip())).unwrap();
        fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            state: root.join("state"),
            root,
            bin,
        }
    }

    fn pty_context(&self) -> Context {
        Context {
            state_candidates: vec![self.state.clone()],
            limits: everpty::Limits::default(),
        }
    }

    fn kill_session(&self, name: &str) {
        run::kill(&self.pty_context(), name)
            .unwrap_or_else(|error| panic!("kill qualification session {name}: {error}"));
    }

    fn private_application_dir(&self, name: &str) -> std::path::PathBuf {
        let path = self.root.join(name);
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(&path).unwrap_or_else(|error| {
            panic!("create application fixture directory {path:?}: {error}")
        });
        path
    }
}

fn route_selected_ip() -> String {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.connect("192.0.2.1:9").unwrap();
    let ip = socket.local_addr().unwrap().ip();
    assert!(
        !ip.is_loopback(),
        "process gate needs a routed local address"
    );
    ip.to_string()
}

fn find_gateway_pid(fixture: &Fixture) -> Option<u32> {
    let state = fixture.state.to_string_lossy();
    fs::read_dir("/proc")
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_string_lossy().parse::<u32>().ok())
        .find(|pid| {
            let command = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
            let arguments: Vec<_> = command
                .split(|byte| *byte == 0)
                .filter(|argument| !argument.is_empty())
                .collect();
            arguments
                .iter()
                .any(|argument| *argument == everudp::GATEWAY_ROLE.as_bytes())
                && arguments
                    .iter()
                    .any(|argument| *argument == state.as_bytes())
        })
}

fn kill_gateway(fixture: &Fixture) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let pid = loop {
        if let Some(pid) = find_gateway_pid(fixture) {
            break pid;
        }
        assert!(
            Instant::now() < deadline,
            "detached everudp gateway did not appear"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(Command::new("/bin/kill")
        .args(["-KILL", &pid.to_string()])
        .status()
        .unwrap()
        .success());
    while std::path::Path::new(&format!("/proc/{pid}")).exists() {
        assert!(
            Instant::now() < deadline,
            "detached everudp gateway did not exit"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[derive(Clone, Copy, Debug)]
struct ProcessResources {
    fds: usize,
    tasks: usize,
    rss_kib: u64,
}

fn gateway_resources(pid: u32) -> ProcessResources {
    let process = std::path::PathBuf::from(format!("/proc/{pid}"));
    let status = fs::read_to_string(process.join("status")).expect("gateway status");
    let rss_kib = status
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmRSS:")
                .and_then(|value| value.trim_end_matches(" kB").trim().parse().ok())
        })
        .expect("gateway status must report VmRSS");
    ProcessResources {
        fds: fs::read_dir(process.join("fd"))
            .expect("gateway fds")
            .count(),
        tasks: fs::read_dir(process.join("task"))
            .expect("gateway tasks")
            .count(),
        rss_kib,
    }
}

fn range(samples: &[u64]) -> u64 {
    samples.iter().max().expect("resource samples")
        - samples.iter().min().expect("resource samples")
}

fn hostile_observer_input(fixture: &Fixture) {
    let limits = Limits::default();
    let identity = ClientIdentity::generate().unwrap();
    let association_id = AssociationId::generate().unwrap();
    let request = BootstrapRequest::new(
        BootstrapOperation::Observe,
        "process-test".to_owned(),
        ConnectionRole::Observer,
        false,
        0,
        0,
        association_id,
        identity.spki_sha256(),
        "badger".to_owned(),
        Vec::new(),
        String::new(),
    )
    .unwrap();
    let remote = format!(
        "{} {} {}",
        env!("CARGO_BIN_EXE_everudp"),
        everudp::BOOTSTRAP_PARENT_ROLE,
        request.encode_token().unwrap()
    );
    let output = Command::new(fixture.bin.join("ssh"))
        .env("EVERSH_STATE_DIR", &fixture.state)
        .env("PATH", "/usr/bin:/bin")
        .env("SHELL", "/bin/sh")
        .args(["localhost", remote.as_str()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "hostile bootstrap: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let record =
        BootstrapRecord::parse_line(&String::from_utf8(output.stdout).unwrap(), &limits).unwrap();
    let hello = ClientHello::initial(
        association_id,
        record.generation(),
        ConnectionRole::Observer,
        ResumePosition {
            input_epoch: 0,
            next_input: 0,
            output_epoch: 0,
            next_output: 0,
            delivered_output_ack: 0,
        },
        record.token().clone(),
    )
    .unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async move {
        let endpoint = ClientEndpoint::bind(
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            &identity,
            record.server_spki_sha256(),
            limits,
        )
        .unwrap();
        let session = endpoint
            .connect_initial(record.endpoint(), &hello)
            .await
            .unwrap();
        let (connection, _, _) = session.into_parts();
        let mut forbidden = connection.open_uni().await.unwrap();
        forbidden
            .write_all(b"forbidden observer input")
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), connection.closed())
            .await
            .expect("gateway did not isolate hostile observer");
    });
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let context = self.pty_context();
        if let Ok(sessions) = run::list(&context) {
            for session in sessions {
                let _ = run::kill(&context, session.name());
            }
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct RunningClient {
    label: String,
    child: std::process::Child,
    master: File,
    stderr_path: std::path::PathBuf,
    status_path: std::path::PathBuf,
    transcript: Vec<u8>,
}

impl RunningClient {
    fn spawn(fixture: &Fixture, label: &str, arguments: &[&str]) -> Self {
        Self::spawn_with_options(fixture, label, arguments, None, &[])
    }

    fn spawn_with_options(
        fixture: &Fixture,
        label: &str,
        arguments: &[&str],
        current_dir: Option<&Path>,
        environment: &[(&str, &Path)],
    ) -> Self {
        let (master, slave) = sys::openpty(24, 80).unwrap();
        let stderr_path = fixture.root.join(format!("{label}.stderr"));
        let status_path = fixture.root.join(format!("{label}.status"));
        let stderr = File::create(&stderr_path).unwrap();
        let stdin = File::from(slave.try_clone().unwrap());
        let stdout = File::from(slave);
        let path = format!("{}:/usr/bin:/bin", fixture.bin.display());
        let mut child = Command::new(env!("CARGO_BIN_EXE_everudp"));
        child
            .env_clear()
            .env("EVERSH_STATE_DIR", &fixture.state)
            .env("EVERUDP_EXIT_TRACE", fixture.root.join("exit.trace"))
            .env("PATH", path)
            .env("SHELL", "/bin/sh")
            .env("TERM", "xterm-256color")
            .stdin(Stdio::from(stdin))
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .args(["--remote-program", env!("CARGO_BIN_EXE_everudp")]);
        if let Some(current_dir) = current_dir {
            child.current_dir(current_dir);
        }
        for (name, value) in environment {
            child.env(name, value);
        }
        let child_boundary = arguments
            .iter()
            .position(|argument| *argument == "--")
            .unwrap_or(arguments.len());
        child
            .args(&arguments[..child_boundary])
            .arg("--status-file")
            .arg(&status_path)
            .args(&arguments[child_boundary..]);
        unsafe {
            child.pre_exec(|| {
                everpty::sys::child_setsid().map_err(std::io::Error::from_raw_os_error)?;
                everpty::sys::set_controlling_tty(0).map_err(std::io::Error::from_raw_os_error)
            });
        }
        let child = child.spawn().unwrap();
        let master = File::from(master);
        sys::set_nonblocking(master.as_fd()).unwrap();
        Self {
            label: label.to_owned(),
            child,
            master,
            stderr_path,
            status_path,
            transcript: Vec::new(),
        }
    }

    fn wait_connected(&mut self) {
        let startup_deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let status = fs::read_to_string(&self.status_path).unwrap_or_default();
            if status.contains("everudp-status-v1 state connected") {
                return;
            }
            if let Some(exit) = self.child.try_wait().unwrap() {
                panic!(
                    "everudp {} exited before activation: {exit}; status={status:?}; stderr={}; snapshot={}; trace={}",
                    self.label,
                    self.stderr(),
                    exit_snapshot::snapshot(&self.status_path.parent().unwrap().join("state")),
                    fs::read_to_string(self.status_path.parent().unwrap().join("exit.trace"))
                        .unwrap_or_default()
                );
            }
            if Instant::now() >= startup_deadline {
                panic!(
                    "everudp {} activation timed out; status={status:?}; stderr={}",
                    self.label,
                    self.stderr()
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn send(&mut self, bytes: &[u8]) {
        self.master.write_all(bytes).unwrap();
    }

    fn pump(&mut self) {
        let mut buffer = [0_u8; 4096];
        loop {
            match self.master.read(&mut buffer) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Ok(0) => return,
                Ok(count) => self.transcript.extend_from_slice(&buffer[..count]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return,
                // Linux PTY masters report EIO once the final slave closes.
                Err(error) if error.raw_os_error() == Some(5) => return,
                Err(error) => panic!("PTY read: {error}"),
            }
        }
    }

    fn wait_for_bytes(&mut self, expected: &[u8]) {
        self.wait_for_bytes_within(expected, Duration::from_secs(15));
    }

    fn wait_for_bytes_within(&mut self, expected: &[u8], timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            self.pump();
            if self
                .transcript
                .windows(expected.len())
                .any(|window| window == expected)
            {
                return;
            }
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!(
                    "everudp {} exited as {status} before {:?}; transcript-bytes={}; tail={:?}; stderr={}",
                    self.label,
                    String::from_utf8_lossy(expected),
                    self.transcript.len(),
                    self.transcript_tail(),
                    self.stderr()
                );
            }
            if Instant::now() >= deadline {
                panic!(
                    "everudp {} output timed out before {:?}; status={:?}; transcript-bytes={}; tail={:?}; stderr={}",
                    self.label,
                    String::from_utf8_lossy(expected),
                    fs::read_to_string(&self.status_path).unwrap_or_default(),
                    self.transcript.len(),
                    self.transcript_tail(),
                    self.stderr()
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait_for_transcript_bytes(&mut self, minimum: usize, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            self.pump();
            if self.transcript.len() >= minimum {
                return;
            }
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!(
                    "everudp {} exited as {status} after only {} transcript bytes; stderr={}",
                    self.label,
                    self.transcript.len(),
                    self.stderr()
                );
            }
            assert!(
                Instant::now() < deadline,
                "everudp {} produced only {} transcript bytes; stderr={}",
                self.label,
                self.transcript.len(),
                self.stderr()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn interrupt_tui(&mut self) -> std::process::ExitStatus {
        for _ in 0..4 {
            self.send(b"\x03");
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                self.pump();
                if let Some(status) = self.child.try_wait().unwrap() {
                    self.pump();
                    return status;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        self.wait_for_exit()
    }

    fn wait_for_exit(&mut self) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            self.pump();
            if let Some(status) = self.child.try_wait().unwrap() {
                self.pump();
                return status;
            }
            if Instant::now() >= deadline {
                panic!(
                    "everudp {} exit timed out; transcript-bytes={}; tail={:?}; stderr={}; link-states={:?}; processes={}; exit-events={}",
                    self.label,
                    self.transcript.len(),
                    self.transcript_tail(),
                    self.stderr(),
                    exit_snapshot::link_states(&self.status_path),
                    exit_snapshot::snapshot(&self.status_path.parent().unwrap().join("state")),
                    fs::read_to_string(self.status_path.parent().unwrap().join("exit.trace")).unwrap_or_default()
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn cancel(&mut self) -> std::process::ExitStatus {
        let status = Command::new("/bin/kill")
            .arg("-TERM")
            .arg(self.child.id().to_string())
            .status()
            .unwrap();
        assert!(status.success());
        self.wait_for_exit()
    }

    fn stderr(&self) -> String {
        fs::read_to_string(&self.stderr_path).unwrap_or_default()
    }

    fn transcript_tail(&self) -> String {
        let start = self.transcript.len().saturating_sub(512);
        String::from_utf8_lossy(&self.transcript[start..]).into_owned()
    }
}

impl Drop for RunningClient {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[test]
fn standalone_client_composes_real_gateway_broker_and_quic() {
    let _serial = process_gate();
    let fixture = Fixture::new();
    let mut client = RunningClient::spawn(
        &fixture,
        "writer",
        &[
            "connect",
            "localhost",
            "--session",
            "process-test",
            "--",
            "/bin/sh",
            "-c",
            "IFS= read -r line; printf 'GOT:%s\\n' \"$line\"; exit 23",
        ],
    );
    client.wait_connected();
    client.send(b"ping\n");
    client.wait_for_bytes(b"GOT:ping");
    let status = client.wait_for_exit();

    assert_eq!(
        status.code(),
        Some(23),
        "transcript={:?}; stderr={}",
        String::from_utf8_lossy(&client.transcript),
        client.stderr()
    );
}

#[test]
fn persistent_gateway_fans_future_output_to_a_concurrent_observer() {
    let _serial = process_gate();
    let fixture = Fixture::new();
    let mut writer = RunningClient::spawn(
        &fixture,
        "writer",
        &[
            "connect",
            "localhost",
            "--session",
            "process-test",
            "--",
            "/bin/sh",
            "-c",
            "while IFS= read -r line; do printf 'OUT:%s\\n' \"$line\"; [ \"$line\" != quit ] || exit 17; done",
        ],
    );
    writer.wait_connected();
    writer.send(b"before\n");
    writer.wait_for_bytes(b"OUT:before");
    let mut observer = RunningClient::spawn(
        &fixture,
        "observer",
        &["observe", "localhost", "process-test"],
    );
    observer.wait_connected();

    writer.send(b"fanout\n");
    writer.wait_for_bytes(b"OUT:fanout");
    observer.wait_for_bytes(b"OUT:fanout");
    writer.send(b"quit\n");
    assert_eq!(writer.wait_for_exit().code(), Some(17));
    assert_eq!(observer.wait_for_exit().code(), Some(17));

    assert!(
        observer
            .transcript
            .windows(b"OUT:fanout".len())
            .any(|window| window == b"OUT:fanout"),
        "transcript={:?}; stderr={}",
        String::from_utf8_lossy(&observer.transcript),
        observer.stderr()
    );
}

#[test]
fn explicit_takeover_revokes_the_old_writer_and_new_writer_is_future_only() {
    let _serial = process_gate();
    let fixture = Fixture::new();
    let mut original = RunningClient::spawn(
        &fixture,
        "original",
        &[
            "connect",
            "localhost",
            "--session",
            "process-test",
            "--",
            "/bin/sh",
            "-c",
            "while IFS= read -r line; do printf 'OUT:%s\\n' \"$line\"; [ \"$line\" != quit ] || exit 19; done",
        ],
    );
    original.wait_connected();
    original.send(b"original\n");
    original.wait_for_bytes(b"OUT:original");

    let mut replacement = RunningClient::spawn(
        &fixture,
        "replacement",
        &["attach", "localhost", "process-test", "--take-over"],
    );
    replacement.wait_connected();
    assert_eq!(original.wait_for_exit().code(), Some(4));

    replacement.send(b"replacement\n");
    replacement.wait_for_bytes(b"OUT:replacement");
    replacement.send(b"quit\n");
    assert_eq!(replacement.wait_for_exit().code(), Some(19));
    assert_eq!(
        replacement
            .stderr()
            .matches("everudp: output skipped during network outage")
            .count(),
        1
    );
}

#[test]
fn disconnected_writer_generation_is_replaced_without_takeover() {
    let _serial = process_gate();
    let fixture = Fixture::new();
    let mut original = RunningClient::spawn(
        &fixture,
        "original",
        &[
            "connect",
            "localhost",
            "--session",
            "process-test",
            "--",
            "/bin/sh",
            "-c",
            "while IFS= read -r line; do printf 'OUT:%s\\n' \"$line\"; [ \"$line\" != quit ] || exit 29; done",
        ],
    );
    original.wait_connected();
    original.send(b"original\n");
    original.wait_for_bytes(b"OUT:original");
    assert_eq!(original.cancel().code(), Some(143));

    // The local QUIC close makes the old association disconnected before a
    // resume-all replacement presents its fresh one-use invitation.
    std::thread::sleep(Duration::from_millis(250));
    let mut replacement = RunningClient::spawn(
        &fixture,
        "replacement",
        &["attach", "localhost", "process-test"],
    );
    replacement.wait_connected();
    replacement.send(b"replacement\n");
    replacement.wait_for_bytes(b"OUT:replacement");
    replacement.send(b"quit\n");
    assert_eq!(replacement.wait_for_exit().code(), Some(29));
    assert_eq!(
        replacement
            .stderr()
            .matches("everudp: output skipped during network outage")
            .count(),
        1
    );
}

#[test]
fn observer_first_replacement_gateway_keeps_a_writer_capable_broker_edge() {
    let _serial = process_gate();
    let fixture = Fixture::new();
    let mut original = RunningClient::spawn(
        &fixture,
        "original",
        &[
            "connect",
            "localhost",
            "--session",
            "process-test",
            "--",
            "/bin/sh",
            "-c",
            "while IFS= read -r line; do printf 'OUT:%s\\n' \"$line\"; [ \"$line\" != quit ] || exit 43; done",
        ],
    );
    original.wait_connected();
    original.send(b"original\n");
    original.wait_for_bytes(b"OUT:original");
    assert_eq!(original.cancel().code(), Some(143));
    std::thread::sleep(Duration::from_millis(250));
    kill_gateway(&fixture);

    // The first association on the replacement gateway is read-only. The
    // gateway must nevertheless claim the broker's persistent writer edge so
    // a later network writer can deliver input without replacing the gateway.
    let mut observer = RunningClient::spawn(
        &fixture,
        "observer-first",
        &["observe", "localhost", "process-test"],
    );
    observer.wait_connected();
    let mut replacement = RunningClient::spawn(
        &fixture,
        "replacement",
        &["attach", "localhost", "process-test"],
    );
    replacement.wait_connected();
    replacement.send(b"replacement\n");
    replacement.wait_for_bytes(b"OUT:replacement");
    observer.wait_for_bytes(b"OUT:replacement");
    replacement.send(b"quit\n");
    assert_eq!(replacement.wait_for_exit().code(), Some(43));
    assert_eq!(observer.wait_for_exit().code(), Some(43));
}

#[test]
fn flow_controlled_observer_never_stalls_writer_or_pty_drain() {
    let _serial = process_gate();
    let fixture = Fixture::new();
    let mut writer = RunningClient::spawn(
        &fixture,
        "writer",
        &[
            "connect",
            "localhost",
            "--session",
            "process-test",
            "--",
            "/bin/sh",
            "-c",
            "chunk=$(yes 0123456789abcdef | head -c 16384); while IFS= read -r line; do if [ \"$line\" = burst ]; then i=0; while [ \"$i\" -lt 288 ]; do printf '%s' \"$chunk\"; i=$((i + 1)); sleep 0.03; done; printf '\\nTAIL\\n'; else exit 23; fi; done",
        ],
    );
    writer.wait_connected();
    let mut observer = RunningClient::spawn(
        &fixture,
        "observer",
        &["observe", "localhost", "process-test"],
    );
    observer.wait_connected();

    // Never read the observer PTY. Its local stdout, QUIC receive window, and
    // gateway output stream all become flow-controlled while the writer keeps
    // consuming the same fanout and reaches the marker at the end.
    writer.send(b"burst\n");
    writer.wait_for_bytes_within(b"TAIL", Duration::from_secs(40));
    assert_eq!(
        writer
            .stderr()
            .matches("everudp: output skipped during network outage")
            .count(),
        0,
        "a slow observer must not gap the healthy writer"
    );

    assert_eq!(observer.cancel().code(), Some(143));
    writer.send(b"quit\n");
    assert_eq!(writer.wait_for_exit().code(), Some(23));
}

#[test]
fn hostile_observer_is_closed_without_disturbing_the_writer() {
    let _serial = process_gate();
    let fixture = Fixture::new();
    let mut writer = RunningClient::spawn(
        &fixture,
        "writer",
        &[
            "connect",
            "localhost",
            "--session",
            "process-test",
            "--",
            "/bin/sh",
            "-c",
            "while IFS= read -r line; do printf 'OUT:%s\\n' \"$line\"; [ \"$line\" != quit ] || exit 31; done",
        ],
    );
    writer.wait_connected();

    hostile_observer_input(&fixture);

    writer.send(b"survived\n");
    writer.wait_for_bytes(b"OUT:survived");
    writer.send(b"quit\n");
    assert_eq!(writer.wait_for_exit().code(), Some(31));
}

#[test]
fn active_writer_rejects_non_takeover_without_udp_fallback_code() {
    let _serial = process_gate();
    let fixture = Fixture::new();
    let mut writer = RunningClient::spawn(
        &fixture,
        "writer",
        &[
            "connect",
            "localhost",
            "--session",
            "process-test",
            "--",
            "/bin/sh",
            "-c",
            "while IFS= read -r line; do printf 'OUT:%s\\n' \"$line\"; [ \"$line\" != quit ] || exit 37; done",
        ],
    );
    writer.wait_connected();

    let mut contender = RunningClient::spawn(
        &fixture,
        "contender",
        &["attach", "localhost", "process-test"],
    );
    let rejected = contender.wait_for_exit();
    assert_ne!(
        rejected.code(),
        Some(i32::from(everudp::UDP_UNREACHABLE_EXIT)),
        "a busy authenticated gateway is not UDP unreachability; stderr={}",
        contender.stderr()
    );

    writer.send(b"survived\n");
    writer.wait_for_bytes(b"OUT:survived");
    writer.send(b"quit\n");
    assert_eq!(writer.wait_for_exit().code(), Some(37));
}

#[test]
fn observer_capacity_is_eight_and_rejection_is_connection_local() {
    let _serial = process_gate();
    let fixture = Fixture::new();
    let mut writer = RunningClient::spawn(
        &fixture,
        "writer",
        &[
            "connect",
            "localhost",
            "--session",
            "process-test",
            "--",
            "/bin/sh",
            "-c",
            "while IFS= read -r line; do printf 'OUT:%s\\n' \"$line\"; [ \"$line\" != quit ] || exit 41; done",
        ],
    );
    writer.wait_connected();

    let mut observers = Vec::new();
    for index in 0..8 {
        let label = format!("observer-{index}");
        let mut observer =
            RunningClient::spawn(&fixture, &label, &["observe", "localhost", "process-test"]);
        observer.wait_connected();
        observers.push(observer);
    }
    let mut ninth = RunningClient::spawn(
        &fixture,
        "observer-8",
        &["observe", "localhost", "process-test"],
    );
    let rejected = ninth.wait_for_exit();
    assert_ne!(
        rejected.code(),
        Some(i32::from(everudp::UDP_UNREACHABLE_EXIT)),
        "capacity is authenticated rejection, not UDP unreachability"
    );

    writer.send(b"survived\n");
    writer.wait_for_bytes(b"OUT:survived");
    for observer in &mut observers {
        assert_eq!(observer.cancel().code(), Some(143));
    }
    for index in 9..19 {
        let label = format!("observer-{index}");
        let mut observer =
            RunningClient::spawn(&fixture, &label, &["observe", "localhost", "process-test"]);
        observer.wait_connected();
        assert_eq!(observer.cancel().code(), Some(143));
    }
    writer.send(b"quit\n");
    assert_eq!(writer.wait_for_exit().code(), Some(41));
}

#[test]
fn sequential_writer_replacements_leave_gateway_resources_bounded() {
    let _serial = process_gate();
    let fixture = Fixture::new();
    let command = [
        "connect",
        "localhost",
        "--session",
        "process-test",
        "--",
        "/bin/sh",
        "-c",
        "while IFS= read -r line; do printf 'OUT:%s\\n' \"$line\"; [ \"$line\" != quit ] || exit 47; done",
    ];
    let mut writer = RunningClient::spawn(&fixture, "writer-0", &command);
    writer.wait_connected();
    let gateway_pid = find_gateway_pid(&fixture).expect("persistent gateway");
    let mut samples = Vec::new();

    for generation in 0..12 {
        let marker = format!("generation-{generation}");
        writer.send(format!("{marker}\n").as_bytes());
        writer.wait_for_bytes(format!("OUT:{marker}").as_bytes());
        let sample = gateway_resources(gateway_pid);
        assert!(sample.fds <= 32, "gateway fd ceiling: {sample:?}");
        assert!(sample.tasks <= 4, "gateway task ceiling: {sample:?}");
        assert!(
            sample.rss_kib <= 96 * 1024,
            "gateway RSS ceiling: {sample:?}"
        );
        samples.push(sample);

        if generation != 11 {
            assert_eq!(writer.cancel().code(), Some(143));
            std::thread::sleep(Duration::from_millis(100));
            let label = format!("writer-{}", generation + 1);
            writer =
                RunningClient::spawn(&fixture, &label, &["attach", "localhost", "process-test"]);
            writer.wait_connected();
            assert_eq!(
                find_gateway_pid(&fixture),
                Some(gateway_pid),
                "writer replacement must reuse the persistent gateway"
            );
        }
    }

    let plateau = &samples[3..];
    let rss: Vec<_> = plateau.iter().map(|sample| sample.rss_kib).collect();
    let fds: Vec<_> = plateau
        .iter()
        .map(|sample| u64::try_from(sample.fds).unwrap())
        .collect();
    let tasks: Vec<_> = plateau
        .iter()
        .map(|sample| u64::try_from(sample.tasks).unwrap())
        .collect();
    assert!(
        range(&rss) <= 8 * 1024,
        "gateway RSS did not plateau: {rss:?}"
    );
    assert!(
        range(&fds) <= 4,
        "gateway descriptors did not plateau: {fds:?}"
    );
    assert_eq!(range(&tasks), 0, "gateway tasks did not plateau: {tasks:?}");

    writer.send(b"quit\n");
    assert_eq!(writer.wait_for_exit().code(), Some(47));
    println!(
        "everudp-resource-bounds: PASS generations={} peak_fds={} peak_tasks={} peak_rss_kib={} rss_plateau_kib={}",
        samples.len(),
        samples.iter().map(|sample| sample.fds).max().unwrap(),
        samples.iter().map(|sample| sample.tasks).max().unwrap(),
        samples.iter().map(|sample| sample.rss_kib).max().unwrap(),
        range(&rss),
    );
}

fn require_qualification_binary(variable: &str) -> String {
    let value = std::env::var(variable)
        .unwrap_or_else(|_| panic!("qualification requires {variable}=ABSOLUTE_PATH"));
    let metadata = fs::metadata(&value)
        .unwrap_or_else(|error| panic!("qualification binary {value}: {error}"));
    assert!(
        metadata.is_file(),
        "qualification binary is not a file: {value}"
    );
    assert!(
        metadata.permissions().mode() & 0o111 != 0,
        "qualification binary is not executable: {value}"
    );
    value
}

fn assert_no_gap(client: &RunningClient) {
    assert_eq!(
        client
            .stderr()
            .matches("everudp: output skipped during network outage")
            .count(),
        0,
        "application smoke required an injected repaint: {}",
        client.stderr()
    );
}

#[test]
fn application_fixture_isolates_working_directory_and_codex_home() {
    let _serial = process_gate();
    let fixture = Fixture::new();
    let workspace = fixture.private_application_dir("application-regression-workspace");
    let codex_home = fixture.private_application_dir("application-regression-codex-home");
    let workspace_text = workspace.to_string_lossy().into_owned();
    let codex_home_text = codex_home.to_string_lossy().into_owned();
    let mut client = RunningClient::spawn_with_options(
        &fixture,
        "application-regression",
        &[
            "connect",
            "localhost",
            "--session",
            "application-regression",
            "--",
            "/bin/sh",
            "-c",
            "printf 'cwd=%s\\ncodex_home=%s\\n' \"$PWD\" \"$CODEX_HOME\"",
        ],
        Some(&workspace),
        &[("CODEX_HOME", &codex_home)],
    );
    client.wait_connected();
    client.wait_for_bytes(workspace_text.as_bytes());
    client.wait_for_bytes(codex_home_text.as_bytes());
    assert!(
        client.wait_for_exit().success(),
        "isolated application command failed: stderr={}",
        client.stderr()
    );
    assert_no_gap(&client);
}

#[test]
#[ignore = "qualification-only: requires installed tmux, nvim, Claude Code, and Codex"]
fn installed_terminal_applications_cross_everudp_without_repaint() {
    let _serial = process_gate();
    let fixture = Fixture::new();
    let claude = require_qualification_binary("EVERUDP_CLAUDE_BIN");
    let codex = require_qualification_binary("EVERUDP_CODEX_BIN");

    let mut shell = RunningClient::spawn(
        &fixture,
        "application-shell",
        &[
            "connect",
            "localhost",
            "--session",
            "application-shell",
            "--",
            "/bin/sh",
            "-i",
        ],
    );
    shell.wait_connected();
    shell.send(b"printf 'EVERUDP-SHELL-PASS\\n'\nexit\n");
    shell.wait_for_bytes(b"EVERUDP-SHELL-PASS");
    assert!(shell.wait_for_exit().success());
    assert_no_gap(&shell);

    let tmux_socket = format!("everudp-{}", std::process::id());
    let mut tmux = RunningClient::spawn(
        &fixture,
        "application-tmux",
        &[
            "connect",
            "localhost",
            "--session",
            "application-tmux",
            "--",
            "/usr/bin/env",
            "-u",
            "TMUX",
            "/usr/bin/tmux",
            "-L",
            &tmux_socket,
            "-f",
            "/dev/null",
            "new-session",
            "/bin/sh",
            "-i",
        ],
    );
    tmux.wait_connected();
    tmux.send(b"printf 'EVERUDP-TMUX-PASS\\n'\n");
    tmux.wait_for_bytes(b"EVERUDP-TMUX-PASS");
    tmux.send(b"exit\n");
    assert!(tmux.wait_for_exit().success());
    assert_no_gap(&tmux);

    let mut nvim = RunningClient::spawn(
        &fixture,
        "application-nvim",
        &[
            "connect",
            "localhost",
            "--session",
            "application-nvim",
            "--",
            "/usr/bin/nvim",
            "--clean",
            "-n",
        ],
    );
    nvim.wait_connected();
    nvim.send(b":echo 'EVERUDP-NVIM-PASS'\r");
    nvim.wait_for_bytes(b"EVERUDP-NVIM-PASS");
    nvim.send(b":qa!\r");
    assert!(nvim.wait_for_exit().success());
    assert_no_gap(&nvim);

    let claude_workspace = fixture.private_application_dir("claude-workspace");
    let claude_config = fixture.private_application_dir("claude-config");
    let mut claude_client = RunningClient::spawn_with_options(
        &fixture,
        "application-claude",
        &[
            "connect",
            "localhost",
            "--session",
            "application-claude",
            "--",
            &claude,
            "--no-chrome",
        ],
        Some(&claude_workspace),
        &[("CLAUDE_CONFIG_DIR", &claude_config)],
    );
    claude_client.wait_connected();
    claude_client.wait_for_transcript_bytes(256, Duration::from_secs(20));
    fixture.kill_session("application-claude");
    let _ = claude_client.wait_for_exit();
    assert_no_gap(&claude_client);

    let codex_workspace = fixture.private_application_dir("codex-workspace");
    let codex_home = fixture.private_application_dir("codex-home");
    let codex_workspace_text = codex_workspace.to_string_lossy().into_owned();
    let mut codex_client = RunningClient::spawn_with_options(
        &fixture,
        "application-codex",
        &[
            "connect",
            "localhost",
            "--session",
            "application-codex",
            "--",
            &codex,
            "--config",
            "cli_auth_credentials_store=\"file\"",
            "--no-alt-screen",
            "--cd",
            &codex_workspace_text,
        ],
        Some(&codex_workspace),
        &[("CODEX_HOME", &codex_home)],
    );
    codex_client.wait_connected();
    codex_client.wait_for_transcript_bytes(256, Duration::from_secs(20));
    let _ = codex_client.interrupt_tui();
    assert_no_gap(&codex_client);

    println!(
        "everudp-application-compatibility: PASS shell={} tmux={} nvim={} claude={} codex={} repaint_injections=0",
        shell.transcript.len(),
        tmux.transcript.len(),
        nvim.transcript.len(),
        claude_client.transcript.len(),
        codex_client.transcript.len(),
    );
}
