//! Real combined-binary composition for the direct everudp transport.
//!
//! OpenSSH alone is replaced by a localhost shim. The test still runs the
//! public `eversh` supervisor, its `__everudp` client and remote roles, a
//! detached gateway, a real everpty broker, and the QUIC data plane.
#![cfg(all(target_os = "linux", feature = "cli"))]
#![allow(clippy::unwrap_used)]

use everpty::sys;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

#[path = "../../everudp/tests/support/exit_snapshot.rs"]
mod exit_snapshot;

static NEXT: AtomicU64 = AtomicU64::new(0);
static PROCESS_GATE: Mutex<()> = Mutex::new(());

const UDP_UNREACHABLE_EXIT: i32 = 69;
const FALLBACK_EXIT: i32 = 47;
const FALLBACK_NOTICE: &str =
    "eversh: direct UDP unavailable before commit; falling back once to everssh";

fn binary() -> &'static OsStr {
    OsStr::new(env!("CARGO_BIN_EXE_eversh"))
}

fn process_gate() -> MutexGuard<'static, ()> {
    PROCESS_GATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The shim records only invocation classes, never argument vectors or the
/// one-use bootstrap token. `blackhole` obtains a genuine signed bootstrap
/// record, kills that gateway, and substitutes an unroutable endpoint so the
/// real client owns the three-second pre-commit UDP deadline.
const SSH_SHIM: &str = r#"#!/bin/sh
set -eu

for argument in "$@"; do
  if [ "$argument" = "-G" ]; then
    printf 'hostname localhost\nproxycommand none\nproxyjump none\n'
    exit 0
  fi
done

for argument in "$@"; do
  case "$argument" in
    ProxyCommand=*__everssh*)
      printf '%s\n' everssh-fallback >> "$FAKE_EVERUDP_LOG"
      exit 47
      ;;
  esac
done

remote=
for argument in "$@"; do remote=$argument; done
[ -n "$remote" ] || exit 255
case "$remote" in
  *" __everudp __bootstrap-parent-v1 "*)
    printf '%s\n' everudp-bootstrap >> "$FAKE_EVERUDP_LOG"
    ;;
  *) exit 254 ;;
esac

export SSH_CONNECTION='127.0.0.1 40000 SERVER_IP 22'
if [ "${FAKE_EVERUDP_MODE:-normal}" = blackhole ]; then
  line=$(/bin/sh -c "$remote")
  set -- $line
  [ "$#" -eq 9 ] || exit 253
  [ "$1" = everudp ] && [ "$2" = v1 ] || exit 252
  /bin/kill -KILL "$9" >/dev/null 2>&1 || true
  printf '%s %s 192.0.2.1 %s %s %s %s %s %s\n' \
    "$1" "$2" "$4" "$5" "$6" "$7" "$8" "$9"
  exit 0
fi

exec /bin/sh -c "$remote"
"#;

struct Fixture {
    root: PathBuf,
    state: PathBuf,
    bin: PathBuf,
    log: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        let root = loop {
            let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
            let candidate = std::env::temp_dir().join(format!(
                "eversh-everudp-process-{}-{sequence}",
                std::process::id()
            ));
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
        let log = root.join("invocations.log");
        File::create(&log).unwrap();
        Self {
            state: root.join("state"),
            root,
            bin,
            log,
        }
    }

    fn path(&self) -> String {
        format!("{}:/usr/bin:/bin", self.bin.display())
    }

    fn log(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn status_files(&self) -> HashSet<PathBuf> {
        fs::read_dir(self.state.join("link-status"))
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Panics must not strand detached brokers or gateways. Match an exact
        // private state-root environment entry and suppress process output so
        // token-bearing argv can never leak through cleanup diagnostics.
        let expected = format!("EVERSH_STATE_DIR={}", self.state.display()).into_bytes();
        for _ in 0..3 {
            let pids: Vec<u32> = fs::read_dir("/proc")
                .into_iter()
                .flatten()
                .filter_map(Result::ok)
                .filter_map(|entry| entry.file_name().to_string_lossy().parse().ok())
                .filter(|pid| *pid != std::process::id())
                .filter(|pid| {
                    fs::read(format!("/proc/{pid}/environ"))
                        .unwrap_or_default()
                        .split(|byte| *byte == 0)
                        .any(|entry| entry == expected)
                })
                .collect();
            if pids.is_empty() {
                break;
            }
            for pid in pids {
                let _ = Command::new("/bin/kill")
                    .args(["-KILL", &pid.to_string()])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = fs::remove_dir_all(&self.root);
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

struct RunningClient {
    state_path: PathBuf,
    label: String,
    child: Child,
    master: File,
    stderr_path: PathBuf,
    status_before: HashSet<PathBuf>,
    transcript: Vec<u8>,
    initial_termios: sys::TerminalAttributes,
}

impl RunningClient {
    fn spawn(fixture: &Fixture, label: &str, mode: &str, arguments: &[&str]) -> Self {
        let status_before = fixture.status_files();
        let (master, slave) = sys::openpty(24, 80).unwrap();
        let initial_termios = sys::terminal_attributes(slave.as_fd()).unwrap();
        let stdin = File::from(slave.try_clone().unwrap());
        let stdout = File::from(slave);
        let stderr_path = fixture.root.join(format!("{label}.stderr"));
        let stderr = File::create(&stderr_path).unwrap();
        let mut command = Command::new(binary());
        command
            .env_clear()
            .env("EVERSH_STATE_DIR", &fixture.state)
            .env("FAKE_EVERUDP_LOG", &fixture.log)
            .env("FAKE_EVERUDP_MODE", mode)
            .env("PATH", fixture.path())
            .env("SHELL", "/bin/sh")
            .arg("--remote-eversh")
            .arg(binary())
            .args(arguments)
            .stdin(Stdio::from(stdin))
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        unsafe {
            command.pre_exec(|| {
                sys::child_setsid().map_err(std::io::Error::from_raw_os_error)?;
                sys::set_controlling_tty(0).map_err(std::io::Error::from_raw_os_error)
            });
        }
        let child = command.spawn().unwrap();
        let master = File::from(master);
        sys::set_nonblocking(master.as_fd()).unwrap();
        Self {
            state_path: fixture.state.clone(),
            label: label.to_owned(),
            child,
            master,
            stderr_path,
            status_before,
            transcript: Vec::new(),
            initial_termios,
        }
    }

    fn wait_connected(&mut self, fixture: &Fixture) {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let connected = fixture.status_files().iter().any(|path| {
                !self.status_before.contains(path)
                    && fs::read_to_string(path)
                        .unwrap_or_default()
                        .contains("everudp-status-v1 state connected")
            });
            if connected {
                return;
            }
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!(
                    "combined everudp {} exited before activation: {status}; stderr={}",
                    self.label,
                    self.stderr()
                );
            }
            assert!(
                Instant::now() < deadline,
                "combined everudp {} activation timed out; stderr={}",
                self.label,
                self.stderr()
            );
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
                Err(error) if error.raw_os_error() == Some(5) => return,
                Err(error) => panic!("PTY read: {error}"),
            }
        }
    }

    fn wait_for_bytes(&mut self, expected: &[u8]) {
        let deadline = Instant::now() + Duration::from_secs(15);
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
                    "combined everudp {} exited as {status} before {:?}; tail={:?}; stderr={}",
                    self.label,
                    String::from_utf8_lossy(expected),
                    self.transcript_tail(),
                    self.stderr()
                );
            }
            assert!(
                Instant::now() < deadline,
                "combined everudp {} output timed out before {:?}; tail={:?}; stderr={}",
                self.label,
                String::from_utf8_lossy(expected),
                self.transcript_tail(),
                self.stderr()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait_for_exit(&mut self, timeout: Duration) -> ExitStatus {
        self.wait_for_exit_inner(timeout, false)
    }

    fn wait_for_precommit_exit(&mut self, timeout: Duration) -> ExitStatus {
        self.wait_for_exit_inner(timeout, true)
    }

    fn wait_for_exit_inner(
        &mut self,
        timeout: Duration,
        require_original_termios: bool,
    ) -> ExitStatus {
        let deadline = Instant::now() + timeout;
        loop {
            if require_original_termios {
                self.assert_terminal_unchanged();
            }
            self.pump();
            if let Some(status) = self.child.try_wait().unwrap() {
                self.pump();
                if require_original_termios {
                    self.assert_terminal_unchanged();
                }
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "combined everudp {} exit timed out; tail={:?}; stderr={}; processes={}; link-states={:?}",
                self.label,
                self.transcript_tail(),
                self.stderr(),
                exit_snapshot::snapshot(&self.state_path),
                fs::read_dir(self.state_path.join("link-status"))
                    .into_iter().flatten().flatten()
                    .map(|entry| exit_snapshot::link_states(&entry.path()))
                    .collect::<Vec<_>>()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn assert_terminal_unchanged(&self) {
        let after = sys::terminal_attributes(self.master.as_fd()).unwrap();
        assert!(
            after == self.initial_termios,
            "{} changed terminal mode before commit",
            self.label
        );
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

fn count_line(text: &str, expected: &str) -> usize {
    text.lines().filter(|line| *line == expected).count()
}

#[test]
fn combined_binary_carries_terminal_directly_over_everudp() {
    let _serial = process_gate();
    let fixture = Fixture::new();
    let mut client = RunningClient::spawn(
        &fixture,
        "direct",
        "normal",
        &[
            "connect",
            "localhost",
            "--transport",
            "everudp",
            "--session",
            "combined-direct",
            "--",
            "/bin/sh",
            "-c",
            "IFS= read -r line; printf 'GOT:%s\\n' \"$line\"; exit 23",
        ],
    );
    client.wait_connected(&fixture);
    client.send(b"ping\n");
    client.wait_for_bytes(b"GOT:ping");
    let status = client.wait_for_exit(Duration::from_secs(15));

    assert_eq!(status.code(), Some(23), "stderr={}", client.stderr());
    let log = fixture.log();
    assert_eq!(count_line(&log, "everudp-bootstrap"), 1, "{log}");
    assert_eq!(count_line(&log, "everssh-fallback"), 0, "{log}");
    assert!(!client.stderr().contains(FALLBACK_NOTICE));
}

#[test]
fn strict_udp_failure_is_69_and_auto_falls_back_exactly_once_precommit() {
    let _serial = process_gate();
    let fixture = Fixture::new();

    let mut strict = RunningClient::spawn(
        &fixture,
        "strict",
        "blackhole",
        &[
            "connect",
            "localhost",
            "--transport",
            "everudp",
            "--session",
            "strict-blackhole",
            "--",
            "/bin/sh",
            "-c",
            "sleep 600",
        ],
    );
    let strict_status = strict.wait_for_precommit_exit(Duration::from_secs(12));
    assert_eq!(strict_status.code(), Some(UDP_UNREACHABLE_EXIT));
    assert_terminal_failure(&strict, false);
    let mut auto = RunningClient::spawn(
        &fixture,
        "auto",
        "blackhole",
        &[
            "connect",
            "localhost",
            "--transport",
            "auto",
            "--session",
            "auto-blackhole",
            "--",
            "/bin/sh",
            "-c",
            "sleep 600",
        ],
    );
    let auto_status = auto.wait_for_precommit_exit(Duration::from_secs(12));
    assert_eq!(auto_status.code(), Some(FALLBACK_EXIT));
    assert_terminal_failure(&auto, true);
    let log = fixture.log();
    assert_eq!(count_line(&log, "everudp-bootstrap"), 2, "{log}");
    assert_eq!(count_line(&log, "everssh-fallback"), 1, "{log}");
}

fn assert_terminal_failure(client: &RunningClient, fell_back: bool) {
    client.assert_terminal_unchanged();
    assert_eq!(
        client.stderr().matches(FALLBACK_NOTICE).count(),
        usize::from(fell_back),
        "stderr={}",
        client.stderr()
    );
}

#[test]
fn authenticated_busy_in_auto_mode_never_falls_back() {
    let _serial = process_gate();
    let fixture = Fixture::new();
    let mut writer = RunningClient::spawn(
        &fixture,
        "writer",
        "normal",
        &[
            "connect",
            "localhost",
            "--transport",
            "everudp",
            "--session",
            "combined-busy",
            "--",
            "/bin/sh",
            "-c",
            "while IFS= read -r line; do printf 'OUT:%s\\n' \"$line\"; [ \"$line\" != quit ] || exit 37; done",
        ],
    );
    writer.wait_connected(&fixture);

    let mut contender = RunningClient::spawn(
        &fixture,
        "contender",
        "normal",
        &[
            "attach",
            "localhost",
            "combined-busy",
            "--transport",
            "auto",
        ],
    );
    let rejected = contender.wait_for_exit(Duration::from_secs(15));
    assert_ne!(rejected.code(), Some(UDP_UNREACHABLE_EXIT));
    assert_ne!(rejected.code(), Some(0));
    assert_eq!(contender.stderr().matches(FALLBACK_NOTICE).count(), 0);

    writer.send(b"survived\n");
    writer.wait_for_bytes(b"OUT:survived");
    writer.send(b"quit\n");
    assert_eq!(
        writer.wait_for_exit(Duration::from_secs(15)).code(),
        Some(37)
    );
    let log = fixture.log();
    assert_eq!(count_line(&log, "everudp-bootstrap"), 2, "{log}");
    assert_eq!(count_line(&log, "everssh-fallback"), 0, "{log}");
}
