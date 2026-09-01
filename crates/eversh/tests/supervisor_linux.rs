//! Supervisor composition tests (design 11.4) with fake ssh and Kitty
//! launcher binaries capturing exact argv, plus REAL everpty brokers, real
//! PTYs, and the real combined eversh binary. The fake ssh executes the
//! remote command locally, so the transport hop is simulated while every
//! session, broker, writer, and reconnect boundary is real.
#![cfg(all(target_os = "linux", feature = "cli"))]
#![allow(clippy::unwrap_used)]

use everpty::sys;
use eversh::remote::{base64url_decode, origin_label, sanitize_host_label, ControlRequest};
use eversh::supervisor::{
    Config as SupervisorConfig, SessionEnd, SilentNotifier, TransportFailure,
};
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Send a signal via the system `kill` binary (no extra test dependencies).
fn send_signal(pid: i32, signal: &str) {
    let status = Command::new("kill")
        .args([signal, &pid.to_string()])
        .status()
        .unwrap();
    assert!(status.success(), "kill {signal} {pid} failed");
}

static FIXTURE: AtomicU64 = AtomicU64::new(0);

fn binary() -> &'static OsStr {
    OsStr::new(env!("CARGO_BIN_EXE_eversh"))
}

/// The fake ssh script: captures argv NUL-separated plus its pid and
/// environment, honors a mode file (`run` executes the remote command
/// locally as a child with the inherited terminal descriptors; `fail255`
/// exits like an unreachable transport; `hang` sleeps well past any test
/// deadline, simulating a wedged transport), turns SIGUSR1 into a hard
/// transport failure — the remote side is killed and the "ssh client" exits
/// 255, while the broker survives — and simulates a raced writer-revoke on
/// reattach: `busyonce` answers the FIRST non-probe (reattach) invocation
/// with the real Busy exit code once, then behaves like `run`; `busypersist`
/// always answers Busy for non-probe invocations. Both answer any probe
/// invocation `Live` (exit 0) without touching the real broker.
const FAKE_SSH: &str = r#"#!/bin/sh
set -u
stamp=$(date +%s%N)-$$
cap="$FAKE_CAPTURE_DIR/ssh-$stamp"
: > "$cap.argv.part"
for arg in "$@"; do printf '%s\0' "$arg" >> "$cap.argv.part"; done
mv "$cap.argv.part" "$cap.argv"
printf '%s' "$$" > "$cap.pid"
env -0 > "$cap.env" 2>/dev/null || true
mode=run
[ -f "${FAKE_SSH_MODE_FILE:-/nonexistent}" ] && mode=$(cat "$FAKE_SSH_MODE_FILE")
if [ "$mode" = fail255 ]; then exit 255; fi
if [ "$mode" = hang ]; then exec sleep 600; fi
if [ "$mode" = busyonce ] || [ "$mode" = busypersist ]; then
  is_probe=0
  for arg in "$@"; do
    if [ "$arg" = probe ]; then is_probe=1; fi
  done
  if [ "$is_probe" -eq 1 ]; then exit 0; fi
  if [ "$mode" = busypersist ]; then exit 3; fi
  marker="$FAKE_CAPTURE_DIR/.busyonce-used"
  if [ ! -f "$marker" ]; then
    : > "$marker"
    exit 3
  fi
  # marker already consumed: fall through to a real reattach exec below.
fi
while [ "$#" -gt 0 ] && [ "$1" != -- ]; do shift; done
[ "$#" -gt 0 ] && shift
[ "$#" -gt 0 ] && shift
if [ "$#" -eq 0 ]; then exit 255; fi
exec 3<&0
"$@" <&3 3<&- &
child=$!
exec 3<&-
trap 'kill -KILL "$child" 2>/dev/null; exit 255' USR1
wait "$child"
exit $?
"#;

/// The fake Kitty launcher: captures argv and environment; fails when told
/// to for one name.
const FAKE_KITTY: &str = r#"#!/bin/sh
set -u
stamp=$(date +%s%N)-$$
cap="$FAKE_CAPTURE_DIR/kitty-$stamp"
: > "$cap.argv.part"
for arg in "$@"; do printf '%s\0' "$arg" >> "$cap.argv.part"; done
mv "$cap.argv.part" "$cap.argv"
env -0 > "$cap.env" 2>/dev/null || true
if [ -n "${FAKE_KITTY_FAIL:-}" ]; then
  for arg in "$@"; do
    if [ "$arg" = "$FAKE_KITTY_FAIL" ]; then exit 1; fi
  done
fi
exit 0
"#;

struct Fixture {
    base: PathBuf,
    state: PathBuf,
    bin: PathBuf,
    capture: PathBuf,
    mode_file: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        let base = loop {
            let n = FIXTURE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("eversh-sup-{}-{n}", std::process::id()));
            match builder.create(&path) {
                Ok(()) => break path,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("fixture: {error}"),
            }
        };
        let state = base.join("state");
        let bin = base.join("bin");
        let capture = base.join("capture");
        builder.create(&bin).unwrap();
        builder.create(&capture).unwrap();
        let mode_file = base.join("ssh-mode");

        for (name, body) in [("ssh", FAKE_SSH), ("kitty", FAKE_KITTY)] {
            let path = bin.join(name);
            fs::write(&path, body).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::os::unix::fs::symlink(binary(), bin.join("eversh")).unwrap();
        Self {
            base,
            state,
            bin,
            capture,
            mode_file,
        }
    }

    fn set_mode(&self, mode: &str) {
        fs::write(&self.mode_file, mode).unwrap();
    }

    fn command(&self) -> Command {
        let mut command = Command::new(binary());
        let path = format!("{}:/usr/bin:/bin", self.bin.display());
        command
            .env_clear()
            .env("EVERSH_STATE_DIR", &self.state)
            .env("PATH", path)
            .env("SHELL", "/bin/sh")
            .env("FAKE_CAPTURE_DIR", &self.capture)
            .env("FAKE_SSH_MODE_FILE", &self.mode_file)
            .stdin(Stdio::null());
        command
    }

    /// Captured fake invocations (kind = "ssh" or "kitty"), oldest first.
    fn captures(&self, kind: &str) -> Vec<(String, Vec<String>)> {
        let mut entries: Vec<String> = fs::read_dir(&self.capture)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.starts_with(&format!("{kind}-")) && name.ends_with(".argv"))
            .collect();
        entries.sort();
        entries
            .into_iter()
            .map(|name| {
                let bytes = fs::read(self.capture.join(&name)).unwrap();
                let argv = bytes
                    .split(|byte| *byte == 0)
                    .filter(|part| !part.is_empty())
                    .map(|part| String::from_utf8(part.to_vec()).unwrap())
                    .collect();
                (name, argv)
            })
            .collect()
    }

    fn ssh_pid_files(&self) -> Vec<String> {
        let mut entries: Vec<String> = fs::read_dir(&self.capture)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.starts_with("ssh-") && name.ends_with(".pid"))
            .collect();
        entries.sort();
        entries
    }

    fn newest_ssh_pid(&self) -> i32 {
        let entries = self.ssh_pid_files();
        let newest = entries.last().expect("at least one fake ssh ran");
        fs::read_to_string(self.capture.join(newest))
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }

    /// Every captured `kind-*.env` file's NUL-separated `KEY=VALUE` entries
    /// (kind = "ssh" or "kitty"), oldest first.
    fn captured_env(&self, kind: &str) -> Vec<Vec<u8>> {
        let mut entries: Vec<String> = fs::read_dir(&self.capture)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.starts_with(&format!("{kind}-")) && name.ends_with(".env"))
            .collect();
        entries.sort();
        entries
            .into_iter()
            .flat_map(|name| {
                let bytes = fs::read(self.capture.join(&name)).unwrap();
                bytes
                    .split(|byte| *byte == 0)
                    .filter(|part| !part.is_empty())
                    .map(<[u8]>::to_vec)
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}

/// A minor finding repair: no captured supervisor-invoked process
/// environment may carry a bootstrap token (a 64-hex-character run) or a raw
/// bootstrap record line (`everlink v1 ...`) — the supervisor never places
/// secrets in argv or environment (design 3, 4, 10).
fn assert_no_secret_env(fixture: &Fixture, kind: &str) {
    let entries = fixture.captured_env(kind);
    assert!(
        !entries.is_empty(),
        "no captured {kind} environments to check"
    );
    for entry in entries {
        let text = String::from_utf8_lossy(&entry);
        let value = text.split_once('=').map_or("", |(_, value)| value);
        assert!(
            !contains_hex64(value),
            "captured {kind} environment leaked a 64-hex token: {text}"
        );
        assert!(
            !value.starts_with("everlink v1 "),
            "captured {kind} environment leaked a bootstrap record: {text}"
        );
    }
}

fn contains_hex64(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 64 {
        return false;
    }
    (0..=bytes.len() - 64).any(|start| bytes[start..start + 64].iter().all(u8::is_ascii_hexdigit))
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Kill any surviving broker sessions before removing state.
        if let Ok(entries) = fs::read_dir(&self.state) {
            for entry in entries.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    let _ = self
                        .command()
                        .args(["__everpty", "v1", "kill", &name])
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                }
            }
        }
        let _ = fs::remove_dir_all(&self.base);
    }
}

fn wait_bounded(child: &mut Child, label: &str) -> ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{label} exceeded its deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn read_available(reader: &mut File, collected: &mut Vec<u8>) {
    let mut chunk = [0u8; 4096];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => return,
            Ok(count) => collected.extend_from_slice(&chunk[..count]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return,
            Err(error) if error.raw_os_error() == Some(libc_eio()) => return,
            Err(error) => panic!("master read: {error}"),
        }
    }
}

fn libc_eio() -> i32 {
    5
}

fn read_until(reader: &mut File, collected: &mut Vec<u8>, needle: &[u8], label: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        read_available(reader, collected);
        if collected.windows(needle.len()).any(|part| part == needle) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{label} marker timeout: {:?}",
            String::from_utf8_lossy(collected)
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Extract complete `T:<n>` tick numbers, dropping torn leading/trailing
/// fragments (delivery boundaries may split a line).
fn ticks(bytes: &[u8]) -> Vec<u64> {
    let text = String::from_utf8_lossy(bytes);
    let mut numbers = Vec::new();
    let mut lines: Vec<&str> = text.split('\n').collect();
    // The final element is either empty (complete last line) or torn.
    lines.pop();
    let mut first = true;
    for line in lines {
        let line = line.trim_end_matches('\r');
        if let Some(value) = line.strip_prefix("T:") {
            if let Ok(number) = value.parse::<u64>() {
                numbers.push(number);
                first = false;
                continue;
            }
        }
        // A torn first line is tolerated; anything else must be READY.
        assert!(
            first || line == "READY" || line.is_empty(),
            "unexpected session output line {line:?}"
        );
        first = false;
    }
    numbers
}

struct PtySession {
    child: Child,
    master: File,
    stderr_path: PathBuf,
}

fn spawn_interactive(fixture: &Fixture, label: &str, args: &[&str]) -> PtySession {
    let (master, slave) = sys::openpty(24, 80).unwrap();
    let stdin = slave.try_clone().unwrap();
    let stderr_path = fixture.base.join(format!("{label}.stderr"));
    let stderr = File::create(&stderr_path).unwrap();
    let mut command = fixture.command();
    command
        .process_group(0)
        .stdin(Stdio::from(File::from(stdin)))
        .stdout(Stdio::from(File::from(slave)))
        .stderr(Stdio::from(stderr))
        .args(args);
    let child = command.spawn().unwrap();
    let master = File::from(master);
    sys::set_nonblocking(master.as_fd()).unwrap();
    PtySession {
        child,
        master,
        stderr_path,
    }
}

const TICK_SCRIPT: &str =
    "trap 'exit 41' TERM; printf 'READY\\n'; i=0; while :; do printf 'T:%d\\n' \"$i\"; i=$((i+1)); sleep 0.05; done";

#[test]
fn transport_failure_reattaches_same_session_without_replay() {
    let fixture = Fixture::new();
    fixture.set_mode("run");
    let mut session = spawn_interactive(
        &fixture,
        "reconnect",
        &[
            "connect",
            "testhost",
            "--session",
            "work",
            "--",
            "/bin/sh",
            "-c",
            TICK_SCRIPT,
        ],
    );

    // Established: READY plus at least four complete ticks delivered.
    let mut pre = Vec::new();
    read_until(&mut session.master, &mut pre, b"T:4\r", "pre-failure ticks");

    // Hard transport failure: the fake ssh kills the remote side and exits
    // 255; the broker and child survive.
    let ssh_pid = fixture.newest_ssh_pid();
    send_signal(ssh_pid, "-USR1");

    // Drain everything delivered before the failure: once the fake ssh is
    // gone the writer is dead, so after 100ms of silence the pre-failure
    // stream is complete — reattach cannot begin before the 250ms minimum
    // backoff.
    let gone_deadline = Instant::now() + Duration::from_secs(5);
    while std::path::Path::new(&format!("/proc/{ssh_pid}")).exists() {
        assert!(Instant::now() < gone_deadline, "fake ssh survived SIGUSR1");
        std::thread::sleep(Duration::from_millis(2));
    }
    let mut quiet = Instant::now();
    let mut last_len = pre.len();
    loop {
        read_available(&mut session.master, &mut pre);
        if pre.len() != last_len {
            last_len = pre.len();
            quiet = Instant::now();
        }
        if quiet.elapsed() >= Duration::from_millis(100) {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let pre_ticks = ticks(&pre);
    assert!(pre_ticks.len() >= 4, "pre ticks: {pre_ticks:?}");
    let max_pre = *pre_ticks.last().unwrap();

    // The SAME eversh process reconnects: probe then plain attach. Wait for
    // fresh output on the SAME local terminal.
    let mut post = Vec::new();
    let reattach_deadline = Instant::now() + Duration::from_secs(20);
    loop {
        read_available(&mut session.master, &mut post);
        if !ticks(&post).is_empty() {
            break;
        }
        assert!(
            session.child.try_wait().unwrap().is_none(),
            "eversh exited instead of reconnecting: {}",
            fs::read_to_string(&session.stderr_path).unwrap()
        );
        assert!(
            Instant::now() < reattach_deadline,
            "no post-reattach output"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    // Let a few more ticks arrive.
    let settle = Instant::now() + Duration::from_millis(300);
    while Instant::now() < settle {
        read_available(&mut session.master, &mut post);
        std::thread::sleep(Duration::from_millis(10));
    }
    let post_ticks = ticks(&post);

    // No replay: nothing generated while detached is delivered afterwards,
    // and the detached interval's output is genuinely absent (a gap).
    let min_post = *post_ticks.first().unwrap();
    assert!(
        min_post >= max_pre + 2,
        "detached output replayed or not discarded: max_pre={max_pre} min_post={min_post}"
    );
    for window in post_ticks.windows(2) {
        assert!(
            window[1] > window[0],
            "post ticks not increasing: {post_ticks:?}"
        );
    }
    for tick in &post_ticks {
        assert!(!pre_ticks.contains(tick), "tick {tick} delivered twice");
    }

    // The reconnect used probe then plain attach — never attach-or-create.
    let captures = fixture.captures("ssh");
    assert!(captures.len() >= 3, "expected >=3 ssh invocations");
    let first = &captures[0].1;
    assert!(first.contains(&"attach-or-create".to_owned()));
    assert_eq!(first[0], "-o");
    assert!(first[1].starts_with("ProxyCommand='"));
    assert!(first.contains(&"-t".to_owned()));
    let probe = &captures[captures.len() - 2].1;
    assert!(probe.contains(&"probe".to_owned()), "{probe:?}");
    assert!(probe.contains(&"work".to_owned()));
    assert!(!probe.contains(&"-t".to_owned()));
    let reattach = &captures[captures.len() - 1].1;
    assert!(reattach.contains(&"attach".to_owned()), "{reattach:?}");
    assert!(
        !reattach.contains(&"attach-or-create".to_owned()),
        "reconnect must never recreate the session: {reattach:?}"
    );

    let stderr = fs::read_to_string(&session.stderr_path).unwrap();
    assert!(stderr.contains("probing session 'work'"), "{stderr}");
    assert!(stderr.contains("reattaching session 'work'"), "{stderr}");
    // No-swallow fidelity: the versioned status-channel protocol is parsed
    // and swallowed entirely — it must never leak into eversh's own stderr.
    assert!(
        !stderr.contains("eversh-status-v1"),
        "status channel line leaked into stderr: {stderr}"
    );

    // Minor finding repair: no captured fake-ssh environment carries a
    // secret (a bootstrap token or a raw bootstrap record).
    assert_no_secret_env(&fixture, "ssh");

    // Kill the session; the child's TERM trap exit code must reach the SAME
    // local process unchanged (child/session exit distinction).
    let killed = fixture
        .command()
        .args(["kill", "testhost", "work"])
        .output()
        .unwrap();
    assert_eq!(killed.status.code(), Some(0), "kill failed");
    let status = wait_bounded(&mut session.child, "connect exit");
    assert_eq!(
        status.code(),
        Some(41),
        "child exit status must pass through"
    );
}

#[test]
fn child_exit_returns_status_without_any_retry() {
    let fixture = Fixture::new();
    fixture.set_mode("run");
    let mut session = spawn_interactive(
        &fixture,
        "child-exit",
        &[
            "connect",
            "testhost",
            "--session",
            "quick",
            "--",
            "/bin/sh",
            "-c",
            "exit 37",
        ],
    );
    let status = wait_bounded(&mut session.child, "quick child");
    assert_eq!(status.code(), Some(37));
    let captures = fixture.captures("ssh");
    assert_eq!(
        captures.len(),
        1,
        "child exit must not probe or retry: {captures:?}"
    );
}

#[test]
fn auth_failure_before_establishment_is_not_retried() {
    // Finding 1: a first-attempt 255 with the session never established
    // (an OpenSSH auth failure, for instance) must be reported immediately
    // as an ordinary SSH failure — no probe, no retry.
    let fixture = Fixture::new();
    fixture.set_mode("fail255");
    let mut session = spawn_interactive(
        &fixture,
        "authfail",
        &[
            "connect",
            "testhost",
            "--session",
            "authf1",
            "--",
            "/bin/sh",
            "-c",
            "exit 0",
        ],
    );
    let status = wait_bounded(&mut session.child, "auth failure connect");
    assert_eq!(status.code(), Some(255));
    let captures = fixture.captures("ssh");
    assert_eq!(
        captures.len(),
        1,
        "pre-establishment failure must not probe or retry: {captures:?}"
    );
    let stderr = fs::read_to_string(&session.stderr_path).unwrap();
    assert!(!stderr.contains("probing"), "{stderr}");
}

#[test]
fn remote_child_exit_255_passes_through_without_retry() {
    // Finding 2: a remote child that itself exits 255 must be reported as
    // that exit code via the status-channel exit record, not misread as
    // transport failure.
    let fixture = Fixture::new();
    fixture.set_mode("run");
    let mut session = spawn_interactive(
        &fixture,
        "child255",
        &[
            "connect",
            "testhost",
            "--session",
            "c255",
            "--",
            "/bin/sh",
            "-c",
            "exit 255",
        ],
    );
    let status = wait_bounded(&mut session.child, "child 255 connect");
    assert_eq!(status.code(), Some(255));
    let captures = fixture.captures("ssh");
    assert_eq!(
        captures.len(),
        1,
        "child exit 255 must not probe or retry: {captures:?}"
    );
    let stderr = fs::read_to_string(&session.stderr_path).unwrap();
    assert!(
        !stderr.contains("probing") && !stderr.contains("reconnect"),
        "{stderr}"
    );
}

#[test]
fn remote_child_signal_maps_to_128_plus_signal() {
    // Finding 2: a remote child killed by a signal (no trap) is reported via
    // its status-channel exit record and maps to 128+signal, never an
    // ambiguous ssh-255.
    let fixture = Fixture::new();
    fixture.set_mode("run");
    let mut session = spawn_interactive(
        &fixture,
        "childsig",
        &[
            "connect",
            "testhost",
            "--session",
            "csig",
            "--",
            "/bin/sh",
            "-c",
            "kill -TERM $$",
        ],
    );
    let status = wait_bounded(&mut session.child, "child signal connect");
    assert_eq!(status.code(), Some(128 + 15));
    let captures = fixture.captures("ssh");
    assert_eq!(
        captures.len(),
        1,
        "signaled child must not probe or retry: {captures:?}"
    );
}

#[test]
fn busy_and_missing_sessions_are_visible_and_never_retried() {
    let fixture = Fixture::new();
    fixture.set_mode("run");
    let mut holder = spawn_interactive(
        &fixture,
        "holder",
        &[
            "connect",
            "testhost",
            "--session",
            "busy1",
            "--",
            "/bin/sh",
            "-c",
            TICK_SCRIPT,
        ],
    );
    let mut seen = Vec::new();
    read_until(&mut holder.master, &mut seen, b"READY", "holder ready");
    let before = fixture.captures("ssh").len();

    // Second writer without takeover: Busy (exit 3), exactly one invocation.
    let busy = spawn_interactive(&fixture, "busy", &["attach", "testhost", "busy1"]);
    let mut busy_child = busy.child;
    let status = wait_bounded(&mut busy_child, "busy attach");
    assert_eq!(status.code(), Some(3), "Busy must map to exit 3");
    let stderr = fs::read_to_string(&busy.stderr_path).unwrap();
    assert!(!stderr.is_empty(), "busy failure must be visible");
    assert_eq!(fixture.captures("ssh").len(), before + 1);

    // Missing session: visible failure, no probe, no restart.
    let missing = spawn_interactive(&fixture, "missing", &["attach", "testhost", "nosuch"]);
    let mut missing_child = missing.child;
    let status = wait_bounded(&mut missing_child, "missing attach");
    assert_eq!(status.code(), Some(1));
    assert_eq!(fixture.captures("ssh").len(), before + 2);

    let killed = fixture
        .command()
        .args(["kill", "testhost", "busy1"])
        .output()
        .unwrap();
    assert_eq!(killed.status.code(), Some(0));
    let status = wait_bounded(&mut holder.child, "holder exit");
    assert_eq!(status.code(), Some(41));
}

#[test]
fn gone_session_is_not_restarted_after_transport_failure() {
    let fixture = Fixture::new();
    fixture.set_mode("run");
    let mut session = spawn_interactive(
        &fixture,
        "gone",
        &[
            "connect",
            "testhost",
            "--session",
            "gone1",
            "--",
            "/bin/sh",
            "-c",
            TICK_SCRIPT,
        ],
    );
    let mut seen = Vec::new();
    read_until(&mut session.master, &mut seen, b"T:1\r", "gone ready");

    // Make probes fail while the session is torn down, then let one probe
    // through: it must find the session gone and stop, deterministically.
    fixture.set_mode("fail255");
    let ssh_pid = fixture.newest_ssh_pid();
    send_signal(ssh_pid, "-USR1");
    let killed = fixture
        .command()
        .args(["__everpty", "v1", "kill", "gone1"])
        .output()
        .unwrap();
    assert_eq!(killed.status.code(), Some(0), "direct kill failed");
    fixture.set_mode("run");

    let status = wait_bounded(&mut session.child, "gone reconnect");
    assert_eq!(status.code(), Some(255), "transport failure exit");
    let stderr = fs::read_to_string(&session.stderr_path).unwrap();
    assert!(
        stderr.contains("no longer live"),
        "gone session must be reported: {stderr}"
    );
    // The last invocation is the probe; no attach followed it.
    let captures = fixture.captures("ssh");
    let last = &captures.last().unwrap().1;
    assert!(last.contains(&"probe".to_owned()), "{last:?}");
}

#[test]
fn unreachable_transport_exhausts_bounded_attempts() {
    let fixture = Fixture::new();
    fixture.set_mode("run");
    let mut session = spawn_interactive(
        &fixture,
        "exhaust",
        &[
            "connect",
            "testhost",
            "--session",
            "exh1",
            "--",
            "/bin/sh",
            "-c",
            TICK_SCRIPT,
        ],
    );
    let mut seen = Vec::new();
    read_until(&mut session.master, &mut seen, b"T:1\r", "exhaust ready");
    let before = fixture.captures("ssh").len();

    // Fail the transport and make every later invocation unreachable.
    fixture.set_mode("fail255");
    let ssh_pid = fixture.newest_ssh_pid();
    send_signal(ssh_pid, "-USR1");

    let status = wait_bounded(&mut session.child, "exhausted reconnect");
    assert_eq!(status.code(), Some(255));
    let stderr = fs::read_to_string(&session.stderr_path).unwrap();
    assert!(
        stderr.contains("reconnect attempts exhausted") || stderr.contains("deadline"),
        "{stderr}"
    );
    // Exactly the bounded number of probes ran, and no attach ever did.
    let mut all = fixture.captures("ssh");
    let after = all.split_off(before);
    assert_eq!(
        after.len(),
        5,
        "default retry_attempts_max probes: {after:?}"
    );
    for (name, argv) in &after {
        assert!(argv.contains(&"probe".to_owned()), "{name}: {argv:?}");
    }

    // Cleanup: broker still alive.
    fixture.set_mode("run");
    let killed = fixture
        .command()
        .args(["__everpty", "v1", "kill", "exh1"])
        .output()
        .unwrap();
    assert_eq!(killed.status.code(), Some(0));
}

/// Every "attach" (never "attach-or-create") invocation's control-request
/// token, decoded — used to check `take_over` never escalates during a
/// busy-gated reconnect.
fn attach_requests(captures: &[(String, Vec<String>)]) -> Vec<ControlRequest> {
    let limits = eversh::Limits::default();
    captures
        .iter()
        .filter(|(_, argv)| {
            argv.contains(&"attach".to_owned()) && !argv.contains(&"attach-or-create".to_owned())
        })
        .map(|(_, argv)| {
            let token = argv.last().expect("attach argv carries a trailing token");
            let bytes = base64url_decode(token, limits.remote_control_max).unwrap();
            ControlRequest::decode(&bytes, &limits).unwrap()
        })
        .collect()
}

#[test]
fn reattach_busy_once_is_retried_within_the_episode() {
    let fixture = Fixture::new();
    fixture.set_mode("run");
    let mut session = spawn_interactive(
        &fixture,
        "busyonce",
        &[
            "connect",
            "testhost",
            "--session",
            "bz1",
            "--",
            "/bin/sh",
            "-c",
            TICK_SCRIPT,
        ],
    );
    let mut pre = Vec::new();
    read_until(
        &mut session.master,
        &mut pre,
        b"T:4\r",
        "busyonce pre-failure ticks",
    );
    let before = fixture.captures("ssh").len();

    let ssh_pid = fixture.newest_ssh_pid();
    send_signal(ssh_pid, "-USR1");
    let gone_deadline = Instant::now() + Duration::from_secs(5);
    while std::path::Path::new(&format!("/proc/{ssh_pid}")).exists() {
        assert!(Instant::now() < gone_deadline, "fake ssh survived SIGUSR1");
        std::thread::sleep(Duration::from_millis(2));
    }
    // Every subsequent reattach gets the real Busy exit code exactly once.
    fixture.set_mode("busyonce");

    // The SAME session still reattaches: fresh ticks resume once the
    // one-time Busy response is absorbed and retried.
    let mut post = Vec::new();
    let reattach_deadline = Instant::now() + Duration::from_secs(20);
    loop {
        read_available(&mut session.master, &mut post);
        if !ticks(&post).is_empty() {
            break;
        }
        assert!(
            session.child.try_wait().unwrap().is_none(),
            "eversh exited instead of retrying busy: {}",
            fs::read_to_string(&session.stderr_path).unwrap()
        );
        assert!(
            Instant::now() < reattach_deadline,
            "no post-busy-retry output"
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    // Exactly one extra attempt was consumed by the Busy response: probe,
    // busy attach, probe, successful attach.
    let mut all = fixture.captures("ssh");
    let after = all.split_off(before);
    let attach_count = after
        .iter()
        .filter(|(_, argv)| {
            argv.contains(&"attach".to_owned()) && !argv.contains(&"attach-or-create".to_owned())
        })
        .count();
    assert_eq!(
        attach_count, 2,
        "expected one busy attach plus one successful reattach: {after:?}"
    );
    let probe_count = after
        .iter()
        .filter(|(_, argv)| argv.contains(&"probe".to_owned()))
        .count();
    assert_eq!(probe_count, 2, "{after:?}");
    for request in attach_requests(&after) {
        assert!(
            !request.take_over,
            "busy retry must never escalate to take_over"
        );
    }

    let stderr = fs::read_to_string(&session.stderr_path).unwrap();
    assert!(stderr.contains("busy"), "{stderr}");

    let killed = fixture
        .command()
        .args(["kill", "testhost", "bz1"])
        .output()
        .unwrap();
    assert_eq!(killed.status.code(), Some(0));
    let status = wait_bounded(&mut session.child, "busyonce exit");
    assert_eq!(
        status.code(),
        Some(41),
        "child exit status must pass through"
    );
}

#[test]
fn reattach_busy_persisting_exhausts_and_never_escalates() {
    let fixture = Fixture::new();
    fixture.set_mode("run");
    let mut session = spawn_interactive(
        &fixture,
        "busypersist",
        &[
            "connect",
            "testhost",
            "--session",
            "bzp1",
            "--",
            "/bin/sh",
            "-c",
            TICK_SCRIPT,
        ],
    );
    let mut seen = Vec::new();
    read_until(
        &mut session.master,
        &mut seen,
        b"T:1\r",
        "busypersist ready",
    );
    let before = fixture.captures("ssh").len();

    let ssh_pid = fixture.newest_ssh_pid();
    send_signal(ssh_pid, "-USR1");
    let gone_deadline = Instant::now() + Duration::from_secs(5);
    while std::path::Path::new(&format!("/proc/{ssh_pid}")).exists() {
        assert!(Instant::now() < gone_deadline, "fake ssh survived SIGUSR1");
        std::thread::sleep(Duration::from_millis(2));
    }
    // Every reattach persistently reports Busy; probes stay Live.
    fixture.set_mode("busypersist");

    let status = wait_bounded(&mut session.child, "busypersist exhaustion");
    assert_eq!(status.code(), Some(255));
    let stderr = fs::read_to_string(&session.stderr_path).unwrap();
    assert!(
        stderr.contains("busy"),
        "exhaustion must report the busy diagnostic: {stderr}"
    );

    // Never escalated to take_over on any attach retry.
    let mut all = fixture.captures("ssh");
    let after = all.split_off(before);
    assert!(
        after
            .iter()
            .any(|(_, argv)| argv.contains(&"attach".to_owned())
                && !argv.contains(&"attach-or-create".to_owned())),
        "expected at least one busy-retried attach: {after:?}"
    );
    for request in attach_requests(&after) {
        assert!(
            !request.take_over,
            "persistent busy must never escalate to take_over"
        );
    }

    // Cleanup: the broker (and its writer, still holding the session)
    // persist; kill it directly.
    fixture.set_mode("run");
    let killed = fixture
        .command()
        .args(["__everpty", "v1", "kill", "bzp1"])
        .output()
        .unwrap();
    assert_eq!(killed.status.code(), Some(0));
}

#[test]
fn raw_ssh_passes_through_and_never_retries() {
    let fixture = Fixture::new();
    fixture.set_mode("fail255");
    let output = fixture
        .command()
        .args(["ssh", "testhost", "--", "-L", "8080:localhost:80"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(255));
    let captures = fixture.captures("ssh");
    assert_eq!(captures.len(), 1, "raw ssh must never probe or retry");
    let argv = &captures[0].1;
    assert_eq!(argv[0], "-o");
    assert!(argv[1].starts_with("ProxyCommand='"));
    assert!(argv[1].contains("__everlink ssh-proxy '%n' '%p' --remote-eversh 'eversh'"));
    // `-L` fails the audited allowlist: it must never be mirrored into the
    // everlink bootstrap, but raw mode must not error over it either
    // (finding 4).
    assert!(
        !argv[1].contains("--ssh-option"),
        "unaudited option must not reach the bootstrap: {}",
        argv[1]
    );
    assert_eq!(
        argv[2..],
        ["-L", "8080:localhost:80", "--", "testhost"].map(str::to_owned)
    );
}

#[test]
fn raw_ssh_forwards_a_remote_command_after_inner_separator() {
    let fixture = Fixture::new();
    fixture.set_mode("run");
    // An inner `--` splits outer SSH options (before it) from a remote
    // command (after it, placed after the destination): finding 4.
    let output = fixture
        .command()
        .args([
            "ssh", "testhost", "--", "-4", "--", "/bin/sh", "-c", "exit 37",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(37));
    let captures = fixture.captures("ssh");
    assert_eq!(captures.len(), 1, "raw ssh must never probe or retry");
    let argv = &captures[0].1;
    assert_eq!(argv[0], "-o");
    assert!(argv[1].starts_with("ProxyCommand='"));
    // `-4` passes the audit and is mirrored into the bootstrap.
    assert!(argv[1].contains("--ssh-option '-4'"), "{}", argv[1]);
    assert_eq!(
        argv[2..],
        ["-4", "--", "testhost", "/bin/sh", "-c", "exit 37"].map(str::to_owned)
    );
}

#[test]
fn list_filters_by_origin_and_resume_all_reports_partial_failure() {
    let fixture = Fixture::new();
    fixture.set_mode("run");
    let local_label = {
        let raw = fs::read_to_string("/proc/sys/kernel/hostname").unwrap();
        sanitize_host_label(raw.trim())
    };

    let mut one = spawn_interactive(
        &fixture,
        "resume-one",
        &[
            "connect",
            "testhost",
            "--session",
            "res1",
            "--",
            "/bin/sh",
            "-c",
            TICK_SCRIPT,
        ],
    );
    let mut seen1 = Vec::new();
    read_until(&mut one.master, &mut seen1, b"READY", "res1 ready");
    let mut two = spawn_interactive(
        &fixture,
        "resume-two",
        &[
            "connect",
            "testhost",
            "--session",
            "res2",
            "--",
            "/bin/sh",
            "-c",
            TICK_SCRIPT,
        ],
    );
    let mut seen2 = Vec::new();
    read_until(&mut two.master, &mut seen2, b"READY", "res2 ready");

    // list --json passes through the remote discovery data with origins.
    let listed = fixture
        .command()
        .args(["list", "testhost", "--json"])
        .output()
        .unwrap();
    assert_eq!(listed.status.code(), Some(0));
    let json = String::from_utf8(listed.stdout).unwrap();
    assert!(json.contains("\"name\":\"res1\""), "{json}");
    assert!(json.contains("\"name\":\"res2\""), "{json}");
    let expected_origin = origin_label(&local_label);
    assert!(json.contains(&expected_origin), "{json}");

    // The filter is applied remotely: a foreign local-host matches nothing.
    let filtered = fixture
        .command()
        .args(["list", "testhost", "--local-host", "other-host", "--json"])
        .output()
        .unwrap();
    assert_eq!(filtered.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(filtered.stdout).unwrap(),
        "{\"version\":1,\"sessions\":[]}\n"
    );

    // resume-all: one Kitty tab per matching session; one failure stays
    // visible and the exit reports it.
    let resumed = fixture
        .command()
        .args(["resume-all", "testhost"])
        .env("KITTY_LISTEN_ON", "unix:/tmp/kitty-test.sock")
        .env("FAKE_KITTY_FAIL", "res2")
        .output()
        .unwrap();
    assert_eq!(resumed.status.code(), Some(1), "partial failure must fail");
    let stderr = String::from_utf8(resumed.stderr).unwrap();
    assert!(
        stderr.contains("res2"),
        "failure must name the session: {stderr}"
    );
    let kitty = fixture.captures("kitty");
    assert_eq!(kitty.len(), 2, "one launch per session: {kitty:?}");
    let self_exe = fs::canonicalize(binary()).unwrap();
    for (index, name) in ["res1", "res2"].iter().enumerate() {
        let argv = &kitty[index].1;
        assert_eq!(argv[0], "@");
        assert_eq!(
            argv[1..3],
            ["--to", "unix:/tmp/kitty-test.sock"].map(str::to_owned)
        );
        assert_eq!(argv[3..5], ["launch", "--type=tab"].map(str::to_owned));
        assert_eq!(argv[5], "--tab-title");
        assert_eq!(argv[6], format!("eversh testhost {name}"));
        assert_eq!(argv[7], "--");
        assert_eq!(
            fs::canonicalize(&argv[8]).unwrap(),
            self_exe,
            "tab must run this executable"
        );
        assert_eq!(
            argv[9..],
            ["attach", "testhost", name, "--hold-on-error"].map(str::to_owned)
        );
    }

    for name in ["res1", "res2"] {
        let killed = fixture
            .command()
            .args(["kill", "testhost", name])
            .output()
            .unwrap();
        assert_eq!(killed.status.code(), Some(0));
    }
    assert_eq!(wait_bounded(&mut one.child, "res1 exit").code(), Some(41));
    assert_eq!(wait_bounded(&mut two.child, "res2 exit").code(), Some(41));
}

#[test]
fn hold_on_error_keeps_the_failure_visible_until_stdin_closes() {
    let fixture = Fixture::new();
    fixture.set_mode("run");
    let mut command = fixture.command();
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .args(["attach", "testhost", "absent", "--hold-on-error"]);
    let mut child = command.spawn().unwrap();
    let stdin = child.stdin.take().unwrap();
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        child.try_wait().unwrap().is_none(),
        "hold-on-error must keep the process alive"
    );
    drop(stdin);
    let status = wait_bounded(&mut child, "hold-on-error exit");
    assert_eq!(status.code(), Some(1));
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(stderr.contains("press Enter to close"), "{stderr}");
}

#[test]
fn everpty_role_grammar_and_version_fail_closed_at_the_binary() {
    let fixture = Fixture::new();
    // Unsupported version word: exit 6 naming the supported version.
    let output = fixture
        .command()
        .args(["__everpty", "v2", "probe", "x"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(6));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("v1"), "{stderr}");

    // Grammar violations: exit 2.
    for bad in [
        &["__everpty", "v1", "explode", "x"][..],
        &["__everpty", "v1", "probe", "-bad"],
        &["__everpty", "v1", "attach", "n", "!!"],
    ] {
        let output = fixture.command().args(bad).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{bad:?}");
    }

    // Probe of a missing session: the documented not-live exit.
    let output = fixture
        .command()
        .args(["__everpty", "v1", "probe", "absent"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(5));

    // The everlink role dispatches to the shared edge.
    let output = fixture
        .command()
        .args(["__everlink", "--help"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("ssh-proxy"), "{help}");
}

#[test]
fn unnamed_connect_generates_and_announces_a_session_name() {
    let fixture = Fixture::new();
    fixture.set_mode("run");
    let mut session = spawn_interactive(
        &fixture,
        "unnamed",
        &["connect", "testhost", "--", "/bin/sh", "-c", "exit 21"],
    );
    let status = wait_bounded(&mut session.child, "unnamed connect");
    assert_eq!(status.code(), Some(21));
    let stderr = fs::read_to_string(&session.stderr_path).unwrap();
    assert!(
        stderr.contains("eversh: session name s"),
        "generated name must be announced: {stderr}"
    );
}

/// A `Config` built for library-level calls (no PATH lookup needed: every
/// program reference is absolute).
fn library_config(fixture: &Fixture, limits: eversh::Limits) -> SupervisorConfig {
    SupervisorConfig {
        ssh_program: fixture.bin.join("ssh").into_os_string(),
        kitty_program: fixture.bin.join("kitty").into_os_string(),
        self_exe: fs::canonicalize(binary()).unwrap(),
        remote_eversh: fixture.bin.join("eversh").to_str().unwrap().to_owned(),
        kitty_listen_on: None,
        local_host: "testlocal".to_owned(),
        limits,
    }
}

/// Gives this whole test PROCESS a blocking (never-EOF) fd 0 for its
/// lifetime, restoring the original on drop. Only needed when driving
/// `eversh::supervisor` directly as a library call rather than through a
/// real PTY-backed subprocess (as `spawn_interactive` provides): without
/// this, the writer's attach loop reads the test harness's own already-EOF
/// stdin and ends the attachment immediately as an ordinary "local terminal
/// closed" detach, never reaching the transport-failure path this test
/// means to exercise. Safe here because no other test or spawned command in
/// this file relies on the process's OWN inherited fd 0 (every `Command`
/// either sets `.stdin(...)` explicitly or, like `kill`, never reads it).
struct BlockingStdin {
    saved_original: OwnedFd,
    _keep_open: OwnedFd,
}

impl BlockingStdin {
    fn install() -> Self {
        // Save a duplicate of the current fd 0 at a fresh, kernel-assigned
        // descriptor number; dup2's target-close is atomic, so there is no
        // TOCTOU window to race another thread's own fd use.
        let (saved_slot, spare) = sys::pipe_cloexec().unwrap();
        unsafe { sys::child_dup2(0, saved_slot.as_raw_fd()).unwrap() };
        drop(spare);
        let (stdin_read, stdin_write) = sys::pipe_cloexec().unwrap();
        unsafe { sys::child_dup2(stdin_read.as_raw_fd(), 0).unwrap() };
        Self {
            saved_original: saved_slot,
            _keep_open: stdin_write,
        }
    }
}

impl Drop for BlockingStdin {
    fn drop(&mut self) {
        // SAFETY: restoring this process's own fd 0 from the saved
        // duplicate; best-effort on drop.
        unsafe {
            let _ = sys::child_dup2(self.saved_original.as_raw_fd(), 0);
        }
    }
}

/// Env var marker: when set, this process IS the isolated worker below
/// (rather than the outer `#[test]` that spawns it).
const DEADLINE_TEST_WORKER_ENV: &str = "EVERSH_DEADLINE_TEST_WORKER";

#[test]
fn reconnect_deadline_bounds_a_hung_probe() {
    if std::env::var_os(DEADLINE_TEST_WORKER_ENV).is_some() {
        reconnect_deadline_bounds_a_hung_probe_worker();
        return;
    }
    // `BlockingStdin` below swaps THIS PROCESS's fd 0 for its duration —
    // safe only when this process runs no other test concurrently. cargo
    // test runs tests as threads within ONE process, so re-exec the test
    // binary filtered to just this test, in its OWN process, and propagate
    // its result; the worker (recognized via the env marker) does the real
    // work in that isolated child.
    let exe = std::env::current_exe().unwrap();
    let output = Command::new(exe)
        .args([
            "--exact",
            "reconnect_deadline_bounds_a_hung_probe",
            "--test-threads=1",
        ])
        .env(DEADLINE_TEST_WORKER_ENV, "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "isolated deadline test failed:\n--- stdout ---\n{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn reconnect_deadline_bounds_a_hung_probe_worker() {
    // Finding 3: retry_deadline_ms must bound the WHOLE reconnect episode.
    // A hung probe is killed at the remaining deadline. The CLI always uses
    // the default 60s deadline, so this drives the supervisor LIBRARY
    // directly with a small one to keep the test fast.
    let fixture = Fixture::new();
    fixture.set_mode("run");
    // The library call below spawns the fake ssh directly (not through
    // Fixture::command's env_clear), so it inherits this process's own
    // environment: point it at the same state root and fake-ssh controls
    // phase 1 used.
    std::env::set_var("EVERSH_STATE_DIR", &fixture.state);
    std::env::set_var("FAKE_CAPTURE_DIR", &fixture.capture);
    std::env::set_var("FAKE_SSH_MODE_FILE", &fixture.mode_file);
    // The library-driven attach() below inherits this process's stdin; give
    // it a blocking one so the writer loop doesn't see immediate local EOF.
    let _stdin_guard = BlockingStdin::install();

    // Establish a real broker+child through an ordinary interactive
    // connect, then cleanly detach (the broker and child persist) so the
    // session is idle and ready for our own library-level attach() below.
    let mut setup = spawn_interactive(
        &fixture,
        "hang-setup",
        &[
            "connect",
            "testhost",
            "--session",
            "hang1",
            "--",
            "/bin/sh",
            "-c",
            TICK_SCRIPT,
        ],
    );
    let mut seen = Vec::new();
    read_until(&mut setup.master, &mut seen, b"READY", "hang setup ready");
    let detached = fixture
        .command()
        .args(["detach", "testhost", "hang1"])
        .output()
        .unwrap();
    assert_eq!(
        detached.status.code(),
        Some(0),
        "setup detach failed: {}",
        String::from_utf8_lossy(&detached.stderr)
    );
    // The writer's own connection observes a plain socket EOF after being
    // detached (everpty's existing NotLive-on-EOF behavior, unrelated to
    // this repair): exit 1, not 0. The broker and child persist regardless.
    let status = wait_bounded(&mut setup.child, "setup connect after detach");
    assert_eq!(
        status.code(),
        Some(1),
        "setup stderr: {}",
        fs::read_to_string(&setup.stderr_path).unwrap()
    );

    let limits = eversh::Limits {
        retry_deadline_ms: 2_500,
        retry_backoff_base_ms: 50,
        retry_backoff_cap_ms: 100,
        retry_attempts_max: 10,
        ..eversh::Limits::default()
    };
    let config = library_config(&fixture, limits);
    let before = fixture.ssh_pid_files().len();

    let handle = std::thread::spawn(move || {
        let mut notifier = SilentNotifier;
        eversh::supervisor::attach(&config, "testhost", "hang1", false, &[], &mut notifier)
    });

    // Wait for this call's own first ssh invocation's pid file to actually
    // exist (not just its argv capture, written slightly earlier), then let
    // it establish for real (mode is still "run"), then kill ITS transport
    // and make every later invocation hang.
    let seen_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if fixture.ssh_pid_files().len() > before {
            break;
        }
        assert!(Instant::now() < seen_deadline, "attach() never invoked ssh");
        std::thread::sleep(Duration::from_millis(5));
    }
    std::thread::sleep(Duration::from_millis(300));
    let ssh_pid = fixture.newest_ssh_pid();
    assert!(
        std::path::Path::new(&format!("/proc/{ssh_pid}")).exists(),
        "the established attach() ssh process (pid {ssh_pid}) already exited; captures: {:?}",
        fixture.captures("ssh")
    );
    send_signal(ssh_pid, "-USR1");
    fixture.set_mode("hang");

    let start = Instant::now();
    let result = handle.join().unwrap();
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "deadline not enforced promptly: {elapsed:?}"
    );
    assert_eq!(
        result.unwrap(),
        SessionEnd::TransportFailed(TransportFailure::DeadlineExceeded)
    );

    // No fake-ssh process remains: the hung probe was killed and reaped.
    let hung_pid = fixture.newest_ssh_pid();
    assert!(
        !std::path::Path::new(&format!("/proc/{hung_pid}")).exists(),
        "hung fake ssh (pid {hung_pid}) was not reaped"
    );

    // Cleanup: the broker is still alive.
    fixture.set_mode("run");
    let killed = fixture
        .command()
        .args(["__everpty", "v1", "kill", "hang1"])
        .output()
        .unwrap();
    assert_eq!(killed.status.code(), Some(0));
}
