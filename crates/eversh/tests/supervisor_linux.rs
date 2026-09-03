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
    Config as SupervisorConfig, Event, Notifier, SessionEnd, SilentNotifier, TransportFailure,
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
use std::sync::{Arc, Mutex};
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
/// environment, honors a mode file, and simulates the LOCAL everssh
/// link-status file protocol eversh's supervisor now reads (design 3, 7)
/// instead of any remote channel — including merging what a real remote
/// role's stderr would produce into the SAME stream as stdout whenever a
/// pty was requested (`-t`), exactly like real sshd does, so a test relying
/// on an in-band-stderr assumption fails here the same way it would against
/// real OpenSSH. The status path is extracted from the `--status-file`
/// argument inside the ProxyCommand option value, exactly as the real
/// everssh edge receives it from its own argv after the local shell splits
/// the ProxyCommand line — never from the environment.
///
/// Modes: `run` (default) actually execs the remote command, writing
/// `carrying` before (for non-probe ops) and a terminal `cause clean-close
/// carried=1` after it exits naturally; SIGUSR1 kills the exec'd child and
/// exits 255 without writing a terminal record (mirroring an uncatchable
/// SIGKILL to a real everssh process), publishing `FAKE_SSH_NEXT_MODE` as
/// the next mode when set. `fail255` writes `cause clean-close
/// carried=0` and exits 255 (an ordinary SSH-level failure/rejection — also
/// used to make a probe report Unreachable, which never reads the file).
/// `hang` execs `sleep 600` unconditionally (a wedged transport that never
/// carries anything). `hangreattach` answers a probe `Live` but hangs the
/// same way for any non-probe (reattach) invocation. `carrieddeath`
/// answers a probe `Live` but, for a reattach, writes `carrying` then
/// `cause transport-failure carried=1`, restores mode `run`, and exits
/// 255 — a reattach that briefly carried real bytes before dying again.
/// `carriedflap` is the same carried death WITHOUT ever restoring `run` —
/// a topology that flaps forever, driving the supervisor into its
/// invocation-wide episode-restart cap. `busyonce` answers the FIRST
/// non-probe (reattach) invocation with the real Busy exit code once, then
/// behaves like `run`; `busypersist` always answers Busy for non-probe
/// invocations; `busyhold` answers Busy for the first
/// `FAKE_BUSY_HOLD` (default 6) non-probe invocations via a counter file,
/// then behaves like `run` — simulating a remote writer whose slot is
/// legitimately held past the old attempt budget and released before the
/// episode deadline. Every probe-classifying mode answers a probe
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

has_pty=0
is_probe=0
for arg in "$@"; do
  case "$arg" in
    --) break ;;
    -t) has_pty=1 ;;
  esac
done
for arg in "$@"; do
  if [ "$arg" = probe ]; then is_probe=1; fi
done

# The per-spawn status path arrives as a --status-file argument inside the
# ProxyCommand option value (never an environment variable): extract it the
# same way the real everssh edge receives it after the local shell splits
# the ProxyCommand line.
status_file=
for arg in "$@"; do
  case "$arg" in
    ProxyCommand=*" --status-file '"*)
      rest=${arg#*" --status-file '"}
      status_file=${rest%%"'"*}
      ;;
  esac
done

status_carrying() {
  [ -n "$status_file" ] || return 0
  printf 'everssh-status-v1 carrying\n' >> "$status_file" 2>/dev/null || true
}
status_cause() {
  [ -n "$status_file" ] || return 0
  printf 'everssh-status-v1 cause %s carried=%s\n' "$1" "$2" >> "$status_file" 2>/dev/null || true
}

mode=run
[ -f "${FAKE_SSH_MODE_FILE:-/nonexistent}" ] && mode=$(cat "$FAKE_SSH_MODE_FILE")

if [ "$mode" = fail255 ]; then
  status_cause clean-close 0
  exit 255
fi
if [ "$mode" = terminalcarried ]; then
  if [ "$is_probe" -eq 1 ]; then exit 0; fi
  status_cause transport-failure 1
  printf %s run > "$FAKE_SSH_MODE_FILE" 2>/dev/null || true
  exit 255
fi
if [ "$mode" = hang ]; then
  exec sleep 600
fi
if [ "$mode" = hangreattach ]; then
  if [ "$is_probe" -eq 1 ]; then exit 0; fi
  exec sleep 600
fi
if [ "$mode" = carrieddeath ] || [ "$mode" = carriedflap ]; then
  if [ "$is_probe" -eq 1 ]; then exit 0; fi
  status_carrying
  status_cause transport-failure 1
  # The dying reattach itself restores the `run` phase so the restarted
  # episode's probe/reattach is real — again strictly before the
  # supervisor can observe this exit. carriedflap deliberately never
  # restores it: every later reattach dies the same carried death.
  if [ "$mode" = carrieddeath ]; then
    printf %s run > "$FAKE_SSH_MODE_FILE" 2>/dev/null || true
  fi
  exit 255
fi
if [ "$mode" = busyonce ] || [ "$mode" = busypersist ] || [ "$mode" = busyhold ]; then
  if [ "$is_probe" -eq 1 ]; then exit 0; fi
  if [ "$mode" = busypersist ]; then exit 3; fi
  marker="$FAKE_CAPTURE_DIR/.busyonce-used"
  if [ "$mode" = busyonce ] && [ ! -f "$marker" ]; then
    : > "$marker"
    exit 3
  fi
  if [ "$mode" = busyhold ]; then
    count_file="$FAKE_CAPTURE_DIR/.busyhold-count"
    n=0
    [ -f "$count_file" ] && n=$(cat "$count_file")
    n=$((n+1))
    printf %s "$n" > "$count_file"
    hold=${FAKE_BUSY_HOLD:-6}
    if [ "$n" -le "$hold" ]; then exit 3; fi
  fi
  # Budget consumed (or marker already used): fall through to a real
  # reattach exec below.
fi

# mode=run, or busyonce's post-marker fallthrough: a real invocation.
while [ "$#" -gt 0 ] && [ "$1" != -- ]; do shift; done
[ "$#" -gt 0 ] && shift
[ "$#" -gt 0 ] && shift
if [ "$#" -eq 0 ]; then exit 255; fi
if [ "$is_probe" -eq 0 ]; then status_carrying; fi
exec 3<&0
if [ "$has_pty" -eq 1 ]; then
  "$@" <&3 3<&- 2>&1 &
else
  "$@" <&3 3<&- &
fi
child=$!
exec 3<&-
# A USR1 death publishes FAKE_SSH_NEXT_MODE (when set) as the next
# scenario phase BEFORE exiting — strictly before the supervisor can
# observe this exit and spawn anything new, so a slow test thread can
# never race the supervisor's probe/reattach cycle with a late mode
# write.
trap 'kill -KILL "$child" 2>/dev/null; if [ -n "${FAKE_SSH_NEXT_MODE:-}" ]; then printf "%s" "$FAKE_SSH_NEXT_MODE" > "$FAKE_SSH_MODE_FILE" 2>/dev/null || true; fi; exit 255' USR1
wait "$child"
code=$?
if [ "$is_probe" -eq 0 ]; then status_cause clean-close 1; fi
exit "$code"
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

    /// One specific capture's own `.env` file, given the `.argv` capture
    /// name `captures()` returned for it (empty if none was captured).
    fn env_for(&self, argv_capture_name: &str) -> Vec<Vec<u8>> {
        let Some(base) = argv_capture_name.strip_suffix(".argv") else {
            return Vec::new();
        };
        let bytes = fs::read(self.capture.join(format!("{base}.env"))).unwrap_or_default();
        bytes
            .split(|byte| *byte == 0)
            .filter(|part| !part.is_empty())
            .map(<[u8]>::to_vec)
            .collect()
    }
}

/// A minor finding repair: no captured supervisor-invoked process
/// environment may carry a bootstrap token (a 64-hex-character run) or a raw
/// bootstrap record line (`everssh v1 ...`) — the supervisor never places
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
            !value.starts_with("everssh v1 "),
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
    spawn_interactive_env(fixture, label, args, &[])
}

/// [`spawn_interactive`] with extra environment entries for the spawned
/// eversh process (used to preset fake-ssh scenario controls such as
/// `FAKE_SSH_NEXT_MODE`).
fn spawn_interactive_env(
    fixture: &Fixture,
    label: &str,
    args: &[&str],
    extra_env: &[(&str, &str)],
) -> PtySession {
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
    for (key, value) in extra_env {
        command.env(key, value);
    }
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

    // Every structured invocation (attach-or-create, probe, attach) embeds
    // its own per-spawn status path as a --status-file ProxyCommand argument
    // (design 3, 7) — and none carries it as an environment variable.
    for index in [0, captures.len() - 2, captures.len() - 1] {
        let (name, argv) = &captures[index];
        assert!(
            argv[1].contains(" --status-file '"),
            "{name} must embed the status path as a ProxyCommand argument: {}",
            argv[1]
        );
        let env = fixture.env_for(name);
        assert!(
            env.iter().all(|entry| {
                !String::from_utf8_lossy(entry).starts_with("EVERSH_LINK_STATUS_FILE=")
            }),
            "{name} must never carry a link-status environment variable"
        );
    }

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
    // The deterministic pre-bridge diagnostic the real-OpenSSH gate greps.
    assert!(
        stderr.contains("ssh reported failure with the transport intact"),
        "pre-bridge failure diagnostic missing: {stderr}"
    );
}

/// Round 4, G1/G2: a classification-carrying invocation must fail closed
/// with the pinned local error BEFORE any ssh child exists — asserted via
/// the argv-capturing fake seeing ZERO ssh spawns.
#[test]
fn percent_state_root_fails_closed_before_any_ssh_spawn() {
    let fixture = Fixture::new();
    fixture.set_mode("run");
    // A state root whose own path contains a percent token: OpenSSH
    // expands `%h` inside the quoted --status-file ProxyCommand word
    // before the local shell sees the quotes, so everssh would receive
    // (and write) a DIFFERENT path than the supervisor allocated.
    let hostile = fixture.base.join("st%hate");
    fs::create_dir_all(&hostile).unwrap();
    let output = fixture
        .command()
        .env("EVERSH_STATE_DIR", &hostile)
        .args([
            "connect",
            "testhost",
            "--session",
            "pct1",
            "--",
            "/bin/sh",
            "-c",
            "exit 0",
        ])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(1),
        "a percent state root must be a local error, not a spawn: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The pinned G1 diagnostic (exact, trailing newline aside).
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().trim(),
        format!(
            "eversh: cannot allocate the private link-status channel under {}: \
             state root path is not a safe ProxyCommand word (percent tokens rejected)",
            hostile.display()
        )
    );
    assert!(
        fixture.captures("ssh").is_empty(),
        "no ssh may spawn under a percent state root: {:?}",
        fixture.captures("ssh")
    );
    // Rejection happens before anything is created on disk.
    let entries: Vec<_> = fs::read_dir(&hostile).unwrap().flatten().collect();
    assert!(entries.is_empty(), "hostile root was touched: {entries:?}");
}

/// Round 4, G1: an unallocatable state root (the private link-status
/// directory cannot exist under it — here a regular file occupies the
/// path) fails closed with the pinned local error before any ssh spawn,
/// deterministically for every uid (the same fault branch an EACCES on an
/// unwritable root takes).
#[test]
fn unallocatable_state_root_fails_closed_before_any_ssh_spawn() {
    let fixture = Fixture::new();
    fixture.set_mode("run");
    let hostile = fixture.base.join("blocked-state");
    fs::create_dir(&hostile).unwrap();
    File::create(hostile.join("link-status")).unwrap();
    let output = fixture
        .command()
        .env("EVERSH_STATE_DIR", &hostile)
        .args([
            "connect",
            "testhost",
            "--session",
            "blk1",
            "--",
            "/bin/sh",
            "-c",
            "exit 0",
        ])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(1),
        "an unallocatable state root must be a local error, not a spawn: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains(&format!(
            "cannot allocate the private link-status channel under {}",
            hostile.display()
        )),
        "{stderr}"
    );
    assert!(
        stderr.contains("cannot create the private link-status directory"),
        "{stderr}"
    );
    assert!(
        fixture.captures("ssh").is_empty(),
        "no ssh may spawn under an unallocatable root: {:?}",
        fixture.captures("ssh")
    );
    // Nothing was created or replaced under the root.
    let entries: Vec<String> = fs::read_dir(&hostile)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().into_string().unwrap())
        .collect();
    assert_eq!(entries, vec!["link-status".to_owned()]);
}

/// Round 4, G1: with NO state-root candidate at all (no env var, no
/// HOME), a classification-carrying invocation fails closed with the
/// pinned no-root diagnostic instead of spawning uninstrumented.
#[test]
fn missing_state_root_fails_closed_before_any_ssh_spawn() {
    let fixture = Fixture::new();
    fixture.set_mode("run");
    let output = fixture
        .command()
        .env_remove("EVERSH_STATE_DIR")
        .args([
            "connect",
            "testhost",
            "--session",
            "noroot",
            "--",
            "/bin/sh",
            "-c",
            "exit 0",
        ])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(1),
        "a missing state root must be a local error, not a spawn: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().trim(),
        "eversh: cannot allocate the private link-status channel: no state root resolved \
         (set EVERSH_STATE_DIR, XDG_RUNTIME_DIR, XDG_STATE_HOME, or HOME)"
    );
    assert!(
        fixture.captures("ssh").is_empty(),
        "no ssh may spawn without a state root: {:?}",
        fixture.captures("ssh")
    );
}

/// Round 4, G4 regression pin at supervisor level: a NORMAL root plus a
/// pre-bridge auth-style failure (clean-close 255, carried=0) reports the
/// typed `SshFailed` after exactly ONE ssh spawn — no probe, no retry —
/// and the allocated status file is gone afterwards (G3).
#[test]
fn normal_root_pre_bridge_auth_failure_is_ssh_failed_no_probe() {
    if is_isolated_worker("normal_root_pre_bridge_auth_failure_is_ssh_failed_no_probe") {
        normal_root_pre_bridge_auth_failure_is_ssh_failed_no_probe_worker();
        return;
    }
    run_isolated("normal_root_pre_bridge_auth_failure_is_ssh_failed_no_probe");
}

fn normal_root_pre_bridge_auth_failure_is_ssh_failed_no_probe_worker() {
    let fixture = Fixture::new();
    fixture.set_mode("fail255");
    // The library-driven attach() below spawns the fake ssh directly (not
    // through Fixture::command's env_clear), so it inherits this process's
    // own environment: point it at this fixture's capture/mode controls.
    std::env::set_var("FAKE_CAPTURE_DIR", &fixture.capture);
    std::env::set_var("FAKE_SSH_MODE_FILE", &fixture.mode_file);
    let config = library_config(&fixture, eversh::Limits::default());
    let mut notifier = SilentNotifier;
    let result =
        eversh::supervisor::attach(&config, "testhost", "authpin", false, &[], &mut notifier);
    assert_eq!(
        result.unwrap(),
        SessionEnd::SshFailed,
        "a pre-bridge auth failure must classify clean-close, never retry"
    );
    let captures = fixture.captures("ssh");
    assert_eq!(captures.len(), 1, "no probe, no retry: {captures:?}");
    assert!(
        !captures
            .iter()
            .any(|(_, argv)| argv.contains(&"probe".to_owned())),
        "{captures:?}"
    );
    // G3: the classified spawn's status file was removed.
    let dir = fixture.state.join("link-status");
    let left: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().into_string().unwrap())
        .collect();
    assert!(left.is_empty(), "status files leaked: {left:?}");
}

/// Round 4, G3: an error AFTER allocation but BEFORE the spawn (an SSH
/// option rejected by the audited allowlist) must still leave no status
/// file behind — the allocation-to-removal guard, not a scattered removal.
#[test]
fn guard_removes_the_status_file_on_a_pre_spawn_error() {
    let fixture = Fixture::new();
    let config = library_config(&fixture, eversh::Limits::default());
    let mut notifier = SilentNotifier;
    let result = eversh::supervisor::attach(
        &config,
        "testhost",
        "guard1",
        false,
        &["-p22".to_owned()],
        &mut notifier,
    );
    assert!(
        matches!(result, Err(eversh::Error::SshOptionRejected)),
        "expected the audited allowlist to reject -p22: {result:?}"
    );
    assert!(fixture.captures("ssh").is_empty());
    let dir = fixture.state.join("link-status");
    let left: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().into_string().unwrap())
        .collect();
    assert!(left.is_empty(), "status files leaked: {left:?}");
}

/// Round 4, G3: a spawn that itself fails (the ssh program cannot be
/// executed) returns through the `?` on `spawn()` — previously a leak —
/// and the guard still removes the allocated file.
#[test]
fn guard_removes_the_status_file_on_a_spawn_error() {
    let fixture = Fixture::new();
    let mut config = library_config(&fixture, eversh::Limits::default());
    config.ssh_program = fixture.bin.join("ssh-does-not-exist").into_os_string();
    let mut notifier = SilentNotifier;
    let result =
        eversh::supervisor::attach(&config, "testhost", "guard2", false, &[], &mut notifier);
    assert!(result.is_err(), "a missing ssh binary must be an error");
    let dir = fixture.state.join("link-status");
    let left: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().into_string().unwrap())
        .collect();
    assert!(left.is_empty(), "status files leaked: {left:?}");
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
    // Interactive ops request a pty (`-t`), so the remote role's own stderr
    // diagnostic merges into the SAME stream as stdout — exactly like real
    // sshd — and shows up on the pty master, not the separate local stderr.
    let mut busy = spawn_interactive(&fixture, "busy", &["attach", "testhost", "busy1"]);
    let status = wait_bounded(&mut busy.child, "busy attach");
    assert_eq!(status.code(), Some(3), "Busy must map to exit 3");
    let mut busy_output = Vec::new();
    read_available(&mut busy.master, &mut busy_output);
    assert!(!busy_output.is_empty(), "busy failure must be visible");
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

/// Common setup for the library-level busy-retry workers: establish a real
/// broker+child, detach it (the broker and child persist, writerless), and
/// leave the fake-ssh controls pointed at this process's environment so the
/// library-driven `attach()` below sees them.
fn busy_retry_setup(label: &str, name: &str) -> Fixture {
    let fixture = Fixture::new();
    fixture.set_mode("run");
    std::env::set_var("EVERSH_STATE_DIR", &fixture.state);
    std::env::set_var("FAKE_CAPTURE_DIR", &fixture.capture);
    std::env::set_var("FAKE_SSH_MODE_FILE", &fixture.mode_file);
    let mut setup = spawn_interactive(
        &fixture,
        label,
        &[
            "connect",
            "testhost",
            "--session",
            name,
            "--",
            "/bin/sh",
            "-c",
            TICK_SCRIPT,
        ],
    );
    let mut seen = Vec::new();
    read_until(
        &mut setup.master,
        &mut seen,
        b"READY",
        &format!("{label} ready"),
    );
    let detached = fixture
        .command()
        .args(["detach", "testhost", name])
        .output()
        .unwrap();
    assert_eq!(
        detached.status.code(),
        Some(0),
        "{label} setup detach failed: {}",
        String::from_utf8_lossy(&detached.stderr)
    );
    let status = wait_bounded(&mut setup.child, &format!("{label} setup after detach"));
    assert_eq!(
        status.code(),
        Some(1),
        "{label} setup stderr: {}",
        fs::read_to_string(&setup.stderr_path).unwrap()
    );
    fixture
}

/// Kill the library call's own first (established) ssh spawn and switch the
/// fakes to `mode` for every later invocation.
fn kill_first_spawn_and_set_mode(fixture: &Fixture, before: usize, mode: &str) {
    let seen_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if fixture.ssh_pid_files().len() > before {
            break;
        }
        assert!(
            Instant::now() < seen_deadline,
            "attach() never invoked ssh; captures: {:?}",
            fixture.captures("ssh")
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    std::thread::sleep(Duration::from_millis(300));
    let ssh_pid = fixture.newest_ssh_pid();
    assert!(
        std::path::Path::new(&format!("/proc/{ssh_pid}")).exists(),
        "the established attach() ssh process (pid {ssh_pid}) already exited"
    );
    send_signal(ssh_pid, "-USR1");
    fixture.set_mode(mode);
}

#[test]
fn reattach_busy_persisting_ends_at_the_episode_deadline_never_escalating() {
    if is_isolated_worker("reattach_busy_persisting_ends_at_the_episode_deadline_never_escalating")
    {
        reattach_busy_persisting_ends_at_the_episode_deadline_never_escalating_worker();
        return;
    }
    run_isolated("reattach_busy_persisting_ends_at_the_episode_deadline_never_escalating");
}

#[test]
fn carried_terminal_failure_waits_association_drain_before_probing() {
    if is_isolated_worker("carried_terminal_failure_waits_association_drain_before_probing") {
        carried_terminal_failure_waits_association_drain_before_probing_worker();
        return;
    }
    run_isolated("carried_terminal_failure_waits_association_drain_before_probing");
}

fn carried_terminal_failure_waits_association_drain_before_probing_worker() {
    let fixture = Fixture::new();
    fixture.set_mode("run");
    let mut setup = spawn_interactive(
        &fixture,
        "drain-setup",
        &[
            "connect",
            "testhost",
            "--session",
            "drain1",
            "--",
            "/bin/sh",
            "-c",
            TICK_SCRIPT,
        ],
    );
    let mut seen = Vec::new();
    read_until(&mut setup.master, &mut seen, b"READY", "drain setup ready");
    let detached = fixture
        .command()
        .args(["detach", "testhost", "drain1"])
        .output()
        .unwrap();
    assert_eq!(
        detached.status.code(),
        Some(0),
        "setup detach failed: {}",
        String::from_utf8_lossy(&detached.stderr)
    );
    let status = wait_bounded(&mut setup.child, "drain setup after detach");
    assert_eq!(status.code(), Some(1));

    fixture.set_mode("terminalcarried");
    std::env::set_var("EVERSH_STATE_DIR", &fixture.state);
    std::env::set_var("FAKE_CAPTURE_DIR", &fixture.capture);
    std::env::set_var("FAKE_SSH_MODE_FILE", &fixture.mode_file);
    let _stdin_guard = BlockingStdin::install();
    let limits = eversh::Limits {
        association_drain_ms: 300,
        retry_deadline_ms: 5_000,
        retry_backoff_base_ms: 10,
        retry_backoff_cap_ms: 20,
        ..eversh::Limits::default()
    };
    let config = library_config(&fixture, limits);
    let count_probes = |fixture: &Fixture| {
        fixture
            .captures("ssh")
            .into_iter()
            .filter(|(_, argv)| argv.iter().any(|argument| argument == "probe"))
            .count()
    };
    let before = count_probes(&fixture);
    let handle = std::thread::spawn(move || {
        let mut notifier = SilentNotifier;
        eversh::supervisor::attach(&config, "testhost", "drain1", false, &[], &mut notifier)
    });

    let drain_deadline = Instant::now() + Duration::from_millis(200);
    while Instant::now() < drain_deadline {
        assert!(
            count_probes(&fixture) == before,
            "probe ran before association drain"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let probe_deadline = Instant::now() + Duration::from_secs(3);
    while count_probes(&fixture) == before {
        assert!(
            Instant::now() < probe_deadline,
            "probe did not run after drain"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let killed = fixture
        .command()
        .args(["kill", "testhost", "drain1"])
        .output()
        .unwrap();
    assert_eq!(
        killed.status.code(),
        Some(0),
        "kill failed: {}",
        String::from_utf8_lossy(&killed.stderr)
    );
    let end = handle.join().unwrap().unwrap();
    assert_eq!(end, SessionEnd::Remote(41));
}

fn reattach_busy_persisting_ends_at_the_episode_deadline_never_escalating_worker() {
    // Finding 1: a reattach that persistently reports Busy is retried
    // against the episode's OWN deadline, never the attempt budget and
    // never `--take-over` — so the busy streak must run PAST the old
    // attempt budget (5) before the deadline ends it.
    let fixture = busy_retry_setup("busypersist", "bzp1");
    let _stdin_guard = BlockingStdin::install();

    let limits = eversh::Limits {
        retry_deadline_ms: 5_000,
        association_drain_ms: 10,
        retry_backoff_base_ms: 50,
        retry_backoff_cap_ms: 100,
        ..eversh::Limits::default()
    };
    let config = library_config(&fixture, limits);
    let before = fixture.ssh_pid_files().len();

    let handle = std::thread::spawn(move || {
        let mut notifier = SilentNotifier;
        eversh::supervisor::attach(&config, "testhost", "bzp1", false, &[], &mut notifier)
    });
    kill_first_spawn_and_set_mode(&fixture, before, "busypersist");

    let start = Instant::now();
    let result = handle.join().unwrap();
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(10),
        "deadline not enforced promptly: {elapsed:?}"
    );
    assert_eq!(
        result.unwrap(),
        SessionEnd::TransportFailed(TransportFailure::Busy)
    );

    // The busy streak ran past the old attempt budget before the deadline
    // bound it, and no attach ever escalated to take_over.
    let mut all = fixture.captures("ssh");
    let after = all.split_off(before);
    let probes = after
        .iter()
        .filter(|(_, argv)| argv.contains(&"probe".to_owned()))
        .count();
    let attaches = after
        .iter()
        .filter(|(_, argv)| {
            argv.contains(&"attach".to_owned()) && !argv.contains(&"attach-or-create".to_owned())
        })
        .count();
    assert!(
        probes > 5,
        "busy retries must not be attempt-capped: {after:?}"
    );
    assert!(attaches > 5, "{after:?}");
    for request in attach_requests(&after) {
        assert!(
            !request.take_over,
            "persistent busy must never escalate to take_over"
        );
    }

    // Cleanup: the broker persists; kill it directly.
    fixture.set_mode("run");
    let killed = fixture
        .command()
        .args(["__everpty", "v1", "kill", "bzp1"])
        .output()
        .unwrap();
    assert_eq!(killed.status.code(), Some(0));
}

#[test]
fn busy_retries_span_past_the_old_attempt_budget_until_the_writer_releases() {
    if is_isolated_worker("busy_retries_span_past_the_old_attempt_budget_until_the_writer_releases")
    {
        busy_retries_span_past_the_old_attempt_budget_until_the_writer_releases_worker();
        return;
    }
    run_isolated("busy_retries_span_past_the_old_attempt_budget_until_the_writer_releases");
}

fn busy_retries_span_past_the_old_attempt_budget_until_the_writer_releases_worker() {
    // Finding 1, the S3 shape: after a path death the remote writer slot is
    // legitimately held for a long window (everssh's idle timeout), so a
    // reattach keeps reporting Busy. With the deadline governing the busy
    // path, the supervisor must still be reattaching WELL past the old
    // 5-attempt budget when the slot finally releases — and then succeed,
    // on the same local process, without ever taking over.
    let fixture = busy_retry_setup("busyhold", "bzh1");
    std::env::set_var("FAKE_BUSY_HOLD", "9");
    let _stdin_guard = BlockingStdin::install();

    let limits = eversh::Limits {
        // Generous deadline: the release must land well inside it.
        retry_deadline_ms: 30_000,
        association_drain_ms: 10,
        retry_backoff_base_ms: 50,
        retry_backoff_cap_ms: 100,
        ..eversh::Limits::default()
    };
    let config = library_config(&fixture, limits);
    let before = fixture.ssh_pid_files().len();

    let handle = std::thread::spawn(move || {
        let mut notifier = SilentNotifier;
        eversh::supervisor::attach(&config, "testhost", "bzh1", false, &[], &mut notifier)
    });
    kill_first_spawn_and_set_mode(&fixture, before, "busyhold");

    let start = Instant::now();
    // The post-hold REAL reattach is the 11th attach-type spawn (1 first
    // spawn + 9 busy). Wait for it, then give it the same 300ms
    // establishment margin the restart test uses before terminating the
    // session, so the child's TERM-trap exit code is delivered through the
    // reattached writer.
    let reattach_deadline = Instant::now() + Duration::from_secs(25);
    loop {
        let mut all = fixture.captures("ssh");
        let attach_spawns = all
            .split_off(before)
            .iter()
            .filter(|(_, argv)| {
                argv.contains(&"attach".to_owned())
                    && !argv.contains(&"attach-or-create".to_owned())
            })
            .count();
        if attach_spawns >= 11 {
            break;
        }
        assert!(
            Instant::now() < reattach_deadline,
            "busy retries never spanned the hold: {:?}",
            fixture.captures("ssh")
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(Duration::from_millis(300));
    let killed = fixture
        .command()
        .args(["__everpty", "v1", "kill", "bzh1"])
        .output()
        .unwrap();
    assert_eq!(killed.status.code(), Some(0));

    let result = handle.join().unwrap();
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(25),
        "reattach did not settle promptly: {elapsed:?}"
    );
    assert_eq!(
        result.unwrap(),
        SessionEnd::Remote(41),
        "the post-hold reattach must deliver the child's exit status"
    );

    // Nine busy reattaches ran first — four more than the old attempt
    // budget ever allowed — then the tenth reattached for real. (The
    // initial attach() spawn is itself one attach invocation, so: 1 first
    // spawn + 9 busy + 1 real = 11 attaches against 10 probes.)
    let mut all = fixture.captures("ssh");
    let after = all.split_off(before);
    let probes = after
        .iter()
        .filter(|(_, argv)| argv.contains(&"probe".to_owned()))
        .count();
    let attaches = after
        .iter()
        .filter(|(_, argv)| {
            argv.contains(&"attach".to_owned()) && !argv.contains(&"attach-or-create".to_owned())
        })
        .count();
    assert_eq!(probes, 10, "{after:?}");
    assert_eq!(
        attaches, 11,
        "1 first spawn + 9 busy reattaches + 1 real reattach: {after:?}"
    );
    for request in attach_requests(&after) {
        assert!(!request.take_over, "busy retry must never escalate");
    }
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
    assert!(argv[1].contains("__everssh ssh-proxy '%n' '%p' --remote-eversh 'eversh'"));
    // `-L` fails the audited allowlist: it must never be mirrored into the
    // everssh bootstrap, but raw mode must not error over it either
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

    // The everssh role dispatches to the shared edge.
    let output = fixture
        .command()
        .args(["__everssh", "--help"])
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
        link_status_root: Some(fixture.state.clone()),
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

/// Env var marker: when set to a test's name, this process IS the isolated
/// worker for that test (rather than the outer `#[test]` that spawns it).
const ISOLATED_WORKER_ENV: &str = "EVERSH_ISOLATED_WORKER";

fn is_isolated_worker(test_name: &str) -> bool {
    std::env::var(ISOLATED_WORKER_ENV).ok().as_deref() == Some(test_name)
}

/// Re-exec this same test binary filtered to exactly `test_name`, in its
/// OWN process, and assert it succeeded. Some tests need full process
/// isolation: `BlockingStdin` swaps the WHOLE process's fd 0 for its
/// duration, which is unsafe to do inside the shared, multi-threaded
/// `cargo test` process alongside unrelated parallel tests.
fn run_isolated(test_name: &str) {
    let exe = std::env::current_exe().unwrap();
    let output = Command::new(exe)
        .args(["--exact", test_name, "--test-threads=1"])
        .env(ISOLATED_WORKER_ENV, test_name)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "isolated test {test_name} failed:\n--- stdout ---\n{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Records every supervisor event (Debug-formatted) so a failure can show
/// the exact path the supervisor took — probe, reattach, busy retry,
/// exhaustion, restart — rather than only its final outcome. Cloned into
/// the supervisor thread; the joined result and the trace are read
/// together after the thread ends.
#[derive(Clone, Default)]
struct RecordingNotifier(Arc<Mutex<Vec<String>>>);

impl RecordingNotifier {
    fn trace(&self) -> String {
        self.0.lock().unwrap().join("\n")
    }
}

impl Notifier for RecordingNotifier {
    fn notify(&mut self, event: Event<'_>) {
        self.0.lock().unwrap().push(format!("{event:?}"));
    }
}

#[test]
fn reconnect_deadline_bounds_a_hung_probe() {
    if is_isolated_worker("reconnect_deadline_bounds_a_hung_probe") {
        reconnect_deadline_bounds_a_hung_probe_worker();
        return;
    }
    run_isolated("reconnect_deadline_bounds_a_hung_probe");
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
        association_drain_ms: 10,
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

#[test]
fn reconnect_deadline_bounds_a_never_carrying_reattach() {
    if is_isolated_worker("reconnect_deadline_bounds_a_never_carrying_reattach") {
        reconnect_deadline_bounds_a_never_carrying_reattach_worker();
        return;
    }
    run_isolated("reconnect_deadline_bounds_a_never_carrying_reattach");
}

fn reconnect_deadline_bounds_a_never_carrying_reattach_worker() {
    // Finding 3: a reattach that never shows `carrying` is bounded by the
    // remaining episode deadline (probes stay Live so this specifically
    // exercises the REATTACH's own bounded wait, not the probe's).
    let fixture = Fixture::new();
    fixture.set_mode("run");
    std::env::set_var("EVERSH_STATE_DIR", &fixture.state);
    std::env::set_var("FAKE_CAPTURE_DIR", &fixture.capture);
    std::env::set_var("FAKE_SSH_MODE_FILE", &fixture.mode_file);
    let _stdin_guard = BlockingStdin::install();

    let mut setup = spawn_interactive(
        &fixture,
        "reattach-hang-setup",
        &[
            "connect",
            "testhost",
            "--session",
            "rh1",
            "--",
            "/bin/sh",
            "-c",
            TICK_SCRIPT,
        ],
    );
    let mut seen = Vec::new();
    read_until(
        &mut setup.master,
        &mut seen,
        b"READY",
        "reattach hang setup ready",
    );
    let detached = fixture
        .command()
        .args(["detach", "testhost", "rh1"])
        .output()
        .unwrap();
    assert_eq!(
        detached.status.code(),
        Some(0),
        "setup detach failed: {}",
        String::from_utf8_lossy(&detached.stderr)
    );
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
        eversh::supervisor::attach(&config, "testhost", "rh1", false, &[], &mut notifier)
    });

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
        "the established attach() ssh process (pid {ssh_pid}) already exited"
    );
    send_signal(ssh_pid, "-USR1");
    // The probe stays Live; the REATTACH specifically hangs without ever
    // showing `carrying`.
    fixture.set_mode("hangreattach");

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

    let hung_pid = fixture.newest_ssh_pid();
    assert!(
        !std::path::Path::new(&format!("/proc/{hung_pid}")).exists(),
        "hung fake ssh (pid {hung_pid}) was not reaped"
    );

    fixture.set_mode("run");
    let killed = fixture
        .command()
        .args(["__everpty", "v1", "kill", "rh1"])
        .output()
        .unwrap();
    assert_eq!(killed.status.code(), Some(0));
}

#[test]
fn episode_restarts_after_a_carrying_reattach_dies_again() {
    if is_isolated_worker("episode_restarts_after_a_carrying_reattach_dies_again") {
        episode_restarts_after_a_carrying_reattach_dies_again_worker();
        return;
    }
    run_isolated("episode_restarts_after_a_carrying_reattach_dies_again");
}

fn episode_restarts_after_a_carrying_reattach_dies_again_worker() {
    // Finding 3: a reattach whose OWN status file shows `carried=1` before
    // it dies again must start a FRESH episode (fresh attempt/deadline
    // budgets), not consume the current episode's budget. Proven with
    // `retry_attempts_max: 1`: without a real restart, the SECOND
    // probe+reattach cycle (attempt 2 of a never-restarted episode) would
    // immediately exceed the budget and exhaust — so this test would time
    // out waiting for a post-restart reattach if the restart didn't happen.
    let fixture = Fixture::new();
    fixture.set_mode("run");
    std::env::set_var("EVERSH_STATE_DIR", &fixture.state);
    std::env::set_var("FAKE_CAPTURE_DIR", &fixture.capture);
    std::env::set_var("FAKE_SSH_MODE_FILE", &fixture.mode_file);
    let _stdin_guard = BlockingStdin::install();

    let mut setup = spawn_interactive(
        &fixture,
        "restart-setup",
        &[
            "connect",
            "testhost",
            "--session",
            "rs1",
            "--",
            "/bin/sh",
            "-c",
            TICK_SCRIPT,
        ],
    );
    let mut seen = Vec::new();
    read_until(
        &mut setup.master,
        &mut seen,
        b"READY",
        "restart setup ready",
    );
    let detached = fixture
        .command()
        .args(["detach", "testhost", "rs1"])
        .output()
        .unwrap();
    assert_eq!(
        detached.status.code(),
        Some(0),
        "setup detach failed: {}",
        String::from_utf8_lossy(&detached.stderr)
    );
    let status = wait_bounded(&mut setup.child, "setup connect after detach");
    assert_eq!(
        status.code(),
        Some(1),
        "setup stderr: {}",
        fs::read_to_string(&setup.stderr_path).unwrap()
    );

    let limits = eversh::Limits {
        // Generous on purpose: this test proves RestartEpisode happens
        // (via retry_attempts_max=1's tight per-episode budget), not that
        // it happens fast — under heavy parallel test-suite load, process
        // spawn overhead alone can dominate a tight deadline/backoff.
        retry_deadline_ms: 120_000,
        association_drain_ms: 10,
        retry_backoff_base_ms: 50,
        retry_backoff_cap_ms: 100,
        retry_attempts_max: 1,
        ..eversh::Limits::default()
    };
    let config = library_config(&fixture, limits);
    let before = fixture.ssh_pid_files().len();
    let notifier = RecordingNotifier::default();

    // Both scenario transitions are driven BY the fake ssh processes, not
    // by this (schedulable, stallable) test thread: the USR1-killed first
    // spawn publishes `carrieddeath` via FAKE_SSH_NEXT_MODE from inside its
    // trap, and the carrieddeath reattach restores `run` before it exits.
    // Each write lands strictly before the supervisor can observe that
    // child's exit and spawn the next probe/reattach — which can happen
    // within ~370ms of the death (300ms status grace + backoff) — so no
    // amount of parallel-suite load can make an invocation read a stale
    // mode.
    std::env::set_var("FAKE_SSH_NEXT_MODE", "carrieddeath");

    let handle = {
        let mut notifier = notifier.clone();
        std::thread::spawn(move || {
            eversh::supervisor::attach(&config, "testhost", "rs1", false, &[], &mut notifier)
        })
    };

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
        "the established attach() ssh process (pid {ssh_pid}) already exited"
    );
    send_signal(ssh_pid, "-USR1");

    // Observation only (the mode transitions happen inside the fakes):
    // +1 is attach()'s own first spawn (just SIGUSR1-killed above); episode
    // 1 then adds +1 probe and +1 carrieddeath reattach, so the carrieddeath
    // reattach lands at +3.
    let mut carrieddeath_seen = false;
    let carrieddeath_deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < carrieddeath_deadline {
        if fixture.ssh_pid_files().len() >= before + 3 {
            carrieddeath_seen = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    // If the episode restarted with a fresh budget, a SECOND probe+reattach
    // cycle (+2 more: +4 probe, +5 real reattach) must still run rather
    // than exhausting.
    let mut restarted_seen = false;
    let real_deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < real_deadline {
        if fixture.ssh_pid_files().len() >= before + 5 {
            restarted_seen = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    // Terminate the session no matter which phase stalled: a live
    // reattached writer ends as Remote(41) once its child is killed, and an
    // already-stopped supervisor has nothing left to kill. Either way
    // join() returns promptly instead of the test panicking blind.
    std::thread::sleep(Duration::from_millis(300));
    let killed = fixture
        .command()
        .args(["__everpty", "v1", "kill", "rs1"])
        .output()
        .unwrap();
    assert_eq!(killed.status.code(), Some(0));

    let result = handle.join().unwrap();
    let context = format!(
        "supervisor events:\n{}\nssh invocations: {:?}\npid files: {:?}",
        notifier.trace(),
        fixture.captures("ssh"),
        fixture.ssh_pid_files()
    );
    assert!(
        carrieddeath_seen,
        "episode-1 probe/reattach never ran: {context}"
    );
    let end = result.unwrap_or_else(|error| {
        panic!("attach() errored; episode restart not proven: {error}; {context}")
    });
    assert_eq!(
        end,
        SessionEnd::Remote(41),
        "the restarted episode's real reattach must deliver the child's exit status; \
         restarted_seen={restarted_seen}; {context}"
    );
    assert!(
        restarted_seen,
        "attach() ended well but the post-restart probe/reattach was never observed; {context}"
    );
}

#[test]
fn episode_restart_cap_bounds_flapping_reconnects() {
    // Finding 1: carried-death episode restarts are capped invocation-wide.
    // A topology whose every reattach briefly carries and then dies again
    // (banner-only flapping) must end as a visible ordinary failure after
    // the cap, never loop forever. Defaults: episode_restarts_max=3, so
    // exactly four carried-death reattaches run (three restarts allowed,
    // the fourth refused).
    let fixture = Fixture::new();
    fixture.set_mode("run");
    let mut session = spawn_interactive_env(
        &fixture,
        "flap",
        &[
            "connect",
            "testhost",
            "--session",
            "flap1",
            "--",
            "/bin/sh",
            "-c",
            TICK_SCRIPT,
        ],
        // The USR1-killed transport publishes the flapping phase from inside
        // its own trap, strictly before the supervisor can observe the exit.
        &[("FAKE_SSH_NEXT_MODE", "carriedflap")],
    );
    let mut seen = Vec::new();
    read_until(&mut session.master, &mut seen, b"T:1\r", "flap ready");
    let before = fixture.captures("ssh").len();

    let ssh_pid = fixture.newest_ssh_pid();
    send_signal(ssh_pid, "-USR1");

    let status = wait_bounded(&mut session.child, "flap exhaustion");
    assert_eq!(status.code(), Some(255));
    let stderr = fs::read_to_string(&session.stderr_path).unwrap();
    assert!(
        stderr.contains("episode restart"),
        "restart-cap failure must be visible: {stderr}"
    );

    // Exactly four probe+reattach cycles after the initial death — bounded,
    // not infinite — and never a takeover.
    let mut all = fixture.captures("ssh");
    let after = all.split_off(before);
    let probes = after
        .iter()
        .filter(|(_, argv)| argv.contains(&"probe".to_owned()))
        .count();
    let reattaches = after
        .iter()
        .filter(|(_, argv)| {
            argv.contains(&"attach".to_owned()) && !argv.contains(&"attach-or-create".to_owned())
        })
        .count();
    assert_eq!(probes, 4, "{after:?}");
    assert_eq!(reattaches, 4, "{after:?}");
    for request in attach_requests(&after) {
        assert!(
            !request.take_over,
            "a flapping reconnect must never escalate to take_over"
        );
    }

    // Cleanup: the broker and child persist (no writer ever reattached);
    // kill directly.
    fixture.set_mode("run");
    let killed = fixture
        .command()
        .args(["__everpty", "v1", "kill", "flap1"])
        .output()
        .unwrap();
    assert_eq!(killed.status.code(), Some(0));
}

#[test]
fn status_file_argument_on_structured_ops_only_never_raw_ssh_or_env() {
    // Finding 4: the status path travels as a --status-file ProxyCommand
    // ARGUMENT for structured interactive operations and probes only. Raw
    // `eversh ssh` never carries it, and NO invocation ever carries (or
    // honors) a link-status environment variable — the env handoff no
    // longer exists.
    let fixture = Fixture::new();
    fixture.set_mode("run");
    let mut session = spawn_interactive(
        &fixture,
        "envcheck",
        &[
            "connect",
            "testhost",
            "--session",
            "envc1",
            "--",
            "/bin/sh",
            "-c",
            "exit 0",
        ],
    );
    let status = wait_bounded(&mut session.child, "envcheck connect");
    assert_eq!(status.code(), Some(0));
    let structured = fixture.captures("ssh");
    assert_eq!(structured.len(), 1);
    let (name, argv) = &structured[0];
    assert!(
        argv[1].contains(" --status-file '"),
        "{name} must embed the status path as a ProxyCommand argument: {}",
        argv[1]
    );
    let structured_env = fixture.env_for(name);
    assert!(
        structured_env.iter().all(|entry| {
            !String::from_utf8_lossy(entry).starts_with("EVERSH_LINK_STATUS_FILE=")
        }),
        "no invocation may carry a link-status environment variable"
    );

    // Raw ssh never passes it, even though it shares the same outer
    // machinery.
    fixture.set_mode("fail255");
    let output = fixture
        .command()
        .args(["ssh", "testhost", "--", "-4"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(255));
    let mut all = fixture.captures("ssh");
    let raw = all.pop().unwrap();
    assert!(
        !raw.1[1].contains("--status-file"),
        "raw ssh must never carry a status file: {}",
        raw.1[1]
    );

    // The private root the argument points into stays 0700 (design 3, 7).
    let link_status_dir = fixture.state.join("link-status");
    let mode = fs::metadata(&link_status_dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700, "link-status directory must stay private");
}
