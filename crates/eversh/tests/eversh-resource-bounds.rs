//! M5 resource-bounds gate for the long-lived eversh supervisor process
//! (design 4: Process resources, Retry policy; design 13 Milestone 5:
//! descriptor, memory, CPU-idle gates).
//!
//! Drives one `eversh connect` process through repeated transport-kill /
//! reattach cycles (the same fake ssh + fake Kitty + real everpty broker + PTY
//! composition harness as `supervisor_linux.rs`) and samples the SUPERVISOR
//! process itself (not this test process) from `/proc/<pid>` after each
//! reattach settles: open file descriptors and resident memory must stay
//! within a small bounded delta of a first-reattach baseline, and must return
//! to (near) that baseline once the run ends.
//!
//! Integration tests cannot share modules across files without a common
//! module (and `supervisor_linux.rs` must not be refactored for this), so the
//! fake ssh/Kitty fixture is duplicated here rather than factored out.
//!
//! ## Cycle count and episode budgets (post b186fe4/c2f4047)
//!
//! The CLI runs with `Limits::default()` (`main.rs` builds the config; the
//! library reads no arguments or environment), so one invocation carries the
//! production budgets: `retry_attempts_max` in-episode attempts and an
//! invocation-wide `episode_restarts_max` cap on carried-death episode
//! restarts. This gate's SIGUSR1 kill is an UNCLEAN transport death: the fake
//! ssh (simulating the local everssh edge) has already written `carrying` to
//! its per-spawn link-status file but dies without any terminal `cause`
//! record, so the supervisor classifies the exit as a transport failure with
//! `carried=0` — the SAME episode continues and the cycle's probe + attach
//! pair consumes ONE of its finite attempts. CYCLES is therefore exactly
//! `retry_attempts_max`: the first kill enters the episode at attempt 1 and
//! the last cycle's reattach runs at attempt `retry_attempts_max`; one more
//! kill would end the invocation with `AttemptsExhausted`, so no longer
//! single-invocation cycle count exists to drive. (The alternative shape — a
//! `carrieddeath`-style kill — restarts the episode instead, but that mode
//! kills the reattach the instant it spawns, leaving no live reattach to
//! sample, and is anyway capped at `episode_restarts_max` restarts.)
//!
//! A reattach landing while the broker's writer-revoke from the just-killed
//! transport is still in flight can observe a transient `Busy`: since b186fe4
//! a Busy reattach is retried against the episode's deadline WITHOUT
//! consuming an attempt (`Event::ReattachBusy`), so a raced cycle may capture
//! an extra probe + attach pair beyond its one budgeted pair. This test does
//! not force that race (unlike `reattach_busy_once_is_retried_within_the_
//! episode` in `supervisor_linux.rs`, which drives it deterministically via a
//! fake-ssh `busyonce` mode); it can occur here only as a genuine timing
//! race, so invocation counts are asserted per cycle as bounded ranges
//! (>=1 probe, >=1 attach, each <= `retry_attempts_max` as a runaway guard)
//! rather than one fixed total.
//!
//! ## Resource baseline (post 1f49510/c2f4047)
//!
//! Every spawn here keeps stdin/stdout/stderr fully inherited — the stderr
//! relay pipe an earlier revision held open (and one extra thread ran) for
//! each interactive spawn is gone. Classification instead runs through one
//! private per-spawn link-status FILE under the state root: allocated
//! (`O_CREAT`-exclusive, then closed — no descriptor is held open), passed
//! as the `--status-file` ProxyCommand argument, and removed by a scope
//! guard on every exit path of its spawn, including a deadline kill. The
//! supervisor itself therefore contributes NO per-cycle descriptor: the fd
//! table this gate samples is the three inherited stdio descriptors plus
//! two descriptors of the harness itself — this test's `openpty` pair (master
//! and pre-dup slave) leaks into the spawned supervisor because libc's
//! `openpty(3)` does not set close-on-exec — constant for the process's
//! whole lifetime, and the live reattach's status file exists only on disk.
//! The first-reattach baseline (recorded after cycle 1) already includes
//! this shape, so the growth/plateau ceilings below still measure genuine
//! per-cycle drift, and the final cycle's exact fd return additionally
//! proves that the per-spawn status files and probe spawns leak no
//! descriptors.
#![cfg(all(target_os = "linux", feature = "cli"))]
#![allow(clippy::unwrap_used)]

use everpty::sys;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::Read;
use std::os::fd::AsFd;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Fixture (duplicated from supervisor_linux.rs; see the module doc comment).
// ---------------------------------------------------------------------------

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

/// The fake ssh script (kept byte-identical to `supervisor_linux.rs`'s
/// current script, including every mode this gate never exercises, so the two
/// fixtures never silently drift apart). What this gate relies on: it
/// captures argv NUL-separated plus its pid, simulates the LOCAL everssh
/// link-status file protocol (extracting the `--status-file` path from the
/// ProxyCommand option value — never the environment — writing `carrying`
/// before a non-probe exec and a terminal `cause` record on a natural exit),
/// and turns SIGUSR1 into a hard transport failure — the remote side is
/// killed and the "ssh client" exits 255 WITHOUT any terminal record, while
/// the broker survives.
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

/// The fake Kitty launcher (byte-identical to `supervisor_linux.rs`'s):
/// captures argv; fails when told to for one name.
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
            let path = std::env::temp_dir().join(format!("eversh-res-{}-{n}", std::process::id()));
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

// ---------------------------------------------------------------------------
// Reconnect-cycle helpers specific to this gate.
// ---------------------------------------------------------------------------

/// Read until at least one complete tick strictly greater than `after`
/// appears, returning every such fresh tick (oldest first).
fn wait_for_new_ticks(
    master: &mut File,
    buffer: &mut Vec<u8>,
    after: u64,
    deadline: Instant,
    label: &str,
) -> Vec<u64> {
    loop {
        read_available(master, buffer);
        let fresh: Vec<u64> = ticks(buffer)
            .into_iter()
            .filter(|tick| *tick > after)
            .collect();
        if !fresh.is_empty() {
            return fresh;
        }
        assert!(
            Instant::now() < deadline,
            "{label}: no ticks beyond {after}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Read until the stream has been quiet (no new bytes) for `quiet_for`.
fn drain_quiet(master: &mut File, buffer: &mut Vec<u8>, quiet_for: Duration, label: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut quiet_since = Instant::now();
    let mut last_len = buffer.len();
    loop {
        read_available(master, buffer);
        if buffer.len() != last_len {
            last_len = buffer.len();
            quiet_since = Instant::now();
        }
        if quiet_since.elapsed() >= quiet_for {
            return;
        }
        assert!(Instant::now() < deadline, "{label}: stream never quieted");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn wait_pid_gone(pid: i32, label: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while std::path::Path::new(&format!("/proc/{pid}")).exists() {
        assert!(
            Instant::now() < deadline,
            "{label}: pid {pid} survived SIGUSR1"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// A point-in-time observation of the supervisor process's own OS resources.
#[derive(Debug, Clone, Copy)]
struct ResourceSample {
    fds: usize,
    rss_kib: u64,
}

fn sample_process(pid: u32) -> ResourceSample {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let rss_kib = status
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmRSS:")
                .and_then(|value| value.trim_end_matches(" kB").trim().parse().ok())
        })
        .expect("/proc/<pid>/status must report VmRSS");
    let fds = fs::read_dir(format!("/proc/{pid}/fd")).unwrap().count();
    ResourceSample { fds, rss_kib }
}

/// Cycles driven: exactly the CLI's production per-episode attempt budget.
/// Each cycle's unclean transport kill (`carried=0`) consumes one attempt of
/// the invocation's single reconnect episode, so `retry_attempts_max` kills
/// is the most one long-lived invocation can survive — see the module doc
/// comment.
const CYCLES: u32 = 5;
/// Per-cycle fd growth ceiling above the first-reattach baseline.
const FD_GROWTH_CEILING: usize = 8;
/// Per-cycle RSS growth ceiling above the first-reattach baseline, in KiB.
const RSS_GROWTH_CEILING_KIB: u64 = 8192;
/// Final-cycle RSS return-to-plateau ceiling above baseline, in KiB.
const RSS_RETURN_CEILING_KIB: u64 = 4096;

/// Count of a kind (`"probe"` or `"attach"`, the latter excluding
/// `"attach-or-create"`) among one cycle's captured ssh invocations.
fn count_kind(captures: &[(String, Vec<String>)], word: &str) -> usize {
    captures
        .iter()
        .filter(|(_, argv)| {
            argv.contains(&word.to_owned())
                && (word != "attach" || !argv.contains(&"attach-or-create".to_owned()))
        })
        .count()
}

// ---------------------------------------------------------------------------
// The gate.
// ---------------------------------------------------------------------------

#[test]
fn eversh_resource_bounds() {
    let limits = eversh::Limits::default();
    // The CLI's production budgets (see the module doc comment): one episode
    // with this many finite attempts, shared across every cycle's kill.
    let attempts_budget = limits.retry_attempts_max as usize;
    assert_eq!(
        CYCLES, limits.retry_attempts_max,
        "the gate must drive the full attempt budget, no more"
    );

    let fixture = Fixture::new();
    fixture.set_mode("run");
    let mut session = spawn_interactive(
        &fixture,
        "res-gate",
        &[
            "connect",
            "testhost",
            "--session",
            "res-gate",
            "--",
            "/bin/sh",
            "-c",
            TICK_SCRIPT,
        ],
    );

    let mut output = Vec::new();
    read_until(&mut session.master, &mut output, b"READY", "initial ready");
    let established_deadline = Instant::now() + Duration::from_secs(10);
    let established = wait_for_new_ticks(
        &mut session.master,
        &mut output,
        0,
        established_deadline,
        "initial ticks",
    );
    let mut last_max = *established.last().unwrap();

    let pid = session.child.id();
    let mut baseline: Option<ResourceSample> = None;
    let mut peak_fds = 0usize;
    let mut peak_rss_kib = 0u64;
    let mut final_sample = ResourceSample { fds: 0, rss_kib: 0 };

    for cycle in 1..=CYCLES {
        // Each cycle waits for fresh ticks before tearing down the
        // transport: proof that the previous reattach (or the initial
        // connect) is actively delivering, not merely alive.
        let fresh_deadline = Instant::now() + Duration::from_secs(5);
        let fresh = wait_for_new_ticks(
            &mut session.master,
            &mut output,
            last_max,
            fresh_deadline,
            &format!("cycle {cycle} pre-kill freshness"),
        );
        last_max = *fresh.last().unwrap();
        let pre_max = last_max;
        let captures_before = fixture.captures("ssh").len();

        let ssh_pid = fixture.newest_ssh_pid();
        send_signal(ssh_pid, "-USR1");
        wait_pid_gone(ssh_pid, &format!("cycle {cycle} fake ssh"));
        drain_quiet(
            &mut session.master,
            &mut output,
            Duration::from_millis(100),
            &format!("cycle {cycle} drain"),
        );

        // The kill classifies as an unclean transport death (`carried=0`):
        // the SAME episode continues and this cycle's probe + attach pair
        // consumes one of its finite attempts (design 7). Cycle 1's kill
        // ends the original attach-or-create spawn and enters the episode at
        // attempt 1; the last cycle's reattach runs at attempt
        // `retry_attempts_max`.
        let reattach_deadline = Instant::now() + Duration::from_secs(15);
        let post = wait_for_new_ticks(
            &mut session.master,
            &mut output,
            pre_max,
            reattach_deadline,
            &format!("cycle {cycle} reattach"),
        );
        assert!(
            session.child.try_wait().unwrap().is_none(),
            "cycle {cycle}: eversh exited instead of reconnecting: {}",
            fs::read_to_string(&session.stderr_path).unwrap()
        );
        assert!(
            post[0] >= pre_max + 2,
            "cycle {cycle}: no delivery gap across reattach: pre_max={pre_max} first_post={}",
            post[0]
        );

        // Settle: let a few more ticks accumulate before sampling, then
        // sample the supervisor process's own resources.
        let settle = Instant::now() + Duration::from_millis(300);
        while Instant::now() < settle {
            read_available(&mut session.master, &mut output);
            std::thread::sleep(Duration::from_millis(10));
        }
        let all_ticks = ticks(&output);
        for window in all_ticks.windows(2) {
            assert!(
                window[1] > window[0],
                "cycle {cycle}: ticks not strictly increasing (replay or duplicate): {all_ticks:?}"
            );
        }
        last_max = *all_ticks.last().unwrap();

        // Per-cycle ssh-invocation accounting: one budgeted probe + attach
        // pair per cycle, plus (only under a genuine raced writer-revoke)
        // deadline-governed Busy-retried pairs — never any other kind of
        // invocation. The ceiling is a runaway guard: a real race resolves
        // within a retry or two, far inside the episode's attempt budget.
        let all_captures = fixture.captures("ssh");
        let cycle_captures = &all_captures[captures_before..];
        let probe_count = count_kind(cycle_captures, "probe");
        let attach_count = count_kind(cycle_captures, "attach");
        assert!(
            probe_count >= 1,
            "cycle {cycle}: expected at least one probe: {cycle_captures:?}"
        );
        assert!(
            attach_count >= 1,
            "cycle {cycle}: expected at least one attach: {cycle_captures:?}"
        );
        assert!(
            probe_count <= attempts_budget,
            "cycle {cycle}: probe count {probe_count} exceeded the runaway guard {attempts_budget}: {cycle_captures:?}"
        );
        assert!(
            attach_count <= attempts_budget,
            "cycle {cycle}: attach count {attach_count} exceeded the runaway guard {attempts_budget}: {cycle_captures:?}"
        );
        assert_eq!(
            cycle_captures.len(),
            probe_count + attach_count,
            "cycle {cycle}: unexpected non-probe/attach ssh invocation: {cycle_captures:?}"
        );

        let sample = sample_process(pid);
        let baseline_sample = *baseline.get_or_insert(sample);
        peak_fds = peak_fds.max(sample.fds);
        peak_rss_kib = peak_rss_kib.max(sample.rss_kib);
        assert!(
            sample.fds <= baseline_sample.fds + FD_GROWTH_CEILING,
            "cycle {cycle}: fd ceiling exceeded: baseline={} sample={} ceiling={}",
            baseline_sample.fds,
            sample.fds,
            baseline_sample.fds + FD_GROWTH_CEILING
        );
        assert!(
            sample.rss_kib <= baseline_sample.rss_kib + RSS_GROWTH_CEILING_KIB,
            "cycle {cycle}: RSS ceiling exceeded: baseline={} KiB sample={} KiB ceiling={} KiB",
            baseline_sample.rss_kib,
            sample.rss_kib,
            baseline_sample.rss_kib + RSS_GROWTH_CEILING_KIB
        );
        if cycle == CYCLES {
            assert_eq!(
                sample.fds, baseline_sample.fds,
                "final cycle fd count must return exactly to baseline"
            );
            assert!(
                sample.rss_kib <= baseline_sample.rss_kib + RSS_RETURN_CEILING_KIB,
                "final cycle RSS did not return to plateau: baseline={} KiB sample={} KiB ceiling={} KiB",
                baseline_sample.rss_kib,
                sample.rss_kib,
                baseline_sample.rss_kib + RSS_RETURN_CEILING_KIB
            );
            final_sample = sample;
        }
    }
    let baseline = baseline.unwrap();

    // This gate never launches Kitty.
    assert!(
        fixture.captures("kitty").is_empty(),
        "this gate never launches Kitty"
    );

    // Cleanup: kill the session; the child's TERM-trap exit status passes
    // through unchanged, and the broker fully removes its session directory
    // before `kill` returns, so no extra wait-loop is needed here.
    let killed = fixture
        .command()
        .args(["kill", "testhost", "res-gate"])
        .output()
        .unwrap();
    assert_eq!(killed.status.code(), Some(0), "kill failed");
    assert!(
        !fixture.state.join("res-gate").exists(),
        "no session directory must remain after kill"
    );
    let status = wait_bounded(&mut session.child, "connect exit");
    assert_eq!(
        status.code(),
        Some(41),
        "child exit status must pass through"
    );

    // Zero leftover processes: every captured fake-ssh invocation's pid has
    // exited (each was either killed by the next cycle's SIGUSR1 and
    // confirmed gone at the time, or is the final reattach, whose local ssh
    // exited alongside `session.child` above).
    for pid_file in fixture.ssh_pid_files() {
        let captured_pid: i32 = fs::read_to_string(fixture.capture.join(&pid_file))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(
            !std::path::Path::new(&format!("/proc/{captured_pid}")).exists(),
            "leftover fake-ssh process: pid {captured_pid} ({pid_file})"
        );
    }

    println!("stat::baseline_fd: {}", baseline.fds);
    println!("stat::peak_fd: {peak_fds}");
    println!("stat::final_fd: {}", final_sample.fds);
    println!("stat::baseline_rss_kib: {}", baseline.rss_kib);
    println!("stat::peak_rss_kib: {peak_rss_kib}");
    println!("stat::final_rss_kib: {}", final_sample.rss_kib);
    println!("stat::cycles: {CYCLES}");

    println!(
        "eversh-resource-bounds: PASS cycles={CYCLES} fd_baseline={} fd_peak={peak_fds}/{} fd_final={} rss_baseline_kib={} rss_peak_kib={peak_rss_kib}/{} rss_final_kib={}/{}",
        baseline.fds,
        baseline.fds + FD_GROWTH_CEILING,
        final_sample.fds,
        baseline.rss_kib,
        baseline.rss_kib + RSS_GROWTH_CEILING_KIB,
        final_sample.rss_kib,
        baseline.rss_kib + RSS_RETURN_CEILING_KIB,
    );
}
