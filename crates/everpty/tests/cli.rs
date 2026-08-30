//! Focused standalone-CLI coverage for atomic M2 commit 8.
#![cfg(all(target_os = "linux", feature = "cli"))]
#![allow(clippy::unwrap_used)]

use std::ffi::OsStr;
use std::fmt::Write as FmtWrite;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use nix::sys::signal::Signal;

use everpty::run::{self, Context};
use everpty::session::{resolve_state_root_from, SessionMeta};
use everpty::{sys, Limits};

static FIXTURE: AtomicU64 = AtomicU64::new(0);

fn binary() -> &'static OsStr {
    OsStr::new(env!("CARGO_BIN_EXE_everpty"))
}

struct Fixture {
    base: PathBuf,
    state: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        let base = loop {
            let n = FIXTURE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("everpty-cli-{}-{n}", std::process::id()));
            match builder.create(&path) {
                Ok(()) => break path,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("fixture: {error}"),
            }
        };
        let state = base.join("state");
        Self { base, state }
    }

    fn command(&self) -> Command {
        cli_command(&self.state)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

fn cli_command(state: &Path) -> Command {
    let mut command = Command::new(binary());
    command
        .env_clear()
        .env("EVERSH_STATE_DIR", state)
        .env("PATH", "/usr/bin:/bin")
        .env("SHELL", "/bin/sh")
        .stdin(Stdio::null());
    command
}

fn run_context(state: &Path) -> Context {
    Context {
        state_candidates: vec![state.to_owned()],
        limits: Limits::default(),
    }
}

fn exact_simple_list_json(sessions: &[SessionMeta]) -> Vec<u8> {
    let mut out = String::from("{\"version\":1,\"sessions\":[");
    for (index, metadata) in sessions.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        assert_eq!(metadata.exec_label(), "/bin/sh");
        assert!(!metadata.exec_truncated());
        assert!(metadata.origins().is_empty());
        let child = metadata.child().expect("spawned child metadata");
        let _ = write!(
            out,
            "{{\"name\":\"{}\",\"broker\":{{\"pid\":{},\"start_ticks\":\"{}\"}},\
             \"child\":{{\"pid\":{},\"pgid\":{},\"start_ticks\":\"{}\"}},\
             \"created_unix_ms\":\"{}\",\"executable\":\"/bin/sh\",\
             \"executable_truncated\":false,\"origins\":[]}}",
            metadata.name(),
            metadata.broker_pid(),
            metadata.broker_start_ticks(),
            child.pid(),
            child.pgid(),
            child.start_ticks(),
            metadata.created_unix_ms(),
        );
    }
    out.push_str("]}\n");
    out.into_bytes()
}

fn wait_bounded(child: &mut Child, label: &str) -> ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(15);
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

fn status_flags(fd: std::os::fd::BorrowedFd<'_>) -> i32 {
    nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFL).expect("status flags")
}

fn read_until<R: Read + AsFd>(reader: &mut R, needle: &[u8], label: &str) -> Vec<u8> {
    sys::set_nonblocking(reader.as_fd()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut collected = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => panic!("{label} closed before marker; got {collected:?}"),
            Ok(count) => {
                collected.extend_from_slice(&chunk[..count]);
                if collected.windows(needle.len()).any(|part| part == needle) {
                    return collected;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) if error.raw_os_error() == Some(libc::EIO) => {
                panic!("{label} reached PTY EOF before marker; got {collected:?}")
            }
            Err(error) => panic!("{label}: {error}"),
        }
        assert!(
            Instant::now() < deadline,
            "{label} marker timeout: {collected:?}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn spawn_start(
    fixture: &Fixture,
    name: &str,
    script: &str,
) -> (
    Child,
    File,
    std::os::fd::OwnedFd,
    everpty::sys::TerminalAttributes,
    i32,
) {
    let (master, slave) = sys::openpty(27, 91).unwrap();
    let original = sys::terminal_attributes(slave.as_fd()).unwrap();
    let original_flags = status_flags(slave.as_fd());
    let probe = slave.try_clone().unwrap();
    let stdin = slave.try_clone().unwrap();
    let mut command = fixture.command();
    command
        // Keep the caller's job-control group non-orphaned: the test process
        // remains its parent in the same session and a different group.
        .process_group(0)
        .stdin(Stdio::from(File::from(stdin)))
        .stdout(Stdio::from(File::from(slave)))
        .stderr(Stdio::piped())
        .args(["start", name, "--", "/bin/sh", "-c", script]);
    let child = command.spawn().unwrap();
    (child, File::from(master), probe, original, original_flags)
}

fn spawn_gated_start(
    fixture: &Fixture,
    gate: &Path,
) -> (
    Child,
    std::os::fd::OwnedFd,
    std::os::fd::OwnedFd,
    everpty::sys::TerminalAttributes,
) {
    let (master, slave) = sys::openpty(25, 88).unwrap();
    let original = sys::terminal_attributes(slave.as_fd()).unwrap();
    let probe = slave.try_clone().unwrap();
    let stdin = slave.try_clone().unwrap();
    let mut command = Command::new("/bin/sh");
    command
        .env_clear()
        .env("EVERSH_STATE_DIR", &fixture.state)
        .env("PATH", "/usr/bin:/bin")
        .env("SHELL", "/bin/sh")
        .stdin(Stdio::from(File::from(stdin)))
        .stdout(Stdio::from(File::from(slave)))
        .stderr(Stdio::piped())
        .arg("-c")
        .arg("while [ ! -e \"$1\" ]; do sleep 0.001; done; shift; exec \"$@\"")
        .arg("everpty-race-launcher")
        .arg(gate)
        .arg(binary())
        .args([
            OsStr::new("start"),
            OsStr::new("start-race"),
            OsStr::new("--"),
            OsStr::new("/bin/sh"),
            OsStr::new("-c"),
            OsStr::new("sleep 1"),
        ]);
    (command.spawn().unwrap(), master, probe, original)
}

struct LiveSessionGuard {
    state: PathBuf,
    name: String,
    armed: bool,
}

impl LiveSessionGuard {
    fn new(state: &Path, name: &str) -> Self {
        Self {
            state: state.to_owned(),
            name: name.to_owned(),
            armed: true,
        }
    }
}

impl Drop for LiveSessionGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = cli_command(&self.state)
                .args(["kill", self.name.as_str()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

#[test]
fn exact_grammar_usage_codes_and_read_only_empty_discovery() {
    let fixture = Fixture::new();

    let invalid = fixture
        .command()
        .args(["start", "name", "/bin/true"])
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(2), "COMMAND requires --");

    let invalid = fixture
        .command()
        .args(["attach", "name", "--unknown"])
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(2));

    let help = fixture.command().arg("--help").output().unwrap();
    assert_eq!(help.status.code(), Some(0));

    let listed = fixture.command().args(["list", "--json"]).output().unwrap();
    assert_eq!(listed.status.code(), Some(0));
    assert_eq!(listed.stdout, b"{\"version\":1,\"sessions\":[]}\n");
    assert!(
        !fixture.state.exists(),
        "list must not create the state root"
    );

    let current = fixture.command().arg("current").output().unwrap();
    assert_eq!(current.status.code(), Some(1));
    assert!(current.stdout.is_empty());
    assert!(!fixture.state.exists(), "current must remain read-only");

    let attach = fixture
        .command()
        .args(["attach", "missing"])
        .output()
        .unwrap();
    assert_eq!(attach.status.code(), Some(1));
    assert!(!fixture.state.exists(), "attach must remain read-only");
}

#[test]
fn simultaneous_start_creates_exactly_one_broker() {
    let fixture = Fixture::new();
    let gate = fixture.base.join("start-gate");
    let (mut first, _first_master, first_probe, first_before) = spawn_gated_start(&fixture, &gate);
    let (mut second, _second_master, second_probe, second_before) =
        spawn_gated_start(&fixture, &gate);
    std::fs::write(&gate, b"go").unwrap();

    let mut codes = [
        wait_bounded(&mut first, "first racing start").code(),
        wait_bounded(&mut second, "second racing start").code(),
    ];
    codes.sort_unstable();
    assert_eq!(
        codes,
        [Some(0), Some(1)],
        "one creator must win and the other must see AlreadyExists"
    );
    assert!(sys::terminal_attributes(first_probe.as_fd()).unwrap() == first_before);
    assert!(sys::terminal_attributes(second_probe.as_fd()).unwrap() == second_before);

    let deadline = Instant::now() + Duration::from_secs(5);
    while fixture.state.join("start-race").exists() {
        assert!(
            Instant::now() < deadline,
            "winning broker did not clean state"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn real_start_propagates_child_exit_and_restores_outer_termios() {
    let fixture = Fixture::new();
    let mut cleanup = LiveSessionGuard::new(&fixture.state, "exit-code");
    let (mut starter, mut master, probe, before, flags_before) = spawn_start(
        &fixture,
        "exit-code",
        "stty size; printf 'CHILD-READY\\n'; exit 37",
    );
    let bytes = read_until(&mut master, b"CHILD-READY", "start output");
    assert!(
        bytes.windows(b"27 91".len()).any(|part| part == b"27 91"),
        "requested 27x91 dimensions did not reach the real child: {bytes:?}"
    );
    assert!(bytes.windows(11).any(|part| part == b"CHILD-READY"));
    let status = wait_bounded(&mut starter, "start exit status");
    assert_eq!(status.code(), Some(37));
    cleanup.armed = false;
    assert!(sys::terminal_attributes(probe.as_fd()).unwrap() == before);
    assert_eq!(status_flags(probe.as_fd()), flags_before);
    assert!(!fixture.state.join("exit-code").exists());
}

#[test]
fn start_rejects_non_tty_and_each_zero_initial_dimension() {
    let fixture = Fixture::new();
    let non_tty = fixture
        .command()
        .args(["start", "non-tty", "--", "/bin/true"])
        .output()
        .unwrap();
    assert_eq!(non_tty.status.code(), Some(1));
    assert!(!fixture.state.exists(), "non-TTY start created state");

    for (name, rows, cols) in [("zero-rows", 0, 80), ("zero-cols", 24, 0)] {
        let (master, slave) = sys::openpty(rows, cols).unwrap();
        let probe = slave.try_clone().unwrap();
        let stdin = slave.try_clone().unwrap();
        let termios_before = sys::terminal_attributes(probe.as_fd()).unwrap();
        let flags_before = status_flags(probe.as_fd());
        let mut command = fixture.command();
        command
            .stdin(Stdio::from(File::from(stdin)))
            .stdout(Stdio::from(File::from(slave)))
            .stderr(Stdio::piped())
            .args(["start", name, "--", "/bin/true"]);
        let mut starter = command.spawn().unwrap();
        assert_eq!(
            wait_bounded(&mut starter, "zero-size start").code(),
            Some(1)
        );
        assert!(
            !fixture.state.exists(),
            "zero-dimension start created state"
        );
        assert!(sys::terminal_attributes(probe.as_fd()).unwrap() == termios_before);
        assert_eq!(status_flags(probe.as_fd()), flags_before);
        drop(master);
    }
}

#[test]
fn real_start_reraises_attached_child_signal() {
    let fixture = Fixture::new();
    let mut cleanup = LiveSessionGuard::new(&fixture.state, "child-signal");
    let (mut starter, _master, probe, original, flags_before) =
        spawn_start(&fixture, "child-signal", "kill -TERM $$");
    let status = wait_bounded(&mut starter, "child signal propagation");
    assert_eq!(status.signal(), Some(libc::SIGTERM));
    cleanup.armed = false;
    assert!(sys::terminal_attributes(probe.as_fd()).unwrap() == original);
    assert_eq!(status_flags(probe.as_fd()), flags_before);
    assert!(!fixture.state.join("child-signal").exists());
}

#[test]
fn start_without_command_executes_the_captured_default_shell_directly() {
    let fixture = Fixture::new();
    let mut cleanup = LiveSessionGuard::new(&fixture.state, "default-shell");
    let (master, slave) = sys::openpty(24, 80).unwrap();
    let original = sys::terminal_attributes(slave.as_fd()).unwrap();
    let probe = slave.try_clone().unwrap();
    let stdin = slave.try_clone().unwrap();
    let mut command = fixture.command();
    command
        .stdin(Stdio::from(File::from(stdin)))
        .stdout(Stdio::from(File::from(slave)))
        .stderr(Stdio::piped())
        .args(["start", "default-shell"]);
    let mut starter = command.spawn().unwrap();
    let mut master = File::from(master);
    master.write_all(b"exit 12\n").unwrap();
    let status = wait_bounded(&mut starter, "default shell");
    assert_eq!(status.code(), Some(12));
    cleanup.armed = false;
    assert!(sys::terminal_attributes(probe.as_fd()).unwrap() == original);
}

#[test]
fn writer_stdin_eof_detaches_while_real_broker_child_remains_alive() {
    const NAME: &str = "writer-eof-live-child";
    let fixture = Fixture::new();
    let mut cleanup = LiveSessionGuard::new(&fixture.state, NAME);
    let script =
        "trap 'exit 0' TERM; printf 'READY\n'; while :; do printf 'TICK\n'; sleep 0.1; done";
    let (mut starter, mut outer_master, outer_probe, outer_before, outer_flags) =
        spawn_start(&fixture, NAME, script);
    let _ = read_until(&mut outer_master, b"READY", "initial real writer");
    sys::kill(starter.id() as libc::pid_t, Signal::SIGTERM).unwrap();
    assert_eq!(
        wait_bounded(&mut starter, "detach initial writer").signal(),
        Some(libc::SIGTERM)
    );
    assert!(sys::terminal_attributes(outer_probe.as_fd()).unwrap() == outer_before);
    assert_eq!(status_flags(outer_probe.as_fd()), outer_flags);

    let mut writer = fixture.command();
    writer
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .args(["attach", NAME]);
    let mut writer = writer.spawn().unwrap();
    let writer_stdin = writer.stdin.take().unwrap();
    let mut writer_stdout = writer.stdout.take().unwrap();
    let _ = read_until(&mut writer_stdout, b"TICK", "EOF writer");
    drop(writer_stdin);
    assert_eq!(
        wait_bounded(&mut writer, "writer stdin EOF").code(),
        Some(0),
        "writer stdin EOF must be deliberate detach success"
    );

    let sessions = run::list(&run_context(&fixture.state)).unwrap();
    assert_eq!(sessions.len(), 1);
    let child = sessions[0].child().expect("live child metadata");
    assert_eq!(
        sys::proc_start_ticks(child.pid()).expect("live child identity"),
        child.start_ticks(),
        "writer EOF killed or replaced the real broker child"
    );
    let current = fixture
        .command()
        .env("EVERPTY_SESSION", NAME)
        .arg("current")
        .output()
        .unwrap();
    assert_eq!(current.status.code(), Some(0));
    assert_eq!(current.stdout, format!("{NAME}\n").as_bytes());

    assert_eq!(
        fixture
            .command()
            .args(["kill", NAME])
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );
    cleanup.armed = false;
}

#[test]
fn attach_stdout_epipe_is_operational_failure_after_termios_restore() {
    const NAME: &str = "stdout-epipe";
    let fixture = Fixture::new();
    let mut cleanup = LiveSessionGuard::new(&fixture.state, NAME);
    let (_master, slave) = sys::openpty(24, 80).unwrap();
    let original = sys::terminal_attributes(slave.as_fd()).unwrap();
    let probe = slave.try_clone().unwrap();
    let stdin = slave.try_clone().unwrap();
    let (stdout_read, stdout_write) = sys::pipe_cloexec().unwrap();
    let stdout_probe = stdout_write.try_clone().unwrap();
    let stdin_flags = status_flags(probe.as_fd());
    let stdout_flags = status_flags(stdout_probe.as_fd());
    drop(stdout_read);
    let mut command = fixture.command();
    command
        .stdin(Stdio::from(File::from(stdin)))
        .stdout(Stdio::from(File::from(stdout_write)))
        .stderr(Stdio::piped())
        .args([
            "start",
            NAME,
            "--",
            "/bin/sh",
            "-c",
            "printf OUTPUT; trap 'exit 0' TERM; while :; do sleep 1; done",
        ]);
    let mut starter = command.spawn().unwrap();
    let status = wait_bounded(&mut starter, "stdout EPIPE");
    assert_eq!(status.code(), Some(1));
    assert!(sys::terminal_attributes(probe.as_fd()).unwrap() == original);
    assert_eq!(status_flags(probe.as_fd()), stdin_flags);
    assert_eq!(status_flags(stdout_probe.as_fd()), stdout_flags);
    let killed = fixture.command().args(["kill", NAME]).output().unwrap();
    assert_eq!(killed.status.code(), Some(0));
    cleanup.armed = false;
}

#[test]
fn post_hello_exec_failure_is_operational_and_cleans_state() {
    const NAME: &str = "exec-failure";
    let fixture = Fixture::new();
    let mut cleanup = LiveSessionGuard::new(&fixture.state, NAME);
    let (master, slave) = sys::openpty(24, 80).unwrap();
    let original = sys::terminal_attributes(slave.as_fd()).unwrap();
    let probe = slave.try_clone().unwrap();
    let stdin = slave.try_clone().unwrap();
    let mut command = fixture.command();
    command
        .stdin(Stdio::from(File::from(stdin)))
        .stdout(Stdio::from(File::from(slave)))
        .stderr(Stdio::piped())
        .args(["start", NAME, "--", "/definitely/not/an/everpty-executable"]);
    let mut starter = command.spawn().unwrap();
    let status = wait_bounded(&mut starter, "post-Hello exec failure");
    assert_eq!(status.code(), Some(1));
    cleanup.armed = false;
    assert!(sys::terminal_attributes(probe.as_fd()).unwrap() == original);
    drop(master);
    assert!(!fixture.state.join(NAME).exists());
}

#[test]
fn attach_fatal_signals_propagate_after_termios_restoration() {
    let fixture = Fixture::new();
    for (suffix, signal) in [
        ("int", Signal::SIGINT),
        ("term", Signal::SIGTERM),
        ("hup", Signal::SIGHUP),
        ("quit", Signal::SIGQUIT),
    ] {
        let name = format!("fatal-{suffix}");
        let mut cleanup = LiveSessionGuard::new(&fixture.state, &name);
        let script = "trap 'exit 0' TERM; printf 'READY\\n'; while :; do sleep 1; done";
        let (mut starter, mut master, probe, original, flags_before) =
            spawn_start(&fixture, &name, script);
        let _ = read_until(&mut master, b"READY", "fatal-signal starter");
        sys::kill(starter.id() as libc::pid_t, signal).unwrap();
        let status = wait_bounded(&mut starter, "fatal attach signal");
        assert_eq!(status.signal(), Some(signal as i32));
        assert!(sys::terminal_attributes(probe.as_fd()).unwrap() == original);
        assert_eq!(status_flags(probe.as_fd()), flags_before);
        let killed = fixture
            .command()
            .args(["kill", name.as_str()])
            .output()
            .unwrap();
        assert_eq!(killed.status.code(), Some(0));
        cleanup.armed = false;
    }
}

#[test]
fn tstp_restores_and_cont_reenters_raw_and_resizes() {
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
    use nix::unistd::Pid;

    const NAME: &str = "job-control";
    let fixture = Fixture::new();
    let mut cleanup = LiveSessionGuard::new(&fixture.state, NAME);
    let script = "trap 'printf WINCHED\\n' WINCH; trap 'exit 0' TERM; printf 'READY\\n'; while :; do sleep 1; done";
    let (mut starter, mut master, probe, original, flags_before) =
        spawn_start(&fixture, NAME, script);
    let _ = read_until(&mut master, b"READY", "job-control starter");
    let pid = Pid::from_raw(starter.id() as libc::pid_t);
    sys::kill(pid.as_raw(), Signal::SIGTSTP).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match waitpid(pid, Some(WaitPidFlag::WNOHANG | WaitPidFlag::WUNTRACED)).unwrap() {
            WaitStatus::Stopped(_, Signal::SIGTSTP) => break,
            WaitStatus::StillAlive => {
                assert!(Instant::now() < deadline, "starter did not stop");
                std::thread::sleep(Duration::from_millis(5));
            }
            other => panic!("unexpected pre-CONT status: {other:?}"),
        }
    }
    assert!(sys::terminal_attributes(probe.as_fd()).unwrap() == original);
    sys::set_winsize(probe.as_fd(), 44, 120).unwrap();
    sys::kill(pid.as_raw(), Signal::SIGCONT).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if sys::terminal_attributes(probe.as_fd()).unwrap() != original {
            break;
        }
        assert!(Instant::now() < deadline, "CONT did not re-enter raw mode");
        std::thread::sleep(Duration::from_millis(5));
    }
    let _ = read_until(&mut master, b"WINCHED", "CONT resize");
    sys::kill(pid.as_raw(), Signal::SIGTERM).unwrap();
    let status = wait_bounded(&mut starter, "job-control starter exit");
    assert_eq!(status.signal(), Some(libc::SIGTERM));
    assert!(sys::terminal_attributes(probe.as_fd()).unwrap() == original);
    assert_eq!(status_flags(probe.as_fd()), flags_before);
    let killed = fixture.command().args(["kill", NAME]).output().unwrap();
    assert_eq!(killed.status.code(), Some(0));
    cleanup.armed = false;
}

#[test]
fn list_filters_live_dead_and_corrupt_state_and_renders_exact_sorted_json() {
    let fixture = Fixture::new();
    let mut z_cleanup = LiveSessionGuard::new(&fixture.state, "z-live");
    let mut a_cleanup = LiveSessionGuard::new(&fixture.state, "a-live");
    let script = "trap 'exit 0' TERM; printf 'READY\n'; while :; do sleep 1; done";

    let (mut z_starter, mut z_master, z_probe, z_termios, z_flags) =
        spawn_start(&fixture, "z-live", script);
    let _ = read_until(&mut z_master, b"READY", "z-live start");
    sys::kill(z_starter.id() as libc::pid_t, Signal::SIGTERM).unwrap();
    assert_eq!(
        wait_bounded(&mut z_starter, "z-live detach").signal(),
        Some(libc::SIGTERM)
    );
    assert!(sys::terminal_attributes(z_probe.as_fd()).unwrap() == z_termios);
    assert_eq!(status_flags(z_probe.as_fd()), z_flags);

    let (mut a_starter, mut a_master, a_probe, a_termios, a_flags) =
        spawn_start(&fixture, "a-live", script);
    let _ = read_until(&mut a_master, b"READY", "a-live start");
    sys::kill(a_starter.id() as libc::pid_t, Signal::SIGTERM).unwrap();
    assert_eq!(
        wait_bounded(&mut a_starter, "a-live detach").signal(),
        Some(libc::SIGTERM)
    );
    assert!(sys::terminal_attributes(a_probe.as_fd()).unwrap() == a_termios);
    assert_eq!(status_flags(a_probe.as_fd()), a_flags);

    let limits = Limits::default();
    let root = resolve_state_root_from(std::slice::from_ref(&fixture.state)).unwrap();
    let dead = root.session("dead", &limits).unwrap().lock().unwrap();
    let pid = std::process::id() as libc::pid_t;
    let dead_metadata = SessionMeta::new(
        "dead",
        &limits,
        OsStr::new("/bin/false"),
        pid,
        sys::proc_start_ticks(pid).unwrap(),
        123_456_789,
    )
    .unwrap();
    dead.store_metadata(&limits, &dead_metadata).unwrap();
    drop(dead);

    let corrupt_dir = fixture.state.join("corrupt");
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(&corrupt_dir).unwrap();
    let corrupt_meta = corrupt_dir.join("meta");
    std::fs::write(&corrupt_meta, b"not-everpty-metadata").unwrap();
    std::fs::set_permissions(&corrupt_meta, std::fs::Permissions::from_mode(0o600)).unwrap();

    let context = run_context(&fixture.state);
    let sessions = run::list(&context).unwrap();
    assert_eq!(
        sessions.iter().map(SessionMeta::name).collect::<Vec<_>>(),
        ["a-live", "z-live"],
        "run::list did not sort live sessions or filter dead/corrupt state"
    );
    let listed = fixture.command().args(["list", "--json"]).output().unwrap();
    assert_eq!(listed.status.code(), Some(0));
    assert_eq!(
        listed.stdout,
        exact_simple_list_json(&sessions),
        "JSON must be byte-exact with every u64 rendered as a decimal string"
    );

    assert_eq!(
        fixture
            .command()
            .args(["kill", "a-live"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );
    a_cleanup.armed = false;
    assert_eq!(
        fixture
            .command()
            .args(["kill", "z-live"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );
    z_cleanup.armed = false;
}

#[test]
fn live_commands_cover_busy_detach_kill_list_and_current() {
    const NAME: &str = "live";
    let fixture = Fixture::new();
    let mut cleanup = LiveSessionGuard::new(&fixture.state, NAME);
    let script =
        "trap 'exit 0' TERM; printf 'READY\\n'; while :; do printf 'TICK\\n'; sleep 1; done";
    let (mut starter, mut outer_master, outer_probe, outer_before, outer_flags) =
        spawn_start(&fixture, NAME, script);
    let _ = read_until(&mut outer_master, b"READY", "initial writer");

    sys::kill(starter.id() as libc::pid_t, Signal::SIGTERM).unwrap();
    let status = wait_bounded(&mut starter, "starter signal");
    assert_eq!(status.signal(), Some(libc::SIGTERM));
    assert!(sys::terminal_attributes(outer_probe.as_fd()).unwrap() == outer_before);
    assert_eq!(status_flags(outer_probe.as_fd()), outer_flags);

    let listed = fixture.command().args(["list", "--json"]).output().unwrap();
    assert_eq!(listed.status.code(), Some(0));
    let json = String::from_utf8(listed.stdout).unwrap();
    assert!(json.contains("\"name\":\"live\""));
    assert!(json.contains("\"start_ticks\":\""));
    assert!(json.contains("\"created_unix_ms\":\""));

    let current = fixture
        .command()
        .env("EVERPTY_SESSION", NAME)
        .arg("current")
        .output()
        .unwrap();
    assert_eq!(current.status.code(), Some(0));
    assert_eq!(current.stdout, b"live\n");

    let mut writer = fixture.command();
    writer
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .args(["attach", NAME]);
    let mut writer = writer.spawn().unwrap();
    let writer_stdin = writer.stdin.take().unwrap();
    let mut writer_stdout = writer.stdout.take().unwrap();
    let _ = read_until(&mut writer_stdout, b"TICK", "replacement writer");

    let busy = fixture.command().args(["attach", NAME]).output().unwrap();
    assert_eq!(busy.status.code(), Some(3));

    let mut takeover = fixture.command();
    takeover
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .args(["attach", NAME, "--take-over"]);
    let mut takeover = takeover.spawn().unwrap();
    let takeover_stdin = takeover.stdin.take().unwrap();
    let mut takeover_stdout = takeover.stdout.take().unwrap();
    let _ = read_until(&mut takeover_stdout, b"TICK", "takeover writer");

    let mut observer = fixture.command();
    observer
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .args(["observe", NAME]);
    let mut observer = observer.spawn().unwrap();
    let mut observer_stdout = observer.stdout.take().unwrap();
    let _ = read_until(&mut observer_stdout, b"TICK", "observer");

    let detached = fixture.command().args(["detach", NAME]).output().unwrap();
    assert_eq!(detached.status.code(), Some(0));
    drop(takeover_stdin);
    assert_eq!(
        wait_bounded(&mut takeover, "detached takeover writer exit").code(),
        Some(1),
        "post-revocation socket EOF must remain an operational failure"
    );

    let killed = fixture.command().args(["kill", NAME]).output().unwrap();
    assert_eq!(killed.status.code(), Some(0));
    cleanup.armed = false;
    drop(writer_stdin);
    assert_eq!(
        wait_bounded(&mut writer, "revoked writer exit").code(),
        Some(0)
    );
    assert_eq!(wait_bounded(&mut observer, "observer exit").code(), Some(0));

    let listed = fixture.command().args(["list", "--json"]).output().unwrap();
    assert_eq!(listed.status.code(), Some(0));
    assert_eq!(listed.stdout, b"{\"version\":1,\"sessions\":[]}\n");
    let current = fixture
        .command()
        .env("EVERPTY_SESSION", NAME)
        .arg("current")
        .output()
        .unwrap();
    assert_eq!(current.status.code(), Some(1));
    assert!(current.stdout.is_empty());
}
