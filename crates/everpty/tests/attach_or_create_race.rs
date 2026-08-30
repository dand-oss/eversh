//! Harness-free process test for the real `attach_or_create` creation race.
//!
//! Each caller is a separate single-threaded process because the winning
//! caller performs the one daemonizing fork. This keeps the test faithful to
//! the public process-edge contract instead of forking from competing test
//! threads.

use std::ffi::OsString;
use std::fs::{self, File};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use everpty::run::{self, Context, Outcome, StartRequest};
use everpty::{sys, Error, Limits};

const NAME: &str = "two-caller-race";

struct Fixture {
    base: PathBuf,
    state: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        for serial in 0..100u32 {
            let base = std::env::temp_dir()
                .join(format!("everpty-aoc-race-{}-{serial}", std::process::id()));
            match builder.create(&base) {
                Ok(()) => {
                    let state = base.join("state");
                    return Self { base, state };
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("race fixture: {error}"),
            }
        }
        panic!("could not allocate race fixture")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

struct RaceCleanup {
    context: Context,
    children: Vec<Child>,
    armed: bool,
}

impl Drop for RaceCleanup {
    fn drop(&mut self) {
        if self.armed {
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                if run::kill(&self.context, NAME).is_ok() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        for child in &mut self.children {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
    }
}

fn context(state: &Path) -> Context {
    Context {
        state_candidates: vec![state.to_owned()],
        limits: Limits {
            startup_deadline_ms: 5_000,
            control_reply_deadline_ms: 2_000,
            list_probe_deadline_ms: 1_000,
            kill_grace_ms: 2_000,
            ..Limits::default()
        },
    }
}

fn wait_for_gate(gate: &Path) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !gate.exists() {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    true
}

fn worker(state: PathBuf, gate: PathBuf) -> ! {
    if !wait_for_gate(&gate) {
        eprintln!("attach_or_create worker gate timed out");
        std::process::exit(12);
    }
    let stdin_handle = std::io::stdin();
    let stdout_handle = std::io::stdout();
    let result = run::attach_or_create(StartRequest {
        context: context(&state),
        name: NAME.to_owned(),
        command: vec![
            OsString::from("/bin/sh"),
            OsString::from("-c"),
            OsString::from("trap 'exit 0' TERM HUP; while :; do sleep 1; done"),
        ],
        default_shell: None,
        environment: vec![OsString::from("PATH=/usr/bin:/bin")],
        path: Some(OsString::from("/usr/bin:/bin")),
        origins: Vec::new(),
        stdin: stdin_handle.as_fd(),
        stdout: stdout_handle.as_fd(),
    });
    let code = match result {
        Err(Error::Busy { .. }) => 3,
        Ok(
            Outcome::Detached
            | Outcome::ChildExited(_)
            | Outcome::ChildSignaled(_)
            | Outcome::LocalSignaled(_)
            | Outcome::Broker(_),
        ) => 0,
        Ok(Outcome::Success) => {
            eprintln!("unexpected attach_or_create Success outcome");
            13
        }
        Err(error) => {
            eprintln!("unexpected attach_or_create error: {error}");
            14
        }
    };
    std::process::exit(code)
}

fn spawn_worker(executable: &Path, state: &Path, gate: &Path, slave: OwnedFd) -> Child {
    let stdin = slave.try_clone().expect("worker stdin clone");
    Command::new(executable)
        .arg("--worker")
        .arg(state)
        .arg(gate)
        .stdin(Stdio::from(File::from(stdin)))
        .stdout(Stdio::from(File::from(slave)))
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn attach_or_create worker")
}

fn wait_bounded(child: &mut Child, label: &str) -> ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().expect("worker wait") {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let status = child.wait().expect("reap timed-out worker");
            panic!("{label} timed out with {status}");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn coordinator() {
    let fixture = Fixture::new();
    let gate = fixture.base.join("start-gate");
    let executable = std::env::current_exe().expect("current test executable");
    let (master_one, slave_one) = sys::openpty(25, 88).expect("first real PTY");
    let (master_two, slave_two) = sys::openpty(26, 89).expect("second real PTY");
    let first = spawn_worker(&executable, &fixture.state, &gate, slave_one);
    let second = spawn_worker(&executable, &fixture.state, &gate, slave_two);
    let mut cleanup = RaceCleanup {
        context: context(&fixture.state),
        children: vec![first, second],
        armed: true,
    };

    fs::write(&gate, b"go").expect("release workers");
    let deadline = Instant::now() + Duration::from_secs(10);
    let busy_index = loop {
        let mut busy = None;
        for (index, child) in cleanup.children.iter_mut().enumerate() {
            if let Some(status) = child.try_wait().expect("race worker status") {
                match status.code() {
                    Some(3) => busy = Some(index),
                    other => panic!("racing caller exited before cleanup with {other:?}"),
                }
            }
        }
        if let Some(index) = busy {
            break index;
        }
        assert!(
            Instant::now() < deadline,
            "neither racing caller reached Busy"
        );
        std::thread::sleep(Duration::from_millis(5));
    };
    let attached_index = 1 - busy_index;
    assert!(
        cleanup.children[attached_index]
            .try_wait()
            .expect("attached worker status")
            .is_none(),
        "the non-Busy caller did not remain normally attached"
    );

    let sessions = run::list(&cleanup.context).expect("list raced session");
    assert_eq!(sessions.len(), 1, "race published more than one session");
    let metadata = &sessions[0];
    assert_eq!(metadata.name(), NAME);
    assert_eq!(
        sys::proc_start_ticks(metadata.broker_pid()).expect("live broker identity"),
        metadata.broker_start_ticks(),
        "published broker identity is not live"
    );
    let state_entries = fs::read_dir(&fixture.state)
        .expect("state root")
        .collect::<Result<Vec<_>, _>>()
        .expect("state entries");
    assert_eq!(
        state_entries.len(),
        1,
        "race created duplicate session state"
    );
    assert_eq!(state_entries[0].file_name(), NAME);

    assert!(matches!(
        run::kill(&cleanup.context, NAME),
        Ok(Outcome::Success)
    ));
    cleanup.armed = false;
    let mut codes = cleanup
        .children
        .iter_mut()
        .map(|child| wait_bounded(child, "racing caller").code())
        .collect::<Vec<_>>();
    codes.sort_unstable();
    assert_eq!(codes, [Some(0), Some(3)]);
    assert!(
        !fixture.state.join(NAME).exists(),
        "identity-safe kill did not retire the raced session"
    );
    drop((master_one, master_two));
}

fn main() {
    let mut args = std::env::args_os();
    let _program = args.next();
    match args.next().as_deref() {
        Some(mode) if mode == "--worker" => {
            let state = args.next().map(PathBuf::from).expect("worker state path");
            let gate = args.next().map(PathBuf::from).expect("worker gate path");
            assert!(args.next().is_none(), "unexpected worker argument");
            worker(state, gate);
        }
        None => coordinator(),
        Some(other) => panic!("unexpected test mode: {other:?}"),
    }
}
