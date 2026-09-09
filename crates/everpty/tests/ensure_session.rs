//! Harness-free process test for terminal-free, race-safe session ensure.

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use everpty::run::{self, Context, EnsureSessionOutcome, EnsureSessionRequest};
use everpty::{sys, Limits};
use nix::sys::signal::Signal;

const NAME: &str = "terminal-free-race";

struct Fixture {
    base: PathBuf,
    state: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        for serial in 0..100_u32 {
            let base = std::env::temp_dir().join(format!(
                "everpty-ensure-session-{}-{serial}",
                std::process::id()
            ));
            match builder.create(&base) {
                Ok(()) => {
                    let state = base.join("state");
                    return Self { base, state };
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("ensure fixture: {error}"),
            }
        }
        panic!("could not allocate ensure fixture")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

struct BrokerCleanup {
    state: PathBuf,
}

impl Drop for BrokerCleanup {
    fn drop(&mut self) {
        if let Ok(sessions) = run::list(&context(&self.state)) {
            for session in sessions {
                let _ = sys::kill(session.broker_pid(), Signal::SIGTERM);
            }
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

fn request(state: &Path) -> EnsureSessionRequest {
    EnsureSessionRequest {
        context: context(state),
        name: NAME.to_owned(),
        command: vec![
            OsString::from("/bin/sh"),
            OsString::from("-c"),
            OsString::from("trap 'exit 0' TERM HUP; while :; do sleep 1; done"),
        ],
        default_shell: None,
        environment: vec![OsString::from("PATH=/usr/bin:/bin")],
        path: Some(OsString::from("/usr/bin:/bin")),
        origins: vec![OsString::from("everudp")],
        rows: 24,
        columns: 80,
    }
}

fn wait_for_path(path: &Path, wanted: bool, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while path.exists() != wanted {
        assert!(
            Instant::now() < deadline,
            "path state did not settle: {path:?}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn worker(state: PathBuf, gate: PathBuf, marker: PathBuf) -> ! {
    wait_for_path(&gate, true, Duration::from_secs(5));
    match run::ensure_session(request(&state)) {
        Ok(EnsureSessionOutcome::Ready(session)) => {
            let value = if session.created() {
                "created\n"
            } else {
                "existing\n"
            };
            fs::write(marker, value).expect("write ensure marker");
            std::process::exit(0);
        }
        Ok(EnsureSessionOutcome::Broker(exit)) => {
            std::process::exit(i32::from(exit.suggested_exit_code));
        }
        Err(error) => {
            eprintln!("ensure worker failed: {error}");
            std::process::exit(11);
        }
    }
}

fn spawn_worker(executable: &Path, state: &Path, gate: &Path, marker: &Path) -> Child {
    Command::new(executable)
        .arg("--worker")
        .arg(state)
        .arg(gate)
        .arg(marker)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn ensure worker")
}

fn wait_child(child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().expect("worker wait") {
            assert!(status.success(), "ensure worker failed: {status}");
            return;
        }
        assert!(Instant::now() < deadline, "ensure worker timed out");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn coordinator() {
    let fixture = Fixture::new();
    let _cleanup = BrokerCleanup {
        state: fixture.state.clone(),
    };
    let invalid_state = fixture.base.join("invalid-state");
    let mut invalid = request(&invalid_state);
    invalid.rows = 0;
    assert!(run::ensure_session(invalid).is_err());
    assert!(
        !invalid_state.exists(),
        "invalid explicit dimensions created broker state"
    );

    let gate = fixture.base.join("gate");
    let first_marker = fixture.base.join("first");
    let second_marker = fixture.base.join("second");
    let executable = std::env::current_exe().expect("current executable");
    let mut first = spawn_worker(&executable, &fixture.state, &gate, &first_marker);
    let mut second = spawn_worker(&executable, &fixture.state, &gate, &second_marker);
    fs::write(&gate, b"go").expect("release workers");
    wait_child(&mut first);
    wait_child(&mut second);

    let mut outcomes = [
        fs::read_to_string(&first_marker).expect("first result"),
        fs::read_to_string(&second_marker).expect("second result"),
    ];
    outcomes.sort();
    assert_eq!(outcomes, ["created\n", "existing\n"]);

    let sessions = run::list(&context(&fixture.state)).expect("list ensured session");
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].name(), NAME);
    assert!(
        sessions[0].child().is_none(),
        "ensure must not spawn the PTY child before writer commitment"
    );

    match run::ensure_session(request(&fixture.state)).expect("ensure existing") {
        EnsureSessionOutcome::Ready(session) => {
            assert!(!session.created());
            assert_eq!(session.name(), NAME);
            assert!(session.socket_path().ends_with(format!("{NAME}/socket")));
        }
        EnsureSessionOutcome::Broker(_) => panic!("a live session started another broker"),
    }

    sys::kill(sessions[0].broker_pid(), Signal::SIGTERM).expect("stop unstarted broker");
    wait_for_path(&fixture.state.join(NAME), false, Duration::from_secs(5));
}

fn main() {
    let mut args = std::env::args_os();
    let _program = args.next();
    match args.next().as_deref() {
        Some(mode) if mode == "--worker" => {
            let state = args.next().map(PathBuf::from).expect("worker state");
            let gate = args.next().map(PathBuf::from).expect("worker gate");
            let marker = args.next().map(PathBuf::from).expect("worker marker");
            assert!(args.next().is_none(), "unexpected worker argument");
            worker(state, gate, marker);
        }
        None => coordinator(),
        Some(other) => panic!("unexpected test mode: {other:?}"),
    }
}
