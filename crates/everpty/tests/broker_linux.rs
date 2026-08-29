//! Real Linux PTY coverage for M2 commit 7: spawn, resize, signals,
//! ordered Exit delivery, and terminal cleanup.
#![allow(clippy::unwrap_used)]

use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};

use everpty::broker::{Broker, MonotonicClock, SpawnPlan};
use everpty::frame::{self, Frame, Role};
use everpty::lifecycle::{Lifecycle, TerminalCause};
use everpty::session::{resolve_state_root_from, SessionMeta};
use everpty::{sys, Limits};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    base: PathBuf,
    session: PathBuf,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        for attempt in 0..64u32 {
            let base = std::env::temp_dir().join(format!(
                "everpty-broker7-{tag}-{}-{n}-{attempt}",
                std::process::id()
            ));
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            if builder.create(&base).is_ok() {
                return Self {
                    session: base.join("s1"),
                    base,
                };
            }
        }
        panic!("no exclusive fixture directory");
    }

    fn socket(&self) -> PathBuf {
        self.session.join("socket")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

fn os(value: &str) -> OsString {
    OsString::from(value)
}

fn setup_broker(tag: &str, script: &str, limits: Limits) -> (Fixture, Broker) {
    setup_broker_argv(tag, vec![os("/bin/sh"), os("-c"), os(script)], limits)
}

fn setup_broker_argv(tag: &str, argv: Vec<OsString>, mut limits: Limits) -> (Fixture, Broker) {
    // Keep real-process tests fast while preserving deterministic finite phases.
    limits.kill_grace_ms = limits.kill_grace_ms.min(200);
    limits.pty_exit_drain_ms = limits.pty_exit_drain_ms.min(200);
    let fixture = Fixture::new(tag);
    let root = resolve_state_root_from(std::slice::from_ref(&fixture.base)).unwrap();
    let locked = root.session("s1", &limits).unwrap().lock().unwrap();
    let bound = locked.bind_broker_socket(&limits).unwrap();
    let pid = std::process::id() as libc::pid_t;
    let metadata = SessionMeta::new(
        "s1",
        &limits,
        argv.first().map_or(OsStr::new(""), OsString::as_os_str),
        pid,
        sys::proc_start_ticks(pid).unwrap(),
        1,
    )
    .unwrap();
    let mut broker = Broker::new(bound, &limits, Rc::new(MonotonicClock), None).unwrap();
    broker
        .set_spawn_plan(SpawnPlan::new(
            argv,
            vec![os("PATH=/usr/bin:/bin")],
            None,
            metadata,
        ))
        .unwrap();
    (fixture, broker)
}

fn connect(path: &Path) -> UnixStream {
    let stream = UnixStream::connect(path).unwrap();
    stream.set_nonblocking(true).unwrap();
    stream
}

fn send(stream: &mut UnixStream, frame: &Frame) {
    let wire = frame.encode();
    let mut offset = 0;
    for _ in 0..1000 {
        if offset == wire.len() {
            return;
        }
        match stream.write(&wire[offset..]) {
            Ok(0) => panic!("zero socket write"),
            Ok(n) => offset += n,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::yield_now();
            }
            Err(error) => panic!("socket write: {error}"),
        }
    }
    panic!("socket write did not complete");
}

fn hello(role: Role) -> Frame {
    Frame::Hello {
        role,
        take_over: false,
        name: "s1".to_owned(),
        rows: if role == Role::Writer { 24 } else { 0 },
        cols: if role == Role::Writer { 80 } else { 0 },
    }
}

#[derive(Default)]
struct Received {
    wire: Vec<u8>,
    frames: Vec<Frame>,
    eof: bool,
}

impl Received {
    fn read_from(&mut self, stream: &mut UnixStream, limits: &Limits) {
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => {
                    self.eof = true;
                    break;
                }
                Ok(n) => self.wire.extend_from_slice(&chunk[..n]),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) if error.raw_os_error() == Some(libc::ECONNRESET) => {
                    self.eof = true;
                    break;
                }
                Err(error) => panic!("socket read: {error}"),
            }
        }
        loop {
            if self.wire.len() < frame::HEADER_LEN {
                break;
            }
            let total = Frame::validate_header(&self.wire[..frame::HEADER_LEN], limits).unwrap();
            if self.wire.len() < total {
                break;
            }
            let (frame, used) = Frame::decode(&self.wire[..total], limits).unwrap();
            self.wire.drain(..used);
            self.frames.push(frame);
        }
    }
}

fn pump_until_final(
    broker: &mut Broker,
    clients: &mut [(&mut UnixStream, &mut Received)],
    limits: &Limits,
) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        broker.run_once(Some(10)).unwrap();
        for (stream, received) in clients.iter_mut() {
            received.read_from(stream, limits);
        }
        if broker.is_finalized() {
            for (stream, received) in clients.iter_mut() {
                received.read_from(stream, limits);
            }
            return;
        }
    }
    panic!(
        "broker did not finalize: lifecycle={:?} child={:?} outcome={:?} master={} terminal={} deadline={:?} kill={}",
        broker.lifecycle(),
        broker.child_pid(),
        broker.child_outcome(),
        broker.has_pty_master(),
        broker.pty_terminal_pending(),
        broker.pty_exit_deadline(),
        broker.kill_is_active()
    );
}

fn output_bytes(frames: &[Frame]) -> Vec<u8> {
    frames
        .iter()
        .filter_map(|frame| match frame {
            Frame::Output(bytes) => Some(bytes.as_slice()),
            _ => None,
        })
        .flatten()
        .copied()
        .collect()
}

fn exit_position(frames: &[Frame]) -> usize {
    frames
        .iter()
        .position(|frame| matches!(frame, Frame::Exit { .. }))
        .expect("Exit frame")
}

fn pump_until_marker(
    broker: &mut Broker,
    stream: &mut UnixStream,
    received: &mut Received,
    limits: &Limits,
    marker: &[u8],
) {
    for _ in 0..1000 {
        broker.run_once(Some(10)).unwrap();
        received.read_from(stream, limits);
        if output_bytes(&received.frames)
            .windows(marker.len())
            .any(|window| window == marker)
        {
            return;
        }
    }
    panic!("child marker did not arrive");
}

#[test]
fn real_child_output_precedes_exit_for_writer_and_observer_then_state_is_removed() {
    let limits = Limits::default();
    let (fixture, mut broker) = setup_broker("natural", "printf 'alpha'; exit 7", limits);
    let mut observer = connect(&fixture.socket());
    let mut writer = connect(&fixture.socket());
    send(&mut observer, &hello(Role::Observer));
    send(&mut writer, &hello(Role::Writer));

    let mut observer_rx = Received::default();
    let mut writer_rx = Received::default();
    pump_until_final(
        &mut broker,
        &mut [
            (&mut observer, &mut observer_rx),
            (&mut writer, &mut writer_rx),
        ],
        &limits,
    );

    for received in [&observer_rx, &writer_rx] {
        assert_eq!(output_bytes(&received.frames), b"alpha");
        let output = received
            .frames
            .iter()
            .position(|frame| matches!(frame, Frame::Output(_)))
            .unwrap();
        let exit = exit_position(&received.frames);
        assert!(
            output < exit,
            "Output must precede Exit: {:?}",
            received.frames
        );
        assert!(matches!(
            received.frames[exit],
            Frame::Exit {
                signal: false,
                value: 7
            }
        ));
    }
    assert_eq!(broker.lifecycle(), Lifecycle::Exited);
    let exit = broker.broker_exit().unwrap();
    assert_eq!(
        exit.cause,
        TerminalCause::ChildExit {
            signal: false,
            value: 7
        }
    );
    assert_eq!(exit.suggested_exit_code, 0);
    assert!(!fixture.session.exists(), "terminal state must be removed");
}

#[test]
fn concurrent_kill_controls_share_one_term_path_and_both_receive_exit() {
    let limits = Limits {
        kill_grace_ms: 100,
        ..Limits::default()
    };
    let (fixture, mut broker) = setup_broker(
        "kill-waiters",
        "trap 'exit 0' TERM; printf 'READY\\n'; read _line",
        limits,
    );
    let mut writer = connect(&fixture.socket());
    send(&mut writer, &hello(Role::Writer));
    let mut writer_rx = Received::default();
    pump_until_marker(&mut broker, &mut writer, &mut writer_rx, &limits, b"READY");

    // The post-spawn metadata rewrite is visible while the child is live.
    let child_pid = broker.child_pid().expect("spawned child");
    let root = resolve_state_root_from(std::slice::from_ref(&fixture.base)).unwrap();
    let metadata = root
        .session("s1", &limits)
        .unwrap()
        .load_metadata(&limits)
        .unwrap();
    assert_eq!(metadata.child().unwrap().pid(), child_pid);

    let mut first = connect(&fixture.socket());
    let mut second = connect(&fixture.socket());
    send(&mut first, &Frame::Kill);
    send(&mut second, &Frame::Kill);
    let mut first_rx = Received::default();
    let mut second_rx = Received::default();
    pump_until_final(
        &mut broker,
        &mut [
            (&mut writer, &mut writer_rx),
            (&mut first, &mut first_rx),
            (&mut second, &mut second_rx),
        ],
        &limits,
    );

    let first_exit = &first_rx.frames[exit_position(&first_rx.frames)];
    let second_exit = &second_rx.frames[exit_position(&second_rx.frames)];
    assert_eq!(first_exit, second_exit);
    assert!(matches!(
        first_exit,
        Frame::Exit {
            signal: false,
            value: 0
        }
    ));
    assert_eq!(
        broker.broker_exit().unwrap().cause,
        TerminalCause::KillRequested
    );
    assert!(!fixture.session.exists());
}

#[test]
fn pty_eof_while_leader_lives_is_bounded_by_drain_and_kill_deadlines() {
    let limits = Limits {
        pty_exit_drain_ms: 30,
        kill_grace_ms: 30,
        ..Limits::default()
    };
    let (fixture, mut broker) = setup_broker(
        "closed-pty",
        "trap '' HUP; exec 0<&- 1>&- 2>&-; exec sleep 10",
        limits,
    );
    let mut writer = connect(&fixture.socket());
    send(&mut writer, &hello(Role::Writer));
    let mut writer_rx = Received::default();
    pump_until_final(&mut broker, &mut [(&mut writer, &mut writer_rx)], &limits);
    let exit = &writer_rx.frames[exit_position(&writer_rx.frames)];
    assert!(
        matches!(
            exit,
            Frame::Exit {
                signal: true,
                value
            } if *value == libc::SIGTERM as u32 || *value == libc::SIGKILL as u32
        ),
        "unexpected live-leader cleanup outcome: {exit:?}"
    );
    assert!(!fixture.session.exists());
}

#[test]
fn escaped_descendant_held_slave_is_cut_off_by_post_reap_drain_deadline() {
    let limits = Limits {
        pty_exit_drain_ms: 20,
        kill_grace_ms: 20,
        ..Limits::default()
    };
    let (fixture, mut broker) = setup_broker(
        "escaped-slave",
        "trap 'exit 9' USR1; setsid /bin/sh -c 'trap \"\" HUP TERM; kill -USR1 \"$1\"; sleep 0.3' holder $$ & wait",
        limits,
    );
    let mut writer = connect(&fixture.socket());
    send(&mut writer, &hello(Role::Writer));
    let mut received = Received::default();
    pump_until_final(&mut broker, &mut [(&mut writer, &mut received)], &limits);
    assert!(matches!(
        received.frames[exit_position(&received.frames)],
        Frame::Exit {
            signal: false,
            value: 9
        }
    ));
    assert!(!broker.has_pty_master());
    assert!(!fixture.session.exists());
}

#[test]
fn continuously_writing_escaped_descendant_cannot_extend_finalized_drain() {
    let limits = Limits {
        pty_exit_drain_ms: 20,
        kill_grace_ms: 20,
        ..Limits::default()
    };
    let (fixture, mut broker) = setup_broker(
        "escaped-writer",
        "trap 'exit 9' USR1; setsid /bin/sh -c 'trap \"\" HUP TERM; kill -USR1 \"$1\"; exec /usr/bin/timeout -s KILL 5 /usr/bin/yes x' holder $$ & wait",
        limits,
    );
    let mut writer = connect(&fixture.socket());
    send(&mut writer, &hello(Role::Writer));
    let mut received = Received::default();
    let started = std::time::Instant::now();
    pump_until_final(&mut broker, &mut [(&mut writer, &mut received)], &limits);

    assert!(
        started.elapsed() < std::time::Duration::from_secs(2),
        "finalized drain waited for the escaped writer's external timeout"
    );
    assert!(matches!(
        received.frames[exit_position(&received.frames)],
        Frame::Exit {
            signal: false,
            value: 9
        }
    ));
    assert!(!broker.has_pty_master());
    assert!(!fixture.session.exists());
}

#[test]
fn writer_resize_uses_real_tiocswinsz_and_child_observes_sigwinch() {
    let limits = Limits::default();
    let (fixture, mut broker) = setup_broker(
        "resize",
        "trap 'stty size; exit 0' WINCH; printf 'READY\\n'; read _line",
        limits,
    );
    let mut writer = connect(&fixture.socket());
    send(&mut writer, &hello(Role::Writer));
    let mut received = Received::default();
    pump_until_marker(&mut broker, &mut writer, &mut received, &limits, b"READY");
    send(
        &mut writer,
        &Frame::Resize {
            rows: 31,
            cols: 101,
        },
    );
    pump_until_final(&mut broker, &mut [(&mut writer, &mut received)], &limits);
    let output = output_bytes(&received.frames);
    assert!(
        output
            .windows(b"31 101".len())
            .any(|window| window == b"31 101"),
        "child did not observe resized dimensions: {output:?}"
    );
    assert!(!fixture.session.exists());
}

#[test]
fn term_ignoring_child_escalates_to_sigkill_and_reports_actual_outcome() {
    let limits = Limits {
        kill_grace_ms: 40,
        ..Limits::default()
    };
    let (fixture, mut broker) = setup_broker(
        "kill-escalation",
        "trap '' TERM; printf 'READY\\n'; read _line",
        limits,
    );
    let mut writer = connect(&fixture.socket());
    send(&mut writer, &hello(Role::Writer));
    let mut writer_rx = Received::default();
    pump_until_marker(&mut broker, &mut writer, &mut writer_rx, &limits, b"READY");
    let mut control = connect(&fixture.socket());
    send(&mut control, &Frame::Kill);
    let mut control_rx = Received::default();
    pump_until_final(
        &mut broker,
        &mut [
            (&mut writer, &mut writer_rx),
            (&mut control, &mut control_rx),
        ],
        &limits,
    );
    assert!(matches!(
        control_rx.frames[exit_position(&control_rx.frames)],
        Frame::Exit {
            signal: true,
            value
        } if value == libc::SIGKILL as u32
    ));
    assert!(!fixture.session.exists());
}

#[test]
fn exec_failure_sends_internal_error_without_helloack_and_cleans_state() {
    let limits = Limits::default();
    let (fixture, mut broker) = setup_broker_argv(
        "exec-failure",
        vec![os("/nonexistent-everpty/no-such-executable")],
        limits,
    );
    let mut writer = connect(&fixture.socket());
    send(&mut writer, &hello(Role::Writer));
    let mut received = Received::default();
    pump_until_final(&mut broker, &mut [(&mut writer, &mut received)], &limits);
    assert!(received
        .frames
        .iter()
        .any(|frame| matches!(frame, Frame::Error { code: 5, .. })));
    assert!(!received
        .frames
        .iter()
        .any(|frame| matches!(frame, Frame::HelloAck { .. })));
    assert_eq!(broker.lifecycle(), Lifecycle::Failed);
    assert_eq!(
        broker.broker_exit().unwrap().cause,
        TerminalCause::InternalError
    );
    assert!(!fixture.session.exists());
}

#[test]
fn metadata_rewrite_failure_after_spawn_still_reaps_the_owned_child() {
    let limits = Limits {
        kill_grace_ms: 30,
        ..Limits::default()
    };
    let (fixture, mut broker) = setup_broker("post-spawn-failure", "read _line", limits);
    broker.start().unwrap();
    std::fs::remove_file(fixture.session.join("meta")).unwrap();
    std::fs::create_dir(fixture.session.join("meta")).unwrap();

    let mut writer = connect(&fixture.socket());
    send(&mut writer, &hello(Role::Writer));
    let mut received = Received::default();
    let mut spawned_pid = None;
    for _ in 0..100 {
        broker.run_once(Some(10)).unwrap();
        received.read_from(&mut writer, &limits);
        spawned_pid = spawned_pid.or_else(|| broker.child_pid());
        if spawned_pid.is_some() {
            break;
        }
    }
    let spawned_pid = spawned_pid.expect("child existed before metadata failure cleanup");
    pump_until_final(&mut broker, &mut [(&mut writer, &mut received)], &limits);
    assert!(received
        .frames
        .iter()
        .any(|frame| matches!(frame, Frame::Error { code: 5, .. })));
    assert_eq!(broker.lifecycle(), Lifecycle::Failed);
    assert!(broker.broker_exit().unwrap().failure.is_some());
    assert_eq!(
        sys::waitpid_nohang(spawned_pid)
            .expect_err("the exact child was already reaped")
            .raw_os_error(),
        Some(libc::ECHILD)
    );
    // The injected unsafe metadata object is deliberately retained rather
    // than recursively deleted; the fixture owns its eventual removal.
    assert!(fixture.session.join("meta").is_dir());
}

#[test]
fn thread_directed_catchable_signal_runs_the_same_cleanup_path() {
    let limits = Limits {
        kill_grace_ms: 50,
        ..Limits::default()
    };
    let (fixture, mut broker) = setup_broker(
        "broker-signal",
        "trap 'exit 0' TERM; printf 'READY\\n'; read _line",
        limits,
    );
    let mut writer = connect(&fixture.socket());
    send(&mut writer, &hello(Role::Writer));
    let mut received = Received::default();
    pump_until_marker(&mut broker, &mut writer, &mut received, &limits, b"READY");

    // SIGTERM is blocked on this exact thread and therefore becomes a
    // signalfd record rather than invoking the process default action.
    let sent = unsafe { libc::pthread_kill(libc::pthread_self(), libc::SIGTERM) };
    assert_eq!(sent, 0);
    pump_until_final(&mut broker, &mut [(&mut writer, &mut received)], &limits);
    assert_eq!(
        broker.broker_exit().unwrap().cause,
        TerminalCause::KillRequested
    );
    assert!(!fixture.session.exists());
}
