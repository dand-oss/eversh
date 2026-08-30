//! Focused real-Linux coverage for the public attach-client boundary.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used)]

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use everpty::attach::{self, AttachConfig, AttachOutcome, SizeMode};
use everpty::frame::{AttachStatus, Frame, Role, PROTOCOL_VERSION};
use everpty::run::{self, Context, Outcome};
use everpty::session::{resolve_state_root_from, SessionDir};
use everpty::{sys, Error, Limits};

static FIXTURE: AtomicU64 = AtomicU64::new(0);
static SIGNAL_TEST_LOCK: Mutex<()> = Mutex::new(());

struct Fixture {
    base: PathBuf,
    session: SessionDir,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        let base = loop {
            let n = FIXTURE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("everpty-attach-linux-{}-{n}", std::process::id()));
            match builder.create(&path) {
                Ok(()) => break path,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("fixture: {error}"),
            }
        };
        let state = base.join("state");
        let root = resolve_state_root_from(std::slice::from_ref(&state)).unwrap();
        let session = root.session(name, &Limits::default()).unwrap();
        Self { base, session }
    }

    fn listener(&self) -> UnixListener {
        let listener = UnixListener::bind(self.session.socket_path()).unwrap();
        std::fs::set_permissions(
            self.session.socket_path(),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        listener
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

fn recv_frame(stream: &mut impl Read, limits: &Limits) -> Frame {
    let mut header = [0u8; everpty::frame::HEADER_LEN];
    stream.read_exact(&mut header).unwrap();
    let total = Frame::validate_header(&header, limits).unwrap();
    let mut encoded = header.to_vec();
    encoded.resize(total, 0);
    stream
        .read_exact(&mut encoded[everpty::frame::HEADER_LEN..])
        .unwrap();
    Frame::decode(&encoded, limits).unwrap().0
}

fn send_frame(stream: &mut impl Write, frame: &Frame) {
    stream.write_all(&frame.encode()).unwrap();
}

#[test]
fn public_writer_connects_by_session_capability_and_preserves_bytes() {
    let _signal_serial = SIGNAL_TEST_LOCK.lock().unwrap();
    let fixture = Fixture::new("writer");
    let listener = fixture.listener();
    let named = fixture.base.join("state").join("writer");
    let moved = fixture.base.join("state").join("writer-moved");
    std::fs::rename(&named, &moved).unwrap();
    let mut replacement = std::fs::DirBuilder::new();
    replacement.mode(0o700);
    replacement.create(&named).unwrap();
    let replacement_listener = UnixListener::bind(named.join("socket")).unwrap();
    std::fs::set_permissions(named.join("socket"), std::fs::Permissions::from_mode(0o600)).unwrap();
    let limits = Limits::default();
    let first_input = vec![0, 0xff, b'\r', b'\n', 0x1b];
    let second_input = vec![b'[', b'A'];
    let input = [first_input.as_slice(), second_input.as_slice()].concat();
    let first_output = vec![0xff, 0, b'\n', 0x1b];
    let second_output = vec![b']', b'Z', b'\r', b'\n'];
    let output = [first_output.as_slice(), second_output.as_slice()].concat();
    let expected_input = input.clone();
    let (write_second_tx, write_second_rx) = std::sync::mpsc::channel();
    let (client_done_tx, client_done_rx) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        assert!(matches!(
            recv_frame(&mut stream, &limits),
            Frame::Hello {
                role: Role::Writer,
                rows: 0,
                cols: 0,
                ..
            }
        ));
        send_frame(
            &mut stream,
            &Frame::HelloAck {
                client_id: 1,
                broker_protocol_version: PROTOCOL_VERSION,
                status: AttachStatus::WriterGranted,
            },
        );
        let mut received = Vec::new();
        match recv_frame(&mut stream, &limits) {
            Frame::Input(bytes) => received.extend_from_slice(&bytes),
            other => panic!("expected first Input, got {other:?}"),
        }
        write_second_tx.send(()).unwrap();
        while received.len() < expected_input.len() {
            match recv_frame(&mut stream, &limits) {
                Frame::Input(bytes) => received.extend_from_slice(&bytes),
                other => panic!("expected split Input, got {other:?}"),
            }
        }
        assert_eq!(received, expected_input);
        send_frame(&mut stream, &Frame::Output(first_output));
        send_frame(&mut stream, &Frame::Output(second_output));
        send_frame(
            &mut stream,
            &Frame::Exit {
                signal: false,
                value: 19,
            },
        );
    });

    let (stdin_read, stdin_write) = sys::pipe_cloexec().unwrap();
    let (stdout_read, stdout_write) = sys::pipe_cloexec().unwrap();
    let input_writer = std::thread::spawn(move || {
        let mut input_writer = File::from(stdin_write);
        input_writer.write_all(&first_input).unwrap();
        write_second_rx.recv().unwrap();
        input_writer.write_all(&second_input).unwrap();
        client_done_rx.recv().unwrap();
    });
    let outcome = attach::attach(AttachConfig {
        session: &fixture.session,
        name: "writer",
        role: Role::Writer,
        take_over: false,
        size: SizeMode::Existing,
        stdin: stdin_read.as_fd(),
        stdout: stdout_write.as_fd(),
        limits,
    })
    .unwrap();
    assert_eq!(outcome, AttachOutcome::ChildExited(19));
    client_done_tx.send(()).unwrap();
    server.join().unwrap();
    input_writer.join().unwrap();
    drop(stdout_write);
    let mut got = Vec::new();
    File::from(stdout_read).read_to_end(&mut got).unwrap();
    assert_eq!(got, output);
    drop(replacement_listener);
}

#[test]
fn writer_stdin_eof_detaches_and_abrupt_socket_eof_is_not_success() {
    let _signal_serial = SIGNAL_TEST_LOCK.lock().unwrap();
    let fixture = Fixture::new("eof");
    let listener = fixture.listener();
    let limits = Limits::default();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let _ = recv_frame(&mut stream, &limits);
        send_frame(
            &mut stream,
            &Frame::HelloAck {
                client_id: 2,
                broker_protocol_version: PROTOCOL_VERSION,
                status: AttachStatus::WriterGranted,
            },
        );
        let mut byte = [0u8; 1];
        assert_eq!(
            stream.read(&mut byte).unwrap(),
            0,
            "EOF closes only the client"
        );
    });
    let (stdin_read, stdin_write) = sys::pipe_cloexec().unwrap();
    drop(stdin_write);
    let (stdout_read, stdout_write) = sys::pipe_cloexec().unwrap();
    assert_eq!(
        attach::attach(AttachConfig {
            session: &fixture.session,
            name: "eof",
            role: Role::Writer,
            take_over: false,
            size: SizeMode::Existing,
            stdin: stdin_read.as_fd(),
            stdout: stdout_write.as_fd(),
            limits,
        })
        .unwrap(),
        AttachOutcome::Detached
    );
    server.join().unwrap();
    drop((stdout_read, stdout_write));

    let fixture = Fixture::new("disconnect");
    let listener = fixture.listener();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let _ = recv_frame(&mut stream, &limits);
        send_frame(
            &mut stream,
            &Frame::HelloAck {
                client_id: 3,
                broker_protocol_version: PROTOCOL_VERSION,
                status: AttachStatus::ObserverAccepted,
            },
        );
    });
    let (stdin_read, stdin_write) = sys::pipe_cloexec().unwrap();
    let (stdout_read, stdout_write) = sys::pipe_cloexec().unwrap();
    assert!(matches!(
        attach::attach(AttachConfig {
            session: &fixture.session,
            name: "disconnect",
            role: Role::Observer,
            take_over: false,
            size: SizeMode::Existing,
            stdin: stdin_read.as_fd(),
            stdout: stdout_write.as_fd(),
            limits,
        }),
        Err(Error::NotLive)
    ));
    server.join().unwrap();
    drop((stdin_write, stdout_read, stdout_write));
}

fn context_for(fixture: &Fixture, limits: Limits) -> Context {
    Context {
        state_candidates: vec![fixture.base.join("state")],
        limits,
    }
}

#[test]
fn detach_requires_a_complete_revocation_acknowledgement() {
    let fixture = Fixture::new("detach-ok");
    let listener = fixture.listener();
    let limits = Limits::default();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        assert_eq!(recv_frame(&mut stream, &limits), Frame::DetachWriter);
        send_frame(
            &mut stream,
            &Frame::Ownership(everpty::frame::OwnershipEvent::Revoked),
        );
    });
    assert!(matches!(
        run::detach(&context_for(&fixture, limits), "detach-ok"),
        Ok(Outcome::Success)
    ));
    server.join().unwrap();

    let fixture = Fixture::new("detach-eof");
    let listener = fixture.listener();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        assert_eq!(recv_frame(&mut stream, &limits), Frame::DetachWriter);
    });
    assert!(run::detach(&context_for(&fixture, limits), "detach-eof").is_err());
    server.join().unwrap();

    let fixture = Fixture::new("detach-rejected");
    let listener = fixture.listener();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        assert_eq!(recv_frame(&mut stream, &limits), Frame::DetachWriter);
        send_frame(
            &mut stream,
            &Frame::Error {
                code: 3,
                text: "no writer".into(),
            },
        );
    });
    assert!(run::detach(&context_for(&fixture, limits), "detach-rejected").is_err());
    server.join().unwrap();

    let fixture = Fixture::new("detach-timeout");
    let limits = Limits {
        control_reply_deadline_ms: 30,
        ..Limits::default()
    };
    let listener = fixture.listener();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        assert_eq!(recv_frame(&mut stream, &limits), Frame::DetachWriter);
        std::thread::sleep(Duration::from_millis(80));
    });
    assert!(run::detach(&context_for(&fixture, limits), "detach-timeout").is_err());
    server.join().unwrap();
}
