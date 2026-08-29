//! Bounded, process-free commit-6 PTY resource regressions.
#![allow(clippy::field_reassign_with_default, clippy::unwrap_used)]

use std::cell::Cell;
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};

use everpty::broker::{Broker, Clock};
use everpty::frame::{self, AttachStatus, Frame, Role};
use everpty::limits::Limits;
use everpty::session::resolve_state_root_from;
use everpty::sys;

struct MockClock(Rc<Cell<u64>>);

impl Clock for MockClock {
    fn now_ms(&self) -> std::io::Result<u64> {
        Ok(self.0.get())
    }
}

static FIXTURE: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    base: PathBuf,
    session: String,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

impl Fixture {
    fn connect(&self) -> TestClient {
        let stream = UnixStream::connect(self.base.join(&self.session).join("socket")).unwrap();
        stream.set_nonblocking(true).unwrap();
        TestClient {
            stream,
            received: Vec::new(),
        }
    }
}

struct TestClient {
    stream: UnixStream,
    received: Vec<u8>,
}

impl TestClient {
    fn send(&mut self, frame: &Frame) {
        let wire = frame.encode();
        let mut off = 0;
        for _ in 0..128 {
            if off == wire.len() {
                return;
            }
            match self.stream.write(&wire[off..]) {
                Ok(0) => panic!("client write made no progress"),
                Ok(n) => off += n,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("client write failed: {error}"),
            }
        }
        panic!("bounded client write did not complete");
    }

    fn drain_frames(&mut self, limits: &Limits, max_reads: usize) -> Vec<Frame> {
        let mut chunk = [0u8; 8192];
        for _ in 0..max_reads {
            match self.stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => self.received.extend_from_slice(&chunk[..n]),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("client read failed: {error}"),
            }
        }

        let mut frames = Vec::new();
        loop {
            if self.received.len() < frame::HEADER_LEN {
                break;
            }
            let total =
                Frame::validate_header(&self.received[..frame::HEADER_LEN], limits).unwrap();
            if self.received.len() < total {
                break;
            }
            let (frame, used) = Frame::decode(&self.received[..total], limits).unwrap();
            assert_eq!(used, total);
            self.received.drain(..used);
            frames.push(frame);
        }
        frames
    }
}

fn unique_base(tag: &str) -> PathBuf {
    let n = FIXTURE.fetch_add(1, Ordering::Relaxed);
    for attempt in 0..64u32 {
        let base = std::env::temp_dir().join(format!(
            "everpty-res-{tag}-{}-{n}-{attempt}",
            std::process::id()
        ));
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        if builder.create(&base).is_ok() {
            return base;
        }
    }
    panic!("no exclusive fixture directory");
}

fn broker_only(
    tag: &str,
    limits: Limits,
) -> (Fixture, Rc<Cell<u64>>, Result<Broker, everpty::Error>) {
    let base = unique_base(tag);
    let session = "s1".to_owned();
    let root = resolve_state_root_from(std::slice::from_ref(&base)).unwrap();
    let dir = root.session(&session, &limits).unwrap();
    let locked = dir.lock().unwrap();
    let bound = locked.bind_broker_socket(&limits).unwrap();
    let clock = Rc::new(Cell::new(0));
    let broker = Broker::new(bound, &limits, Rc::new(MockClock(clock.clone())), None);
    (Fixture { base, session }, clock, broker)
}

fn setup(tag: &str, limits: Limits) -> (Fixture, Rc<Cell<u64>>, Broker, std::fs::File) {
    let (fixture, clock, broker) = broker_only(tag, limits);
    let mut broker = broker.unwrap();
    let (master, slave) = sys::openpty(24, 80).unwrap();
    let mut attrs = nix::sys::termios::tcgetattr(&slave).unwrap();
    nix::sys::termios::cfmakeraw(&mut attrs);
    nix::sys::termios::tcsetattr(&slave, nix::sys::termios::SetArg::TCSANOW, &attrs).unwrap();
    sys::set_nonblocking(slave.as_fd()).unwrap();
    broker.attach_pty_master(master).unwrap();
    (fixture, clock, broker, std::fs::File::from(slave))
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

fn pump(broker: &mut Broker, count: usize) {
    for _ in 0..count {
        broker.run_once(Some(0)).unwrap();
    }
}

fn grant(client: &mut TestClient, broker: &mut Broker, limits: &Limits, role: Role) {
    client.send(&hello(role));
    pump(broker, 8);
    let frames = client.drain_frames(limits, 32);
    assert!(frames.iter().any(|frame| {
        matches!(
            frame,
            Frame::HelloAck {
                status: AttachStatus::WriterGranted,
                ..
            } if role == Role::Writer
        ) || matches!(
            frame,
            Frame::HelloAck {
                status: AttachStatus::ObserverAccepted,
                ..
            } if role == Role::Observer
        )
    }));
}

fn write_slave(slave: &mut std::fs::File, bytes: &[u8]) {
    let mut off = 0;
    for _ in 0..128 {
        if off == bytes.len() {
            return;
        }
        match slave.write(&bytes[off..]) {
            Ok(0) => panic!("slave write made no progress"),
            Ok(n) => off += n,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("slave write failed: {error}"),
        }
    }
    panic!("bounded slave write did not complete");
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

#[test]
fn constructor_validates_full_encoded_reservation_before_allocation() {
    assert!(broker_only("defaults", Limits::default()).2.is_ok());

    let mut equal = Limits::default();
    equal.frame_max_body = 3;
    equal.read_chunk_bytes = 1;
    equal.writer_queue_bytes = frame::HEADER_LEN + 1;
    equal.aggregate_queue_bytes = equal.writer_queue_bytes;
    assert!(broker_only("equal", equal).2.is_ok());

    let invalid = |tag: &str, limits: Limits| {
        let error = match broker_only(tag, limits).2 {
            Ok(_) => panic!("limits must fail"),
            Err(error) => error,
        };
        assert!(
            matches!(error, everpty::Error::Io(ref io) if io.kind() == std::io::ErrorKind::InvalidInput)
        );
    };

    let mut limits = Limits::default();
    limits.read_chunk_bytes = 0;
    invalid("zero-read", limits);
    let mut limits = Limits::default();
    limits.frame_max_body = 1;
    invalid("tiny-body", limits);
    let mut limits = Limits::default();
    limits.read_chunk_bytes = limits.frame_max_body - 1;
    invalid("payload-side", limits);
    let mut limits = Limits::default();
    limits.writer_queue_bytes = limits.read_chunk_bytes + frame::HEADER_LEN - 1;
    invalid("writer-side", limits);
    let mut limits = Limits::default();
    limits.aggregate_queue_bytes = limits.writer_queue_bytes - 1;
    invalid("aggregate-side", limits);
    let mut limits = Limits::default();
    limits.frame_max_body = usize::MAX;
    limits.read_chunk_bytes = usize::MAX - 5;
    limits.writer_queue_bytes = usize::MAX;
    limits.aggregate_queue_bytes = usize::MAX;
    invalid("overflow", limits);
}

#[test]
fn live_fanout_is_byte_exact_and_later_observer_is_future_only() {
    let limits = Limits::default();
    let (fixture, _clock, mut broker, mut slave) = setup("fanout", limits);
    let mut writer = fixture.connect();
    grant(&mut writer, &mut broker, &limits, Role::Writer);
    let mut first = fixture.connect();
    grant(&mut first, &mut broker, &limits, Role::Observer);

    let before = b"before-later\0\xff";
    write_slave(&mut slave, before);
    pump(&mut broker, 8);
    assert_eq!(output_bytes(&writer.drain_frames(&limits, 32)), before);
    assert_eq!(output_bytes(&first.drain_frames(&limits, 32)), before);

    let mut later = fixture.connect();
    grant(&mut later, &mut broker, &limits, Role::Observer);
    assert!(output_bytes(&later.drain_frames(&limits, 8)).is_empty());

    let after = b"after-grant\xff\0";
    write_slave(&mut slave, after);
    pump(&mut broker, 8);
    assert_eq!(output_bytes(&writer.drain_frames(&limits, 32)), after);
    assert_eq!(output_bytes(&first.drain_frames(&limits, 32)), after);
    assert_eq!(output_bytes(&later.drain_frames(&limits, 32)), after);
    assert_eq!(broker.aggregate_output_live_bytes(), 0);
}

#[test]
fn bounded_small_chunk_barrier_excludes_detached_backlog() {
    let mut limits = Limits::default();
    limits.read_chunk_bytes = 2;
    limits.accepts_per_iteration = 2;
    let (fixture, _clock, mut broker, mut slave) = setup("barrier", limits);

    let old = b"detached-output-spans-many-discard-budgets";
    write_slave(&mut slave, old);
    let mut observer = fixture.connect();
    observer.send(&hello(Role::Observer));

    let mut frames = Vec::new();
    for _ in 0..96 {
        broker.run_once(Some(0)).unwrap();
        frames.extend(observer.drain_frames(&limits, 8));
        if frames
            .iter()
            .any(|frame| matches!(frame, Frame::HelloAck { .. }))
        {
            break;
        }
    }
    assert!(frames
        .iter()
        .any(|frame| matches!(frame, Frame::HelloAck { .. })));
    assert!(
        output_bytes(&frames).is_empty(),
        "detached bytes crossed the grant"
    );

    let post_grant = b"unique-post-grant";
    write_slave(&mut slave, post_grant);
    for _ in 0..64 {
        broker.run_once(Some(0)).unwrap();
        frames.extend(observer.drain_frames(&limits, 8));
        if output_bytes(&frames).len() == post_grant.len() {
            break;
        }
    }
    assert_eq!(output_bytes(&frames), post_grant);
}

#[test]
fn final_slave_output_is_delivered_before_read_side_detach() {
    let limits = Limits::default();
    let (fixture, _clock, mut broker, mut slave) = setup("final", limits);
    let mut observer = fixture.connect();
    grant(&mut observer, &mut broker, &limits, Role::Observer);

    let marker = b"final-before-eio\0\xff";
    write_slave(&mut slave, marker);
    drop(slave);
    let mut frames = Vec::new();
    for _ in 0..32 {
        broker.run_once(Some(0)).unwrap();
        frames.extend(observer.drain_frames(&limits, 16));
        if !broker.has_pty_master() {
            break;
        }
    }
    assert_eq!(output_bytes(&frames), marker);
    assert!(!broker.has_pty_master());
}

#[test]
fn maximum_input_drains_byte_exactly_through_small_slave_reads() {
    let limits = Limits::default();
    let (fixture, _clock, mut broker, mut slave) = setup("input", limits);
    let mut writer = fixture.connect();
    grant(&mut writer, &mut broker, &limits, Role::Writer);

    let payload: Vec<u8> = (0..(limits.frame_max_body - 2))
        .map(|index| (index.wrapping_mul(131) & 0xff) as u8)
        .collect();
    writer.send(&Frame::Input(payload.clone()));

    let mut received = Vec::with_capacity(payload.len());
    let mut small = [0u8; 17];
    for _ in 0..20_000 {
        broker.run_once(Some(0)).unwrap();
        match slave.read(&mut small) {
            Ok(0) => panic!("slave unexpectedly reached EOF"),
            Ok(n) => received.extend_from_slice(&small[..n]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("slave read failed: {error}"),
        }
        if received.len() == payload.len() && broker.writer_input_live_bytes() == Some(0) {
            break;
        }
    }
    assert_eq!(received, payload);
    assert_eq!(broker.writer_input_live_bytes(), Some(0));
    assert_eq!(broker.connection_count(), 1);

    let tail = b"later-input-admitted".to_vec();
    writer.send(&Frame::Input(tail.clone()));
    let mut later = Vec::new();
    for _ in 0..256 {
        broker.run_once(Some(0)).unwrap();
        match slave.read(&mut small) {
            Ok(n) => later.extend_from_slice(&small[..n]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => panic!("slave read failed: {error}"),
        }
        if later.len() == tail.len() {
            break;
        }
    }
    assert_eq!(later, tail);
    assert_eq!(broker.connection_count(), 1);
}
