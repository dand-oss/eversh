//! Bounded PTY, socket, decoder, and Linux process resource regressions.
#![allow(clippy::field_reassign_with_default, clippy::unwrap_used)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use everpty::broker::{Broker, Clock};
use everpty::client::FrameReader;
use everpty::frame::{self, AttachStatus, Frame, Role};
use everpty::lifecycle::{Lifecycle, Ownership};
use everpty::limits::Limits;
use everpty::session::resolve_state_root_from;
use everpty::sys;

struct CountingAllocator;

static COUNT_ALLOCATIONS: AtomicBool = AtomicBool::new(false);
static ALLOCATED_BYTES: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: this allocator delegates the original request unchanged.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() && COUNT_ALLOCATIONS.load(Ordering::Relaxed) {
            ALLOCATED_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: this allocator delegates the original request unchanged.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() && COUNT_ALLOCATIONS.load(Ordering::Relaxed) {
            ALLOCATED_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: `pointer` came from System with this layout.
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: `pointer` came from System and the request is unchanged.
        let new_pointer = unsafe { System.realloc(pointer, layout, new_size) };
        if !new_pointer.is_null() && COUNT_ALLOCATIONS.load(Ordering::Relaxed) {
            ALLOCATED_BYTES.fetch_add(new_size, Ordering::Relaxed);
        }
        new_pointer
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

static TEST_LOCK: Mutex<()> = Mutex::new(());

fn serial_test() -> std::sync::MutexGuard<'static, ()> {
    TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

struct AllocationWindow {
    baseline: usize,
    active: bool,
}

impl AllocationWindow {
    fn start() -> Self {
        assert!(
            !COUNT_ALLOCATIONS.swap(true, Ordering::SeqCst),
            "allocation windows must not overlap"
        );
        Self {
            baseline: ALLOCATED_BYTES.load(Ordering::SeqCst),
            active: true,
        }
    }

    fn finish(mut self) -> usize {
        COUNT_ALLOCATIONS.store(false, Ordering::SeqCst);
        self.active = false;
        ALLOCATED_BYTES
            .load(Ordering::SeqCst)
            .saturating_sub(self.baseline)
    }
}

impl Drop for AllocationWindow {
    fn drop(&mut self) {
        if self.active {
            COUNT_ALLOCATIONS.store(false, Ordering::SeqCst);
        }
    }
}

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

    fn wait_closed(&mut self, deadline: Instant) -> bool {
        let mut chunk = [0u8; 8192];
        loop {
            match self.stream.read(&mut chunk) {
                Ok(0) => return true,
                Ok(n) => self.received.extend_from_slice(&chunk[..n]),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error)
                    if matches!(
                        error.raw_os_error(),
                        Some(libc::ECONNRESET) | Some(libc::ENOTCONN) | Some(libc::EPIPE)
                    ) =>
                {
                    return true;
                }
                Err(error) => panic!("client close probe failed: {error}"),
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
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
    let fixture = Fixture { base, session };
    let root = resolve_state_root_from(std::slice::from_ref(&fixture.base)).unwrap();
    let dir = root.session(&fixture.session, &limits).unwrap();
    let locked = dir.lock().unwrap();
    let bound = locked.bind_broker_socket(&limits).unwrap();
    let clock = Rc::new(Cell::new(0));
    let broker = Broker::new(bound, &limits, Rc::new(MockClock(clock.clone())), None);
    (fixture, clock, broker)
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
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut frames = Vec::new();
    for _ in 0..4096 {
        broker.run_once(Some(0)).unwrap();
        frames.extend(client.drain_frames(limits, 32));
        let granted = frames.iter().any(|frame| {
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
        });
        if granted {
            assert!(
                output_bytes(&frames).is_empty(),
                "pre-grant bytes crossed the live-only barrier"
            );
            return;
        }
        assert!(Instant::now() < deadline, "Hello reply exceeded deadline");
    }
    panic!("Hello reply exceeded the iteration bound");
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

fn pressure_limits(observer_queue_bytes: usize, aggregate_queue_bytes: usize) -> Limits {
    let mut limits = Limits::default();
    limits.frame_max_body = 2048;
    limits.read_chunk_bytes = 1024;
    limits.writer_queue_bytes = 8 * 1024;
    limits.observer_queue_bytes = observer_queue_bytes;
    limits.aggregate_queue_bytes = aggregate_queue_bytes;
    limits.stall_deadline_ms = 60_000;
    limits
}

fn pattern_byte(offset: usize) -> u8 {
    let mixed = (offset as u64)
        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
        .rotate_left(17)
        ^ 0xa5a5_5a5a_d3c1_b2e7;
    (mixed ^ (mixed >> 19) ^ (mixed >> 41)) as u8
}

fn try_write_pattern(slave: &mut std::fs::File, expected: &mut Vec<u8>) -> bool {
    let mut chunk = [0u8; 1024];
    let start = expected.len();
    for (index, byte) in chunk.iter_mut().enumerate() {
        *byte = pattern_byte(start + index);
    }
    match slave.write(&chunk) {
        Ok(0) => panic!("pressure producer made no progress"),
        Ok(n) => {
            expected.extend_from_slice(&chunk[..n]);
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => false,
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => false,
        Err(error) => panic!("pressure producer failed: {error}"),
    }
}

fn drain_output(client: &mut TestClient, limits: &Limits, output: &mut Vec<u8>) {
    output.extend(output_bytes(&client.drain_frames(limits, 128)));
}

fn finish_writer_output(
    broker: &mut Broker,
    writer: &mut TestClient,
    limits: &Limits,
    expected: &[u8],
    actual: &mut Vec<u8>,
) {
    let deadline = Instant::now() + Duration::from_secs(15);
    for _ in 0..200_000 {
        broker.run_once(Some(0)).unwrap();
        drain_output(writer, limits, actual);
        assert!(actual.len() <= expected.len(), "synthetic output appeared");
        assert!(broker.aggregate_output_live_bytes() <= limits.aggregate_queue_bytes);
        if actual.len() == expected.len()
            && broker.writer_output_live_bytes() == Some(0)
            && !broker.pty_read_paused()
        {
            assert_eq!(actual, expected);
            return;
        }
        assert!(Instant::now() < deadline, "writer drain exceeded deadline");
    }
    panic!("writer output did not drain within the iteration bound");
}

fn fill_writer_socket(
    broker: &mut Broker,
    slave: &mut std::fs::File,
    limits: &Limits,
    expected: &mut Vec<u8>,
    require_pause: bool,
) {
    let deadline = Instant::now() + Duration::from_secs(15);
    for _ in 0..200_000 {
        if expected.len() < 8 * 1024 * 1024 {
            let _ = try_write_pattern(slave, expected);
        }
        broker.run_once(Some(0)).unwrap();
        let live = broker.writer_output_live_bytes().unwrap_or(0);
        assert!(live <= limits.writer_queue_bytes);
        assert!(broker.aggregate_output_live_bytes() <= limits.aggregate_queue_bytes);
        if live > 0 && (!require_pause || broker.pty_read_paused()) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "socket pressure exceeded deadline"
        );
    }
    panic!("writer socket never reached observable backpressure");
}

fn proc_fd_count(pid: u32) -> usize {
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .unwrap()
        .count()
}

#[test]
fn constructor_validates_full_encoded_reservation_before_allocation() {
    let _serial = serial_test();
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
    let _serial = serial_test();
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
    let _serial = serial_test();
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
    let _serial = serial_test();
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
    let _serial = serial_test();
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

#[test]
fn writer_output_backpressure_is_bounded_lossless_and_resumes() {
    let _serial = serial_test();
    let limits = pressure_limits(64 * 1024, 8 * 1024);
    let (fixture, _clock, mut broker, mut slave) = setup("writer-pressure", limits);
    let mut writer = fixture.connect();
    grant(&mut writer, &mut broker, &limits, Role::Writer);

    let mut expected = Vec::new();
    fill_writer_socket(&mut broker, &mut slave, &limits, &mut expected, true);
    assert!(broker.pty_read_paused());
    assert!(broker.writer_output_live_bytes().unwrap() > 0);
    assert!(broker.writer_output_live_bytes().unwrap() <= limits.writer_queue_bytes);
    assert!(broker.aggregate_output_live_bytes() <= limits.aggregate_queue_bytes);
    assert_eq!(broker.ownership(), Ownership::Writer(1));

    let mut actual = Vec::with_capacity(expected.len());
    finish_writer_output(&mut broker, &mut writer, &limits, &expected, &mut actual);
    assert_eq!(broker.connection_count(), 1);
    assert_eq!(broker.ownership(), Ownership::Writer(1));
}

#[test]
fn observer_cap_evicts_only_slow_reader_and_later_observer_is_future_only() {
    let _serial = serial_test();
    let limits = pressure_limits(4 * 1024, 128 * 1024);
    let (fixture, _clock, mut broker, mut slave) = setup("observer-pressure", limits);
    let mut writer = fixture.connect();
    grant(&mut writer, &mut broker, &limits, Role::Writer);
    let mut slow = fixture.connect();
    grant(&mut slow, &mut broker, &limits, Role::Observer);

    let mut expected = Vec::new();
    let mut writer_output = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(15);
    for _ in 0..200_000 {
        assert!(
            expected.len() < 8 * 1024 * 1024,
            "observer never reached its cap"
        );
        let _ = try_write_pattern(&mut slave, &mut expected);
        broker.run_once(Some(0)).unwrap();
        drain_output(&mut writer, &limits, &mut writer_output);
        assert!(writer_output.len() <= expected.len());
        assert!(broker.aggregate_output_live_bytes() <= limits.aggregate_queue_bytes);
        if broker.observer_count() == 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "observer eviction exceeded deadline"
        );
    }
    assert_eq!(broker.observer_count(), 0, "slow observer was not evicted");
    assert_eq!(
        broker.connection_count(),
        1,
        "writer must survive observer eviction"
    );
    assert_eq!(broker.ownership(), Ownership::Writer(1));
    assert!(
        !broker.pty_read_paused(),
        "observer pressure must not pause the PTY"
    );
    assert!(slow.wait_closed(Instant::now() + Duration::from_secs(5)));
    finish_writer_output(
        &mut broker,
        &mut writer,
        &limits,
        &expected,
        &mut writer_output,
    );

    let mut later = fixture.connect();
    grant(&mut later, &mut broker, &limits, Role::Observer);
    assert!(output_bytes(&later.drain_frames(&limits, 16)).is_empty());
    let marker = b"future-only-after-observer-eviction\0\xff";
    write_slave(&mut slave, marker);
    let mut writer_marker = Vec::new();
    let mut later_marker = Vec::new();
    for _ in 0..256 {
        broker.run_once(Some(0)).unwrap();
        drain_output(&mut writer, &limits, &mut writer_marker);
        drain_output(&mut later, &limits, &mut later_marker);
        if writer_marker.len() == marker.len() && later_marker.len() == marker.len() {
            break;
        }
    }
    assert_eq!(writer_marker, marker);
    assert_eq!(later_marker, marker);
}

#[test]
fn aggregate_cap_evicts_the_observably_most_full_observer() {
    let _serial = serial_test();
    let limits = pressure_limits(64 * 1024, 12 * 1024);
    let (fixture, _clock, mut broker, mut slave) = setup("aggregate-pressure", limits);
    let mut writer = fixture.connect();
    grant(&mut writer, &mut broker, &limits, Role::Writer);
    let mut first = fixture.connect();
    grant(&mut first, &mut broker, &limits, Role::Observer);

    let mut expected = Vec::new();
    let mut writer_output = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(15);
    for _ in 0..200_000 {
        assert!(
            expected.len() < 8 * 1024 * 1024,
            "first observer never backpressured"
        );
        let _ = try_write_pattern(&mut slave, &mut expected);
        broker.run_once(Some(0)).unwrap();
        drain_output(&mut writer, &limits, &mut writer_output);
        if broker.aggregate_output_live_bytes() > 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "aggregate prefill exceeded deadline"
        );
    }
    assert_eq!(broker.observer_count(), 1);
    assert!(broker.aggregate_output_live_bytes() > 0);
    finish_writer_output(
        &mut broker,
        &mut writer,
        &limits,
        &expected,
        &mut writer_output,
    );
    assert!(broker.aggregate_output_live_bytes() > 0);

    let mut second = fixture.connect();
    grant(&mut second, &mut broker, &limits, Role::Observer);
    let mut second_output = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(15);
    for _ in 0..200_000 {
        assert!(
            expected.len() < 12 * 1024 * 1024,
            "aggregate cap never evicted"
        );
        let _ = try_write_pattern(&mut slave, &mut expected);
        broker.run_once(Some(0)).unwrap();
        drain_output(&mut writer, &limits, &mut writer_output);
        drain_output(&mut second, &limits, &mut second_output);
        assert!(broker.aggregate_output_live_bytes() <= limits.aggregate_queue_bytes);
        if broker.observer_count() == 1 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "aggregate eviction exceeded deadline"
        );
    }
    assert_eq!(broker.observer_count(), 1);
    assert_eq!(
        broker.connection_count(),
        2,
        "writer and healthy observer survive"
    );
    assert_eq!(broker.ownership(), Ownership::Writer(1));
    assert!(first.wait_closed(Instant::now() + Duration::from_secs(5)));
    finish_writer_output(
        &mut broker,
        &mut writer,
        &limits,
        &expected,
        &mut writer_output,
    );
}

#[test]
fn connection_seventeen_gets_resource_limit_closes_and_retains_no_descriptor() {
    let _serial = serial_test();
    let limits = Limits::default();
    let (fixture, _clock, broker) = broker_only("connection-cap", limits);
    let mut broker = broker.unwrap();
    let holders: Vec<_> = (0..limits.max_connections)
        .map(|_| fixture.connect())
        .collect();
    pump(&mut broker, 8);
    assert_eq!(broker.connection_count(), limits.max_connections);
    let baseline_fds = proc_fd_count(std::process::id());

    let mut refused = fixture.connect();
    assert_eq!(proc_fd_count(std::process::id()), baseline_fds + 1);
    pump(&mut broker, 4);
    assert_eq!(broker.connection_count(), limits.max_connections);
    let frames = refused.drain_frames(&limits, 32);
    assert!(frames
        .iter()
        .any(|frame| matches!(frame, Frame::Error { code: 4, .. })));
    assert!(refused.wait_closed(Instant::now() + Duration::from_secs(2)));
    drop(refused);
    let deadline = Instant::now() + Duration::from_secs(2);
    while proc_fd_count(std::process::id()) != baseline_fds {
        assert!(Instant::now() < deadline, "refused descriptor was retained");
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(broker.connection_count(), limits.max_connections);
    drop(holders);
}

#[test]
fn incomplete_decoders_reserve_once_then_allocation_plateaus() {
    let _serial = serial_test();
    let limits = Limits::default();
    let maximum = Frame::Input(vec![0u8; limits.frame_max_body - 2]).encode();
    let header: [u8; frame::HEADER_LEN] = maximum[..frame::HEADER_LEN].try_into().unwrap();
    let fragment = [0xa5u8; 31];
    let mut readers: Vec<_> = (0..limits.max_connections)
        .map(|_| FrameReader::new())
        .collect();

    let initial_window = AllocationWindow::start();
    for reader in &mut readers {
        assert_eq!(reader.append(&header, 7, &limits), header.len());
    }
    let initial_allocation = initial_window.finish();
    let minimum = limits.max_connections * (limits.frame_max_body - frame::HEADER_LEN);
    let maximum_bound = limits
        .max_connections
        .saturating_mul(2)
        .saturating_mul(limits.frame_max_body)
        .saturating_add(limits.read_chunk_bytes)
        .saturating_add(64 * 1024);
    assert!(
        initial_allocation >= minimum,
        "body capacity was not reserved"
    );
    assert!(
        initial_allocation <= maximum_bound,
        "decoder allocation exceeded the planned aggregate bound: {initial_allocation}"
    );
    assert_eq!(
        readers.iter().map(FrameReader::owned_bytes).sum::<usize>(),
        limits.max_connections * frame::HEADER_LEN
    );

    let fragment_window = AllocationWindow::start();
    for reader in &mut readers {
        assert_eq!(reader.append(&fragment, 8, &limits), fragment.len());
    }
    assert_eq!(
        fragment_window.finish(),
        0,
        "drip-fed body bytes allocated after the validated-header reservation"
    );
    assert_eq!(
        readers.iter().map(FrameReader::owned_bytes).sum::<usize>(),
        limits.max_connections * (frame::HEADER_LEN + fragment.len())
    );
}

#[test]
fn control_reply_under_eagain_closes_only_at_immutable_deadline() {
    let _serial = serial_test();
    let mut limits = pressure_limits(64 * 1024, 8 * 1024);
    limits.control_reply_deadline_ms = 37;
    let (fixture, clock, mut broker, mut slave) = setup("control-deadline", limits);
    let mut writer = fixture.connect();
    grant(&mut writer, &mut broker, &limits, Role::Writer);
    let mut expected = Vec::new();
    fill_writer_socket(&mut broker, &mut slave, &limits, &mut expected, false);
    assert!(broker.writer_output_live_bytes().unwrap() > 0);

    writer.send(&Frame::Ping);
    for _ in 0..32 {
        broker.run_once(Some(0)).unwrap();
        if broker.writer_output_live_bytes().is_none() {
            break;
        }
    }
    assert_eq!(
        broker.connection_count(),
        1,
        "reply remains draining before deadline"
    );
    assert_eq!(broker.ownership(), Ownership::Writer(1));
    clock.set(limits.control_reply_deadline_ms - 1);
    pump(&mut broker, 2);
    assert_eq!(broker.connection_count(), 1);
    clock.set(limits.control_reply_deadline_ms);
    pump(&mut broker, 2);
    assert_eq!(broker.connection_count(), 0);
    assert_eq!(broker.ownership(), Ownership::NoWriter);
    assert!(!broker.pty_read_paused());
    assert_eq!(broker.aggregate_output_live_bytes(), 0);
}

#[test]
fn queued_writer_epipe_is_peer_local_and_broker_accepts_a_fresh_writer() {
    let _serial = serial_test();
    let limits = pressure_limits(64 * 1024, 8 * 1024);
    let (fixture, _clock, mut broker, mut slave) = setup("writer-epipe", limits);
    let mut writer = fixture.connect();
    grant(&mut writer, &mut broker, &limits, Role::Writer);
    let mut old = Vec::new();
    fill_writer_socket(&mut broker, &mut slave, &limits, &mut old, true);
    assert!(broker.aggregate_output_live_bytes() > 0);
    drop(writer);
    for _ in 0..1024 {
        broker.run_once(Some(0)).unwrap();
        if broker.connection_count() == 0 {
            break;
        }
    }
    assert_eq!(broker.connection_count(), 0);
    assert_eq!(broker.lifecycle(), Lifecycle::Running);
    assert_eq!(broker.ownership(), Ownership::NoWriter);
    assert!(!broker.pty_read_paused());
    assert_eq!(broker.aggregate_output_live_bytes(), 0);

    let mut fresh = fixture.connect();
    grant(&mut fresh, &mut broker, &limits, Role::Writer);
    assert!(output_bytes(&fresh.drain_frames(&limits, 16)).is_empty());
    let marker = b"only-after-epipe\0\xff";
    write_slave(&mut slave, marker);
    let mut actual = Vec::new();
    for _ in 0..256 {
        broker.run_once(Some(0)).unwrap();
        drain_output(&mut fresh, &limits, &mut actual);
        if actual.len() == marker.len() {
            break;
        }
    }
    assert_eq!(actual, marker);
}

#[cfg(all(target_os = "linux", feature = "cli"))]
mod real_process {
    use super::*;
    use std::fs::File;
    use std::os::fd::AsRawFd;
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::process::{Child, Command, ExitStatus, Stdio};

    use everpty::run::{self, Context};
    use everpty::session::SessionMeta;
    use nix::sys::signal::Signal;

    fn binary() -> &'static str {
        env!("CARGO_BIN_EXE_everpty")
    }

    fn wait_child(child: &mut Child, deadline: Instant) -> Option<ExitStatus> {
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return Some(status);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    fn read_exact_token(file: &mut File, token: &[u8], deadline: Instant) {
        let mut received = Vec::new();
        let mut chunk = [0u8; 128];
        loop {
            match file.read(&mut chunk) {
                Ok(0) => panic!("starter PTY reached EOF before readiness"),
                Ok(n) => received.extend_from_slice(&chunk[..n]),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("starter PTY read failed: {error}"),
            }
            if received.len() >= token.len() {
                assert_eq!(received, token, "synthetic startup bytes appeared");
                return;
            }
            assert!(
                Instant::now() < deadline,
                "starter readiness exceeded deadline"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    fn live_identity(pid: libc::pid_t, ticks: u64) -> bool {
        sys::proc_start_ticks(pid).is_ok_and(|actual| actual == ticks)
    }

    fn process_group_members(pgid: libc::pid_t) -> Vec<libc::pid_t> {
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return Vec::new();
        };
        let mut members = Vec::new();
        for entry in entries.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<libc::pid_t>().ok())
            else {
                continue;
            };
            let Ok(stat) = std::fs::read(entry.path().join("stat")) else {
                continue;
            };
            let Some(close) = stat.iter().rposition(|byte| *byte == b')') else {
                continue;
            };
            let mut fields = stat[(close + 1)..]
                .split(|byte| *byte == b' ')
                .filter(|field| !field.is_empty());
            let _state = fields.next();
            let _parent = fields.next();
            let process_group = fields
                .next()
                .and_then(|field| std::str::from_utf8(field).ok())
                .and_then(|field| field.parse::<libc::pid_t>().ok());
            if process_group == Some(pgid) {
                members.push(pid);
            }
        }
        members.sort_unstable();
        members
    }

    fn rss_status_kib(pid: u32) -> usize {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        status
            .lines()
            .find_map(|line| {
                line.strip_prefix("VmRSS:")
                    .and_then(|value| value.split_ascii_whitespace().next())
                    .and_then(|value| value.parse().ok())
            })
            .unwrap()
    }

    fn rss_statm_kib(pid: u32) -> usize {
        let statm = std::fs::read_to_string(format!("/proc/{pid}/statm")).unwrap();
        let resident_pages: usize = statm
            .split_ascii_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        // SAFETY: sysconf with _SC_PAGESIZE has no pointer arguments.
        let page_bytes = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        assert!(page_bytes > 0);
        resident_pages.saturating_mul(page_bytes as usize) / 1024
    }

    #[derive(Debug)]
    struct ProcSample {
        fds: usize,
        status_rss_kib: usize,
        statm_rss_kib: usize,
    }

    struct StartupGuard {
        base: PathBuf,
        state: PathBuf,
        name: String,
        starter: Option<Child>,
        outer: Option<File>,
        disarmed: bool,
    }

    impl StartupGuard {
        fn cleanup(&mut self) {
            let context = Context {
                state_candidates: vec![self.state.clone()],
                limits: Limits::default(),
            };
            if let Ok(mut killer) = configured_command(&self.state)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .args(["kill", &self.name])
                .spawn()
            {
                if wait_child(&mut killer, Instant::now() + Duration::from_secs(2)).is_none() {
                    let _ = killer.kill();
                    let _ = killer.wait();
                }
            }
            if let Ok(sessions) = run::list(&context) {
                for metadata in sessions {
                    if metadata.name() != self.name {
                        continue;
                    }
                    if let Some(child) = metadata.child() {
                        if live_identity(child.pid(), child.start_ticks())
                            && sys::getpgid_of(child.pid()).ok() == Some(child.pgid())
                        {
                            let _ = sys::killpg(child.pgid(), Signal::SIGKILL);
                        }
                    }
                    if live_identity(metadata.broker_pid(), metadata.broker_start_ticks()) {
                        let _ = sys::kill(metadata.broker_pid(), Signal::SIGKILL);
                    }
                }
            }
            if let Some(mut starter) = self.starter.take() {
                let _ = starter.kill();
                let _ = starter.wait();
            }
            self.outer.take();
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    impl Drop for StartupGuard {
        fn drop(&mut self) {
            if !self.disarmed {
                self.cleanup();
            }
        }
    }

    struct RealSession {
        base: PathBuf,
        state: PathBuf,
        name: String,
        metadata: SessionMeta,
        starter: Option<Child>,
        outer: Option<File>,
        finished: bool,
    }

    impl RealSession {
        fn command(&self) -> Command {
            configured_command(&self.state)
        }

        fn start(tag: &str, script: &str) -> Self {
            let base = unique_base(tag);
            let state = base.join("state");
            let name = "resource".to_owned();
            let mut startup = StartupGuard {
                base,
                state,
                name,
                starter: None,
                outer: None,
                disarmed: false,
            };
            let (master, slave) = sys::openpty(24, 80).unwrap();
            let mut command = configured_command(&startup.state);
            command
                .process_group(0)
                .stdin(Stdio::from(File::from(slave.try_clone().unwrap())))
                .stdout(Stdio::from(File::from(slave.try_clone().unwrap())))
                .stderr(Stdio::from(File::from(slave)))
                .args(["start", &startup.name, "--", "/bin/sh", "-c", script]);
            startup.starter = Some(command.spawn().unwrap());
            let outer = File::from(master);
            sys::set_nonblocking(outer.as_fd()).unwrap();
            startup.outer = Some(outer);
            let deadline = Instant::now() + Duration::from_secs(15);
            read_exact_token(startup.outer.as_mut().unwrap(), b"READY", deadline);

            let context = Context {
                state_candidates: vec![startup.state.clone()],
                limits: Limits::default(),
            };
            let metadata = loop {
                if let Ok(sessions) = run::list(&context) {
                    if let Some(metadata) = sessions.into_iter().find(|metadata| {
                        metadata.name() == startup.name && metadata.child().is_some()
                    }) {
                        break metadata;
                    }
                }
                assert!(Instant::now() < deadline, "session metadata never appeared");
                std::thread::sleep(Duration::from_millis(2));
            };
            assert!(live_identity(
                metadata.broker_pid(),
                metadata.broker_start_ticks()
            ));
            let child = metadata.child().unwrap();
            assert!(live_identity(child.pid(), child.start_ticks()));
            assert_eq!(sys::getpgid_of(child.pid()).unwrap(), child.pgid());

            let session = Self {
                base: startup.base.clone(),
                state: startup.state.clone(),
                name: startup.name.clone(),
                metadata,
                starter: startup.starter.take(),
                outer: startup.outer.take(),
                finished: false,
            };
            startup.disarmed = true;
            session
        }

        fn sample(&self) -> ProcSample {
            let pid = self.metadata.broker_pid() as u32;
            ProcSample {
                fds: proc_fd_count(pid),
                status_rss_kib: rss_status_kib(pid),
                statm_rss_kib: rss_statm_kib(pid),
            }
        }

        fn identities_gone(&self) -> bool {
            let broker_gone = !live_identity(
                self.metadata.broker_pid(),
                self.metadata.broker_start_ticks(),
            );
            let child_gone = self
                .metadata
                .child()
                .is_none_or(|child| !live_identity(child.pid(), child.start_ticks()));
            broker_gone && child_gone
        }

        fn state_gone(&self) -> bool {
            !self.state.join(&self.name).exists()
        }

        fn run_kill_command(&self) {
            let Ok(child) = self
                .command()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .args(["kill", &self.name])
                .spawn()
            else {
                return;
            };
            let mut child = child;
            if wait_child(&mut child, Instant::now() + Duration::from_secs(3)).is_none() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }

        fn direct_signal(&self, signal: Signal) {
            if let Some(child) = self.metadata.child() {
                if live_identity(child.pid(), child.start_ticks())
                    && sys::getpgid_of(child.pid()).ok() == Some(child.pgid())
                {
                    let _ = sys::killpg(child.pgid(), signal);
                }
            }
            if live_identity(
                self.metadata.broker_pid(),
                self.metadata.broker_start_ticks(),
            ) {
                let _ = sys::kill(self.metadata.broker_pid(), signal);
            }
        }

        fn cleanup(&mut self) -> bool {
            self.run_kill_command();
            let first = Instant::now() + Duration::from_secs(2);
            while !self.identities_gone() && Instant::now() < first {
                std::thread::sleep(Duration::from_millis(5));
            }
            if !self.identities_gone() {
                self.direct_signal(Signal::SIGTERM);
                std::thread::sleep(Duration::from_millis(50));
                self.direct_signal(Signal::SIGKILL);
            }
            if let Some(mut starter) = self.starter.take() {
                if wait_child(&mut starter, Instant::now() + Duration::from_secs(2)).is_none() {
                    let _ = starter.kill();
                    let _ = starter.wait();
                }
            }
            self.outer.take();
            let deadline = Instant::now() + Duration::from_secs(3);
            while !self.identities_gone() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            let child_group_gone = self
                .metadata
                .child()
                .is_none_or(|child| process_group_members(child.pgid()).is_empty());
            let clean = self.identities_gone() && child_group_gone;
            let _ = std::fs::remove_dir_all(&self.base);
            clean && !self.base.exists()
        }

        fn terminate_catchably(mut self) -> ExitStatus {
            let child = self.metadata.child().unwrap();
            let pgid = child.pgid();
            assert!(!process_group_members(pgid).is_empty());
            assert!(live_identity(
                self.metadata.broker_pid(),
                self.metadata.broker_start_ticks()
            ));
            sys::kill(self.metadata.broker_pid(), Signal::SIGTERM).unwrap();
            let status = wait_child(
                self.starter.as_mut().unwrap(),
                Instant::now() + Duration::from_secs(10),
            )
            .expect("starter did not observe catchable broker shutdown");
            self.starter.take();
            self.outer.take();
            let deadline = Instant::now() + Duration::from_secs(5);
            while (!self.identities_gone()
                || !self.state_gone()
                || !process_group_members(pgid).is_empty())
                && Instant::now() < deadline
            {
                std::thread::sleep(Duration::from_millis(5));
            }
            assert!(
                self.identities_gone(),
                "broker/child identity survived exit"
            );
            assert!(self.state_gone(), "session state survived exit");
            assert!(
                process_group_members(pgid).is_empty(),
                "child process group survived exit"
            );
            let _ = std::fs::remove_dir_all(&self.base);
            assert!(!self.base.exists());
            self.finished = true;
            status
        }
    }

    impl Drop for RealSession {
        fn drop(&mut self) {
            if !self.finished {
                let _ = self.cleanup();
                self.finished = true;
            }
        }
    }

    fn configured_command(state: &std::path::Path) -> Command {
        let mut command = Command::new(binary());
        command
            .env_clear()
            .env("EVERSH_STATE_DIR", state)
            .env("PATH", "/usr/bin:/bin")
            .env("SHELL", "/bin/sh")
            .env("TERM", "xterm-256color")
            .env("LC_ALL", "C");
        command
    }

    fn range(values: &[usize]) -> usize {
        values.iter().max().unwrap() - values.iter().min().unwrap()
    }

    fn sha256_hex(input: &[u8]) -> String {
        const INITIAL: [u32; 8] = [
            0x6a09_e667,
            0xbb67_ae85,
            0x3c6e_f372,
            0xa54f_f53a,
            0x510e_527f,
            0x9b05_688c,
            0x1f83_d9ab,
            0x5be0_cd19,
        ];
        const ROUND: [u32; 64] = [
            0x428a_2f98,
            0x7137_4491,
            0xb5c0_fbcf,
            0xe9b5_dba5,
            0x3956_c25b,
            0x59f1_11f1,
            0x923f_82a4,
            0xab1c_5ed5,
            0xd807_aa98,
            0x1283_5b01,
            0x2431_85be,
            0x550c_7dc3,
            0x72be_5d74,
            0x80de_b1fe,
            0x9bdc_06a7,
            0xc19b_f174,
            0xe49b_69c1,
            0xefbe_4786,
            0x0fc1_9dc6,
            0x240c_a1cc,
            0x2de9_2c6f,
            0x4a74_84aa,
            0x5cb0_a9dc,
            0x76f9_88da,
            0x983e_5152,
            0xa831_c66d,
            0xb003_27c8,
            0xbf59_7fc7,
            0xc6e0_0bf3,
            0xd5a7_9147,
            0x06ca_6351,
            0x1429_2967,
            0x27b7_0a85,
            0x2e1b_2138,
            0x4d2c_6dfc,
            0x5338_0d13,
            0x650a_7354,
            0x766a_0abb,
            0x81c2_c92e,
            0x9272_2c85,
            0xa2bf_e8a1,
            0xa81a_664b,
            0xc24b_8b70,
            0xc76c_51a3,
            0xd192_e819,
            0xd699_0624,
            0xf40e_3585,
            0x106a_a070,
            0x19a4_c116,
            0x1e37_6c08,
            0x2748_774c,
            0x34b0_bcb5,
            0x391c_0cb3,
            0x4ed8_aa4a,
            0x5b9c_ca4f,
            0x682e_6ff3,
            0x748f_82ee,
            0x78a5_636f,
            0x84c8_7814,
            0x8cc7_0208,
            0x90be_fffa,
            0xa450_6ceb,
            0xbef9_a3f7,
            0xc671_78f2,
        ];

        let bit_len = (input.len() as u64).wrapping_mul(8);
        let mut padded = Vec::with_capacity((input.len() + 72) & !63);
        padded.extend_from_slice(input);
        padded.push(0x80);
        while padded.len() % 64 != 56 {
            padded.push(0);
        }
        padded.extend_from_slice(&bit_len.to_be_bytes());

        let mut hash = INITIAL;
        for block in padded.chunks_exact(64) {
            let mut words = [0u32; 64];
            for (index, word) in words[..16].iter_mut().enumerate() {
                let offset = index * 4;
                *word = u32::from_be_bytes(block[offset..offset + 4].try_into().unwrap());
            }
            for index in 16..64 {
                let s0 = words[index - 15].rotate_right(7)
                    ^ words[index - 15].rotate_right(18)
                    ^ (words[index - 15] >> 3);
                let s1 = words[index - 2].rotate_right(17)
                    ^ words[index - 2].rotate_right(19)
                    ^ (words[index - 2] >> 10);
                words[index] = words[index - 16]
                    .wrapping_add(s0)
                    .wrapping_add(words[index - 7])
                    .wrapping_add(s1);
            }
            let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = hash;
            for index in 0..64 {
                let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let choose = (e & f) ^ ((!e) & g);
                let temp1 = h
                    .wrapping_add(sum1)
                    .wrapping_add(choose)
                    .wrapping_add(ROUND[index])
                    .wrapping_add(words[index]);
                let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let majority = (a & b) ^ (a & c) ^ (b & c);
                let temp2 = sum0.wrapping_add(majority);
                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.wrapping_add(temp2);
            }
            for (value, addition) in hash.iter_mut().zip([a, b, c, d, e, f, g, h]) {
                *value = value.wrapping_add(addition);
            }
        }

        let mut encoded = String::with_capacity(64);
        for byte in hash.into_iter().flat_map(u32::to_be_bytes) {
            use std::fmt::Write as _;
            write!(&mut encoded, "{byte:02x}").unwrap();
        }
        encoded
    }

    #[derive(Debug)]
    struct SocketMeasurement {
        elapsed: Duration,
        peak_outstanding: usize,
        would_block: usize,
    }

    fn socket_write(stream: &UnixStream, bytes: &[u8]) -> std::io::Result<usize> {
        // SAFETY: the descriptor is live and `bytes` is borrowed for the call.
        let count = unsafe {
            libc::write(
                stream.as_raw_fd(),
                bytes.as_ptr().cast::<libc::c_void>(),
                bytes.len(),
            )
        };
        if count < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(count as usize)
        }
    }

    fn socket_read(stream: &UnixStream, bytes: &mut [u8]) -> std::io::Result<usize> {
        // SAFETY: the descriptor is live and `bytes` is exclusively borrowed.
        let count = unsafe {
            libc::read(
                stream.as_raw_fd(),
                bytes.as_mut_ptr().cast::<libc::c_void>(),
                bytes.len(),
            )
        };
        if count < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(count as usize)
        }
    }

    fn measure_throttled_socket(input: &[u8], read_budget: usize) -> SocketMeasurement {
        let (sender, receiver) = UnixStream::pair().unwrap();
        sender.set_nonblocking(true).unwrap();
        receiver.set_nonblocking(true).unwrap();
        let started = Instant::now();
        let deadline = started + Duration::from_secs(20);
        let mut written = 0usize;
        let mut actual = Vec::with_capacity(input.len());
        let mut peak_outstanding = 0usize;
        let mut would_block = 0usize;
        let mut chunk = [0u8; 16 * 1024];

        while actual.len() < input.len() {
            for _ in 0..128 {
                if written == input.len() {
                    break;
                }
                let end = (written + chunk.len()).min(input.len());
                match socket_write(&sender, &input[written..end]) {
                    Ok(0) => panic!("socket measurement writer made no progress"),
                    Ok(count) => written += count,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        would_block += 1;
                        break;
                    }
                    Err(error) => panic!("socket measurement write failed: {error}"),
                }
            }
            peak_outstanding = peak_outstanding.max(written.saturating_sub(actual.len()));

            let mut remaining = read_budget;
            while remaining > 0 && actual.len() < input.len() {
                let want = remaining.min(chunk.len());
                match socket_read(&receiver, &mut chunk[..want]) {
                    Ok(0) => panic!("socket measurement reached early EOF"),
                    Ok(count) => {
                        actual.extend_from_slice(&chunk[..count]);
                        remaining -= count;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => panic!("socket measurement read failed: {error}"),
                }
            }
            assert!(
                Instant::now() < deadline,
                "socket measurement exceeded deadline"
            );
            if actual.len() < input.len() {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        assert_eq!(actual, input);
        SocketMeasurement {
            elapsed: started.elapsed(),
            peak_outstanding,
            would_block,
        }
    }

    struct PtyProcess {
        child: Option<Child>,
        pgid: libc::pid_t,
    }

    impl PtyProcess {
        fn try_wait(&mut self) -> Option<ExitStatus> {
            let status = self.child.as_mut().unwrap().try_wait().unwrap();
            if status.is_some() {
                self.child.take();
            }
            status
        }

        fn terminate(&mut self) {
            if self.child.is_none() {
                return;
            }
            let _ = sys::killpg(self.pgid, Signal::SIGTERM);
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                if self.try_wait().is_some() {
                    return;
                }
                if Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            let _ = sys::killpg(self.pgid, Signal::SIGKILL);
            if let Some(mut child) = self.child.take() {
                let _ = child.wait();
            }
        }
    }

    impl Drop for PtyProcess {
        fn drop(&mut self) {
            self.terminate();
        }
    }

    fn spawn_measurement_pty(
        program: &str,
        arguments: &[&str],
        working_dir: &std::path::Path,
        initially_raw: bool,
    ) -> (PtyProcess, File) {
        let (master, slave) = sys::openpty(24, 80).unwrap();
        if initially_raw {
            let mut attrs = nix::sys::termios::tcgetattr(&slave).unwrap();
            nix::sys::termios::cfmakeraw(&mut attrs);
            nix::sys::termios::tcsetattr(&slave, nix::sys::termios::SetArg::TCSANOW, &attrs)
                .unwrap();
        }
        let mut command = Command::new(program);
        command
            .args(arguments)
            .current_dir(working_dir)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("TERM", "xterm-256color")
            .env("LC_ALL", "C")
            .env("HOME", working_dir)
            .stdin(Stdio::from(File::from(slave.try_clone().unwrap())))
            .stdout(Stdio::from(File::from(slave.try_clone().unwrap())))
            .stderr(Stdio::from(File::from(slave)));
        // SAFETY: the closure contains only async-signal-safe syscalls and
        // constructs fixed OS errors; it runs after stdio has been installed.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().unwrap();
        let pgid = child.id() as libc::pid_t;
        let process = PtyProcess {
            child: Some(child),
            pgid,
        };
        let master = File::from(master);
        sys::set_nonblocking(master.as_fd()).unwrap();
        (process, master)
    }

    #[derive(Debug)]
    struct PtyMeasurement {
        elapsed: Duration,
        peak_outstanding: usize,
        would_block: usize,
        output_bytes: usize,
    }

    fn measure_cat_pty(input: &[u8], base: &std::path::Path) -> PtyMeasurement {
        let (mut process, mut master) = spawn_measurement_pty("/bin/cat", &[], base, true);
        let started = Instant::now();
        let deadline = started + Duration::from_secs(20);
        let mut written = 0usize;
        let mut actual = Vec::with_capacity(input.len());
        let mut peak_outstanding = 0usize;
        let mut would_block = 0usize;
        let mut chunk = [0u8; 16 * 1024];
        while actual.len() < input.len() {
            if written < input.len() {
                let end = (written + chunk.len()).min(input.len());
                match master.write(&input[written..end]) {
                    Ok(0) => panic!("PTY producer made no progress"),
                    Ok(count) => written += count,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        would_block += 1;
                    }
                    Err(error) => panic!("PTY producer failed: {error}"),
                }
            }
            for _ in 0..32 {
                match master.read(&mut chunk) {
                    Ok(0) => panic!("PTY reached EOF before exact output"),
                    Ok(count) => actual.extend_from_slice(&chunk[..count]),
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => panic!("PTY consumer failed: {error}"),
                }
            }
            assert!(actual.len() <= input.len(), "cat emitted synthetic bytes");
            peak_outstanding = peak_outstanding.max(written.saturating_sub(actual.len()));
            assert!(
                Instant::now() < deadline,
                "10 MiB PTY run exceeded deadline"
            );
        }
        assert_eq!(actual, input);
        process.terminate();
        PtyMeasurement {
            elapsed: started.elapsed(),
            peak_outstanding,
            would_block,
            output_bytes: actual.len(),
        }
    }

    fn write_pty_bounded(master: &mut File, bytes: &[u8], deadline: Instant) {
        let mut offset = 0usize;
        let mut sink = [0u8; 16 * 1024];
        while offset < bytes.len() {
            match master.write(&bytes[offset..]) {
                Ok(0) => panic!("Vim input made no progress"),
                Ok(count) => offset += count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    let _ = master.read(&mut sink);
                }
                Err(error) => panic!("Vim input failed: {error}"),
            }
            assert!(Instant::now() < deadline, "Vim input exceeded deadline");
        }
    }

    fn measure_vim_loop(base: &std::path::Path, run: usize) -> PtyMeasurement {
        let file = base.join(format!("vim-{run}.txt"));
        let original = b"alpha\nbeta\ngamma\n";
        std::fs::write(&file, original).unwrap();
        let path = file.to_str().unwrap();
        let (mut process, mut master) = spawn_measurement_pty(
            "/usr/bin/vim",
            &["-u", "NONE", "-i", "NONE", "-n", "-N", path],
            base,
            false,
        );
        let started = Instant::now();
        let deadline = started + Duration::from_secs(15);
        let mut output_bytes = 0usize;
        let mut chunk = [0u8; 16 * 1024];
        while output_bytes == 0 {
            match master.read(&mut chunk) {
                Ok(count) => output_bytes += count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("Vim startup read failed: {error}"),
            }
            assert!(Instant::now() < deadline, "Vim startup exceeded deadline");
            std::thread::sleep(Duration::from_millis(2));
        }

        let mut keys = Vec::new();
        for iteration in 0..32 {
            keys.extend_from_slice(b"gg0iM2-");
            keys.extend_from_slice(iteration.to_string().as_bytes());
            keys.extend_from_slice(b"\x1b$h\x0cG");
        }
        keys.extend_from_slice(b"\x1b:q!\r");
        write_pty_bounded(&mut master, &keys, deadline);

        let status = loop {
            for _ in 0..32 {
                match master.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(count) => output_bytes += count,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
                    Err(error) => panic!("Vim output read failed: {error}"),
                }
            }
            if let Some(status) = process.try_wait() {
                break status;
            }
            assert!(Instant::now() < deadline, "Vim loop exceeded deadline");
            std::thread::sleep(Duration::from_millis(2));
        };
        assert!(status.success(), "Vim loop failed: {status}");
        assert_eq!(
            std::fs::read(&file).unwrap(),
            original,
            "q! wrote the fixture"
        );
        std::fs::remove_file(&file).unwrap();
        PtyMeasurement {
            elapsed: started.elapsed(),
            peak_outstanding: 0,
            would_block: 0,
            output_bytes,
        }
    }

    fn mib_per_second(bytes: usize, elapsed: Duration) -> f64 {
        bytes as f64 / (1024.0 * 1024.0) / elapsed.as_secs_f64()
    }

    #[test]
    #[ignore = "local, bounded Limits remeasurement; run explicitly with --ignored"]
    fn measure_locked_limits_local() {
        let _serial = serial_test();
        assert_eq!(
            std::env::var_os("EVERPTY_RUN_LIMITS_MEASUREMENT").as_deref(),
            Some(std::ffi::OsStr::new("1"))
        );
        let limits = Limits::default();
        let input: Vec<u8> = (0..10 * 1024 * 1024).map(pattern_byte).collect();
        let input_sha256 = sha256_hex(&input);
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let binary_bytes = std::fs::read(binary()).unwrap();
        let binary_sha256 = sha256_hex(&binary_bytes);
        // SAFETY: sysconf with _SC_PAGESIZE has no pointer arguments.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        println!(
            "MEASURE environment os={} arch={} kernel={} cpus={} page_bytes={} binary_sha256={}",
            std::env::consts::OS,
            std::env::consts::ARCH,
            std::fs::read_to_string("/proc/sys/kernel/osrelease")
                .unwrap()
                .trim(),
            std::thread::available_parallelism().unwrap(),
            page_size,
            binary_sha256
        );
        println!(
            "MEASURE input bytes={} sha256={} generator=resources::pattern_byte",
            input.len(),
            input_sha256
        );
        println!("MEASURE limits {limits:?}");

        for read_budget in [8 * 1024, 32 * 1024] {
            for run in 1..=3 {
                let measurement = measure_throttled_socket(&input, read_budget);
                println!(
                    "MEASURE socket run={} budget_per_1ms={} elapsed_ms={} throughput_mib_s={:.3} peak_outstanding={} would_block={} bytes={} sha256={}",
                    run,
                    read_budget,
                    measurement.elapsed.as_millis(),
                    mib_per_second(input.len(), measurement.elapsed),
                    measurement.peak_outstanding,
                    measurement.would_block,
                    input.len(),
                    input_sha256
                );
            }
        }

        let base = Fixture {
            base: unique_base("limits-measurement"),
            session: String::new(),
        };
        for run in 1..=5 {
            let measurement = measure_cat_pty(&input, &base.base);
            println!(
                "MEASURE cat run={} elapsed_ms={} throughput_mib_s={:.3} peak_outstanding={} would_block={} bytes={} sha256={}",
                run,
                measurement.elapsed.as_millis(),
                mib_per_second(input.len(), measurement.elapsed),
                measurement.peak_outstanding,
                measurement.would_block,
                measurement.output_bytes,
                input_sha256
            );
        }
        for run in 1..=3 {
            let measurement = measure_vim_loop(&base.base, run);
            println!(
                "MEASURE vim run={} iterations=32 elapsed_ms={} output_bytes={}",
                run,
                measurement.elapsed.as_millis(),
                measurement.output_bytes
            );
        }
        std::fs::remove_dir_all(&base.base).unwrap();
        assert!(!base.base.exists());
    }

    #[test]
    fn catchable_exits_leave_descriptor_process_and_rss_plateaus() {
        let _serial = serial_test();
        let baseline_fds = proc_fd_count(std::process::id());
        let mut broker_fds = Vec::new();
        let mut broker_status_rss = Vec::new();
        let mut broker_statm_rss = Vec::new();
        let mut harness_status_rss = Vec::new();
        let mut harness_statm_rss = Vec::new();

        for iteration in 0..5 {
            let session = RealSession::start(
                &format!("proc-plateau-{iteration}"),
                "stty raw -echo; printf READY; trap 'exit 0' TERM HUP INT QUIT; while :; do sleep 1; done",
            );
            let sample = session.sample();
            assert!(sample.fds <= 32, "unexpected broker fd count: {sample:?}");
            assert!(
                sample.status_rss_kib <= 64 * 1024,
                "unexpected broker RSS: {sample:?}"
            );
            assert!(
                sample.statm_rss_kib <= 64 * 1024,
                "unexpected broker statm: {sample:?}"
            );
            broker_fds.push(sample.fds);
            broker_status_rss.push(sample.status_rss_kib);
            broker_statm_rss.push(sample.statm_rss_kib);
            let status = session.terminate_catchably();
            assert!(
                status.success() || status.signal() == Some(libc::SIGTERM),
                "unexpected starter status after catchable exit: {status}"
            );
            assert_eq!(proc_fd_count(std::process::id()), baseline_fds);
            harness_status_rss.push(rss_status_kib(std::process::id()));
            harness_statm_rss.push(rss_statm_kib(std::process::id()));
        }

        assert!(
            range(&broker_fds) <= 4,
            "broker descriptors did not plateau"
        );
        assert!(
            range(&broker_status_rss) <= 4 * 1024,
            "broker VmRSS did not plateau: {broker_status_rss:?}"
        );
        assert!(
            range(&broker_statm_rss) <= 4 * 1024,
            "broker statm did not plateau: {broker_statm_rss:?}"
        );
        assert!(
            range(&harness_status_rss[1..]) <= 4 * 1024,
            "harness VmRSS grew after warmup: {harness_status_rss:?}"
        );
        assert!(
            range(&harness_statm_rss[1..]) <= 4 * 1024,
            "harness statm grew after warmup: {harness_statm_rss:?}"
        );
    }
}
