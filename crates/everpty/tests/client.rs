//! Process-free, signal-free integration coverage of the commit-5
//! connection layer over fixture-local Unix sockets
//! (plans/m2-plan.md §5; commit 5, correction pass).
//!
//! Every test builds one broker FROM a `BoundSession` — the listener
//! and the per-session flock are fused inside the broker, so the
//! fixture never separately retains the lock — and drives it with a
//! mock clock: no fork, no Command, no signals, no sleeps, no threads,
//! no closed-pipe writes, no environment mutation. Client sockets are
//! fixture-local blocking `UnixStream`s with FINITE read and write
//! timeouts so a logic failure errors instead of hanging; the broker
//! side is entirely nonblocking.
#![allow(clippy::unwrap_used)]

use std::cell::Cell;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use everpty::broker::{Broker, Clock, Iteration};
use everpty::frame::{self, AttachStatus, Frame, OwnershipEvent, Role};
use everpty::limits::Limits;
use everpty::session::resolve_state_root_from;

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct MockClock(Rc<Cell<u64>>);

impl Clock for MockClock {
    fn now_ms(&self) -> std::io::Result<u64> {
        Ok(self.0.get())
    }
}

/// Exclusive 0700 fixture base (bounded retry; owns and removes only
/// the directory it itself created).
struct Fixture {
    base: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

static FIXTURE: AtomicUsize = AtomicUsize::new(0);

fn setup(name: &str) -> (Fixture, Rc<Cell<u64>>, Broker) {
    use std::os::unix::fs::DirBuilderExt;
    // Bounded-retry EXCLUSIVE 0700 base: the RAII Fixture below owns
    // and removes only the directory created here.
    let n = FIXTURE.fetch_add(1, Ordering::Relaxed);
    let mut base = None;
    for i in 0..64u32 {
        let p = std::env::temp_dir().join(format!("everpty-broker-{}-{n}-{i}", std::process::id()));
        let mut private = std::fs::DirBuilder::new();
        private.mode(0o700);
        if private.create(&p).is_ok() {
            base = Some(p);
            break;
        }
    }
    let base = base.expect("exclusive fixture base");
    let limits = Limits::default();
    let root = resolve_state_root_from(std::slice::from_ref(&base)).expect("state root");
    let dir = root.session(name, &limits).expect("session dir");
    let locked = dir.lock().expect("session lock");
    // The BoundSession CONSUMES the lock: the broker alone keeps the
    // flock and the listener alive, exactly like production.
    let bound = locked.bind_broker_socket(&limits).expect("listener");
    let clock = Rc::new(Cell::new(0u64));
    let broker =
        Broker::new(bound, &limits, Rc::new(MockClock(clock.clone())), None).expect("broker");
    (Fixture { base }, clock, broker)
}

impl Fixture {
    /// A blocking client socket with finite read AND write timeouts.
    fn connect(&self, name: &str) -> UnixStream {
        let path = self.base.join(name).join("socket");
        let s = UnixStream::connect(path).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        s.set_write_timeout(Some(Duration::from_secs(5)))
            .expect("write timeout");
        s
    }
}

// ---------------------------------------------------------------------------
// Frame I/O helpers
// ---------------------------------------------------------------------------

fn send(stream: &mut UnixStream, frame: &Frame) {
    stream.write_all(&frame.encode()).expect("send frame");
}

fn recv_frame(stream: &mut UnixStream) -> Frame {
    let limits = Limits::default();
    let mut header = [0u8; frame::HEADER_LEN];
    stream.read_exact(&mut header).expect("read header");
    let total = frame::Frame::validate_header(&header, &limits).expect("valid header");
    let mut buf = header.to_vec();
    buf.resize(total, 0);
    stream
        .read_exact(&mut buf[frame::HEADER_LEN..])
        .expect("read body");
    let (decoded, used) = frame::Frame::decode(&buf, &limits).expect("decode");
    assert_eq!(used, total);
    decoded
}

fn is_eof(stream: &mut UnixStream) -> bool {
    stream.set_nonblocking(false).expect("blocking");
    let mut byte = [0u8; 1];
    matches!(stream.read(&mut byte), Ok(0))
}

/// The connection is gone from the client's side: a clean EOF, or the
/// RST (ECONNRESET) Linux delivers when the peer closed while this
/// side still had unread outbound bytes buffered.
fn is_closed(stream: &mut UnixStream) -> bool {
    stream.set_nonblocking(false).expect("blocking");
    let mut byte = [0u8; 1];
    match stream.read(&mut byte) {
        Ok(0) => true,
        Err(e) => e.raw_os_error() == Some(libc::ECONNRESET),
        _ => false,
    }
}

fn would_block_not_eof(stream: &mut UnixStream) -> bool {
    stream.set_nonblocking(true).expect("nonblocking");
    let mut byte = [0u8; 1];
    matches!(
        stream.read(&mut byte),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
    )
}

fn hello(role: Role, take_over: bool, rows: u16, cols: u16) -> Frame {
    Frame::Hello {
        role,
        take_over,
        name: "s1".to_owned(),
        rows,
        cols,
    }
}

/// Two zero-timeout iterations: one to accept, one to read/dispatch.
fn pump(broker: &mut Broker) -> Vec<Iteration> {
    let a = broker.run_once(Some(0)).expect("iterate");
    let b = broker.run_once(Some(0)).expect("iterate");
    vec![a, b]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn writer_hello_gets_helloack_and_really_transitions() {
    let (fx, _clock, mut broker) = setup("s1");
    let mut w = fx.connect("s1");
    send(&mut w, &hello(Role::Writer, false, 24, 80));
    pump(&mut broker);
    assert_eq!(broker.connection_count(), 1);
    // The runtime state genuinely changed, not just the effects.
    assert_eq!(broker.lifecycle(), everpty::lifecycle::Lifecycle::Running);
    assert_eq!(broker.ownership(), everpty::lifecycle::Ownership::Writer(1));
    match recv_frame(&mut w) {
        Frame::HelloAck {
            client_id,
            broker_protocol_version,
            status,
        } => {
            assert_eq!(client_id, 1, "client ids start at 1");
            assert_eq!(broker_protocol_version, frame::PROTOCOL_VERSION);
            assert_eq!(status, AttachStatus::WriterGranted);
        }
        other => panic!("expected HelloAck, got {other:?}"),
    }
    assert!(
        broker
            .deferred()
            .iter()
            .any(|e| matches!(e, everpty::state::Effect::SpawnChild { rows: 24, cols: 80 })),
        "spawn is a recorded deferred effect: {:?}",
        broker.deferred()
    );
    assert!(would_block_not_eof(&mut w), "writer stays attached");
}

#[test]
fn ping_gets_pong_then_bounded_close() {
    let (fx, _clock, mut broker) = setup("s1");
    let mut c = fx.connect("s1");
    send(&mut c, &Frame::Ping);
    pump(&mut broker);
    assert!(matches!(recv_frame(&mut c), Frame::Pong));
    assert!(is_eof(&mut c), "control connection closes after the reply");
    assert_eq!(broker.connection_count(), 0);
}

#[test]
fn draining_connection_excludes_reads() {
    let (fx, _clock, mut broker) = setup("s1");
    let mut c = fx.connect("s1");
    // Ping plus a pipelined second frame in ONE write: recv is
    // frame-boundary-limited, so the second frame stays in the kernel
    // and is never dispatched once draining starts.
    let mut wire = Frame::Ping.encode();
    wire.extend_from_slice(&Frame::Ping.encode());
    c.write_all(&wire).expect("pipelined send");
    pump(&mut broker);
    assert!(
        matches!(recv_frame(&mut c), Frame::Pong),
        "exactly one reply, no second dispatch"
    );
    // The broker closed after the reply drained. Because the peer's
    // pipelined bytes were never read (that is the point), Linux
    // closes with RST — the close manifests as ECONNRESET, not a
    // clean EOF. Either way the connection is gone and nothing more
    // was dispatched.
    assert!(is_closed(&mut c), "closed after the Pong drained");
    assert_eq!(broker.connection_count(), 0);
}

#[test]
fn accept_budget_is_eight_per_iteration() {
    let (fx, _clock, mut broker) = setup("s1");
    let mut clients = Vec::new();
    for _ in 0..12 {
        clients.push(fx.connect("s1"));
    }
    let it = broker.run_once(Some(0)).expect("iterate");
    assert_eq!(it.accepted, 8, "at most accepts_per_iteration per pass");
    assert_eq!(it.connections, 8);
    let it = broker.run_once(Some(0)).expect("iterate");
    assert_eq!(it.connections, 12, "backlog drains on later passes");
    drop(clients);
}

#[test]
fn connection_seventeen_is_peer_checked_and_refused() {
    let (fx, _clock, mut broker) = setup("s1");
    let mut holders = Vec::new();
    for _ in 0..16 {
        holders.push(fx.connect("s1"));
    }
    pump(&mut broker);
    assert_eq!(broker.connection_count(), 16, "cap is exactly 16");
    let mut refused = fx.connect("s1");
    pump(&mut broker);
    assert_eq!(broker.connection_count(), 16, "no slot for #17");
    match recv_frame(&mut refused) {
        Frame::Error { code, .. } => assert_eq!(code, 4, "ResourceLimit"),
        other => panic!("expected Error(ResourceLimit), got {other:?}"),
    }
    assert!(is_eof(&mut refused), "refused connection is closed");
    drop(holders);
}

#[test]
fn takeover_fixes_runtime_ownership_and_both_roles() {
    let (fx, _clock, mut broker) = setup("s1");
    let mut w1 = fx.connect("s1");
    send(&mut w1, &hello(Role::Writer, false, 24, 80));
    pump(&mut broker);
    assert!(matches!(recv_frame(&mut w1), Frame::HelloAck { .. }));
    let mut w2 = fx.connect("s1");
    send(&mut w2, &hello(Role::Writer, true, 30, 100));
    pump(&mut broker);
    // The old writer receives Revoked first...
    assert!(matches!(
        recv_frame(&mut w1),
        Frame::Ownership(OwnershipEvent::Revoked)
    ));
    // ...and stays attached output-only as a real observer.
    assert!(
        would_block_not_eof(&mut w1),
        "old writer became an observer"
    );
    assert_eq!(broker.connection_count(), 2);
    assert_eq!(broker.observer_count(), 1);
    // Runtime ownership AND both connection roles are fixed.
    assert_eq!(broker.ownership(), everpty::lifecycle::Ownership::Writer(2));
    assert_eq!(
        broker.role_of_client(1),
        Some(everpty::client::ConnRole::Observer { client_id: 1 })
    );
    assert_eq!(
        broker.role_of_client(2),
        Some(everpty::client::ConnRole::Writer { client_id: 2 })
    );
    // The new writer is granted after the revocation.
    assert!(matches!(recv_frame(&mut w2), Frame::HelloAck { .. }));
    assert!(matches!(
        recv_frame(&mut w2),
        Frame::Ownership(OwnershipEvent::Granted)
    ));
    assert!(
        broker.deferred().iter().any(|e| matches!(
            e,
            everpty::state::Effect::ApplyDimensions {
                rows: 30,
                cols: 100
            }
        )),
        "takeover dimensions are a deferred effect"
    );
}

#[test]
fn second_writer_without_takeover_is_busy_then_closed() {
    let (fx, _clock, mut broker) = setup("s1");
    let mut w1 = fx.connect("s1");
    send(&mut w1, &hello(Role::Writer, false, 24, 80));
    pump(&mut broker);
    assert!(matches!(recv_frame(&mut w1), Frame::HelloAck { .. }));
    let mut w2 = fx.connect("s1");
    send(&mut w2, &hello(Role::Writer, false, 24, 80));
    pump(&mut broker);
    match recv_frame(&mut w2) {
        Frame::Busy { current_writer_id } => assert_eq!(current_writer_id, 1),
        other => panic!("expected Busy, got {other:?}"),
    }
    assert!(
        is_eof(&mut w2),
        "rejected writer closes after its Busy frame"
    );
    assert_eq!(broker.connection_count(), 1, "the writer is untouched");
    assert_eq!(broker.ownership(), everpty::lifecycle::Ownership::Writer(1));
    assert!(
        would_block_not_eof(&mut w1),
        "original writer still attached"
    );
}

#[test]
fn writer_protocol_close_permits_a_later_writer() {
    let (fx, _clock, mut broker) = setup("s1");
    let mut w1 = fx.connect("s1");
    send(&mut w1, &hello(Role::Writer, false, 24, 80));
    pump(&mut broker);
    assert!(matches!(recv_frame(&mut w1), Frame::HelloAck { .. }));
    // A post-Hello control frame is a protocol error: bounded Error,
    // close, and a REAL ownership revoke on disconnect.
    send(&mut w1, &Frame::Ping);
    pump(&mut broker);
    match recv_frame(&mut w1) {
        Frame::Error { code, .. } => assert_eq!(code, 1, "Protocol"),
        other => panic!("expected Error(Protocol), got {other:?}"),
    }
    assert!(is_eof(&mut w1));
    assert_eq!(broker.ownership(), everpty::lifecycle::Ownership::NoWriter);
    assert_eq!(broker.lifecycle(), everpty::lifecycle::Lifecycle::Running);
    // A later writer can now be granted.
    let mut w2 = fx.connect("s1");
    send(&mut w2, &hello(Role::Writer, false, 24, 80));
    pump(&mut broker);
    assert!(matches!(recv_frame(&mut w2), Frame::HelloAck { .. }));
    assert_eq!(broker.ownership(), everpty::lifecycle::Ownership::Writer(2));
}

#[test]
fn observer_protocol_close_frees_observer_capacity() {
    let (fx, _clock, mut broker) = setup("s1");
    let mut observers = Vec::new();
    for _ in 0..8 {
        observers.push(fx.connect("s1"));
    }
    for o in &mut observers {
        send(o, &hello(Role::Observer, false, 0, 0));
    }
    pump(&mut broker);
    assert_eq!(broker.observer_count(), 8, "observer cap filled");
    // Drain each observer's HelloAck so later reads see only what the
    // test is actually asserting on.
    for o in &mut observers {
        assert!(matches!(recv_frame(o), Frame::HelloAck { .. }));
    }
    // One observer misbehaves: protocol error closes it and its slot
    // leaves the set.
    send(&mut observers[0], &Frame::Ping);
    pump(&mut broker);
    match recv_frame(&mut observers[0]) {
        Frame::Error { code, .. } => assert_eq!(code, 1, "Protocol"),
        other => panic!("expected Error(Protocol), got {other:?}"),
    }
    assert!(is_eof(&mut observers[0]));
    assert_eq!(broker.observer_count(), 7, "capacity was freed");
    // A ninth observer now fits.
    let mut ninth = fx.connect("s1");
    send(&mut ninth, &hello(Role::Observer, false, 0, 0));
    pump(&mut broker);
    match recv_frame(&mut ninth) {
        Frame::HelloAck { status, .. } => assert_eq!(status, AttachStatus::ObserverAccepted),
        other => panic!("expected HelloAck, got {other:?}"),
    }
    assert_eq!(broker.observer_count(), 8);
}

#[test]
fn incomplete_frame_deadline_closes_via_mock_clock() {
    let (fx, clock, mut broker) = setup("s1");
    let mut c = fx.connect("s1");
    // Three header bytes start an incomplete frame at mock time 0.
    c.write_all(&[0, 0, 0]).expect("partial header");
    pump(&mut broker);
    assert_eq!(broker.connection_count(), 1, "parked mid-frame");
    clock.set(5_001);
    broker.run_once(Some(0)).expect("iterate");
    assert_eq!(
        broker.connection_count(),
        0,
        "expired frame closes the conn"
    );
    assert!(is_eof(&mut c));
}

#[test]
fn pre_spawn_kill_reports_no_writer_and_mutates_nothing() {
    let (fx, _clock, mut broker) = setup("s1");
    let mut c = fx.connect("s1");
    send(&mut c, &Frame::Kill);
    pump(&mut broker);
    match recv_frame(&mut c) {
        Frame::Error { code, .. } => assert_eq!(code, 3, "NoWriter"),
        other => panic!("expected Error(NoWriter), got {other:?}"),
    }
    assert!(is_eof(&mut c));
    assert_eq!(
        broker.lifecycle(),
        everpty::lifecycle::Lifecycle::WaitingForWriter
    );
    assert!(
        !broker
            .deferred()
            .iter()
            .any(|e| matches!(e, everpty::state::Effect::BeginKill)),
        "pre-spawn Kill never begins a kill"
    );
    assert!(
        !broker
            .deferred()
            .iter()
            .any(|e| matches!(e, everpty::state::Effect::Shutdown)),
        "pre-spawn Kill never terminates the broker"
    );
}

#[test]
fn observer_attaches_then_cannot_send_anything() {
    let (fx, _clock, mut broker) = setup("s1");
    let mut o = fx.connect("s1");
    send(&mut o, &hello(Role::Observer, false, 0, 0));
    pump(&mut broker);
    match recv_frame(&mut o) {
        Frame::HelloAck { status, .. } => assert_eq!(status, AttachStatus::ObserverAccepted),
        other => panic!("expected HelloAck, got {other:?}"),
    }
    send(&mut o, &Frame::Ping);
    pump(&mut broker);
    match recv_frame(&mut o) {
        Frame::Error { code, .. } => assert_eq!(code, 1, "Protocol"),
        other => panic!("expected Error(Protocol), got {other:?}"),
    }
    assert!(is_eof(&mut o));
}

#[test]
fn input_saturation_retains_bytes_and_backpressures_without_eviction() {
    let (fx, _clock, mut broker) = setup("s1");
    let mut w = fx.connect("s1");
    send(&mut w, &hello(Role::Writer, false, 24, 80));
    pump(&mut broker);
    assert!(matches!(recv_frame(&mut w), Frame::HelloAck { .. }));

    // One maximum-legal Input frame (payload = frame_max_body - 2).
    let limits = Limits::default();
    let max_payload = limits.frame_max_body - 2;
    send(&mut w, &Frame::Input(vec![0xAB; max_payload]));
    pump(&mut broker);
    pump(&mut broker);
    assert_eq!(
        broker.writer_input_live_bytes(),
        Some(max_payload),
        "every accepted Input byte is retained"
    );
    assert_eq!(broker.connection_count(), 1, "the writer is NOT evicted");
    assert_eq!(broker.ownership(), everpty::lifecycle::Ownership::Writer(1));
    assert_eq!(broker.lifecycle(), everpty::lifecycle::Lifecycle::Running);

    // With the queue full, admission stops socket reads: another Input
    // frame is NOT read, nothing is dropped, and the healthy writer
    // stays connected (socket backpressure, not eviction).
    send(&mut w, &Frame::Input(vec![0xCD; 1024]));
    pump(&mut broker);
    pump(&mut broker);
    assert_eq!(
        broker.writer_input_live_bytes(),
        Some(max_payload),
        "the over-cap frame was never admitted, never dropped-silently"
    );
    assert_eq!(broker.connection_count(), 1);
    assert_eq!(broker.ownership(), everpty::lifecycle::Ownership::Writer(1));
    assert!(would_block_not_eof(&mut w), "writer still connected");
}

#[test]
fn backpressured_writer_hup_stays_observable_and_revokes() {
    let (fx, _clock, mut broker) = setup("s1");
    let mut w = fx.connect("s1");
    send(&mut w, &hello(Role::Writer, false, 24, 80));
    pump(&mut broker);
    assert!(matches!(recv_frame(&mut w), Frame::HelloAck { .. }));
    // Saturate the writer's input queue: reads are withheld.
    let limits = Limits::default();
    let max_payload = limits.frame_max_body - 2;
    send(&mut w, &Frame::Input(vec![0xAB; max_payload]));
    pump(&mut broker);
    pump(&mut broker);
    assert_eq!(broker.writer_input_live_bytes(), Some(max_payload));

    // The peer vanishes while fully backpressured: the fd is still
    // polled (empty event set) so HUP is observed, the connection is
    // removed, ownership is revoked, and a later writer can attach.
    drop(w);
    pump(&mut broker);
    pump(&mut broker);
    assert_eq!(
        broker.connection_count(),
        0,
        "HUP observed despite backpressure"
    );
    assert_eq!(broker.ownership(), everpty::lifecycle::Ownership::NoWriter);

    let mut w2 = fx.connect("s1");
    send(&mut w2, &hello(Role::Writer, false, 24, 80));
    pump(&mut broker);
    assert!(matches!(recv_frame(&mut w2), Frame::HelloAck { .. }));
    assert_eq!(broker.ownership(), everpty::lifecycle::Ownership::Writer(2));
}
