//! Client connection I/O state (plans/m2-plan.md §1, §5, §6; commit 5).
//!
//! Three bounded primitives and one per-connection aggregate:
//!
//! - [`FrameReader`]: the header-gated incremental framing decoder. It
//!   accepts ONLY the bytes still needed for the current frame — the
//!   six-byte header first, and body-sized storage only after
//!   [`frame::Frame::validate_header`] approved the declared length —
//!   so the maximum owned encoded-frame storage is `frame_max_body + 4`
//!   bytes (the u32 length field plus a body that already includes
//!   version and kind). Bytes of later pipelined frames stay behind the
//!   caller's read cursor until the current frame is dispatched. The
//!   incomplete-frame deadline is stamped when the FIRST byte of each
//!   individual frame is read and is never reset or extended by
//!   drip-fed bytes.
//! - [`OutQueue`]: a bounded queue of immutable encoded-frame chunks
//!   (`Arc<[u8]>`) with a per-entry write offset. Caps are hard ceilings
//!   checked with checked arithmetic BEFORE any enqueue; remaining
//!   logical bytes are charged to each consumer even when the
//!   underlying bytes are Arc-shared; a partial write retains its exact
//!   offset and `EAGAIN` retains every remaining byte. Clearing drops
//!   everything — there is no replay or retained history.
//! - [`InputQueue`]: the writer's bounded raw input queue with the same
//!   accounting discipline (its PTY drain wiring is commit 6).
//! - [`ClientConn`]: role + reader + queues + the close-after-flush
//!   (`draining`) state and its bounded reply deadline.
//!
//! Nothing here touches a real descriptor by itself: queues flush
//! through an injected writer function so partial-write behavior is
//! deterministically testable; the broker supplies the
//! `send(MSG_NOSIGNAL)` closure. No Debug output ever contains payload
//! bytes.

use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::sync::Arc;

use crate::frame::{self, Frame, FrameError};
use crate::limits::Limits;

/// The protocol role a connection has settled into. Fixed by the first
/// Hello (or by a control first frame) and never re-negotiated on a
/// live connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnRole {
    /// Connected and peer-UID-checked; the first frame has not arrived.
    AwaitingFirstFrame,
    /// The first frame was a control kind (Ping, DetachWriter, Kill)
    /// sent without Hello. Control connections are one-shot and never
    /// become observers.
    Control,
    /// A Hello-accepted writer carrying its granted protocol client id.
    Writer { client_id: u32 },
    /// A Hello-accepted observer carrying its granted client id.
    Observer { client_id: u32 },
}

// ---------------------------------------------------------------------------
// Header-gated incremental framing
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum Phase {
    /// Collecting the six header bytes.
    Header,
    /// Header validated; collecting through `total` bytes.
    Body { total: usize },
}

/// Per-frame incremental decoder with a hard owned-storage bound.
pub struct FrameReader {
    buf: Vec<u8>,
    phase: Phase,
    started_ms: Option<u64>,
    fatal: Option<FrameError>,
}

impl FrameReader {
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(frame::HEADER_LEN),
            phase: Phase::Header,
            started_ms: None,
            fatal: None,
        }
    }

    /// Consumes ONLY the bytes still needed for the current frame from
    /// the front of `bytes` and returns how many were taken; the rest
    /// stay with the caller. The first byte taken for a NEW frame
    /// stamps `started_ms`; later bytes never re-stamp it. Body-sized
    /// storage is reserved only after `validate_header` approved the
    /// declared length, so the owned buffer can never exceed
    /// `frame_max_body + 4` bytes.
    pub fn append(&mut self, bytes: &[u8], now_ms: u64, limits: &Limits) -> usize {
        if self.fatal.is_some() || bytes.is_empty() {
            return 0;
        }
        let mut taken = 0usize;
        if let Phase::Header = self.phase {
            let want = frame::HEADER_LEN - self.buf.len();
            let take = want.min(bytes.len());
            if self.buf.is_empty() && take > 0 {
                self.started_ms = Some(now_ms);
            }
            self.buf.extend_from_slice(&bytes[..take]);
            taken += take;
            if self.buf.len() < frame::HEADER_LEN {
                return taken;
            }
            match Frame::validate_header(&self.buf, limits) {
                Ok(total) => {
                    // Only now may body-sized storage be reserved.
                    self.buf.reserve_exact(total - self.buf.len());
                    self.phase = Phase::Body { total };
                }
                Err(e) => {
                    self.fatal = Some(e);
                    return taken;
                }
            }
        }
        if let Phase::Body { total } = self.phase {
            let want = total - self.buf.len();
            let take = want.min(bytes.len() - taken);
            if take > 0 {
                self.buf.extend_from_slice(&bytes[taken..taken + take]);
                taken += take;
            }
        }
        taken
    }

    /// Whether a complete frame awaits [`FrameReader::take_frame`].
    pub fn frame_ready(&self) -> bool {
        match self.phase {
            Phase::Header => false,
            Phase::Body { total } => self.buf.len() == total,
        }
    }

    /// Bytes still needed for the CURRENT frame (header or validated
    /// body). The broker bounds each `recv` by this so pipelined bytes
    /// of later frames remain in the kernel until the current frame is
    /// dispatched. Zero when a frame is ready to take.
    pub fn bytes_needed(&self) -> usize {
        match self.phase {
            Phase::Header => frame::HEADER_LEN - self.buf.len(),
            Phase::Body { total } => total - self.buf.len(),
        }
    }

    /// Whether the reader wants more bytes for the current frame.
    pub fn needs_input(&self) -> bool {
        self.fatal.is_none() && !self.frame_ready()
    }

    /// Takes the completed frame, resetting the reader for the next
    /// one. `Err` is a framing failure: the connection closes silently.
    /// `Ok(None)` means no complete frame is ready or a fatal error
    /// already latched (check [`FrameReader::has_fatal`] first).
    pub fn take_frame(&mut self, limits: &Limits) -> Result<Option<Frame>, FrameError> {
        if let Some(e) = self.fatal.take() {
            return Err(e);
        }
        if !self.frame_ready() {
            return Ok(None);
        }
        match Frame::decode(&self.buf, limits) {
            Ok((f, consumed)) => {
                debug_assert_eq!(consumed, self.buf.len());
                self.buf.clear();
                self.phase = Phase::Header;
                self.started_ms = None;
                Ok(Some(f))
            }
            Err(e) => Err(e),
        }
    }

    /// Whether a framing failure already latched (the next
    /// [`FrameReader::take_frame`] returns it; the connection then
    /// closes silently).
    pub fn has_fatal(&self) -> bool {
        self.fatal.is_some()
    }

    /// Bytes of the current frame owned right now (≤ `frame_max_body + 4`).
    pub fn owned_bytes(&self) -> usize {
        self.buf.len()
    }

    /// Whether a partial frame is in progress (an EOF now is a silent
    /// framing close, not a clean disconnect).
    pub fn has_partial_frame(&self) -> bool {
        !self.buf.is_empty()
    }

    /// When the current frame's first byte was read.
    pub fn started_ms(&self) -> Option<u64> {
        self.started_ms
    }

    /// Whether the current frame exceeded its incomplete-frame window.
    /// The window starts at the frame's FIRST byte and is never
    /// extended.
    pub fn deadline_expired(&self, now_ms: u64, deadline_ms: u64) -> bool {
        match self.started_ms {
            Some(start) => now_ms.saturating_sub(start) >= deadline_ms,
            None => false,
        }
    }
}

impl Default for FrameReader {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for FrameReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // No frame bytes are ever printed.
        f.debug_struct("FrameReader")
            .field("owned_bytes", &self.buf.len())
            .field("started_ms", &self.started_ms)
            .field("fatal", &self.fatal.is_some())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Bounded encoded-output queue with partial-write offsets
// ---------------------------------------------------------------------------

/// An immutable encoded frame shared by reference; identical live bytes
/// may fan out to several consumers (each charged separately).
pub type SharedChunk = Arc<[u8]>;

pub struct OutQueue {
    entries: VecDeque<(SharedChunk, usize)>,
    live_bytes: usize,
    cap_bytes: usize,
}

impl OutQueue {
    pub fn new(cap_bytes: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            live_bytes: 0,
            cap_bytes,
        }
    }

    /// Remaining logical queued bytes (each consumer is charged for its
    /// own reference, Arc sharing never hides bytes from the cap).
    pub fn live_bytes(&self) -> usize {
        self.live_bytes
    }

    pub fn cap_bytes(&self) -> usize {
        self.cap_bytes
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Lowers or raises the cap, returning false when live bytes would
    /// exceed the new ceiling — the wrong cap is never silently kept.
    /// Role transitions run after a queue drop, so a demotion to the
    /// smaller observer cap always succeeds in the ordered flow.
    pub fn set_cap(&mut self, cap_bytes: usize) -> bool {
        if self.live_bytes > cap_bytes {
            return false;
        }
        self.cap_bytes = cap_bytes;
        true
    }

    /// Hard-ceiling enqueue of a pre-encoded shared chunk: checked
    /// arithmetic, capacity verified BEFORE the entry exists, never a
    /// transient overshoot. An EMPTY chunk is a successful no-op that
    /// is never queued. `false` = refused, queue unchanged.
    pub fn push_shared(&mut self, chunk: SharedChunk) -> bool {
        if chunk.is_empty() {
            return true;
        }
        match self.live_bytes.checked_add(chunk.len()) {
            Some(live) if live <= self.cap_bytes => {
                self.live_bytes = live;
                self.entries.push_back((chunk, 0));
                true
            }
            _ => false,
        }
    }

    /// Encodes and enqueues one frame under the same hard ceiling.
    pub fn push_frame(&mut self, frame: &Frame) -> bool {
        let mut encoded = Vec::new();
        frame.encode_into(&mut encoded);
        self.push_shared(encoded.into())
    }

    /// Drains through the injected writer. Each call passes only the
    /// unsent remainder of the front chunk; a partial write records the
    /// exact offset and stops; a `WouldBlock` error retains every
    /// remaining byte. A writer claiming more than the supplied slice
    /// length is `InvalidData` — accounting never underflows. Returns
    /// whether the queue emptied.
    pub fn flush_with<F>(&mut self, mut write: F) -> io::Result<bool>
    where
        F: FnMut(&[u8]) -> io::Result<usize>,
    {
        while let Some((chunk, off)) = self.entries.front().cloned() {
            let n = write(&chunk[off..])?;
            if n > chunk.len() - off {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "output writer over-reported its write count",
                ));
            }
            if n == 0 {
                return Err(io::Error::from(io::ErrorKind::WriteZero));
            }
            self.live_bytes -= n;
            if off + n == chunk.len() {
                self.entries.pop_front();
            } else {
                let front = self.entries.front_mut().expect("front checked above");
                front.1 = off + n;
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Drops every queued byte. No replay, no retained history.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.live_bytes = 0;
    }
}

impl fmt::Debug for OutQueue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Byte counts only; queued bytes are never printed.
        f.debug_struct("OutQueue")
            .field("entries", &self.entries.len())
            .field("live_bytes", &self.live_bytes)
            .field("cap_bytes", &self.cap_bytes)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Bounded writer-input queue
// ---------------------------------------------------------------------------

pub struct InputQueue {
    chunks: VecDeque<Vec<u8>>,
    front_off: usize,
    live_bytes: usize,
    cap_bytes: usize,
}

impl InputQueue {
    pub fn new(cap_bytes: usize) -> Self {
        Self {
            chunks: VecDeque::new(),
            front_off: 0,
            live_bytes: 0,
            cap_bytes,
        }
    }

    pub fn live_bytes(&self) -> usize {
        self.live_bytes
    }

    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// Hard-ceiling enqueue (checked arithmetic, capacity before
    /// enqueue). `false` = refused, queue unchanged. The PTY-drain and
    /// socket-backpressure wiring over this primitive is commit 6.
    pub fn push(&mut self, bytes: Vec<u8>) -> bool {
        if bytes.is_empty() {
            return true;
        }
        match self.live_bytes.checked_add(bytes.len()) {
            Some(live) if live <= self.cap_bytes => {
                self.live_bytes = live;
                self.chunks.push_back(bytes);
                true
            }
            _ => false,
        }
    }

    /// Drains front-chunk-at-a-time through the injected writer with
    /// exact partial offsets; `WouldBlock` retains the remainder; a
    /// writer claiming more than the supplied slice length is
    /// `InvalidData`. Returns whether the queue emptied.
    pub fn drain_with<F>(&mut self, mut write: F) -> io::Result<bool>
    where
        F: FnMut(&[u8]) -> io::Result<usize>,
    {
        while let Some(front) = self.chunks.front() {
            let n = write(&front[self.front_off..])?;
            let full = front.len();
            if n > full - self.front_off {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "input writer over-reported its write count",
                ));
            }
            if n == 0 {
                return Err(io::Error::from(io::ErrorKind::WriteZero));
            }
            self.live_bytes -= n;
            let consumed = self.front_off + n;
            if consumed == full {
                self.chunks.pop_front();
                self.front_off = 0;
            } else {
                self.front_off = consumed;
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Drops every queued byte. No replay, no retained history.
    pub fn clear(&mut self) {
        self.chunks.clear();
        self.front_off = 0;
        self.live_bytes = 0;
    }
}

impl fmt::Debug for InputQueue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InputQueue")
            .field("chunks", &self.chunks.len())
            .field("front_off", &self.front_off)
            .field("live_bytes", &self.live_bytes)
            .field("cap_bytes", &self.cap_bytes)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Per-connection aggregate
// ---------------------------------------------------------------------------

pub struct ClientConn {
    role: ConnRole,
    reader: FrameReader,
    out: OutQueue,
    input: InputQueue,
    draining: bool,
    reply_deadline_at: Option<u64>,
}

impl ClientConn {
    pub fn new(limits: &Limits) -> Self {
        Self {
            role: ConnRole::AwaitingFirstFrame,
            reader: FrameReader::new(),
            out: OutQueue::new(limits.observer_queue_bytes),
            input: InputQueue::new(limits.writer_input_queue_bytes),
            draining: false,
            reply_deadline_at: None,
        }
    }

    pub fn role(&self) -> ConnRole {
        self.role
    }

    /// Role transitions happen only through reducer effects; a Writer
    /// gets the writer output cap, anything else gets the observer cap
    /// exactly (a downgrade runs after the queue was dropped, so it
    /// cannot refuse). A refused cap change reports Err WITHOUT
    /// changing the role — the caller closes the connection.
    pub fn set_role(&mut self, limits: &Limits, role: ConnRole) -> io::Result<()> {
        let cap = if matches!(role, ConnRole::Writer { .. }) {
            limits.writer_queue_bytes
        } else {
            limits.observer_queue_bytes
        };
        if !self.out.set_cap(cap) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "role cap change would exceed live queue bytes",
            ));
        }
        self.role = role;
        Ok(())
    }

    pub fn reader(&mut self) -> &mut FrameReader {
        &mut self.reader
    }

    /// When the current in-progress frame's first byte was read.
    pub fn reader_started_ms(&self) -> Option<u64> {
        self.reader.started_ms()
    }

    /// Whether the current frame exceeded its incomplete-frame window.
    pub fn reader_deadline_expired(&self, now_ms: u64, deadline_ms: u64) -> bool {
        self.reader.deadline_expired(now_ms, deadline_ms)
    }

    /// Bytes still needed for the reader's current frame — bounds every
    /// recv so pipelined frames stay in the kernel.
    pub fn reader_bytes_needed(&self) -> usize {
        self.reader.bytes_needed()
    }

    /// Live bytes retained in the writer-input queue.
    pub fn input_live_bytes(&self) -> usize {
        self.input.live_bytes()
    }

    pub fn out(&self) -> &OutQueue {
        &self.out
    }

    pub fn out_mut(&mut self) -> &mut OutQueue {
        &mut self.out
    }

    pub fn input_mut(&mut self) -> &mut InputQueue {
        &mut self.input
    }

    /// Close-after-flush: reads are ignored from here on (no re-Hello),
    /// the queue drains until empty or the reply deadline expires.
    pub fn begin_draining(&mut self) {
        self.draining = true;
    }

    pub fn is_draining(&self) -> bool {
        self.draining
    }

    /// Arms the bounded reply deadline at queue time; partial drain
    /// progress never re-arms it. An overflowing deadline expires
    /// IMMEDIATELY (never becomes an un-armed None).
    pub fn arm_reply_deadline(&mut self, now_ms: u64, deadline_ms: u64) {
        if self.reply_deadline_at.is_none() {
            self.reply_deadline_at = Some(now_ms.checked_add(deadline_ms).unwrap_or(now_ms));
        }
    }

    /// The armed reply deadline, if any (for poll-timeout computation).
    pub fn reply_deadline_at(&self) -> Option<u64> {
        self.reply_deadline_at
    }

    pub fn reply_deadline_expired(&self, now_ms: u64) -> bool {
        match self.reply_deadline_at {
            Some(at) => now_ms >= at,
            None => false,
        }
    }
}

impl fmt::Debug for ClientConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConn")
            .field("role", &self.role)
            .field("out", &self.out)
            .field("input", &self.input)
            .field("draining", &self.draining)
            .field("reply_deadline_at", &self.reply_deadline_at)
            .finish()
    }
}

/// Aggregate live queue bytes across consumers: the SATURATING sum of
/// each consumer's remaining logical bytes — Arc-shared chunks count
/// once PER CONSUMER, never once total; an astronomically large total
/// saturates at `usize::MAX` rather than overflowing.
pub fn aggregate_live_bytes<'a>(queues: impl IntoIterator<Item = &'a OutQueue>) -> usize {
    queues
        .into_iter()
        .fold(0usize, |acc, q| acc.saturating_add(q.live_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits::default()
    }

    /// A writer closure that accepts at most `max` bytes per call.
    struct PartialWriter {
        max: usize,
        written: Vec<u8>,
    }

    impl PartialWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let n = self.max.min(buf.len());
            self.written.extend_from_slice(&buf[..n]);
            Ok(n)
        }
    }

    #[test]
    fn frame_reader_validates_header_before_any_body_storage() {
        // Custom cap: a header declaring more than the cap must be
        // rejected with the owned buffer never growing past the header.
        let mut small = limits();
        small.frame_max_body = 64;
        // body = version+kind+payload; declare body 100 > 64.
        let mut bytes = 100u32.to_be_bytes().to_vec();
        bytes.push(frame::PROTOCOL_VERSION);
        bytes.push(frame::Kind::Input as u8);
        let mut r = FrameReader::new();
        let took = r.append(&bytes, 0, &small);
        assert_eq!(took, frame::HEADER_LEN);
        assert_eq!(r.owned_bytes(), frame::HEADER_LEN, "no body byte accepted");
        assert!(matches!(
            r.take_frame(&small),
            Err(FrameError::BodyTooLarge { declared: 100, .. })
        ));
    }

    #[test]
    fn frame_reader_rejects_unsupported_version_and_unknown_kind() {
        let mut r = FrameReader::new();
        let mut bytes = 8u32.to_be_bytes().to_vec();
        bytes.push(9); // unsupported version
        bytes.push(frame::Kind::Ping as u8);
        r.append(&bytes, 0, &limits());
        assert!(matches!(
            r.take_frame(&limits()),
            Err(FrameError::UnsupportedVersion { got: 9 })
        ));

        let mut r = FrameReader::new();
        let mut bytes = 8u32.to_be_bytes().to_vec();
        bytes.push(frame::PROTOCOL_VERSION);
        bytes.push(99); // unknown kind
        r.append(&bytes, 0, &limits());
        assert!(matches!(
            r.take_frame(&limits()),
            Err(FrameError::UnknownKind { got: 99 })
        ));
    }

    #[test]
    fn frame_reader_deadline_starts_at_first_byte_and_never_extends() {
        let mut r = FrameReader::new();
        let header = Frame::Ping.encode();
        // One byte at t=100 starts the window.
        r.append(&header[..1], 100, &limits());
        assert_eq!(r.started_ms(), Some(100));
        // Drip-fed bytes at t=4900 do NOT move the stamp.
        r.append(&header[1..4], 4_900, &limits());
        assert_eq!(r.started_ms(), Some(100));
        assert!(!r.deadline_expired(5_099, 5_000));
        assert!(r.deadline_expired(5_100, 5_000));
    }

    #[test]
    fn frame_reader_reset_stamps_the_next_frame_fresh() {
        let mut r = FrameReader::new();
        let mut wire = Frame::Ping.encode();
        wire.extend_from_slice(&Frame::Pong.encode());
        let mut taken = r.append(&wire, 10, &limits());
        assert_eq!(taken, Frame::Ping.encode().len(), "only frame one consumed");
        assert!(matches!(
            r.take_frame(&limits()).expect("take"),
            Some(Frame::Ping)
        ));
        assert_eq!(r.started_ms(), None, "cleared with the completed frame");
        assert!(r.needs_input());
        taken = r.append(&wire[taken..], 9_999, &limits());
        assert_eq!(taken, Frame::Pong.encode().len());
        assert_eq!(r.started_ms(), Some(9_999), "the new frame stamps fresh");
        assert!(matches!(
            r.take_frame(&limits()).expect("take"),
            Some(Frame::Pong)
        ));
    }

    #[test]
    fn frame_reader_owned_storage_never_exceeds_the_bound() {
        // Feed two full frames plus a partial third in one slice; the
        // reader owns at most one validated frame at a time.
        let mut small = limits();
        small.frame_max_body = 2 + 16;
        let mk = |b: u8| Frame::Input(vec![b; 16]);
        let mut wire = mk(1).encode();
        wire.extend_from_slice(&mk(2).encode());
        wire.extend_from_slice(&mk(3).encode()[..10]);
        let bound = 4 + small.frame_max_body;
        let mut r = FrameReader::new();
        let mut off = 0;
        let mut frames = 0;
        while off < wire.len() {
            let took = r.append(&wire[off..], 100, &small);
            assert!(r.owned_bytes() <= bound, "bound exceeded");
            if took == 0 {
                break;
            }
            off += took;
            while r.frame_ready() {
                assert!(r.take_frame(&small).expect("take").is_some());
                frames += 1;
            }
        }
        assert_eq!(frames, 2);
        assert!(r.has_partial_frame(), "third frame is partial");
        assert!(r.owned_bytes() <= bound);
    }

    #[test]
    fn frame_reader_partial_frame_at_eof_is_silent_framing_close() {
        let mut r = FrameReader::new();
        r.append(b"\x00\x00\x00\x08", 0, &limits());
        assert!(r.has_partial_frame());
        assert!(r.needs_input());
        assert!(!r.frame_ready());
    }

    #[test]
    fn out_queue_hard_cap_checked_before_enqueue() {
        let mut q = OutQueue::new(10);
        let a: SharedChunk = vec![0u8; 6].into();
        assert!(q.push_shared(a.clone()));
        let b: SharedChunk = vec![1u8; 6].into();
        // 6 + 6 > 10: refused without a transient overshoot.
        assert!(!q.push_shared(b));
        assert_eq!(q.live_bytes(), 6);
        assert_eq!(q.len(), 1);
        // Aggregate charges the SAME chunk per consumer.
        let mut other = OutQueue::new(10);
        assert!(other.push_shared(a));
        assert_eq!(aggregate_live_bytes([&q, &other]), 12);
    }

    #[test]
    fn out_queue_partial_writes_keep_exact_offsets() {
        let mut q = OutQueue::new(64);
        assert!(q.push_frame(&Frame::Pong));
        let total = q.live_bytes();
        let mut w = PartialWriter {
            max: 3,
            written: Vec::new(),
        };
        assert!(!q.flush_with(|b| w.write(b)).expect("flush partial"));
        assert_eq!(q.live_bytes(), total - 3);
        // EAGAIN retains every remaining byte.
        let err = q
            .flush_with(|_| Err(io::Error::from(io::ErrorKind::WouldBlock)))
            .expect_err("would block");
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(q.live_bytes(), total - 3);
        let mut rest = Vec::new();
        assert!(q
            .flush_with(|b| {
                rest.extend_from_slice(b);
                Ok(b.len())
            })
            .expect("flush rest"));
        assert!(q.is_empty());
        let expect = Frame::Pong.encode();
        let mut all = w.written;
        all.extend_from_slice(&rest);
        assert_eq!(all, expect, "byte-exact in order");
        q.clear();
        assert_eq!(q.live_bytes(), 0);
    }

    #[test]
    fn input_queue_cap_and_partial_drain() {
        let mut q = InputQueue::new(10);
        assert!(q.push(vec![7u8; 6]));
        assert!(!q.push(vec![8u8; 6]));
        assert_eq!(q.live_bytes(), 6);
        let mut w = PartialWriter {
            max: 4,
            written: Vec::new(),
        };
        assert!(!q.drain_with(|b| w.write(b)).expect("drain partial"));
        assert_eq!(q.live_bytes(), 2);
        let mut rest = Vec::new();
        assert!(q
            .drain_with(|b| {
                rest.extend_from_slice(b);
                Ok(b.len())
            })
            .expect("drain rest"));
        assert_eq!(
            [w.written.as_slice(), rest.as_slice()].concat(),
            vec![7u8; 6]
        );
        q.clear();
        assert!(q.is_empty());
    }

    #[test]
    fn client_conn_role_caps_and_draining() {
        let l = limits();
        let mut c = ClientConn::new(&l);
        assert_eq!(c.role(), ConnRole::AwaitingFirstFrame);
        assert_eq!(c.out().cap_bytes(), l.observer_queue_bytes);
        c.set_role(&l, ConnRole::Writer { client_id: 1 })
            .expect("writer role");
        assert_eq!(c.out().cap_bytes(), l.writer_queue_bytes);
        // A demotion sets the observer cap EXACTLY (queue is empty).
        c.set_role(&l, ConnRole::Observer { client_id: 1 })
            .expect("observer role");
        assert_eq!(c.out().cap_bytes(), l.observer_queue_bytes);
        // A cap below live bytes refuses without changing anything.
        let chunk: SharedChunk = vec![0u8; 32].into();
        assert!(c.out_mut().push_shared(chunk));
        assert_eq!(c.out().cap_bytes(), l.observer_queue_bytes);
        assert!(!c.out_mut().set_cap(8), "refuses below live");
        assert_eq!(c.out().cap_bytes(), l.observer_queue_bytes, "cap unchanged");
        assert!(!c.is_draining());
        assert!(!c.reply_deadline_expired(10_000));
        c.arm_reply_deadline(100, 5_000);
        assert!(!c.reply_deadline_expired(5_099));
        assert!(c.reply_deadline_expired(5_100));
        // Re-arming never extends an armed deadline.
        c.arm_reply_deadline(9_000, 5_000);
        assert!(c.reply_deadline_expired(5_100));
        c.begin_draining();
        assert!(c.is_draining());
    }

    #[test]
    fn reply_deadline_overflow_expires_immediately() {
        let l = limits();
        let mut c = ClientConn::new(&l);
        // checked_add overflow must become an IMMEDIATE expiry, never
        // an un-armed None.
        c.arm_reply_deadline(u64::MAX - 1, 5_000);
        assert_eq!(c.reply_deadline_at(), Some(u64::MAX - 1));
        assert!(c.reply_deadline_expired(u64::MAX - 1));
        assert!(c.reply_deadline_expired(u64::MAX));
    }

    #[test]
    fn bytes_needed_progresses_through_a_frame() {
        let l = limits();
        let mut r = FrameReader::new();
        assert_eq!(r.bytes_needed(), frame::HEADER_LEN);
        let wire = Frame::Input(vec![b'x'; 100]).encode();
        let taken = r.append(&wire[..3], 0, &l);
        assert_eq!(taken, 3);
        assert_eq!(r.bytes_needed(), frame::HEADER_LEN - 3);
        r.append(&wire[taken..], 1, &l);
        assert!(r.frame_ready());
        assert_eq!(r.bytes_needed(), 0, "complete frame needs nothing");
        assert!(matches!(
            r.take_frame(&l).expect("take"),
            Some(Frame::Input(_))
        ));
        assert_eq!(r.bytes_needed(), frame::HEADER_LEN, "reset for next frame");
    }

    #[test]
    fn queue_writers_over_reporting_is_invalid_data() {
        let mut q = OutQueue::new(64);
        assert!(q.push_frame(&Frame::Pong));
        let err = q.flush_with(|b| Ok(b.len() + 1)).expect_err("over-report");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        // Accounting unchanged — no underflow, data retained.
        assert_eq!(q.live_bytes(), Frame::Pong.encode().len());
        assert!(!q.is_empty());

        let mut iq = InputQueue::new(64);
        assert!(iq.push(vec![1u8; 8]));
        let err = iq.drain_with(|b| Ok(b.len() + 1)).expect_err("over-report");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(iq.live_bytes(), 8);
    }

    #[test]
    fn empty_shared_chunk_is_a_no_op() {
        let mut q = OutQueue::new(8);
        let empty: SharedChunk = Vec::new().into();
        assert!(q.push_shared(empty));
        assert!(q.is_empty(), "nothing queued");
        assert_eq!(q.live_bytes(), 0);
        assert!(
            q.flush_with(|b| Ok(b.len())).expect("flush"),
            "flushes trivially"
        );
    }
}
