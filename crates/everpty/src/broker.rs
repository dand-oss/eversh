//! Single-threaded poll-loop broker skeleton (plans/m2-plan.md §3, §4
//! read side, §5; commit 5, correction pass).
//!
//! One thread, one `poll(2)` per iteration over the listener and every
//! client socket (the PTY master slot arrives with commit 6). All
//! descriptors are `O_NONBLOCK`; all socket writes go through
//! `send(MSG_NOSIGNAL)`. Time comes from an injected [`Clock`] so every
//! deadline is deterministically testable — no sleeps anywhere, and a
//! clock failure propagates instead of being masked.
//!
//! Every frame decision goes through the pure reducer
//! ([`crate::state::reduce`]); this module only executes effects. The
//! deferred effects (`SpawnChild`, `BeginKill`, `ApplyDimensions`,
//! `Shutdown`) are recorded and NEVER executed here — commit 7 owns
//! signal wiring, spawn, and shutdown. In particular `Kill` never
//! terminates anything in commit 5.
//!
//! **No-loss writer input (commit-5 admission gate).** A Writer's
//! socket is read only while its input queue has headroom for the
//! maximum legal Input payload, and each `recv` is bounded by the
//! reader's `bytes_needed` — so pipelined frames stay in the kernel,
//! and a frame that started is guaranteed queue space. A full queue
//! stops socket reads (backpressure) without dropping a byte or
//! evicting the writer; the PTY drain and low-water re-enable are
//! commit 6.
//!
//! **Centralized close.** Every disconnect — framing fault, EOF,
//! `POLLNVAL`/`POLLHUP`/`POLLERR`, deadline expiry, queue refusal,
//! I/O failure, `CloseNow`, completed `CloseAfterFlush` — goes through
//! [`Broker::remove_conn`], which closes the descriptor exactly once
//! and reduces `Disconnected` exactly once with the former role, so
//! writer closure revokes ownership and observer closure leaves the
//! observer set on every path.
//!
//! **Capability.** The broker is constructed FROM a
//! [`BoundSession`]: the listener and the per-session `flock` are
//! fused, so no broker (or listener) can outlive the lock that
//! authorizes it, and the session name is derived from the bound
//! session — never accepted as an independent parameter.
//!
//! **Readiness/SIGPIPE boundary**: the normative CLOEXEC readiness pipe
//! is implemented as a fixed-size record codec, ownership halves, and
//! the blocking READ side. The WRITE side is deliberately NOT wired:
//! the broker does not yet ignore SIGPIPE (that arrives with the
//! commit-7 signal setup), and a pipe write to a dead starter would
//! kill the broker. [`Broker::readiness_record`] hands the encoded
//! record to the commit-7 loop as an explicit later effect; no
//! socketpair is substituted and no closed pipe is ever written.

use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::rc::Rc;

use crate::client::{ClientConn, ConnRole};
use crate::error::Error;
use crate::frame::{Frame, Kind};
use crate::lifecycle::{Lifecycle, Ownership};
use crate::limits::Limits;
use crate::session::BoundSession;
use crate::state::{self, ConnId, Effect, Event, Runtime, Target};
use crate::sys::{self, PollFd, PollFlags};

/// Monotonic time source. Production uses [`MonotonicClock`]; tests
/// inject a mock — deadline behavior must never depend on real sleeps,
/// and a clock read failure propagates as an error, never a zero
/// timestamp.
pub trait Clock {
    fn now_ms(&self) -> io::Result<u64>;
}

/// `CLOCK_MONOTONIC` milliseconds through [`sys::clock_monotonic_ms`].
#[derive(Debug, Clone, Copy, Default)]
pub struct MonotonicClock;

impl Clock for MonotonicClock {
    fn now_ms(&self) -> io::Result<u64> {
        sys::clock_monotonic_ms()
    }
}

// ---------------------------------------------------------------------------
// Readiness record (normative CLOEXEC pipe; READ side only in commit 5)
// ---------------------------------------------------------------------------

/// Fixed size of the readiness record.
pub const READY_RECORD_LEN: usize = 8;
const READY_MAGIC: u8 = 0xE7;

/// What the child broker reports through the readiness pipe: socket
/// bound (ready) or a pre-readiness failure carrying the raw errno.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadyStatus {
    Ready,
    Failed { errno: i32 },
}

impl ReadyStatus {
    /// `[magic][status][reserved=0;2][errno BE i32]`.
    pub fn encode(self) -> [u8; READY_RECORD_LEN] {
        let (status, errno) = match self {
            Self::Ready => (0u8, 0i32),
            Self::Failed { errno } => (1u8, errno),
        };
        let e = errno.to_be_bytes();
        [READY_MAGIC, status, 0, 0, e[0], e[1], e[2], e[3]]
    }

    /// Total decode: exact length, magic, reserved bytes, and a
    /// well-formed status byte, or an error — never a guess.
    pub fn decode(rec: &[u8]) -> io::Result<Self> {
        if rec.len() != READY_RECORD_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "readiness record has the wrong length",
            ));
        }
        if rec[0] != READY_MAGIC || rec[2] != 0 || rec[3] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "readiness record is malformed",
            ));
        }
        let errno = i32::from_be_bytes([rec[4], rec[5], rec[6], rec[7]]);
        match rec[1] {
            0 if errno == 0 => Ok(Self::Ready),
            1 => Ok(Self::Failed { errno }),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "readiness record has an unknown status",
            )),
        }
    }
}

/// Ownership halves of the CLOEXEC readiness pipe. The starter keeps
/// `read`; the broker keeps `write` UNWRITTEN until commit 7's loop
/// performs the explicit write effect (see the module boundary note).
pub struct ReadinessChannel {
    pub read: OwnedFd,
    pub write: OwnedFd,
}

impl ReadinessChannel {
    /// `pipe2(O_CLOEXEC)` (nix): both ends close on any exec.
    pub fn new() -> io::Result<Self> {
        let (read, write) = sys::pipe_cloexec()?;
        Ok(Self { read, write })
    }
}

/// Blocking starter-side read of one complete readiness record. EOF
/// before eight bytes is an error — a truncated record is never
/// half-accepted.
pub fn read_ready_record(fd: std::os::fd::BorrowedFd<'_>) -> io::Result<ReadyStatus> {
    let mut rec = [0u8; READY_RECORD_LEN];
    sys::read_exact_blocking(fd, &mut rec)?;
    ReadyStatus::decode(&rec)
}

/// The pure peer-admission policy: a connection is frame-dispatchable
/// only from the broker's own effective UID. (Cross-UID coverage is
/// this pure matrix plus real same-UID credentials — an unprivileged
/// cross-UID integration test is never claimed.)
pub fn peer_uid_allowed(peer_uid: libc::uid_t, broker_euid: libc::uid_t) -> bool {
    peer_uid == broker_euid
}

/// The pure connection-id allocator: strictly monotonic, checked, and
/// NEVER reused — at exhaustion it refuses (the accept is answered with
/// ResourceLimit and gets no slot or dispatch) instead of wrapping or
/// aliasing an existing connection.
pub fn alloc_conn_id(next: &mut ConnId) -> Option<ConnId> {
    if *next == ConnId::MAX {
        return None;
    }
    let id = *next;
    *next += 1;
    Some(id)
}

/// How a per-connection socket fault is handled: peer-local failures
/// (connection reset/aborted/not connected, broken pipe) close exactly
/// THAT connection; everything else — resource exhaustion, I/O errors,
/// anything environmental — is systemic and propagates out of the loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnFault {
    /// Close this one connection through `remove_conn`.
    ConnectionLocal,
    /// Propagate: the loop itself may be unhealthy.
    Systemic,
}

/// The pure fault classifier over a recv/send errno.
pub fn classify_conn_fault(err: &io::Error) -> ConnFault {
    match err.raw_os_error() {
        Some(libc::ECONNRESET) | Some(libc::ECONNABORTED) | Some(libc::ENOTCONN)
        | Some(libc::EPIPE) => ConnFault::ConnectionLocal,
        _ => ConnFault::Systemic,
    }
}

// ---------------------------------------------------------------------------
// Connection table and broker
// ---------------------------------------------------------------------------

struct ConnSlot {
    conn: ConnId,
    fd: OwnedFd,
    client: ClientConn,
}

/// What one `run_once` pass did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Iteration {
    pub accepted: usize,
    pub closed: usize,
    pub connections: usize,
}

/// The broker skeleton, constructed from a [`BoundSession`] (listener +
/// session lock fused) exactly when the socket is bound: the runtime
/// enters `WaitingForWriter` and the startup deadline is armed ONCE
/// from the injected clock at construction.
pub struct Broker {
    limits: Limits,
    clock: Rc<dyn Clock>,
    bound: BoundSession,
    runtime: Runtime,
    slots: Vec<Option<ConnSlot>>,
    next_conn_id: ConnId,
    deferred: Vec<Effect>,
    ready_at_ms: u64,
    read_buf: Vec<u8>,
    accepted_total: usize,
    closed_total: usize,
    /// Held for ownership, never written in commit 5 (see the module
    /// boundary note); the commit-7 loop writes it.
    _readiness_write: Option<OwnedFd>,
}

impl Broker {
    pub fn new(
        bound: BoundSession,
        limits: &Limits,
        clock: Rc<dyn Clock>,
        readiness_write: Option<OwnedFd>,
    ) -> Result<Self, Error> {
        sys::set_nonblocking(bound.listener())?;
        let runtime =
            Runtime::new_ready(bound.session_name(), limits).map_err(|e| {
                Error::Io(io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
            })?;
        // The startup deadline is armed exactly once, from the injected
        // clock, at construction.
        let ready_at_ms = clock.now_ms().map_err(Error::Io)?;
        Ok(Self {
            limits: limits.clone(),
            clock,
            bound,
            runtime,
            slots: Vec::new(),
            next_conn_id: 1,
            deferred: Vec::new(),
            ready_at_ms,
            read_buf: vec![0u8; limits.read_chunk_bytes.max(1)],
            accepted_total: 0,
            closed_total: 0,
            _readiness_write: readiness_write,
        })
    }

    // -- read-only observability (tests and the future CLI) --

    pub fn connection_count(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    pub fn lifecycle(&self) -> Lifecycle {
        self.runtime.state.lifecycle
    }

    pub fn ownership(&self) -> Ownership {
        self.runtime.state.ownership
    }

    pub fn observer_count(&self) -> usize {
        self.runtime.observers.len()
    }

    /// The connection role currently carrying a protocol client id.
    pub fn role_of_client(&self, client_id: u32) -> Option<ConnRole> {
        self.slots
            .iter()
            .flatten()
            .find(|s| match s.client.role() {
                ConnRole::Writer { client_id: id } | ConnRole::Observer { client_id: id } => {
                    id == client_id
                }
                _ => false,
            })
            .map(|s| s.client.role())
    }

    /// Live bytes in the current writer's input queue (the no-loss
    /// admission proof surface).
    pub fn writer_input_live_bytes(&self) -> Option<usize> {
        let Ownership::Writer(id) = self.runtime.state.ownership else {
            return None;
        };
        self.slots
            .iter()
            .flatten()
            .find(|s| matches!(s.client.role(), ConnRole::Writer { client_id } if client_id == id))
            .map(|s| s.client.input_live_bytes())
    }

    /// Deferred effects recorded so far (SpawnChild/BeginKill/
    /// ApplyDimensions/Shutdown). Commit 7 wires their execution.
    pub fn deferred(&self) -> &[Effect] {
        &self.deferred
    }

    pub fn take_deferred(&mut self) -> Vec<Effect> {
        std::mem::take(&mut self.deferred)
    }

    /// The encoded readiness record for the commit-7 loop to WRITE as
    /// an explicit effect once SIGPIPE is handled. Commit 5 never
    /// writes to the pipe.
    pub fn readiness_record(&self) -> [u8; READY_RECORD_LEN] {
        ReadyStatus::Ready.encode()
    }

    // -- the poll loop --

    /// One poll iteration. `max_wait_ms` bounds the poll sleep as a
    /// DURATION — tests pass `Some(0)` so nothing ever really sleeps;
    /// production passes `None` to let the earliest deadline decide.
    pub fn run_once(&mut self, max_wait_ms: Option<u32>) -> io::Result<Iteration> {
        let accepted_before = self.accepted_total;
        let closed_before = self.closed_total;
        let now = self.clock.now_ms()?;
        self.check_deadlines(now)?;

        // Build the poll set while immutably borrowing the slots, then
        // harvest the events before any mutation.
        let mut pfds: Vec<PollFd<'_>> = Vec::with_capacity(1 + self.slots.len());
        let mut owners: Vec<Option<usize>> = Vec::with_capacity(1 + self.slots.len());
        pfds.push(PollFd::new(self.bound.listener(), PollFlags::POLLIN));
        owners.push(None);
        for (idx, slot) in self.slots.iter().enumerate() {
            let Some(slot) = slot else { continue };
            // EVERY live client fd is polled, even with no requested
            // events: HUP/ERR/NVAL are always reported by poll, so a
            // fully backpressured writer (reads withheld) stays
            // observable. A draining connection requests no POLLIN; a
            // Writer is read only with input-queue headroom for a
            // maximal Input frame (re-checked again before every
            // recv).
            let wants_read = !slot.client.is_draining() && self.read_admitted(slot);
            let mut events = PollFlags::empty();
            if wants_read {
                events |= PollFlags::POLLIN;
            }
            if !slot.client.out().is_empty() {
                events |= PollFlags::POLLOUT;
            }
            pfds.push(PollFd::new(slot.fd.as_fd(), events));
            owners.push(Some(idx));
        }
        let wait = self.poll_wait_ms(now, max_wait_ms);
        sys::poll(&mut pfds, wait)?;
        let mut listener_ready = false;
        let mut conn_events: Vec<(usize, ConnId, PollFlags)> = Vec::new();
        for (pidx, pfd) in pfds.iter().enumerate() {
            let re = pfd.revents().unwrap_or(PollFlags::empty());
            if re.is_empty() {
                continue;
            }
            match owners[pidx] {
                None => listener_ready = true,
                Some(idx) => {
                    if let Some(slot) = &self.slots[idx] {
                        conn_events.push((idx, slot.conn, re));
                    }
                }
            }
        }
        drop(pfds);
        drop(owners);

        if listener_ready {
            self.handle_accept()?;
        }
        let now = self.clock.now_ms()?;
        for (idx, conn_id, re) in conn_events {
            // The slot may have been closed (and never refilled within
            // this iteration); a stale event is skipped, never applied
            // to a reused entry.
            let live = self
                .slots
                .get(idx)
                .and_then(|s| s.as_ref())
                .is_some_and(|s| s.conn == conn_id);
            if !live {
                continue;
            }
            self.handle_conn_events(idx, re, now)?;
        }
        Ok(Iteration {
            accepted: self.accepted_total - accepted_before,
            closed: self.closed_total - closed_before,
            connections: self.connection_count(),
        })
    }

    /// Whether this connection may be read right now: never while
    /// draining, and for a Writer only with input-queue headroom for
    /// the maximum legal Input payload (`frame_max_body` minus the
    /// version+kind bytes).
    fn read_admitted(&self, slot: &ConnSlot) -> bool {
        if slot.client.is_draining() {
            return false;
        }
        if matches!(slot.client.role(), ConnRole::Writer { .. }) {
            let max_input = self.limits.frame_max_body.saturating_sub(2);
            slot.client.input_live_bytes().saturating_add(max_input)
                <= self.limits.writer_input_queue_bytes
        } else {
            true
        }
    }

    /// Earliest relevant deadline as a poll timeout. `max_wait_ms` is a
    /// DURATION (not an absolute timestamp): the result is the minimum
    /// of that duration and every deadline's remaining time, computed
    /// with saturating conversions and clamped to the syscall limit.
    fn poll_wait_ms(&self, now: u64, max_wait_ms: Option<u32>) -> Option<u32> {
        let mut best_abs: Option<u64> = None;
        let consider = |deadline: u64, best: &mut Option<u64>| {
            *best = Some(match *best {
                Some(b) => b.min(deadline),
                None => deadline,
            });
        };
        if self.runtime.state.lifecycle == Lifecycle::WaitingForWriter {
            consider(
                self.ready_at_ms
                    .saturating_add(self.limits.startup_deadline_ms),
                &mut best_abs,
            );
        }
        for slot in self.slots.iter().flatten() {
            if let Some(start) = slot.client.reader_started_ms() {
                consider(
                    start.saturating_add(self.limits.incomplete_frame_deadline_ms),
                    &mut best_abs,
                );
            }
            if let Some(at) = slot.client.reply_deadline_at() {
                consider(at, &mut best_abs);
            }
        }
        let remaining = best_abs.map(|d| d.saturating_sub(now));
        match (max_wait_ms, remaining) {
            (Some(m), Some(r)) => Some(u64::from(m).min(r).min(i32::MAX as u64) as u32),
            (Some(m), None) => Some(m.min(i32::MAX as u32)),
            (None, Some(r)) => Some(r.min(i32::MAX as u64) as u32),
            (None, None) => None,
        }
    }

    fn check_deadlines(&mut self, now: u64) -> io::Result<()> {
        let mut expired: Vec<(usize, ConnId, bool)> = Vec::new();
        for (idx, slot) in self.slots.iter().enumerate() {
            let Some(slot) = slot else { continue };
            let incomplete = slot
                .client
                .reader_deadline_expired(now, self.limits.incomplete_frame_deadline_ms);
            let reply = slot.client.reply_deadline_expired(now);
            if incomplete || reply {
                expired.push((idx, slot.conn, incomplete));
            }
        }
        for (idx, conn, incomplete) in expired {
            let live = self
                .slots
                .get(idx)
                .and_then(|s| s.as_ref())
                .is_some_and(|s| s.conn == conn);
            if !live {
                continue;
            }
            let ev = if incomplete {
                Event::IncompleteFrameExpired { conn }
            } else {
                Event::ReplyDeadlineExpired { conn }
            };
            let fx = state::reduce(&mut self.runtime, &self.limits, ev);
            self.apply_effects(fx, now);
        }
        if self.runtime.state.lifecycle == Lifecycle::WaitingForWriter {
            let deadline = self
                .ready_at_ms
                .saturating_add(self.limits.startup_deadline_ms);
            if now >= deadline {
                let fx = state::reduce(
                    &mut self.runtime,
                    &self.limits,
                    Event::StartupDeadlineExpired,
                );
                self.apply_effects(fx, now);
            }
        }
        Ok(())
    }

    fn handle_accept(&mut self) -> io::Result<()> {
        for _ in 0..self.limits.accepts_per_iteration {
            let fd = match sys::accept_nonblock(self.bound.listener()) {
                Ok(Some(fd)) => fd,
                Ok(None) => break,
                Err(e) => return Err(e),
            };
            self.accepted_total += 1;
            // The peer gate runs BEFORE any frame byte is read.
            let uid_ok = sys::peer_uid(fd.as_fd())
                .map(|u| peer_uid_allowed(u, sys::effective_uid()))
                .unwrap_or(false);
            if !uid_ok {
                continue; // drop the fd: silent close, nothing read
            }
            // The connection cap is checked BEFORE a ConnId is
            // allocated: a cap-refused connection burns no id.
            if self.connection_count() >= self.limits.max_connections {
                // Connection #N+1: peer-checked, refused with a bounded
                // ResourceLimit frame, never a slot, a client id, or
                // frame dispatch. The drain is one immediate
                // nonblocking attempt — holding a slot to retry would
                // violate the cap.
                let mut refused = ClientConn::new(&self.limits);
                let frame = state::error_frame(
                    state::ErrorCode::ResourceLimit,
                    "connection cap exceeded",
                    &self.limits,
                );
                if refused.out_mut().push_frame(&frame) {
                    let _ = refused
                        .out_mut()
                        .flush_with(|buf| sys::send_no_sigpipe(fd.as_fd(), buf));
                }
                continue; // fd + refused drop → close
            }
            let Some(conn) = alloc_conn_id(&mut self.next_conn_id) else {
                // Sequence exhaustion: peer-checked, refused with a
                // bounded ResourceLimit frame, no slot or dispatch.
                let mut refused = ClientConn::new(&self.limits);
                let frame = state::error_frame(
                    state::ErrorCode::ResourceLimit,
                    "connection ids exhausted",
                    &self.limits,
                );
                if refused.out_mut().push_frame(&frame) {
                    let _ = refused
                        .out_mut()
                        .flush_with(|buf| sys::send_no_sigpipe(fd.as_fd(), buf));
                }
                continue; // fd + refused drop → close
            };
            let client = ClientConn::new(&self.limits);
            let slot = ConnSlot { conn, fd, client };
            match self.slots.iter().position(|s| s.is_none()) {
                Some(idx) => self.slots[idx] = Some(slot),
                None => self.slots.push(Some(slot)),
            }
        }
        Ok(())
    }

    fn handle_conn_events(&mut self, idx: usize, re: PollFlags, now: u64) -> io::Result<()> {
        if re.contains(PollFlags::POLLNVAL) {
            self.remove_conn(idx);
            return Ok(());
        }
        if re.contains(PollFlags::POLLIN) {
            self.handle_readable(idx, now)?;
        }
        if !self.slot_live(idx) {
            return Ok(());
        }
        if re.contains(PollFlags::POLLOUT)
            || re.intersects(PollFlags::POLLERR | PollFlags::POLLHUP)
        {
            self.flush_slot(idx);
        }
        if self.slot_live(idx) && re.intersects(PollFlags::POLLERR | PollFlags::POLLHUP) {
            // HUP/ERR: deliver what drained, then disconnect
            // role-appropriately.
            self.remove_conn(idx);
        }
        Ok(())
    }

    fn slot_live(&self, idx: usize) -> bool {
        self.slots.get(idx).and_then(|s| s.as_ref()).is_some()
    }

    fn handle_readable(&mut self, idx: usize, now: u64) -> io::Result<()> {
        loop {
            // Admission is re-checked before EVERY recv — the poll-set
            // decision alone is never trusted.
            if !self.slot_live(idx) {
                return Ok(());
            }
            {
                let slot = self.slots[idx].as_ref().expect("live slot");
                if slot.client.is_draining() {
                    return Ok(()); // no reads while draining
                }
                if !self.read_admitted(slot) {
                    return Ok(()); // input queue full: socket backpressure
                }
            }
            // Bound the recv by the current frame's remaining bytes so
            // pipelined later frames stay in the kernel.
            let want = {
                let slot = self.slots[idx].as_ref().expect("live slot");
                slot.client.reader_bytes_needed().min(self.read_buf.len())
            };
            let n = {
                let fd = self.slots[idx].as_ref().expect("live slot").fd.as_fd();
                match sys::recv(fd, &mut self.read_buf[..want]) {
                    Ok(Some(0)) => {
                        self.remove_conn(idx);
                        return Ok(());
                    }
                    Ok(Some(n)) => n,
                    Ok(None) => return Ok(()), // WouldBlock
                    // A peer-local fault closes exactly this
                    // connection; a systemic fault propagates.
                    Err(e) => match classify_conn_fault(&e) {
                        ConnFault::ConnectionLocal => {
                            self.remove_conn(idx);
                            return Ok(());
                        }
                        ConnFault::Systemic => return Err(e),
                    },
                }
            };
            self.consume_chunk(idx, n, now)?;
            if !self.slot_live(idx) {
                return Ok(()); // closed during dispatch
            }
        }
    }

    fn consume_chunk(&mut self, idx: usize, n: usize, now: u64) -> io::Result<()> {
        let mut off = 0usize;
        while off < n {
            if !self.slot_live(idx) {
                return Ok(());
            }
            {
                let slot = self.slots[idx].as_ref().expect("live slot");
                // Stop consuming the moment this connection became a
                // drainer; the bytes beyond the current frame were
                // never recv'd (frame-boundary-limited reads), so
                // nothing pipelined is dispatched or lost.
                if slot.client.is_draining() {
                    return Ok(());
                }
            }
            let took = {
                let slot = self.slots[idx].as_mut().expect("live slot");
                slot.client
                    .reader()
                    .append(&self.read_buf[off..n], now, &self.limits)
            };
            if took == 0 {
                break;
            }
            off += took;
            loop {
                let res = {
                    let slot = self.slots[idx].as_mut().expect("live slot");
                    slot.client.reader().take_frame(&self.limits)
                };
                match res {
                    Ok(Some(frame)) => {
                        self.dispatch_frame(idx, frame, now);
                        if !self.slot_live(idx) {
                            return Ok(());
                        }
                    }
                    Ok(None) => break,
                    // Malformed/oversized/unsupported/truncated framing:
                    // immediate silent close.
                    Err(_) => {
                        self.remove_conn(idx);
                        return Ok(());
                    }
                }
            }
        }
        Ok(())
    }

    fn dispatch_frame(&mut self, idx: usize, frame: Frame, now: u64) {
        let (conn, role) = {
            let slot = self.slots[idx].as_ref().expect("live slot");
            (slot.conn, slot.client.role())
        };
        let fx = state::reduce(
            &mut self.runtime,
            &self.limits,
            Event::Frame {
                conn,
                role,
                frame: &frame,
            },
        );
        self.apply_effects(fx, now);
    }

    fn apply_effects(&mut self, fx: Vec<Effect>, now: u64) {
        for effect in fx {
            if effect.is_deferred() {
                self.deferred.push(effect);
                continue;
            }
            match effect {
                Effect::SetRole { target, role } => {
                    if let Some(idx) = self.resolve(target) {
                        let ok = self.slots[idx]
                            .as_mut()
                            .expect("resolved")
                            .client
                            .set_role(&self.limits, role)
                            .is_ok();
                        if !ok {
                            // The cap change refused (queue not empty):
                            // never keep a wrong cap silently.
                            self.remove_conn(idx);
                        }
                    }
                }
                Effect::QueueFrame { target, frame } => {
                    let Some(idx) = self.resolve(target) else { continue };
                    let is_control_reply = {
                        let slot = self.slots[idx].as_ref().expect("resolved");
                        slot.client.role() == ConnRole::Control
                            && matches!(
                                frame.kind(),
                                Kind::Pong | Kind::Ownership | Kind::Error | Kind::Exit
                            )
                    };
                    let queued = {
                        let slot = self.slots[idx].as_mut().expect("resolved");
                        if is_control_reply {
                            // The reply deadline starts at queue time.
                            slot.client
                                .arm_reply_deadline(now, self.limits.control_reply_deadline_ms);
                        }
                        slot.client.out_mut().push_frame(&frame)
                    };
                    if !queued {
                        // A reply that cannot be queued cannot be
                        // delivered at all: close without it.
                        self.remove_conn(idx);
                    } else {
                        self.flush_slot(idx);
                    }
                }
                Effect::DeliverInput { client_id, bytes } => {
                    if let Some(idx) = self.resolve(Target::Client(client_id)) {
                        let ok = self.slots[idx]
                            .as_mut()
                            .expect("resolved")
                            .client
                            .input_mut()
                            .push(bytes);
                        if !ok {
                            // Admission guarantees headroom; reaching
                            // this means the guarantee was broken —
                            // surface it as a connection fault, never a
                            // silent byte drop.
                            self.remove_conn(idx);
                        }
                    }
                }
                Effect::DropQueues { target } => {
                    if let Some(idx) = self.resolve(target) {
                        let slot = self.slots[idx].as_mut().expect("resolved");
                        slot.client.out_mut().clear();
                        slot.client.input_mut().clear();
                    }
                }
                Effect::CloseNow { conn } => {
                    if let Some(idx) = self.resolve(Target::Conn(conn)) {
                        self.remove_conn(idx);
                    }
                }
                Effect::CloseAfterFlush { conn } => {
                    if let Some(idx) = self.resolve(Target::Conn(conn)) {
                        self.begin_draining(idx, now);
                    }
                }
                Effect::CloseClientNow { client_id } => {
                    if let Some(idx) = self.resolve(Target::Client(client_id)) {
                        self.remove_conn(idx);
                    }
                }
                Effect::CloseClientAfterFlush { client_id } => {
                    if let Some(idx) = self.resolve(Target::Client(client_id)) {
                        self.begin_draining(idx, now);
                    }
                }
                deferred => self.deferred.push(deferred),
            }
        }
    }

    fn begin_draining(&mut self, idx: usize, now: u64) {
        if let Some(slot) = self.slots[idx].as_mut() {
            slot.client.begin_draining();
            slot.client
                .arm_reply_deadline(now, self.limits.control_reply_deadline_ms);
        }
        self.flush_slot(idx);
    }

    /// Best-effort immediate flush; closes on hard I/O errors and on a
    /// finished drain.
    fn flush_slot(&mut self, idx: usize) {
        let result = {
            let Some(slot) = self.slots[idx].as_mut() else {
                return;
            };
            let ConnSlot { fd, client, .. } = slot;
            client
                .out_mut()
                .flush_with(|buf| sys::send_no_sigpipe(fd.as_fd(), buf))
        };
        match result {
            Ok(fully_flushed) => {
                let drained_done = fully_flushed
                    && self
                        .slots
                        .get(idx)
                        .and_then(|s| s.as_ref())
                        .is_some_and(|s| s.client.is_draining());
                if drained_done {
                    self.remove_conn(idx);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => self.remove_conn(idx),
        }
    }

    /// THE one close path: takes the slot, closes the descriptor
    /// exactly once, and reduces `Disconnected` exactly once with the
    /// former role — writer closure revokes ownership, observer
    /// closure leaves the observer set, and already-revoked or demoted
    /// closes are harmless.
    fn remove_conn(&mut self, idx: usize) {
        let Some(slot) = self.slots.get_mut(idx).and_then(|s| s.take()) else {
            return;
        };
        let role = slot.client.role();
        drop(slot); // the fd closes here, exactly once
        self.closed_total += 1;
        let fx = state::reduce(&mut self.runtime, &self.limits, Event::Disconnected { role });
        self.apply_effects(fx, 0);
    }

    fn resolve(&self, target: Target) -> Option<usize> {
        match target {
            Target::Conn(conn) => self
                .slots
                .iter()
                .position(|s| s.as_ref().is_some_and(|slot| slot.conn == conn)),
            Target::Client(client_id) => self.slots.iter().position(|s| {
                s.as_ref().is_some_and(|slot| {
                    matches!(
                        slot.client.role(),
                        ConnRole::Writer { client_id: id } if id == client_id
                    ) || matches!(
                        slot.client.role(),
                        ConnRole::Observer { client_id: id } if id == client_id
                    )
                })
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::os::unix::fs::DirBuilderExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MockClock(Rc<Cell<u64>>);

    impl Clock for MockClock {
        fn now_ms(&self) -> io::Result<u64> {
            Ok(self.0.get())
        }
    }

    static FIXTURE: AtomicUsize = AtomicUsize::new(0);

    /// Bounded-retry EXCLUSIVE 0700 fixture base as an RAII guard.
    /// Declared BEFORE the broker in every test so the broker (and its
    /// BoundSession fds) drops first; Drop removes only the base this
    /// guard itself created — never anything else, never pre-cleaned.
    struct BaseGuard(PathBuf);

    impl BaseGuard {
        fn new(tag: &str) -> Self {
            let n = FIXTURE.fetch_add(1, Ordering::Relaxed);
            for i in 0..64u32 {
                let p = std::env::temp_dir().join(format!(
                    "everpty-brk-{tag}-{}-{n}-{i}",
                    std::process::id()
                ));
                let mut b = std::fs::DirBuilder::new();
                b.mode(0o700);
                if b.create(&p).is_ok() {
                    return Self(p);
                }
            }
            panic!("no exclusive fixture base");
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for BaseGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A broker around a truly bound+locked session with a preset mock
    /// clock (nonzero start times included). The guard comes FIRST in
    /// the returned tuple so it drops LAST.
    fn broker_at(t0: u64) -> (BaseGuard, Rc<Cell<u64>>, Broker) {
        use crate::session::resolve_state_root_from;
        let base = BaseGuard::new("b");
        let limits = Limits::default();
        let root = resolve_state_root_from(std::slice::from_ref(&base.path().to_path_buf()))
            .expect("root");
        let dir = root.session("s1", &limits).expect("session");
        let locked = dir.lock().expect("lock");
        let bound = locked.bind_broker_socket(&limits).expect("bind");
        let clock = Rc::new(Cell::new(t0));
        let broker = Broker::new(bound, &limits, Rc::new(MockClock(clock.clone())), None)
            .expect("broker");
        (base, clock, broker)
    }

    #[test]
    fn conn_fault_classifier_splits_local_from_systemic() {
        let local = |errno| {
            classify_conn_fault(&io::Error::from_raw_os_error(errno))
        };
        assert_eq!(local(libc::ECONNRESET), ConnFault::ConnectionLocal);
        assert_eq!(local(libc::ECONNABORTED), ConnFault::ConnectionLocal);
        assert_eq!(local(libc::ENOTCONN), ConnFault::ConnectionLocal);
        assert_eq!(local(libc::EPIPE), ConnFault::ConnectionLocal);
        // Resource exhaustion and environmental I/O are systemic —
        // they must propagate, never close just one connection.
        for errno in [libc::EMFILE, libc::ENFILE, libc::ENOMEM, libc::EIO] {
            assert_eq!(
                local(errno),
                ConnFault::Systemic,
                "errno {errno} must propagate"
            );
        }
        // Non-errno io errors are systemic too.
        assert_eq!(
            classify_conn_fault(&io::Error::from(io::ErrorKind::UnexpectedEof)),
            ConnFault::Systemic
        );
    }

    #[test]
    fn ready_record_round_trips_and_rejects_malformed() {
        let rec = ReadyStatus::Ready.encode();
        assert!(matches!(ReadyStatus::decode(&rec), Ok(ReadyStatus::Ready)));
        let rec = ReadyStatus::Failed {
            errno: libc::ENOENT,
        }
        .encode();
        assert!(matches!(
            ReadyStatus::decode(&rec),
            Ok(ReadyStatus::Failed {
                errno: libc::ENOENT
            })
        ));
        // Length, magic, status, reserved, and errno-field violations.
        assert!(ReadyStatus::decode(&[]).is_err());
        assert!(ReadyStatus::decode(&rec[..7]).is_err());
        assert!(ReadyStatus::decode(&[rec.as_slice(), &[0]].concat()).is_err());
        let mut bad = rec;
        bad[0] ^= 0xFF;
        assert!(ReadyStatus::decode(&bad).is_err());
        let mut bad = ReadyStatus::Ready.encode();
        bad[1] = 7;
        assert!(ReadyStatus::decode(&bad).is_err());
        let mut bad = ReadyStatus::Ready.encode();
        bad[2] = 1;
        assert!(ReadyStatus::decode(&bad).is_err());
        let mut bad = ReadyStatus::Ready.encode();
        bad[7] = 9; // Ready must carry errno 0
        assert!(ReadyStatus::decode(&bad).is_err());
    }

    #[test]
    fn read_ready_record_over_an_open_pipe() {
        use std::io::Write;
        // Both pipe ends stay open in-process for the whole test: no
        // SIGPIPE is possible and none is provoked — this covers only
        // the OPEN-pipe read behavior.
        let chan = ReadinessChannel::new().expect("pipe");
        let mut w = std::fs::File::from(chan.write.try_clone().expect("dup"));
        w.write_all(
            &ReadyStatus::Failed {
                errno: libc::EACCES,
            }
            .encode(),
        )
        .expect("write record");
        let status = read_ready_record(chan.read.as_fd()).expect("read record");
        assert_eq!(
            status,
            ReadyStatus::Failed {
                errno: libc::EACCES
            }
        );

        // A truncated record followed by EOF is an error, never a
        // half-accepted status.
        let chan = ReadinessChannel::new().expect("pipe");
        let mut w = std::fs::File::from(chan.write.try_clone().expect("dup"));
        w.write_all(&ReadyStatus::Ready.encode()[..5]).expect("write 5");
        drop(w);
        drop(chan.write);
        assert!(read_ready_record(chan.read.as_fd()).is_err());
    }

    #[test]
    fn peer_uid_policy_matrix_plus_real_same_uid() {
        let euid = sys::effective_uid();
        assert!(peer_uid_allowed(euid, euid));
        assert!(!peer_uid_allowed(euid.wrapping_add(1), euid));
        assert!(!peer_uid_allowed(0, euid), "root peer is not auto-admitted");
        // Real same-UID credentials on a fixture socketpair.
        let (a, _b) = std::os::unix::net::UnixStream::pair().expect("pair");
        let uid = sys::peer_uid(a.as_fd()).expect("uid");
        assert!(peer_uid_allowed(uid, euid));
    }

    #[test]
    fn monotonic_clock_never_goes_backwards() {
        let a = MonotonicClock.now_ms().expect("t1");
        let b = MonotonicClock.now_ms().expect("t2");
        assert!(b >= a, "monotonic clock went backwards: {a} -> {b}");
    }

    #[test]
    fn conn_id_allocator_is_monotonic_and_never_aliases() {
        let mut next: ConnId = 1;
        let mut last = 0;
        for _ in 0..1000 {
            let id = alloc_conn_id(&mut next).expect("id");
            assert!(id > last, "strictly monotonic");
            last = id;
        }
        next = ConnId::MAX;
        assert_eq!(alloc_conn_id(&mut next), None, "exhaustion refuses");
        assert_eq!(alloc_conn_id(&mut next), None, "and keeps refusing");
        assert_eq!(next, ConnId::MAX, "no wrap, no reuse");
    }

    #[test]
    fn startup_deadline_armed_once_from_nonzero_clock() {
        let (_base, clock, mut broker) = broker_at(12_345);
        assert_eq!(broker.lifecycle(), Lifecycle::WaitingForWriter);
        // Before the deadline: repeated iterations stay Waiting.
        clock.set(12_345 + 9_999);
        broker.run_once(Some(0)).expect("iterate");
        assert_eq!(broker.lifecycle(), Lifecycle::WaitingForWriter);
        // At/after the deadline (armed once at 12_345, +10s): Failed +
        // a single deferred Shutdown.
        clock.set(12_345 + 10_000);
        broker.run_once(Some(0)).expect("iterate");
        assert_eq!(broker.lifecycle(), Lifecycle::Failed);
        assert!(
            matches!(broker.deferred(), [Effect::Shutdown]),
            "unexpected deferred: {:?}",
            broker.deferred()
        );
    }

    #[test]
    fn bounded_max_wait_is_a_duration_not_absolute() {
        let (_base, _clock, mut broker) = broker_at(50_000);
        // Even with no deadlines pending, Some(0) must return
        // immediately (a duration of zero) — never "now=50000ms
        // interpreted as a deadline already long past".
        let it = broker.run_once(Some(0)).expect("iterate");
        assert_eq!(it.connections, 0);
        // A positive bounded duration is honored directly: at now
        // 50_000 with the startup deadline 10 s out, a 1 ms max wait
        // yields exactly Some(1) — the minimum of the duration and the
        // deadline's remaining time. No sleeping.
        assert_eq!(broker.poll_wait_ms(50_000, Some(1)), Some(1));
    }
}
