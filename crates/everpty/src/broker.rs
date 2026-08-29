//! Single-threaded poll-loop broker (plans/m2-plan.md §3–§6; commit 6,
//! corrected detached-boundary and terminal-pressure pass).
//!
//! One thread, one `poll(2)` per iteration over the listener, PTY
//! master, and every client socket. All descriptors are `O_NONBLOCK`;
//! all socket writes go through
//! `send(MSG_NOSIGNAL)`. Time comes from an injected [`Clock`] so every
//! deadline is deterministically testable — no sleeps anywhere, and a
//! clock failure propagates instead of being masked.
//!
//! Every frame decision goes through the pure reducer
//! ([`crate::state::reduce`]); this module only executes effects. The
//! deferred effects (`SpawnChild`, `BeginKill`, `ApplyDimensions`,
//! `Shutdown`) are recorded and NEVER executed here — commit 7 owns
//! signal wiring, spawn, and shutdown. In particular `Kill` never
//! terminates anything in commit 6.
//!
//! **No-loss writer input.** A Writer's socket is read only while its
//! input queue has headroom for the maximum legal Input payload, and
//! each `recv` is bounded by the reader's `bytes_needed` — so pipelined
//! frames stay in the kernel and a frame that started is guaranteed
//! queue space. A full queue stops socket reads without dropping or
//! eviction; PTY `POLLOUT` drains exact partial-write offsets.
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

use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::rc::Rc;

use crate::client::{aggregate_live_bytes, ClientConn, ConnRole, SharedChunk};
use crate::error::Error;
use crate::frame::{self, Frame, Kind};
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
        Some(libc::ECONNRESET)
        | Some(libc::ECONNABORTED)
        | Some(libc::ENOTCONN)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriterStallBand {
    HighEpisode,
    LowDeficit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WriterStall {
    writer_id: u32,
    since_ms: u64,
    band: WriterStallBand,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PollOwner {
    Listener,
    Master,
    Client { idx: usize, conn: ConnId },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BarrierResult {
    Safe,
    Deferred,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecipientKind {
    Writer,
    Observer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Recipient {
    idx: usize,
    conn: ConnId,
    client_id: u32,
    kind: RecipientKind,
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
    output_reservation: usize,
    master: Option<std::fs::File>,
    master_terminal_pending: bool,
    writer_stall: Option<WriterStall>,
    accepted_total: usize,
    closed_total: usize,
    /// Held for ownership, never written in commit 6 (see the module
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
        let invalid =
            |message: &'static str| Error::Io(io::Error::new(io::ErrorKind::InvalidInput, message));
        if limits.read_chunk_bytes == 0 {
            return Err(invalid("read_chunk_bytes must be nonzero"));
        }
        if limits.frame_max_body < 2 {
            return Err(invalid("frame_max_body must include version and kind"));
        }
        if limits.read_chunk_bytes > limits.frame_max_body - 2 {
            return Err(invalid("read chunk exceeds Output payload capacity"));
        }
        let output_reservation = limits
            .read_chunk_bytes
            .checked_add(frame::HEADER_LEN)
            .ok_or_else(|| invalid("encoded Output reservation overflow"))?;
        if output_reservation > limits.writer_queue_bytes {
            return Err(invalid("writer queue cannot reserve one full Output frame"));
        }
        if limits.writer_queue_bytes > limits.aggregate_queue_bytes {
            return Err(invalid("writer queue exceeds aggregate output cap"));
        }

        sys::set_nonblocking(bound.listener())?;
        let runtime = Runtime::new_ready(bound.session_name(), limits)
            .map_err(|e| Error::Io(io::Error::new(io::ErrorKind::InvalidInput, e.to_string())))?;
        // The startup deadline is armed exactly once, from the injected
        // clock, at construction.
        let ready_at_ms = clock.now_ms().map_err(Error::Io)?;
        Ok(Self {
            limits: *limits,
            clock,
            bound,
            runtime,
            slots: Vec::new(),
            next_conn_id: 1,
            deferred: Vec::new(),
            ready_at_ms,
            read_buf: vec![0u8; limits.read_chunk_bytes],
            output_reservation,
            master: None,
            master_terminal_pending: false,
            writer_stall: None,
            accepted_total: 0,
            closed_total: 0,
            _readiness_write: readiness_write,
        })
    }

    /// Installs the one PTY master owned by this broker. Replacement is
    /// refused so no live descriptor or queued input can be lost.
    pub fn attach_pty_master(&mut self, fd: OwnedFd) -> io::Result<()> {
        if self.master.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "PTY master is already attached",
            ));
        }
        sys::set_nonblocking(fd.as_fd())?;
        self.master = Some(std::fs::File::from(fd));
        self.master_terminal_pending = false;
        Ok(())
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

    pub fn has_pty_master(&self) -> bool {
        self.master.is_some()
    }

    pub fn pty_terminal_pending(&self) -> bool {
        self.master_terminal_pending
    }

    pub fn writer_output_live_bytes(&self) -> Option<usize> {
        let (idx, _) = self.eligible_writer_slot()?;
        Some(self.slots[idx].as_ref()?.client.out().live_bytes())
    }

    pub fn aggregate_output_live_bytes(&self) -> usize {
        aggregate_live_bytes(self.slots.iter().flatten().map(|slot| slot.client.out()))
    }

    pub fn pty_read_paused(&self) -> bool {
        self.writer_stall.is_some()
    }

    pub fn writer_stall_observation(&self) -> Option<(u32, u64, WriterStallBand)> {
        self.writer_stall
            .map(|stall| (stall.writer_id, stall.since_ms, stall.band))
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
    /// an explicit effect once SIGPIPE is handled. Commit 6 never
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
        self.reconcile_writer_stall(now);
        self.expire_writer_stall(now);

        // Build the complete poll set under immutable borrows, then
        // harvest identity-bound events before mutating anything.
        let mut pfds: Vec<PollFd<'_>> = Vec::with_capacity(2 + self.slots.len());
        let mut owners: Vec<PollOwner> = Vec::with_capacity(2 + self.slots.len());
        pfds.push(PollFd::new(self.bound.listener(), PollFlags::POLLIN));
        owners.push(PollOwner::Listener);

        let master_events = self.master_poll_events();
        if let (Some(master), Some(events)) = (self.master.as_ref(), master_events) {
            pfds.push(PollFd::new(master.as_fd(), events));
            owners.push(PollOwner::Master);
        }

        for (idx, slot) in self.slots.iter().enumerate() {
            let Some(slot) = slot else { continue };
            // Even a socket with no requested readiness stays in the
            // set so HUP/ERR/NVAL cannot hide behind backpressure.
            let mut events = PollFlags::empty();
            if self.read_admitted(slot) {
                events |= PollFlags::POLLIN;
            }
            if !slot.client.out().is_empty() {
                events |= PollFlags::POLLOUT;
            }
            pfds.push(PollFd::new(slot.fd.as_fd(), events));
            owners.push(PollOwner::Client {
                idx,
                conn: slot.conn,
            });
        }

        let wait = self.poll_wait_ms(now, max_wait_ms);
        sys::poll(&mut pfds, wait)?;
        let mut listener_ready = false;
        let mut master_ready = None;
        let mut conn_events = Vec::new();
        for (pfd, owner) in pfds.iter().zip(&owners) {
            let re = pfd.revents().unwrap_or(PollFlags::empty());
            if re.is_empty() {
                continue;
            }
            match *owner {
                PollOwner::Listener => listener_ready = true,
                PollOwner::Master => master_ready = Some(re),
                PollOwner::Client { idx, conn } => conn_events.push((idx, conn, re)),
            }
        }
        drop(pfds);
        drop(owners);

        // Deadline expiry wins ties with readiness and is reconciled
        // again after the poll wait, before any PTY byte is consumed.
        let now = self.clock.now_ms()?;
        self.check_deadlines(now)?;
        self.reconcile_writer_stall(now);
        self.expire_writer_stall(now);

        let mut discard_budget = self.limits.accepts_per_iteration.max(1);
        if let Some(re) = master_ready {
            self.handle_master_events(re, now, &mut discard_budget)?;
        }
        if listener_ready {
            self.handle_accept()?;
        }
        for (idx, conn, re) in conn_events {
            if !self.slot_identity_live(idx, conn) {
                continue;
            }
            self.handle_conn_events(idx, re, now, &mut discard_budget)?;
        }
        self.reconcile_writer_stall(now);

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

    fn slot_identity_live(&self, idx: usize, conn: ConnId) -> bool {
        self.slots
            .get(idx)
            .and_then(Option::as_ref)
            .is_some_and(|slot| slot.conn == conn)
    }

    fn eligible_writer_slot(&self) -> Option<(usize, u32)> {
        let Ownership::Writer(writer_id) = self.runtime.state.ownership else {
            return None;
        };
        self.slots.iter().enumerate().find_map(|(idx, slot)| {
            let slot = slot.as_ref()?;
            (!slot.client.is_draining()
                && matches!(
                    slot.client.role(),
                    ConnRole::Writer { client_id } if client_id == writer_id
                ))
            .then_some((idx, writer_id))
        })
    }

    fn writer_frame_fits(&self, live: usize) -> bool {
        live.checked_add(self.output_reservation)
            .is_some_and(|projected| projected <= self.limits.writer_queue_bytes)
    }

    fn reconcile_writer_stall(&mut self, now: u64) {
        let Some((idx, writer_id)) = self.eligible_writer_slot() else {
            self.writer_stall = None;
            return;
        };
        let live = self.slots[idx]
            .as_ref()
            .expect("eligible writer slot")
            .client
            .out()
            .live_bytes();
        let fits = self.writer_frame_fits(live);
        let low = self.limits.writer_queue_bytes / 2;

        let Some(stall) = self.writer_stall else {
            if !fits {
                self.writer_stall = Some(WriterStall {
                    writer_id,
                    since_ms: now,
                    band: if live < low {
                        WriterStallBand::LowDeficit
                    } else {
                        WriterStallBand::HighEpisode
                    },
                });
            }
            return;
        };

        if stall.writer_id != writer_id {
            self.writer_stall = None;
            if !fits {
                self.writer_stall = Some(WriterStall {
                    writer_id,
                    since_ms: now,
                    band: if live < low {
                        WriterStallBand::LowDeficit
                    } else {
                        WriterStallBand::HighEpisode
                    },
                });
            }
            return;
        }

        match stall.band {
            WriterStallBand::HighEpisode if live < low => {
                if fits {
                    self.writer_stall = None;
                } else {
                    // The old high episode recovers once, but an actual
                    // full-frame deficit below low water gets a fresh,
                    // subsequently immutable deadline.
                    self.writer_stall = Some(WriterStall {
                        writer_id,
                        since_ms: now,
                        band: WriterStallBand::LowDeficit,
                    });
                }
            }
            WriterStallBand::HighEpisode => {
                // Hysteresis: at/above low water, even restored
                // headroom cannot move or clear the original episode.
            }
            WriterStallBand::LowDeficit if live < low => {
                if fits {
                    self.writer_stall = None;
                }
            }
            WriterStallBand::LowDeficit => {
                self.writer_stall = Some(WriterStall {
                    band: WriterStallBand::HighEpisode,
                    ..stall
                });
            }
        }
    }

    fn expire_writer_stall(&mut self, now: u64) {
        self.reconcile_writer_stall(now);
        let Some(stall) = self.writer_stall else {
            return;
        };
        let deadline = stall.since_ms.saturating_add(self.limits.stall_deadline_ms);
        if now < deadline {
            return;
        }
        let Some((idx, writer_id)) = self.eligible_writer_slot() else {
            self.writer_stall = None;
            return;
        };
        if writer_id != stall.writer_id {
            self.writer_stall = None;
            self.reconcile_writer_stall(now);
            return;
        }
        // The surviving identity-bound pressure latch is sufficient:
        // expiry is valid below low water too.
        self.writer_stall = None;
        self.remove_conn(idx, now);
        self.reconcile_writer_stall(now);
    }

    fn master_read_admitted(&self) -> bool {
        self.eligible_writer_slot().is_none() || self.writer_stall.is_none()
    }

    fn has_output_recipients(&self) -> bool {
        self.eligible_writer_slot().is_some()
            || self.runtime.observers.client_ids().iter().any(|&id| {
                self.resolve_observer(id).is_some_and(|idx| {
                    !self.slots[idx]
                        .as_ref()
                        .expect("resolved")
                        .client
                        .is_draining()
                })
            })
    }

    fn master_poll_events(&self) -> Option<PollFlags> {
        self.master.as_ref()?;
        let mut events = PollFlags::empty();
        if self.master_read_admitted() {
            events |= PollFlags::POLLIN;
        }
        if !self.master_terminal_pending {
            if let Some((idx, _)) = self.eligible_writer_slot() {
                if self.slots[idx]
                    .as_ref()
                    .expect("eligible writer")
                    .client
                    .input_live_bytes()
                    > 0
                {
                    events |= PollFlags::POLLOUT;
                }
            }
        }
        (!events.is_empty()).then_some(events)
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
        if let Some(stall) = self.writer_stall {
            consider(
                stall.since_ms.saturating_add(self.limits.stall_deadline_ms),
                &mut best_abs,
            );
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

    fn handle_master_events(
        &mut self,
        re: PollFlags,
        now: u64,
        discard_budget: &mut usize,
    ) -> io::Result<()> {
        if self.master.is_none() {
            return Ok(());
        }
        if re.contains(PollFlags::POLLNVAL) {
            self.detach_master();
            return Ok(());
        }

        self.reconcile_writer_stall(now);
        let terminal_hint = re.intersects(PollFlags::POLLHUP | PollFlags::POLLERR);
        if self.master_read_admitted() && (re.contains(PollFlags::POLLIN) || terminal_hint) {
            if self.has_output_recipients() {
                self.read_master_output_once(now)?;
            } else {
                let _ = self.discard_master_until_boundary(discard_budget)?;
            }
        }

        if terminal_hint {
            if self.master.is_some() {
                self.master_terminal_pending = true;
            }
            // Never probe the terminal write side after HUP/ERR: on a
            // PTY that can destroy the only handle to final output.
            return Ok(());
        }
        if re.contains(PollFlags::POLLOUT) && !self.master_terminal_pending && self.master.is_some()
        {
            self.drain_writer_input()?;
        }
        Ok(())
    }

    fn detach_master(&mut self) {
        self.master = None;
        self.master_terminal_pending = false;
    }

    fn read_master_output_once(&mut self, now: u64) -> io::Result<()> {
        loop {
            let result = {
                let master = self.master.as_mut().expect("master checked");
                master.read(&mut self.read_buf)
            };
            match result {
                Ok(0) => {
                    self.detach_master();
                    return Ok(());
                }
                Ok(n) => {
                    self.fan_out_output(n, now);
                    return Ok(());
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) if error.raw_os_error() == Some(libc::EIO) => {
                    self.detach_master();
                    return Ok(());
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn discard_master_until_boundary(&mut self, budget: &mut usize) -> io::Result<BarrierResult> {
        if self.master.is_none() {
            return Ok(BarrierResult::Safe);
        }
        while *budget > 0 {
            *budget -= 1;
            let result = {
                let master = self.master.as_mut().expect("master checked");
                master.read(&mut self.read_buf)
            };
            match result {
                Ok(0) => {
                    self.detach_master();
                    return Ok(BarrierResult::Safe);
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(BarrierResult::Safe);
                }
                // Interrupted attempts consume budget. This is the
                // bounded grant barrier, not an unbounded retry loop.
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.raw_os_error() == Some(libc::EIO) => {
                    self.detach_master();
                    return Ok(BarrierResult::Safe);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(BarrierResult::Deferred)
    }

    fn drain_writer_input(&mut self) -> io::Result<()> {
        if self.master_terminal_pending || self.master.is_none() {
            return Ok(());
        }
        let Some((idx, _)) = self.eligible_writer_slot() else {
            return Ok(());
        };
        if self.slots[idx]
            .as_ref()
            .expect("eligible writer")
            .client
            .input_live_bytes()
            == 0
        {
            return Ok(());
        }

        let result = {
            let master = self.master.as_mut().expect("master checked");
            let slot = self.slots[idx].as_mut().expect("eligible writer");
            slot.client.input_mut().drain_with(|bytes| loop {
                match master.write(bytes) {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    other => return other,
                }
            })
        };
        match result {
            Ok(_) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(error)
                if error.kind() == io::ErrorKind::WriteZero
                    || error.raw_os_error() == Some(libc::EIO) =>
            {
                self.master_terminal_pending = true;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn capture_recipients(&self) -> Vec<Recipient> {
        let mut recipients = Vec::new();
        if let Some((idx, writer_id)) = self.eligible_writer_slot() {
            let slot = self.slots[idx].as_ref().expect("eligible writer");
            recipients.push(Recipient {
                idx,
                conn: slot.conn,
                client_id: writer_id,
                kind: RecipientKind::Writer,
            });
        }
        for &client_id in self.runtime.observers.client_ids() {
            let Some(idx) = self.resolve_observer(client_id) else {
                continue;
            };
            let slot = self.slots[idx].as_ref().expect("resolved observer");
            if !slot.client.is_draining() {
                recipients.push(Recipient {
                    idx,
                    conn: slot.conn,
                    client_id,
                    kind: RecipientKind::Observer,
                });
            }
        }
        recipients
    }

    fn recipient_live(&self, recipient: Recipient) -> bool {
        let Some(slot) = self
            .slots
            .get(recipient.idx)
            .and_then(Option::as_ref)
            .filter(|slot| slot.conn == recipient.conn)
        else {
            return false;
        };
        if slot.client.is_draining() {
            return false;
        }
        match recipient.kind {
            RecipientKind::Writer => {
                self.runtime.state.ownership == Ownership::Writer(recipient.client_id)
                    && matches!(
                        slot.client.role(),
                        ConnRole::Writer { client_id } if client_id == recipient.client_id
                    )
            }
            RecipientKind::Observer => {
                self.runtime.observers.contains(recipient.client_id)
                    && matches!(
                        slot.client.role(),
                        ConnRole::Observer { client_id } if client_id == recipient.client_id
                    )
            }
        }
    }

    fn projected_fanout_bytes(&self, recipients: &[Recipient], encoded_len: usize) -> usize {
        recipients
            .iter()
            .filter(|&&recipient| self.recipient_live(recipient))
            .count()
            .saturating_mul(encoded_len)
    }

    fn aggregate_fanout_fits(&self, recipients: &[Recipient], encoded_len: usize) -> bool {
        self.aggregate_output_live_bytes()
            .saturating_add(self.projected_fanout_bytes(recipients, encoded_len))
            <= self.limits.aggregate_queue_bytes
    }

    fn most_full_observer(
        &self,
        exclude: Option<(usize, ConnId)>,
        require_queued_bytes: bool,
    ) -> Option<usize> {
        let mut best: Option<(usize, usize)> = None;
        for &client_id in self.runtime.observers.client_ids() {
            let Some(idx) = self.resolve_observer(client_id) else {
                continue;
            };
            let slot = self.slots[idx].as_ref().expect("resolved observer");
            if exclude == Some((idx, slot.conn)) {
                continue;
            }
            let live = slot.client.out().live_bytes();
            if require_queued_bytes && live == 0 {
                continue;
            }
            // Iteration is attachment order; strict comparison leaves
            // the first attached observer as the deterministic tie.
            if best.is_none_or(|(_, best_live)| live > best_live) {
                best = Some((idx, live));
            }
        }
        best.map(|(idx, _)| idx)
    }

    fn most_full_non_writer_queue(&self) -> Option<usize> {
        let writer_idx = self.eligible_writer_slot().map(|(idx, _)| idx);
        let mut best: Option<(usize, usize, ConnId)> = None;
        for (idx, slot) in self.slots.iter().enumerate() {
            let Some(slot) = slot else { continue };
            if Some(idx) == writer_idx {
                continue;
            }
            let live = slot.client.out().live_bytes();
            if live == 0 {
                continue;
            }
            match best {
                Some((_, best_live, _)) if live <= best_live => {}
                _ => best = Some((idx, live, slot.conn)),
            }
        }
        best.map(|(idx, _, _)| idx)
    }

    fn fan_out_output(&mut self, n: usize, now: u64) {
        let frame = Frame::Output(self.read_buf[..n].to_vec());
        let encoded: SharedChunk = frame.encode().into();
        let encoded_len = encoded.len();
        let recipients = self.capture_recipients();
        if recipients.is_empty() {
            return;
        }

        // Per-observer cap refusal happens before any append.
        for recipient in recipients.iter().copied() {
            if recipient.kind != RecipientKind::Observer || !self.recipient_live(recipient) {
                continue;
            }
            let slot = self.slots[recipient.idx].as_ref().expect("live recipient");
            let fits = slot
                .client
                .out()
                .live_bytes()
                .checked_add(encoded_len)
                .is_some_and(|projected| projected <= slot.client.out().cap_bytes());
            if !fits {
                self.remove_conn(recipient.idx, now);
            }
        }

        // Aggregate pressure evicts observers in most-full/attachment
        // order, including a zero-live captured observer when dropping
        // its pending reservation is what creates room.
        while !self.aggregate_fanout_fits(&recipients, encoded_len) {
            let Some(idx) = self.most_full_observer(None, false) else {
                break;
            };
            self.remove_conn(idx, now);
        }

        // Non-recipient queues may consume the writer's aggregate
        // guarantee. Evict the most-full stable non-writer slots until
        // the complete projection fits; the constructor proves the
        // writer alone always can.
        let writer_survives = recipients.iter().copied().any(|recipient| {
            recipient.kind == RecipientKind::Writer && self.recipient_live(recipient)
        });
        while writer_survives && !self.aggregate_fanout_fits(&recipients, encoded_len) {
            let Some(idx) = self.most_full_non_writer_queue() else {
                break;
            };
            self.remove_conn(idx, now);
        }

        for recipient in recipients {
            if !self.recipient_live(recipient) {
                continue;
            }
            let queued = self.slots[recipient.idx]
                .as_mut()
                .expect("live recipient")
                .client
                .out_mut()
                .push_shared(encoded.clone());
            if !queued {
                self.remove_conn(recipient.idx, now);
                continue;
            }
            self.reconcile_writer_stall(now);
            self.flush_slot(recipient.idx, now);
        }
        debug_assert!(
            self.aggregate_output_live_bytes() <= self.limits.aggregate_queue_bytes,
            "aggregate output cap exceeded"
        );
    }

    fn handle_conn_events(
        &mut self,
        idx: usize,
        re: PollFlags,
        now: u64,
        discard_budget: &mut usize,
    ) -> io::Result<()> {
        if re.contains(PollFlags::POLLNVAL) {
            self.remove_conn(idx, now);
            return Ok(());
        }
        if re.contains(PollFlags::POLLIN) {
            self.handle_readable(idx, now, discard_budget)?;
        }
        if !self.slot_live(idx) {
            return Ok(());
        }
        if re.contains(PollFlags::POLLOUT) || re.intersects(PollFlags::POLLERR | PollFlags::POLLHUP)
        {
            self.flush_slot(idx, now);
        }
        if self.slot_live(idx) && re.intersects(PollFlags::POLLERR | PollFlags::POLLHUP) {
            self.remove_conn(idx, now);
        }
        Ok(())
    }

    fn slot_live(&self, idx: usize) -> bool {
        self.slots.get(idx).and_then(Option::as_ref).is_some()
    }

    fn handle_readable(
        &mut self,
        idx: usize,
        now: u64,
        discard_budget: &mut usize,
    ) -> io::Result<()> {
        loop {
            // Admission is re-checked before EVERY recv — the poll-set
            // decision alone is never trusted.
            if !self.slot_live(idx) {
                return Ok(());
            }
            {
                let slot = self.slots[idx].as_ref().expect("live slot");
                if !self.read_admitted(slot) {
                    return Ok(());
                }
            }

            let awaiting_grant = matches!(
                self.slots[idx].as_ref().expect("live slot").client.role(),
                ConnRole::AwaitingFirstFrame
            );
            if awaiting_grant && !self.has_output_recipients() {
                if self.discard_master_until_boundary(discard_budget)? == BarrierResult::Deferred {
                    return Ok(());
                }
                // Never cache the safe boundary: the next fragmented
                // first-frame recv must certify it again.
                if !self.slot_live(idx) {
                    return Ok(());
                }
            }

            // Frame-boundary-limited recv keeps pipelined later frames
            // in the socket until the current one has been dispatched.
            let want = self.slots[idx]
                .as_ref()
                .expect("live slot")
                .client
                .reader_bytes_needed()
                .min(self.read_buf.len());
            let n = {
                let fd = self.slots[idx].as_ref().expect("live slot").fd.as_fd();
                match sys::recv(fd, &mut self.read_buf[..want]) {
                    Ok(Some(0)) => {
                        self.remove_conn(idx, now);
                        return Ok(());
                    }
                    Ok(Some(n)) => n,
                    Ok(None) => return Ok(()),
                    Err(error) => match classify_conn_fault(&error) {
                        ConnFault::ConnectionLocal => {
                            self.remove_conn(idx, now);
                            return Ok(());
                        }
                        ConnFault::Systemic => return Err(error),
                    },
                }
            };
            self.consume_chunk(idx, n, now)?;
            if !self.slot_live(idx) {
                return Ok(());
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
                        self.remove_conn(idx, now);
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
                            self.remove_conn(idx, now);
                        } else {
                            self.reconcile_writer_stall(now);
                        }
                    }
                }
                Effect::QueueFrame { target, frame } => {
                    self.queue_effect_frame(target, frame, now);
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
                            self.remove_conn(idx, now);
                        }
                    }
                }
                Effect::DropQueues { target } => {
                    if let Some(idx) = self.resolve(target) {
                        {
                            let slot = self.slots[idx].as_mut().expect("resolved");
                            slot.client.out_mut().clear();
                            slot.client.input_mut().clear();
                        }
                        self.reconcile_writer_stall(now);
                    }
                }
                Effect::CloseNow { conn } => {
                    if let Some(idx) = self.resolve(Target::Conn(conn)) {
                        self.remove_conn(idx, now);
                    }
                }
                Effect::CloseAfterFlush { conn } => {
                    if let Some(idx) = self.resolve(Target::Conn(conn)) {
                        self.begin_draining(idx, now);
                    }
                }
                Effect::CloseClientNow { client_id } => {
                    if let Some(idx) = self.resolve(Target::Client(client_id)) {
                        self.remove_conn(idx, now);
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

    fn queue_effect_frame(&mut self, target: Target, frame: Frame, now: u64) {
        let Some(idx) = self.resolve(target) else {
            return;
        };
        let conn = self.slots[idx].as_ref().expect("resolved").conn;
        let is_control_reply = {
            let slot = self.slots[idx].as_ref().expect("resolved");
            slot.client.role() == ConnRole::Control
                && matches!(
                    frame.kind(),
                    Kind::Pong | Kind::Ownership | Kind::Error | Kind::Exit
                )
        };
        let encoded: SharedChunk = frame.encode().into();
        let encoded_len = encoded.len();

        let target_fits = {
            let out = self.slots[idx].as_ref().expect("resolved").client.out();
            out.live_bytes()
                .checked_add(encoded_len)
                .is_some_and(|projected| projected <= out.cap_bytes())
        };
        if !target_fits {
            self.remove_conn(idx, now);
            return;
        }

        while self
            .aggregate_output_live_bytes()
            .checked_add(encoded_len)
            .is_none_or(|projected| projected > self.limits.aggregate_queue_bytes)
        {
            let Some(observer_idx) = self.most_full_observer(Some((idx, conn)), true) else {
                break;
            };
            self.remove_conn(observer_idx, now);
            if !self.slot_identity_live(idx, conn) {
                return;
            }
        }
        let aggregate_fits = self
            .aggregate_output_live_bytes()
            .checked_add(encoded_len)
            .is_some_and(|projected| projected <= self.limits.aggregate_queue_bytes);
        if !aggregate_fits || !self.slot_identity_live(idx, conn) {
            if self.slot_identity_live(idx, conn) {
                self.remove_conn(idx, now);
            }
            return;
        }

        let queued = self.slots[idx]
            .as_mut()
            .expect("target identity checked")
            .client
            .out_mut()
            .push_shared(encoded);
        if !queued {
            self.remove_conn(idx, now);
            return;
        }
        if is_control_reply {
            self.slots[idx]
                .as_mut()
                .expect("queued target")
                .client
                .arm_reply_deadline(now, self.limits.control_reply_deadline_ms);
        }
        self.reconcile_writer_stall(now);
        self.flush_slot(idx, now);
        debug_assert!(self.aggregate_output_live_bytes() <= self.limits.aggregate_queue_bytes);
    }

    fn begin_draining(&mut self, idx: usize, now: u64) {
        if let Some(slot) = self.slots[idx].as_mut() {
            slot.client.begin_draining();
            slot.client
                .arm_reply_deadline(now, self.limits.control_reply_deadline_ms);
        }
        self.reconcile_writer_stall(now);
        self.flush_slot(idx, now);
    }

    /// Best-effort immediate flush; closes on hard I/O errors and on a
    /// finished drain.
    fn flush_slot(&mut self, idx: usize, now: u64) {
        let result = {
            let Some(slot) = self.slots[idx].as_mut() else {
                return;
            };
            let ConnSlot { fd, client, .. } = slot;
            client
                .out_mut()
                .flush_with(|buf| sys::send_no_sigpipe(fd.as_fd(), buf))
        };
        self.reconcile_writer_stall(now);
        match result {
            Ok(fully_flushed) => {
                let drained_done = fully_flushed
                    && self
                        .slots
                        .get(idx)
                        .and_then(Option::as_ref)
                        .is_some_and(|slot| slot.client.is_draining());
                if drained_done {
                    self.remove_conn(idx, now);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => self.remove_conn(idx, now),
        }
        debug_assert!(self.aggregate_output_live_bytes() <= self.limits.aggregate_queue_bytes);
    }

    /// THE one close path: takes the slot, closes the descriptor
    /// exactly once, and reduces `Disconnected` exactly once with the
    /// former role — writer closure revokes ownership, observer
    /// closure leaves the observer set, and already-revoked or demoted
    /// closes are harmless.
    fn remove_conn(&mut self, idx: usize, now: u64) {
        let Some(slot) = self.slots.get_mut(idx).and_then(Option::take) else {
            return;
        };
        let role = slot.client.role();
        // A takeover joins the old writer to ObserverSet before its
        // ordered SetRole effect. If an intervening bounded queue
        // refusal closes it, repair that pending membership here too.
        if let ConnRole::Writer { client_id } | ConnRole::Observer { client_id } = role {
            self.runtime.observers.leave(client_id);
        }
        drop(slot);
        self.closed_total += 1;
        let fx = state::reduce(
            &mut self.runtime,
            &self.limits,
            Event::Disconnected { role },
        );
        self.apply_effects(fx, now);
        self.reconcile_writer_stall(now);
        debug_assert!(self.aggregate_output_live_bytes() <= self.limits.aggregate_queue_bytes);
    }

    fn resolve_observer(&self, client_id: u32) -> Option<usize> {
        self.slots.iter().position(|slot| {
            slot.as_ref().is_some_and(|slot| {
                matches!(
                    slot.client.role(),
                    ConnRole::Observer { client_id: id } if id == client_id
                )
            })
        })
    }

    fn resolve(&self, target: Target) -> Option<usize> {
        match target {
            Target::Conn(conn) => self
                .slots
                .iter()
                .position(|slot| slot.as_ref().is_some_and(|slot| slot.conn == conn)),
            Target::Client(client_id) => self.slots.iter().position(|slot| {
                slot.as_ref().is_some_and(|slot| {
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
    use std::os::unix::net::UnixStream;
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
                let p = std::env::temp_dir()
                    .join(format!("everpty-brk-{tag}-{}-{n}-{i}", std::process::id()));
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
        broker_with_limits_at(t0, Limits::default())
    }

    fn broker_with_limits_at(t0: u64, limits: Limits) -> (BaseGuard, Rc<Cell<u64>>, Broker) {
        use crate::session::resolve_state_root_from;
        let base = BaseGuard::new("b");
        let root = resolve_state_root_from(std::slice::from_ref(&base.path().to_path_buf()))
            .expect("root");
        let dir = root.session("s1", &limits).expect("session");
        let locked = dir.lock().expect("lock");
        let bound = locked.bind_broker_socket(&limits).expect("bind");
        let clock = Rc::new(Cell::new(t0));
        let broker =
            Broker::new(bound, &limits, Rc::new(MockClock(clock.clone())), None).expect("broker");
        (base, clock, broker)
    }

    fn test_hello(role: crate::frame::Role, take_over: bool) -> Frame {
        Frame::Hello {
            role,
            take_over,
            name: "s1".to_owned(),
            rows: if role == crate::frame::Role::Writer {
                24
            } else {
                0
            },
            cols: if role == crate::frame::Role::Writer {
                80
            } else {
                0
            },
        }
    }

    fn send_test_frame(stream: &mut UnixStream, frame: &Frame) {
        let wire = frame.encode();
        let mut off = 0;
        for _ in 0..64 {
            if off == wire.len() {
                return;
            }
            match stream.write(&wire[off..]) {
                Ok(0) => panic!("zero client write"),
                Ok(n) => off += n,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("client write: {error}"),
            }
        }
        panic!("bounded client write did not finish");
    }

    fn connect_and_grant(
        base: &BaseGuard,
        broker: &mut Broker,
        role: crate::frame::Role,
        take_over: bool,
    ) -> UnixStream {
        let mut stream = UnixStream::connect(base.path().join("s1/socket")).expect("connect");
        stream.set_nonblocking(true).expect("nonblocking");
        send_test_frame(&mut stream, &test_hello(role, take_over));
        for _ in 0..8 {
            broker.run_once(Some(0)).expect("grant pass");
        }
        stream
    }

    fn drain_test_frames(stream: &mut UnixStream, limits: &Limits) -> Vec<Frame> {
        let mut wire = Vec::new();
        let mut chunk = [0u8; 1024];
        for _ in 0..64 {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => wire.extend_from_slice(&chunk[..n]),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("client read: {error}"),
            }
        }
        let mut frames = Vec::new();
        while wire.len() >= frame::HEADER_LEN {
            let total = Frame::validate_header(&wire[..frame::HEADER_LEN], limits).expect("header");
            if wire.len() < total {
                break;
            }
            let (frame, used) = Frame::decode(&wire[..total], limits).expect("frame");
            wire.drain(..used);
            frames.push(frame);
        }
        assert!(wire.is_empty(), "test left a fragmented outbound frame");
        frames
    }

    fn attach_test_master(broker: &mut Broker) -> std::fs::File {
        let (master, slave) = sys::openpty(24, 80).expect("openpty");
        let mut attrs = nix::sys::termios::tcgetattr(&slave).expect("termios");
        nix::sys::termios::cfmakeraw(&mut attrs);
        nix::sys::termios::tcsetattr(&slave, nix::sys::termios::SetArg::TCSANOW, &attrs)
            .expect("raw");
        sys::set_nonblocking(slave.as_fd()).expect("nonblocking slave");
        broker.attach_pty_master(master).expect("attach master");
        std::fs::File::from(slave)
    }

    #[test]
    fn conn_fault_classifier_splits_local_from_systemic() {
        let local = |errno| classify_conn_fault(&io::Error::from_raw_os_error(errno));
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
        w.write_all(&ReadyStatus::Ready.encode()[..5])
            .expect("write 5");
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

    fn one_frame_cap_limits(writer_cap: usize, aggregate_cap: usize) -> Limits {
        Limits {
            frame_max_body: 12,
            read_chunk_bytes: 10,
            writer_queue_bytes: writer_cap,
            observer_queue_bytes: 64,
            aggregate_queue_bytes: aggregate_cap,
            stall_deadline_ms: 10,
            ..Limits::default()
        }
    }

    #[test]
    fn fresh_below_low_deficit_keeps_deadline_and_evicts_exact_writer() {
        let limits = one_frame_cap_limits(16, 128);
        let (base, clock, mut broker) = broker_with_limits_at(100, limits);
        let mut writer = connect_and_grant(&base, &mut broker, crate::frame::Role::Writer, false);
        let mut observer =
            connect_and_grant(&base, &mut broker, crate::frame::Role::Observer, false);
        let _ = drain_test_frames(&mut writer, &limits);
        let _ = drain_test_frames(&mut observer, &limits);
        let mut slave = attach_test_master(&mut broker);

        let (writer_idx, writer_id) = broker.eligible_writer_slot().expect("writer");
        assert!(broker.slots[writer_idx]
            .as_mut()
            .expect("writer")
            .client
            .out_mut()
            .push_shared(vec![0xA5; 7].into()));
        broker.reconcile_writer_stall(100);
        assert_eq!(
            broker.writer_stall_observation(),
            Some((writer_id, 100, WriterStallBand::LowDeficit))
        );
        for now in [101, 105, 110, 111] {
            broker.reconcile_writer_stall(now);
            assert_eq!(
                broker.writer_stall_observation(),
                Some((writer_id, 100, WriterStallBand::LowDeficit)),
                "below-low deadline moved at {now}"
            );
        }

        clock.set(111);
        broker.expire_writer_stall(111);
        assert_eq!(broker.ownership(), Ownership::NoWriter);
        assert_eq!(broker.connection_count(), 1, "observer alone survives");
        assert!(!broker.pty_read_paused());
        assert!(broker
            .master_poll_events()
            .is_some_and(|events| events.contains(PollFlags::POLLIN)));

        slave.write_all(b"resume").expect("post-eviction output");
        for _ in 0..8 {
            broker.run_once(Some(0)).expect("resume pass");
        }
        let output: Vec<u8> = drain_test_frames(&mut observer, &limits)
            .into_iter()
            .filter_map(|frame| match frame {
                Frame::Output(bytes) => Some(bytes),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(output, b"resume");
    }

    #[test]
    fn high_stall_crossing_low_without_headroom_gets_one_fresh_deadline() {
        let limits = one_frame_cap_limits(16, 128);
        let (base, clock, mut broker) = broker_with_limits_at(100, limits);
        let mut writer = connect_and_grant(&base, &mut broker, crate::frame::Role::Writer, false);
        let mut observer =
            connect_and_grant(&base, &mut broker, crate::frame::Role::Observer, false);
        let _ = drain_test_frames(&mut writer, &limits);
        let _ = drain_test_frames(&mut observer, &limits);
        let mut slave = attach_test_master(&mut broker);
        let (idx, writer_id) = broker.eligible_writer_slot().expect("writer");
        assert!(broker.slots[idx]
            .as_mut()
            .expect("writer")
            .client
            .out_mut()
            .push_shared(vec![0xB6; 8].into()));
        broker.reconcile_writer_stall(100);
        assert_eq!(
            broker.writer_stall_observation(),
            Some((writer_id, 100, WriterStallBand::HighEpisode))
        );

        assert!(!broker.slots[idx]
            .as_mut()
            .expect("writer")
            .client
            .out_mut()
            .flush_with(|_| Ok(1))
            .expect("one-byte trickle"));
        broker.reconcile_writer_stall(200);
        assert_eq!(
            broker.writer_stall_observation(),
            Some((writer_id, 200, WriterStallBand::LowDeficit))
        );
        for now in [201, 205, 210, 211] {
            broker.reconcile_writer_stall(now);
            assert_eq!(
                broker.writer_stall_observation(),
                Some((writer_id, 200, WriterStallBand::LowDeficit))
            );
        }
        clock.set(211);
        broker.expire_writer_stall(211);
        assert_eq!(broker.ownership(), Ownership::NoWriter);
        assert_eq!(broker.connection_count(), 1, "only observer survives");
        assert!(!broker.pty_read_paused());
        assert!(broker
            .master_poll_events()
            .is_some_and(|events| events.contains(PollFlags::POLLIN)));
        slave.write_all(b"high-resume").expect("resumed output");
        for _ in 0..8 {
            broker.run_once(Some(0)).expect("resumed pass");
        }
        let output: Vec<u8> = drain_test_frames(&mut observer, &limits)
            .into_iter()
            .filter_map(|frame| match frame {
                Frame::Output(bytes) => Some(bytes),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(output, b"high-resume");
    }

    #[test]
    fn high_episode_ignores_trickle_until_true_low_water_recovery() {
        let limits = one_frame_cap_limits(64, 128);
        let (base, _clock, mut broker) = broker_with_limits_at(100, limits);
        let mut writer = connect_and_grant(&base, &mut broker, crate::frame::Role::Writer, false);
        let _ = drain_test_frames(&mut writer, &limits);
        let (idx, writer_id) = broker.eligible_writer_slot().expect("writer");
        assert!(broker.slots[idx]
            .as_mut()
            .expect("writer")
            .client
            .out_mut()
            .push_shared(vec![7; 55].into()));
        broker.reconcile_writer_stall(100);
        assert_eq!(
            broker.writer_stall_observation(),
            Some((writer_id, 100, WriterStallBand::HighEpisode))
        );
        assert!(!broker.slots[idx]
            .as_mut()
            .expect("writer")
            .client
            .out_mut()
            .flush_with(|_| Ok(10))
            .expect("trickle"));
        broker.reconcile_writer_stall(105);
        assert!(broker.writer_frame_fits(45));
        assert_eq!(
            broker.writer_stall_observation(),
            Some((writer_id, 100, WriterStallBand::HighEpisode))
        );
        assert!(!broker.slots[idx]
            .as_mut()
            .expect("writer")
            .client
            .out_mut()
            .flush_with(|_| Ok(14))
            .expect("below low"));
        broker.reconcile_writer_stall(106);
        assert_eq!(broker.writer_output_live_bytes(), Some(31));
        assert!(!broker.pty_read_paused(), "true recovery clears once");
    }

    #[test]
    fn observer_and_aggregate_evictions_are_preappend_and_deterministic() {
        let limits = one_frame_cap_limits(64, 100);
        let (base, _clock, mut broker) = broker_with_limits_at(0, limits);
        let _writer = connect_and_grant(&base, &mut broker, crate::frame::Role::Writer, false);
        let _first = connect_and_grant(&base, &mut broker, crate::frame::Role::Observer, false);
        let _second = connect_and_grant(&base, &mut broker, crate::frame::Role::Observer, false);
        let first_idx = broker.resolve_observer(2).expect("first observer");
        let second_idx = broker.resolve_observer(3).expect("second observer");
        for idx in [first_idx, second_idx] {
            assert!(broker.slots[idx]
                .as_mut()
                .expect("observer")
                .client
                .out_mut()
                .push_shared(vec![9; 30].into()));
        }
        broker.read_buf[..10].copy_from_slice(b"0123456789");
        broker.fan_out_output(10, 1);
        assert_eq!(broker.role_of_client(2), None, "first tie is evicted");
        assert_eq!(
            broker.role_of_client(3),
            Some(ConnRole::Observer { client_id: 3 })
        );
        assert_eq!(broker.observer_count(), 1);
        assert!(broker.aggregate_output_live_bytes() <= limits.aggregate_queue_bytes);
        assert!(
            !broker.pty_read_paused(),
            "observer pressure never gates PTY reads"
        );
    }

    #[test]
    fn observer_cap_charges_the_complete_output_header_before_append() {
        let mut limits = one_frame_cap_limits(32, 128);
        limits.observer_queue_bytes = 15;
        let (base, _clock, mut broker) = broker_with_limits_at(0, limits);
        let _writer = connect_and_grant(&base, &mut broker, crate::frame::Role::Writer, false);
        let _observer = connect_and_grant(&base, &mut broker, crate::frame::Role::Observer, false);
        broker.read_buf[..10].copy_from_slice(b"0123456789");
        broker.fan_out_output(10, 1);
        assert_eq!(broker.observer_count(), 0, "16-byte frame exceeds cap 15");
        assert_eq!(broker.ownership(), Ownership::Writer(1));
        assert!(broker.aggregate_output_live_bytes() <= limits.aggregate_queue_bytes);
        assert!(!broker.pty_read_paused());
    }

    #[test]
    fn writer_takeover_inherits_no_stall_identity_or_timestamp() {
        let limits = one_frame_cap_limits(32, 128);
        let (base, _clock, mut broker) = broker_with_limits_at(100, limits);
        let _old = connect_and_grant(&base, &mut broker, crate::frame::Role::Writer, false);
        let (idx, old_id) = broker.eligible_writer_slot().expect("old writer");
        assert!(broker.slots[idx]
            .as_mut()
            .expect("old writer")
            .client
            .out_mut()
            .push_shared(vec![8; 20].into()));
        broker.reconcile_writer_stall(100);
        assert_eq!(
            broker.writer_stall_observation(),
            Some((old_id, 100, WriterStallBand::HighEpisode))
        );

        let _new = connect_and_grant(&base, &mut broker, crate::frame::Role::Writer, true);
        assert_eq!(broker.ownership(), Ownership::Writer(2));
        assert_eq!(
            broker.role_of_client(old_id),
            Some(ConnRole::Observer { client_id: old_id })
        );
        assert_eq!(broker.writer_stall_observation(), None);
        assert!(!broker.pty_read_paused());
    }

    #[test]
    fn nonrecipient_queue_is_evicted_for_the_guaranteed_writer_append() {
        let mut limits = one_frame_cap_limits(16, 20);
        limits.observer_queue_bytes = 20;
        let (base, _clock, mut broker) = broker_with_limits_at(0, limits);
        let _writer = connect_and_grant(&base, &mut broker, crate::frame::Role::Writer, false);
        let first = UnixStream::connect(base.path().join("s1/socket")).expect("first awaiting");
        let second = UnixStream::connect(base.path().join("s1/socket")).expect("second awaiting");
        broker.run_once(Some(0)).expect("accept awaiting");
        let awaiting: Vec<usize> = broker
            .slots
            .iter()
            .enumerate()
            .filter_map(|(idx, slot)| {
                matches!(
                    slot.as_ref().map(|slot| slot.client.role()),
                    Some(ConnRole::AwaitingFirstFrame)
                )
                .then_some(idx)
            })
            .collect();
        assert_eq!(awaiting.len(), 2);
        assert!(broker.slots[awaiting[0]]
            .as_mut()
            .expect("awaiting")
            .client
            .out_mut()
            .push_shared(vec![4; 15].into()));
        let target_conn = broker.slots[awaiting[1]].as_ref().expect("target").conn;
        broker.slots[awaiting[1]]
            .as_mut()
            .expect("target")
            .client
            .set_role(&limits, ConnRole::Control)
            .expect("control role");
        broker.queue_effect_frame(Target::Conn(target_conn), Frame::Pong, 1);
        assert!(!broker.slot_identity_live(awaiting[1], target_conn));
        assert_eq!(broker.aggregate_output_live_bytes(), 15);

        broker.read_buf[..10].copy_from_slice(b"abcdefghij");
        broker.fan_out_output(10, 2);
        assert!(!broker.slot_live(awaiting[0]));
        assert_eq!(broker.ownership(), Ownership::Writer(1));
        assert!(broker.aggregate_output_live_bytes() <= limits.aggregate_queue_bytes);
        drop((first, second));
    }

    #[test]
    fn terminal_hint_under_pressure_preserves_master_input_and_deadline() {
        let mut limits = one_frame_cap_limits(32, 128);
        limits.stall_deadline_ms = 50;
        let (base, clock, mut broker) = broker_with_limits_at(100, limits);
        let mut writer = connect_and_grant(&base, &mut broker, crate::frame::Role::Writer, false);
        let mut observer =
            connect_and_grant(&base, &mut broker, crate::frame::Role::Observer, false);
        let _ = drain_test_frames(&mut writer, &limits);
        let _ = drain_test_frames(&mut observer, &limits);
        let mut slave = attach_test_master(&mut broker);
        let (idx, writer_id) = broker.eligible_writer_slot().expect("writer");

        // Fill the real Unix receive path without reading it until a
        // complete writer queue remains EAGAIN'd. Every pass is
        // bounded; no socket-buffer-size assumption determines the
        // exact iteration that stalls.
        for _ in 0..20_000 {
            let live = broker.slots[idx]
                .as_ref()
                .expect("writer")
                .client
                .out()
                .live_bytes();
            if live < limits.writer_queue_bytes {
                assert!(broker.slots[idx]
                    .as_mut()
                    .expect("writer")
                    .client
                    .out_mut()
                    .push_shared(vec![3; limits.writer_queue_bytes - live].into()));
            }
            broker.flush_slot(idx, 100);
            if broker.pty_read_paused() {
                break;
            }
        }
        assert!(broker.pty_read_paused(), "writer socket never stalled");
        assert!(broker.slots[idx]
            .as_mut()
            .expect("writer")
            .client
            .input_mut()
            .push(b"queued-input".to_vec()));
        let original = Some((writer_id, 100, WriterStallBand::HighEpisode));
        assert_eq!(broker.writer_stall_observation(), original);

        slave.write_all(b"final!").expect("final marker");
        drop(slave);
        broker.run_once(Some(0)).expect("real pressure-gated HUP");
        assert!(broker.has_pty_master());
        assert!(broker.pty_terminal_pending());
        assert_eq!(
            broker.writer_input_live_bytes(),
            Some(b"queued-input".len())
        );
        assert_eq!(broker.writer_stall_observation(), original);
        for now in [101, 125, 149] {
            clock.set(now);
            broker.run_once(Some(0)).expect("bounded terminal pass");
            assert!(broker.has_pty_master());
            assert_eq!(broker.writer_stall_observation(), original);
        }

        clock.set(150);
        for _ in 0..8 {
            broker.run_once(Some(0)).expect("expiry/final drain");
            if !broker.has_pty_master() {
                break;
            }
        }
        assert_eq!(broker.ownership(), Ownership::NoWriter);
        assert_eq!(broker.connection_count(), 1);
        assert!(!broker.has_pty_master());
        let output: Vec<u8> = drain_test_frames(&mut observer, &limits)
            .into_iter()
            .filter_map(|frame| match frame {
                Frame::Output(bytes) => Some(bytes),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(output, b"final!");
    }
}
