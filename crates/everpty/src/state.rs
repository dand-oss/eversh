//! Pure poll-event reducer over the M1 [`BrokerState`] transitions
//! (plans/m2-plan.md §5; commit 5).
//!
//! [`reduce`] turns one connection event into an ordered effect list.
//! It performs no I/O and touches no descriptor; the broker executes
//! the effects. Observer membership is an orthogonal
//! [`ObserverSet`]: nothing here mutates the M1 [`Ownership`] for
//! observer operations, so the M1 transition tests stay green.
//!
//! Identifier discipline: `ConnId` names an accepted socket; the
//! protocol `client_id` is granted ONLY with an accepted HelloAck.
//! Control connections, `AwaitingFirstFrame` connections, Busy writers,
//! and cap-rejected connections never consume a client id. Client ids
//! are positive, monotonic, and never wrap.
//!
//! Deferred effects ([`Effect::SpawnChild`], [`Effect::BeginKill`],
//! [`Effect::ApplyDimensions`], [`Effect::Shutdown`]) are recorded,
//! never executed: commit 7 owns signal wiring, child spawn, and
//! shutdown; nothing in this module signals or terminates anything.

use std::fmt;

use crate::client::ConnRole;
use crate::frame::{self, AttachStatus, Frame, Kind, OwnershipEvent};
use crate::lifecycle::{
    BrokerState, InvalidTransition, Lifecycle, Ownership, WriterRequestOutcome,
};
use crate::limits::Limits;

/// Connection identifier: names one accepted socket (distinct from the
/// protocol client id granted with a HelloAck). u64 so a checked,
/// never-reused sequence cannot wrap in any practical lifetime.
pub type ConnId = u64;

/// Wire error codes carried in `Error` frames (§5). Error frames are
/// sent ONLY for semantic errors after a valid v1 frame; framing faults
/// close silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ErrorCode {
    Protocol = 1,
    Forbidden = 2,
    NoWriter = 3,
    ResourceLimit = 4,
    Internal = 5,
}

/// Builds a bounded `Error` frame from a STATIC protocol description
/// (never received payload bytes). The text is capped on a UTF-8
/// character boundary by the MINIMUM of `error_text_max`, `u16::MAX`
/// (the wire length field), and the Error frame's payload headroom
/// under `frame_max_body` (body = version + kind + code + len + text,
/// so text ≤ `frame_max_body - 6`).
pub fn error_frame(code: ErrorCode, text: &str, limits: &Limits) -> Frame {
    let cap = limits
        .error_text_max
        .min(u16::MAX as usize)
        .min(limits.frame_max_body.saturating_sub(6));
    let mut t = text;
    if t.len() > cap {
        let mut end = cap;
        while !t.is_char_boundary(end) {
            end -= 1;
        }
        t = &t[..end];
    }
    Frame::Error {
        code: code as u16,
        text: t.to_owned(),
    }
}

// ---------------------------------------------------------------------------
// Orthogonal observer set
// ---------------------------------------------------------------------------

/// Bounded observer membership, tracked OUTSIDE the M1 `Ownership`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObserverSet {
    members: Vec<u32>,
    cap: usize,
}

impl ObserverSet {
    pub fn new(cap: usize) -> Self {
        Self {
            members: Vec::new(),
            cap,
        }
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.members.len() >= self.cap
    }

    pub fn contains(&self, client_id: u32) -> bool {
        self.members.contains(&client_id)
    }

    pub fn client_ids(&self) -> &[u32] {
        &self.members
    }

    /// Adds a member if capacity permits and it is not already present.
    pub fn join(&mut self, client_id: u32) -> bool {
        if self.is_full() || self.contains(client_id) {
            return false;
        }
        self.members.push(client_id);
        true
    }

    pub fn leave(&mut self, client_id: u32) {
        self.members.retain(|&id| id != client_id);
    }
}

// ---------------------------------------------------------------------------
// Runtime and identifiers
// ---------------------------------------------------------------------------

/// The reducer's mutable world: the M1 state machine, the orthogonal
/// observer set, the session name Hello must match, and the client-id
/// sequence.
pub struct Runtime {
    pub state: BrokerState,
    pub observers: ObserverSet,
    pub session_name: String,
    next_client_id: u32,
}

impl Runtime {
    /// A broker becomes a Runtime exactly when its socket is bound and
    /// readiness signaled: `Starting → WaitingForWriter`.
    pub fn new_ready(session_name: &str, limits: &Limits) -> Result<Self, InvalidTransition> {
        Ok(Self {
            state: BrokerState::new().ready()?,
            observers: ObserverSet::new(limits.observer_count),
            session_name: session_name.to_owned(),
            next_client_id: 1,
        })
    }

    /// Peeks the next candidate client id WITHOUT consuming it:
    /// positive, monotonic, refusing (never wrapping) at exhaustion.
    /// The transition is attempted with the peeked id; only a
    /// successful transition may commit it.
    fn peek_client_id(&self) -> Option<u32> {
        if self.next_client_id == u32::MAX {
            None
        } else {
            Some(self.next_client_id)
        }
    }

    /// Commits the peeked CANDIDATE id — private to this module so the
    /// peek-transition-commit contract cannot be bypassed. Requires
    /// `next_client_id == candidate` and advances with checked
    /// arithmetic only; a mismatch or exhaustion returns `false`
    /// WITHOUT mutating anything. Callers compute the transition first,
    /// commit the candidate, and only then install the mutation — so a
    /// failed commit never leaves lifecycle, ownership, or observer
    /// state partially mutated.
    fn commit_client_id(&mut self, candidate: u32) -> bool {
        if self.next_client_id != candidate {
            return false;
        }
        match candidate.checked_add(1) {
            Some(next) => {
                self.next_client_id = next;
                true
            }
            None => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Effects and events
// ---------------------------------------------------------------------------

/// Where an effect lands: one connection by id, or the connection
/// currently carrying a protocol client id (Writer/Observer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Conn(ConnId),
    Client(u32),
}

/// Ordered effects. `SpawnChild`, `BeginKill`, `ApplyDimensions`, and
/// `Shutdown` are DEFERRED: the broker records them; commit 7 wires
/// their execution. Nothing here may signal or terminate a process.
pub enum Effect {
    SetRole { target: Target, role: ConnRole },
    QueueFrame { target: Target, frame: Frame },
    /// Raw writer input destined for the bounded writer-input queue.
    DeliverInput { client_id: u32, bytes: Vec<u8> },
    /// Discard the target's queued output and input (takeover/detach).
    DropQueues { target: Target },
    /// Silent immediate close (framing faults, deadline expiry).
    CloseNow { conn: ConnId },
    /// Bounded close-after-flush: stop reading, drain the reply, close
    /// on empty or the reply deadline.
    CloseAfterFlush { conn: ConnId },
    /// [`Effect::CloseNow`] resolved by protocol client id.
    CloseClientNow { client_id: u32 },
    /// [`Effect::CloseAfterFlush`] resolved by protocol client id.
    CloseClientAfterFlush { client_id: u32 },
    /// DEFERRED: spawn the PTY child with the granted dimensions.
    SpawnChild { rows: u16, cols: u16 },
    /// DEFERRED: begin the kill path (commit 7: TERM→grace→KILL, reap,
    /// then `Exit` delivery).
    BeginKill,
    /// DEFERRED: apply new dimensions (commit 7: TIOCSWINSZ only when
    /// actually changed).
    ApplyDimensions { rows: u16, cols: u16 },
    /// DEFERRED: broker shutdown (unlink state, close all, exit).
    Shutdown,
}

impl Effect {
    /// Whether this effect must be recorded, not executed, in commit 5.
    pub fn is_deferred(&self) -> bool {
        matches!(
            self,
            Self::SpawnChild { .. }
                | Self::BeginKill
                | Self::ApplyDimensions { .. }
                | Self::Shutdown
        )
    }
}

impl fmt::Debug for Effect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Frame KINDS only — no frame payloads are ever printed.
        let kind = |fr: &Frame| match fr {
            Frame::Hello { .. } => "Hello",
            Frame::HelloAck { .. } => "HelloAck",
            Frame::Busy { .. } => "Busy",
            Frame::Input(_) => "Input",
            Frame::Output(_) => "Output",
            Frame::Resize { .. } => "Resize",
            Frame::Ownership(_) => "Ownership",
            Frame::DetachWriter => "DetachWriter",
            Frame::Kill => "Kill",
            Frame::Ping => "Ping",
            Frame::Pong => "Pong",
            Frame::Exit { .. } => "Exit",
            Frame::Error { .. } => "Error",
        };
        match self {
            Self::SetRole { target, role } => {
                write!(f, "SetRole({target:?}, {role:?})")
            }
            Self::QueueFrame { target, frame } => {
                write!(f, "QueueFrame({target:?}, {})", kind(frame))
            }
            Self::DeliverInput { client_id, bytes } => {
                write!(f, "DeliverInput(client {client_id}, {} bytes)", bytes.len())
            }
            Self::DropQueues { target } => write!(f, "DropQueues({target:?})"),
            Self::CloseNow { conn } => write!(f, "CloseNow({conn})"),
            Self::CloseAfterFlush { conn } => write!(f, "CloseAfterFlush({conn})"),
            Self::CloseClientNow { client_id } => write!(f, "CloseClientNow({client_id})"),
            Self::CloseClientAfterFlush { client_id } => {
                write!(f, "CloseClientAfterFlush({client_id})")
            }
            Self::SpawnChild { rows, cols } => write!(f, "SpawnChild({rows}x{cols})"),
            Self::BeginKill => write!(f, "BeginKill"),
            Self::ApplyDimensions { rows, cols } => write!(f, "ApplyDimensions({rows}x{cols})"),
            Self::Shutdown => write!(f, "Shutdown"),
        }
    }
}

/// One poll-loop event for the reducer.
pub enum Event<'a> {
    /// A complete, decoded frame arrived on a connection with the given
    /// settled role.
    Frame { conn: ConnId, role: ConnRole, frame: &'a Frame },
    /// A connection went away (EOF, HUP, or error close).
    Disconnected { role: ConnRole },
    /// The incomplete-frame deadline expired mid-frame.
    IncompleteFrameExpired { conn: ConnId },
    /// A reply-drain deadline expired.
    ReplyDeadlineExpired { conn: ConnId },
    /// No initial writer arrived before the startup deadline.
    StartupDeadlineExpired,
}

// ---------------------------------------------------------------------------
// The reducer
// ---------------------------------------------------------------------------

/// Pure reduction of one event into ordered effects.
pub fn reduce(rt: &mut Runtime, limits: &Limits, ev: Event<'_>) -> Vec<Effect> {
    match ev {
        Event::Frame { conn, role, frame } => {
            if matches!(
                rt.state.lifecycle,
                Lifecycle::Exited | Lifecycle::Failed
            ) {
                // Terminal broker: no new semantics, no replies owed.
                return vec![Effect::CloseNow { conn }];
            }
            match role {
                ConnRole::AwaitingFirstFrame => match frame.kind() {
                    Kind::Hello => on_hello(rt, limits, conn, frame),
                    Kind::Ping => vec![
                        Effect::SetRole {
                            target: Target::Conn(conn),
                            role: ConnRole::Control,
                        },
                        Effect::QueueFrame {
                            target: Target::Conn(conn),
                            frame: Frame::Pong,
                        },
                        Effect::CloseAfterFlush { conn },
                    ],
                    Kind::DetachWriter => control_detach(rt, limits, conn),
                    Kind::Kill => control_kill(rt, limits, conn),
                    // First-frame taxonomy: every other kind is a
                    // protocol error after a valid frame.
                    _ => protocol_error(limits, conn),
                },
                // Control connections are one-shot: a second frame
                // before the close is a protocol error.
                ConnRole::Control => protocol_error(limits, conn),
                // Observers never send anything after Hello.
                ConnRole::Observer { .. } => protocol_error(limits, conn),
                ConnRole::Writer { client_id } => {
                    on_writer_frame(rt, limits, conn, client_id, frame)
                }
            }
        }
        Event::Disconnected { role } => {
            match role {
                ConnRole::Writer { client_id } => {
                    if rt.state.ownership == Ownership::Writer(client_id) {
                        // The M1 transitions are FUNCTIONAL: the new
                        // state is the return value.
                        if let Ok(next) = rt.state.revoke_writer() {
                            rt.state = next;
                        }
                    }
                }
                ConnRole::Observer { client_id } => rt.observers.leave(client_id),
                ConnRole::Control | ConnRole::AwaitingFirstFrame => {}
            }
            Vec::new()
        }
        Event::IncompleteFrameExpired { conn } => vec![Effect::CloseNow { conn }],
        Event::ReplyDeadlineExpired { conn } => vec![Effect::CloseNow { conn }],
        Event::StartupDeadlineExpired => {
            match rt.state.startup_deadline() {
                Ok(next) => rt.state = next,
                Err(_) => return vec![Effect::Shutdown],
            }
            vec![Effect::Shutdown]
        }
    }
}

fn protocol_error(limits: &Limits, conn: ConnId) -> Vec<Effect> {
    vec![
        Effect::QueueFrame {
            target: Target::Conn(conn),
            frame: error_frame(ErrorCode::Protocol, "protocol error", limits),
        },
        Effect::CloseAfterFlush { conn },
    ]
}

fn on_writer_frame(
    rt: &mut Runtime,
    limits: &Limits,
    conn: ConnId,
    client_id: u32,
    frame: &Frame,
) -> Vec<Effect> {
    let is_current = rt.state.ownership == Ownership::Writer(client_id);
    match frame {
        Frame::Input(bytes) if is_current => vec![Effect::DeliverInput {
            client_id,
            bytes: bytes.clone(),
        }],
        Frame::Resize { rows, cols } => {
            let (rows, cols) = (*rows, *cols);
            // A zero-valued Resize is a protocol error; only the
            // current writer may resize.
            if rows == 0 || cols == 0 || !is_current {
                return protocol_error(limits, conn);
            }
            vec![Effect::ApplyDimensions { rows, cols }]
        }
        Frame::DetachWriter if is_current => {
            // Self-detach: revoke, discard this writer's queues, tell it
            // Revoked, and close after the reply drains. No PTY byte is
            // ever sent.
            match rt.state.revoke_writer() {
                Ok(next) => rt.state = next,
                Err(_) => return internal_error_close(limits, conn),
            }
            vec![
                Effect::DropQueues {
                    target: Target::Conn(conn),
                },
                Effect::QueueFrame {
                    target: Target::Conn(conn),
                    frame: Frame::Ownership(OwnershipEvent::Revoked),
                },
                Effect::CloseAfterFlush { conn },
            ]
        }
        // A second Hello, a post-Hello control frame (Ping/Kill), and
        // every broker→client kind are protocol errors from a writer.
        _ => protocol_error(limits, conn),
    }
}

fn control_detach(rt: &mut Runtime, limits: &Limits, conn: ConnId) -> Vec<Effect> {
    let mut fx = vec![Effect::SetRole {
        target: Target::Conn(conn),
        role: ConnRole::Control,
    }];
    match rt.state.ownership {
        Ownership::NoWriter => {
            // Includes pre-spawn (WaitingForWriter): reported, no
            // lifecycle mutation, nothing terminated.
            fx.push(Effect::QueueFrame {
                target: Target::Conn(conn),
                frame: error_frame(ErrorCode::NoWriter, "no writer", limits),
            });
            fx.push(Effect::CloseAfterFlush { conn });
        }
        Ownership::Writer(w) => {
            match rt.state.revoke_writer() {
                Ok(next) => rt.state = next,
                Err(_) => return internal_error_close(limits, conn),
            }
            fx.push(Effect::DropQueues {
                target: Target::Client(w),
            });
            fx.push(Effect::QueueFrame {
                target: Target::Client(w),
                frame: Frame::Ownership(OwnershipEvent::Revoked),
            });
            fx.push(Effect::CloseClientAfterFlush { client_id: w });
            fx.push(Effect::QueueFrame {
                target: Target::Conn(conn),
                frame: Frame::Ownership(OwnershipEvent::Revoked),
            });
            fx.push(Effect::CloseAfterFlush { conn });
        }
    }
    fx
}

fn control_kill(rt: &mut Runtime, limits: &Limits, conn: ConnId) -> Vec<Effect> {
    let mut fx = vec![Effect::SetRole {
        target: Target::Conn(conn),
        role: ConnRole::Control,
    }];
    match rt.state.lifecycle {
        // Kill depends on the child/lifecycle state, NOT ownership: a
        // child exists in Running whether or not a writer is attached.
        Lifecycle::Running => {
            fx.push(Effect::BeginKill);
            // The control connection stays open awaiting the Exit
            // reply, which commit 7's kill path delivers.
        }
        // Pre-spawn: no child exists; report NoWriter, close, and
        // leave WaitingForWriter untouched — never a secret
        // termination.
        Lifecycle::WaitingForWriter => {
            fx.push(Effect::QueueFrame {
                target: Target::Conn(conn),
                frame: error_frame(ErrorCode::NoWriter, "no writer", limits),
            });
            fx.push(Effect::CloseAfterFlush { conn });
        }
        Lifecycle::Starting | Lifecycle::Exited | Lifecycle::Failed => {
            fx.push(Effect::CloseNow { conn });
        }
    }
    fx
}

fn on_hello(rt: &mut Runtime, limits: &Limits, conn: ConnId, frame: &Frame) -> Vec<Effect> {
    let Frame::Hello {
        role,
        take_over,
        name,
        rows,
        cols,
    } = frame
    else {
        return protocol_error(limits, conn);
    };
    let wire_role = *role;
    let (take_over, rows, cols) = (*take_over, *rows, *cols);
    // The Hello name must match the socket's session.
    if name != &rt.session_name {
        return protocol_error(limits, conn);
    }
    match wire_role {
        frame::Role::Observer => {
            if take_over {
                return vec![Effect::QueueFrame {
                    target: Target::Conn(conn),
                    frame: error_frame(ErrorCode::Forbidden, "observer cannot take over", limits),
                }]
                .close_after_flush(conn);
            }
            if rt.observers.is_full() {
                return vec![Effect::QueueFrame {
                    target: Target::Conn(conn),
                    frame: error_frame(ErrorCode::ResourceLimit, "observer cap reached", limits),
                }]
                .close_after_flush(conn);
            }
            // The id is granted only now that the Hello is accepted:
            // commit the candidate before joining the observer set.
            let Some(client_id) = rt.peek_client_id() else {
                return vec![Effect::QueueFrame {
                    target: Target::Conn(conn),
                    frame: error_frame(ErrorCode::ResourceLimit, "client ids exhausted", limits),
                }]
                .close_after_flush(conn);
            };
            if !rt.commit_client_id(client_id) {
                return internal_error_close(limits, conn);
            }
            rt.observers.join(client_id);
            vec![
                Effect::SetRole {
                    target: Target::Conn(conn),
                    role: ConnRole::Observer { client_id },
                },
                Effect::QueueFrame {
                    target: Target::Conn(conn),
                    frame: Frame::HelloAck {
                        client_id,
                        broker_protocol_version: frame::PROTOCOL_VERSION,
                        status: AttachStatus::ObserverAccepted,
                    },
                },
            ]
        }
        frame::Role::Writer => match rt.state.lifecycle {
            Lifecycle::WaitingForWriter => {
                // The initial writer must carry real dimensions; (0,0)
                // preserve-existing is for later attachers only.
                if rows == 0 || cols == 0 {
                    return protocol_error(limits, conn);
                }
                let Some(client_id) = rt.peek_client_id() else {
                    return resource_limit_close(limits, conn);
                };
                let next = match rt.state.initial_writer(client_id) {
                    Ok(next) => next,
                    Err(_) => return internal_error_close(limits, conn),
                };
                if !rt.commit_client_id(client_id) {
                    return internal_error_close(limits, conn);
                }
                rt.state = next;
                vec![
                    Effect::SetRole {
                        target: Target::Conn(conn),
                        role: ConnRole::Writer { client_id },
                    },
                    Effect::SpawnChild { rows, cols },
                    Effect::QueueFrame {
                        target: Target::Conn(conn),
                        frame: Frame::HelloAck {
                            client_id,
                            broker_protocol_version: frame::PROTOCOL_VERSION,
                            status: AttachStatus::WriterGranted,
                        },
                    },
                ]
            }
            Lifecycle::Running => {
                // A later attach may use exactly (0,0) to preserve the
                // session's size; mixed zero is invalid.
                if (rows == 0) != (cols == 0) {
                    return protocol_error(limits, conn);
                }
                match rt.state.ownership {
                    Ownership::NoWriter => {
                        // take_over is meaningless with no writer; the
                        // M1 transition ignores it.
                        let Some(client_id) = rt.peek_client_id() else {
                            return resource_limit_close(limits, conn);
                        };
                        let (next, outcome) = match rt.state.writer_request(client_id, false) {
                            Ok(r) => r,
                            Err(_) => return internal_error_close(limits, conn),
                        };
                        if !matches!(outcome, WriterRequestOutcome::Granted) {
                            return internal_error_close(limits, conn);
                        }
                        if !rt.commit_client_id(client_id) {
                            return internal_error_close(limits, conn);
                        }
                        rt.state = next;
                        let mut fx = vec![Effect::SetRole {
                            target: Target::Conn(conn),
                            role: ConnRole::Writer { client_id },
                        }];
                        if rows != 0 && cols != 0 {
                            fx.push(Effect::ApplyDimensions { rows, cols });
                        }
                        fx.push(Effect::QueueFrame {
                            target: Target::Conn(conn),
                            frame: Frame::HelloAck {
                                client_id,
                                broker_protocol_version: frame::PROTOCOL_VERSION,
                                status: AttachStatus::WriterGranted,
                            },
                        });
                        fx
                    }
                    Ownership::Writer(current) if !take_over => {
                        // Busy: the frame is owed, ownership/lifecycle/
                        // observers are untouched, and NO client id is
                        // granted.
                        vec![
                            Effect::QueueFrame {
                                target: Target::Conn(conn),
                                frame: Frame::Busy {
                                    current_writer_id: current,
                                },
                            },
                            Effect::CloseAfterFlush { conn },
                        ]
                    }
                    Ownership::Writer(_) => {
                        let Some(client_id) = rt.peek_client_id() else {
                            return resource_limit_close(limits, conn);
                        };
                        let (next, outcome) = match rt.state.writer_request(client_id, true) {
                            Ok(r) => r,
                            Err(_) => return internal_error_close(limits, conn),
                        };
                        let old_writer_id = match outcome {
                            WriterRequestOutcome::TakeOver { old_writer_id } => old_writer_id,
                            _ => return internal_error_close(limits, conn),
                        };
                        if !rt.commit_client_id(client_id) {
                            return internal_error_close(limits, conn);
                        }
                        rt.state = next;
                        // Ordering: discard the old writer's queues →
                        // Revoked to the old writer → old writer becomes
                        // an observer or closes after its reply → the
                        // new writer's nonzero dimensions → SetRole the
                        // new writer → HelloAck → Ownership(Granted).
                        let mut fx = vec![
                            Effect::DropQueues {
                                target: Target::Client(old_writer_id),
                            },
                            Effect::QueueFrame {
                                target: Target::Client(old_writer_id),
                                frame: Frame::Ownership(OwnershipEvent::Revoked),
                            },
                        ];
                        if rt.observers.join(old_writer_id) {
                            fx.push(Effect::SetRole {
                                target: Target::Client(old_writer_id),
                                role: ConnRole::Observer {
                                    client_id: old_writer_id,
                                },
                            });
                        } else {
                            fx.push(Effect::CloseClientAfterFlush {
                                client_id: old_writer_id,
                            });
                        }
                        if rows != 0 && cols != 0 {
                            fx.push(Effect::ApplyDimensions { rows, cols });
                        }
                        fx.push(Effect::SetRole {
                            target: Target::Conn(conn),
                            role: ConnRole::Writer { client_id },
                        });
                        fx.push(Effect::QueueFrame {
                            target: Target::Conn(conn),
                            frame: Frame::HelloAck {
                                client_id,
                                broker_protocol_version: frame::PROTOCOL_VERSION,
                                status: AttachStatus::WriterGranted,
                            },
                        });
                        fx.push(Effect::QueueFrame {
                            target: Target::Conn(conn),
                            frame: Frame::Ownership(OwnershipEvent::Granted),
                        });
                        fx
                    }
                }
            }
            Lifecycle::Starting | Lifecycle::Exited | Lifecycle::Failed => {
                vec![Effect::CloseNow { conn }]
            }
        },
    }
}

fn resource_limit_close(limits: &Limits, conn: ConnId) -> Vec<Effect> {
    vec![Effect::QueueFrame {
        target: Target::Conn(conn),
        frame: error_frame(ErrorCode::ResourceLimit, "client ids exhausted", limits),
    }]
    .close_after_flush(conn)
}

fn internal_error_close(limits: &Limits, conn: ConnId) -> Vec<Effect> {
    vec![Effect::QueueFrame {
        target: Target::Conn(conn),
        frame: error_frame(ErrorCode::Internal, "internal error", limits),
    }]
    .close_after_flush(conn)
}

/// Small helper so error paths read as "frame then bounded close".
trait CloseAfterFlushExt {
    fn close_after_flush(self, conn: ConnId) -> Self;
}

impl CloseAfterFlushExt for Vec<Effect> {
    fn close_after_flush(mut self, conn: ConnId) -> Self {
        self.push(Effect::CloseAfterFlush { conn });
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::Role as WireRole;

    fn limits() -> Limits {
        Limits::default()
    }

    fn fresh_rt() -> Runtime {
        Runtime::new_ready("s1", &limits()).expect("runtime")
    }

    fn running_with_writer(id: u32) -> Runtime {
        let mut rt = fresh_rt();
        // Advance the real allocator so granted ids line up with `id`.
        while rt.next_client_id < id {
            let candidate = rt.peek_client_id().expect("candidate");
            assert!(rt.commit_client_id(candidate));
        }
        let candidate = rt.peek_client_id().expect("candidate");
        assert_eq!(candidate, id);
        assert!(rt.commit_client_id(candidate));
        rt.state = rt
            .state
            .initial_writer(id)
            .expect("initial writer");
        rt
    }

    fn hello(wire_role: WireRole, take_over: bool, rows: u16, cols: u16) -> Frame {
        Frame::Hello {
            role: wire_role,
            take_over,
            name: "s1".to_owned(),
            rows,
            cols,
        }
    }

    fn frame_of(effect: &Effect) -> &Frame {
        match effect {
            Effect::QueueFrame { frame, .. } => frame,
            other => panic!("expected QueueFrame, got {other:?}"),
        }
    }

    fn frames_of(fx: &[Effect]) -> Vec<&Frame> {
        fx.iter().filter_map(|e| match e {
            Effect::QueueFrame { frame, .. } => Some(frame),
            _ => None,
        }).collect()
    }

    #[test]
    fn ids_are_positive_monotonic_and_never_wrap() {
        let mut rt = fresh_rt();
        let mut last = 0;
        for _ in 0..1000 {
            let id = rt.peek_client_id().expect("peek id");
            assert!(id > last);
            last = id;
            assert!(rt.commit_client_id(id), "commit accepts the peeked id");
        }
        rt.next_client_id = u32::MAX;
        assert_eq!(rt.peek_client_id(), None, "exhaustion refuses");
        assert_eq!(rt.peek_client_id(), None, "and keeps refusing");
        // A mismatched candidate is refused WITHOUT mutation.
        rt.next_client_id = 5;
        assert!(!rt.commit_client_id(6), "mismatched candidate refused");
        assert_eq!(rt.next_client_id, 5, "no mutation on mismatch");
        // Exhaustion: the candidate equals next but cannot advance.
        rt.next_client_id = u32::MAX;
        assert!(!rt.commit_client_id(u32::MAX), "exhausted commit refuses");
        assert_eq!(rt.next_client_id, u32::MAX, "no wrap, no mutation");
    }

    #[test]
    fn transitions_actually_mutate_runtime_state() {
        // The M1 transitions are functional; the reducer MUST assign
        // them back. Every mutating path is asserted on the runtime.
        let mut rt = fresh_rt();
        assert_eq!(rt.state.lifecycle, Lifecycle::WaitingForWriter);
        reduce(
            &mut rt,
            &limits(),
            Event::Frame {
                conn: 1,
                role: ConnRole::AwaitingFirstFrame,
                frame: &hello(WireRole::Writer, false, 24, 80),
            },
        );
        assert_eq!(rt.state.lifecycle, Lifecycle::Running, "initial_writer assigned");
        assert_eq!(rt.state.ownership, Ownership::Writer(1));
        // Self-detach revokes for real.
        reduce(&mut rt, &limits(), Event::Frame {
            conn: 1,
            role: ConnRole::Writer { client_id: 1 },
            frame: &Frame::DetachWriter,
        });
        assert_eq!(rt.state.ownership, Ownership::NoWriter, "revoke assigned");
        // A later writer grants again.
        reduce(&mut rt, &limits(), Event::Frame {
            conn: 2,
            role: ConnRole::AwaitingFirstFrame,
            frame: &hello(WireRole::Writer, false, 0, 0),
        });
        assert_eq!(rt.state.ownership, Ownership::Writer(2));
        // Control detach revokes for real.
        reduce(&mut rt, &limits(), Event::Frame {
            conn: 3,
            role: ConnRole::AwaitingFirstFrame,
            frame: &Frame::DetachWriter,
        });
        assert_eq!(rt.state.ownership, Ownership::NoWriter, "control revoke assigned");
        // Writer disconnect revokes for real; a stale id is a no-op.
        reduce(&mut rt, &limits(), Event::Frame {
            conn: 4,
            role: ConnRole::AwaitingFirstFrame,
            frame: &hello(WireRole::Writer, false, 24, 80),
        });
        assert_eq!(rt.state.ownership, Ownership::Writer(3));
        reduce(&mut rt, &limits(), Event::Disconnected { role: ConnRole::Writer { client_id: 2 } });
        assert_eq!(rt.state.ownership, Ownership::Writer(3), "stale disconnect is a no-op");
        reduce(&mut rt, &limits(), Event::Disconnected { role: ConnRole::Writer { client_id: 3 } });
        assert_eq!(rt.state.ownership, Ownership::NoWriter, "disconnect revoke assigned");
        // Startup expiry fails the lifecycle for real.
        let mut rt = fresh_rt();
        reduce(&mut rt, &limits(), Event::StartupDeadlineExpired);
        assert_eq!(rt.state.lifecycle, Lifecycle::Failed, "startup_deadline assigned");
    }

    #[test]
    fn observer_set_caps_and_membership() {
        let mut obs = ObserverSet::new(8);
        for id in 1..=8 {
            assert!(obs.join(id));
        }
        assert!(obs.is_full());
        assert!(!obs.join(9), "cap is hard");
        assert!(!obs.join(1), "duplicate refused");
        obs.leave(4);
        assert!(!obs.contains(4));
        assert!(obs.join(9), "freed slot reusable");
        assert_eq!(obs.client_ids().len(), 8);
    }

    #[test]
    fn first_frame_taxonomy_rejects_every_illegal_kind() {
        let illegal = [
            Frame::Input(vec![0]),
            Frame::Output(vec![0]),
            Frame::Resize { rows: 1, cols: 1 },
            Frame::Pong,
            Frame::HelloAck {
                client_id: 1,
                broker_protocol_version: 1,
                status: AttachStatus::WriterGranted,
            },
            Frame::Exit { signal: false, value: 0 },
            Frame::Error { code: 1, text: "x".to_owned() },
            Frame::Ownership(OwnershipEvent::Granted),
            Frame::Busy { current_writer_id: 1 },
        ];
        for frame in &illegal {
            let mut rt = fresh_rt();
            let fx = reduce(
                &mut rt,
                &limits(),
                Event::Frame { conn: 1, role: ConnRole::AwaitingFirstFrame, frame },
            );
            let frames = frames_of(&fx);
            assert_eq!(frames.len(), 1, "{:?} -> one error frame", frame.kind());
            assert!(matches!(frames[0], Frame::Error { code: 1, .. }), "Protocol=1");
            assert!(matches!(fx.last(), Some(Effect::CloseAfterFlush { conn: 1 })));
            assert_eq!(rt.state.lifecycle, Lifecycle::WaitingForWriter, "no mutation");
        }
    }

    #[test]
    fn initial_writer_flow_grants_id_spawns_and_acks() {
        let mut rt = fresh_rt();
        let fx = reduce(
            &mut rt,
            &limits(),
            Event::Frame {
                conn: 7,
                role: ConnRole::AwaitingFirstFrame,
                frame: &hello(WireRole::Writer, false, 24, 80),
            },
        );
        assert_eq!(rt.state.lifecycle, Lifecycle::Running);
        assert_eq!(rt.state.ownership, Ownership::Writer(1));
        assert!(fx
            .iter()
            .any(|e| matches!(e, Effect::SpawnChild { rows: 24, cols: 80 })));
        let ack = frames_of(&fx)
            .iter()
            .find_map(|f| match f {
                Frame::HelloAck { client_id, status, .. } => Some((*client_id, *status)),
                _ => None,
            })
            .expect("ack");
        assert_eq!(ack, (1, AttachStatus::WriterGranted));
        assert!(matches!(
            fx[0],
            Effect::SetRole { role: ConnRole::Writer { client_id: 1 }, .. }
        ));
    }

    #[test]
    fn initial_writer_requires_real_dimensions() {
        for (rows, cols) in [(0, 0), (0, 80), (24, 0)] {
            let mut rt = fresh_rt();
            let fx = reduce(
                &mut rt,
                &limits(),
                Event::Frame {
                    conn: 1,
                    role: ConnRole::AwaitingFirstFrame,
                    frame: &hello(WireRole::Writer, false, rows, cols),
                },
            );
            assert!(matches!(frames_of(&fx).first(), Some(Frame::Error { code: 1, .. })));
            assert_eq!(rt.state.lifecycle, Lifecycle::WaitingForWriter);
        }
    }

    #[test]
    fn hello_name_mismatch_is_protocol_error() {
        let mut rt = fresh_rt();
        let frame = Frame::Hello {
            role: WireRole::Writer,
            take_over: false,
            name: "other".to_owned(),
            rows: 24,
            cols: 80,
        };
        let fx = reduce(
            &mut rt,
            &limits(),
            Event::Frame {
                conn: 1,
                role: ConnRole::AwaitingFirstFrame,
                frame: &frame,
            },
        );
        assert!(matches!(frames_of(&fx).first(), Some(Frame::Error { code: 1, .. })));
    }

    #[test]
    fn observer_hello_flow_and_guards() {
        // take_over=true → Forbidden.
        let mut rt = fresh_rt();
        let fx = reduce(&mut rt, &limits(), Event::Frame {
            conn: 1,
            role: ConnRole::AwaitingFirstFrame,
            frame: &hello(WireRole::Observer, true, 0, 0),
        });
        assert!(matches!(frames_of(&fx).first(), Some(Frame::Error { code: 2, .. })));

        // Observer may attach while WaitingForWriter; receives ObserverAccepted.
        let mut rt = fresh_rt();
        let fx = reduce(&mut rt, &limits(), Event::Frame {
            conn: 1,
            role: ConnRole::AwaitingFirstFrame,
            frame: &hello(WireRole::Observer, false, 0, 0),
        });
        assert_eq!(rt.observers.len(), 1);
        let ack = frames_of(&fx).iter().find_map(|f| match f {
            Frame::HelloAck { status, .. } => Some(*status),
            _ => None,
        }).expect("ack");
        assert_eq!(ack, AttachStatus::ObserverAccepted);

        // Full set → ResourceLimit, no id granted.
        let mut rt = fresh_rt();
        for id in 1..=8 {
            rt.observers.join(id);
        }
        let fx = reduce(&mut rt, &limits(), Event::Frame {
            conn: 9,
            role: ConnRole::AwaitingFirstFrame,
            frame: &hello(WireRole::Observer, false, 0, 0),
        });
        assert!(matches!(frames_of(&fx).first(), Some(Frame::Error { code: 4, .. })));
        assert_eq!(rt.observers.len(), 8);
        assert_eq!(rt.next_client_id, 1, "no id consumed");
    }

    #[test]
    fn busy_changes_nothing_and_consumes_no_client_id() {
        let mut rt = running_with_writer(1);
        let before = rt.state;
        let fx = reduce(&mut rt, &limits(), Event::Frame {
            conn: 5,
            role: ConnRole::AwaitingFirstFrame,
            frame: &hello(WireRole::Writer, false, 24, 80),
        });
        assert_eq!(rt.state, before, "state untouched");
        assert_eq!(rt.observers.len(), 0);
        assert_eq!(rt.next_client_id, 2, "no id consumed for Busy");
        assert!(matches!(
            frames_of(&fx).first(),
            Some(Frame::Busy { current_writer_id: 1 })
        ));
        assert!(matches!(fx.last(), Some(Effect::CloseAfterFlush { conn: 5 })));
    }

    #[test]
    fn takeover_orders_revoked_discard_grant() {
        let mut rt = running_with_writer(1);
        let fx = reduce(&mut rt, &limits(), Event::Frame {
            conn: 5,
            role: ConnRole::AwaitingFirstFrame,
            frame: &hello(WireRole::Writer, true, 30, 100),
        });
        assert_eq!(rt.state.ownership, Ownership::Writer(2));
        // Exact effect order.
        assert!(matches!(fx[0], Effect::DropQueues { target: Target::Client(1) }));
        assert!(matches!(fx[1], Effect::QueueFrame { target: Target::Client(1), .. }));
        assert!(matches!(frame_of(&fx[1]), Frame::Ownership(OwnershipEvent::Revoked)));
        assert!(matches!(
            fx[2],
            Effect::SetRole {
                target: Target::Client(1),
                role: ConnRole::Observer { client_id: 1 }
            }
        ));
        assert!(matches!(fx[3], Effect::ApplyDimensions { rows: 30, cols: 100 }));
        assert!(matches!(
            fx[4],
            Effect::SetRole {
                target: Target::Conn(5),
                role: ConnRole::Writer { client_id: 2 }
            }
        ));
        assert!(matches!(frame_of(&fx[5]), Frame::HelloAck { .. }));
        assert!(matches!(frame_of(&fx[6]), Frame::Ownership(OwnershipEvent::Granted)));
        assert_eq!(rt.observers.len(), 1, "old writer joined observers");
        // (0,0) takeover preserves size: no dimension effect.
        let mut rt = running_with_writer(1);
        let fx = reduce(&mut rt, &limits(), Event::Frame {
            conn: 6,
            role: ConnRole::AwaitingFirstFrame,
            frame: &hello(WireRole::Writer, true, 0, 0),
        });
        assert!(!fx.iter().any(|e| matches!(e, Effect::ApplyDimensions { .. })));
    }

    #[test]
    fn takeover_without_observer_slot_closes_old_after_flush() {
        let mut rt = running_with_writer(1);
        for id in 2..=9 {
            rt.observers.join(id);
        }
        let fx = reduce(&mut rt, &limits(), Event::Frame {
            conn: 5,
            role: ConnRole::AwaitingFirstFrame,
            frame: &hello(WireRole::Writer, true, 24, 80),
        });
        assert!(
            fx.iter()
                .any(|e| matches!(e, Effect::CloseClientAfterFlush { client_id: 1 }))
        );
        assert!(!rt.observers.contains(1));
    }

    #[test]
    fn running_regrant_preserving_dimensions() {
        let mut rt = running_with_writer(1);
        rt.state = rt.state.revoke_writer().expect("revoke");
        let fx = reduce(&mut rt, &limits(), Event::Frame {
            conn: 5,
            role: ConnRole::AwaitingFirstFrame,
            frame: &hello(WireRole::Writer, false, 0, 0),
        });
        assert_eq!(rt.state.ownership, Ownership::Writer(2));
        assert!(!fx.iter().any(|e| matches!(e, Effect::ApplyDimensions { .. })));
        // Mixed zero is invalid even for a re-attach.
        let mut rt = running_with_writer(1);
        rt.state = rt.state.revoke_writer().expect("revoke");
        let fx = reduce(&mut rt, &limits(), Event::Frame {
            conn: 5,
            role: ConnRole::AwaitingFirstFrame,
            frame: &hello(WireRole::Writer, false, 0, 80),
        });
        assert!(matches!(frames_of(&fx).first(), Some(Frame::Error { code: 1, .. })));
    }

    #[test]
    fn writer_frame_rules() {
        // Input from the current writer is delivered.
        let mut rt = running_with_writer(1);
        let fx = reduce(&mut rt, &limits(), Event::Frame {
            conn: 5,
            role: ConnRole::Writer { client_id: 1 },
            frame: &Frame::Input(vec![9, 9]),
        });
        assert!(matches!(&fx[0], Effect::DeliverInput { client_id: 1, bytes } if bytes == &[9, 9]));

        // Valid Resize applies (deferred).
        let fx = reduce(&mut rt, &limits(), Event::Frame {
            conn: 5,
            role: ConnRole::Writer { client_id: 1 },
            frame: &Frame::Resize { rows: 40, cols: 120 },
        });
        assert!(
            matches!(fx.as_slice(), [Effect::ApplyDimensions { rows: 40, cols: 120 }]),
            "unexpected effects: {fx:?}"
        );

        // Zero-valued Resize is a protocol error.
        for (rows, cols) in [(0, 0), (0, 80), (24, 0)] {
            let fx = reduce(&mut rt, &limits(), Event::Frame {
                conn: 5,
                role: ConnRole::Writer { client_id: 1 },
                frame: &Frame::Resize { rows, cols },
            });
            assert!(matches!(frames_of(&fx).first(), Some(Frame::Error { code: 1, .. })));
        }

        // Post-Hello control frames and a second Hello are protocol
        // errors; Input from a non-current writer is too.
        for frame in [
            Frame::Ping,
            Frame::Kill,
            hello(WireRole::Writer, false, 24, 80),
            Frame::Pong,
        ] {
            let fx = reduce(&mut rt, &limits(), Event::Frame {
                conn: 5,
                role: ConnRole::Writer { client_id: 1 },
                frame: &frame,
            });
            assert!(matches!(frames_of(&fx).first(), Some(Frame::Error { code: 1, .. })));
        }
        let fx = reduce(&mut rt, &limits(), Event::Frame {
            conn: 5,
            role: ConnRole::Writer { client_id: 77 },
            frame: &Frame::Input(vec![1]),
        });
        assert!(matches!(frames_of(&fx).first(), Some(Frame::Error { code: 1, .. })));
    }

    #[test]
    fn observer_any_frame_is_protocol_error() {
        let mut rt = running_with_writer(1);
        for frame in [
            Frame::Ping,
            Frame::Kill,
            Frame::DetachWriter,
            Frame::Input(vec![1]),
            Frame::Resize { rows: 1, cols: 1 },
            hello(WireRole::Observer, false, 0, 0),
        ] {
            let fx = reduce(&mut rt, &limits(), Event::Frame {
                conn: 5,
                role: ConnRole::Observer { client_id: 3 },
                frame: &frame,
            });
            assert!(
                matches!(frames_of(&fx).first(), Some(Frame::Error { code: 1, .. })),
                "{:?}",
                frame.kind()
            );
        }
    }

    #[test]
    fn writer_self_detach_revokes_and_closes_after_reply() {
        let mut rt = running_with_writer(1);
        let fx = reduce(&mut rt, &limits(), Event::Frame {
            conn: 5,
            role: ConnRole::Writer { client_id: 1 },
            frame: &Frame::DetachWriter,
        });
        assert_eq!(rt.state.ownership, Ownership::NoWriter);
        assert!(matches!(fx[0], Effect::DropQueues { .. }));
        assert!(matches!(frame_of(&fx[1]), Frame::Ownership(OwnershipEvent::Revoked)));
        assert!(matches!(fx.last(), Some(Effect::CloseAfterFlush { conn: 5 })));
    }

    #[test]
    fn control_ping_pong_bounded_close() {
        let mut rt = fresh_rt();
        let fx = reduce(&mut rt, &limits(), Event::Frame {
            conn: 2,
            role: ConnRole::AwaitingFirstFrame,
            frame: &Frame::Ping,
        });
        assert!(matches!(fx[0], Effect::SetRole { role: ConnRole::Control, .. }));
        assert!(matches!(frame_of(&fx[1]), Frame::Pong));
        assert!(matches!(fx.last(), Some(Effect::CloseAfterFlush { conn: 2 })));
        // A second frame on a control connection is a protocol error.
        let fx = reduce(&mut rt, &limits(), Event::Frame {
            conn: 2,
            role: ConnRole::Control,
            frame: &Frame::Ping,
        });
        assert!(matches!(frames_of(&fx).first(), Some(Frame::Error { code: 1, .. })));
    }

    #[test]
    fn control_detach_full_sequence() {
        let mut rt = running_with_writer(1);
        let fx = reduce(&mut rt, &limits(), Event::Frame {
            conn: 9,
            role: ConnRole::AwaitingFirstFrame,
            frame: &Frame::DetachWriter,
        });
        assert_eq!(rt.state.ownership, Ownership::NoWriter);
        assert!(matches!(fx[0], Effect::SetRole { role: ConnRole::Control, .. }));
        assert!(matches!(fx[1], Effect::DropQueues { target: Target::Client(1) }));
        assert!(matches!(frame_of(&fx[2]), Frame::Ownership(OwnershipEvent::Revoked)));
        assert!(matches!(fx[3], Effect::CloseClientAfterFlush { client_id: 1 }));
        assert!(matches!(frame_of(&fx[4]), Frame::Ownership(OwnershipEvent::Revoked)));
        assert!(matches!(fx.last(), Some(Effect::CloseAfterFlush { conn: 9 })));
    }

    #[test]
    fn control_detach_without_writer_reports_and_preserves_lifecycle() {
        for setup in ["waiting", "running-revoked"] {
            let mut rt = match setup {
                "waiting" => fresh_rt(),
                _ => {
                    let mut rt = running_with_writer(1);
                    rt.state = rt.state.revoke_writer().expect("revoke");
                    rt
                }
            };
            let before = rt.state;
            let fx = reduce(&mut rt, &limits(), Event::Frame {
                conn: 9,
                role: ConnRole::AwaitingFirstFrame,
                frame: &Frame::DetachWriter,
            });
            assert_eq!(rt.state, before, "{setup}: no mutation");
            assert!(
                matches!(frames_of(&fx).first(), Some(Frame::Error { code: 3, .. })),
                "NoWriter=3"
            );
        }
    }

    #[test]
    fn control_kill_depends_on_lifecycle_not_ownership() {
        // Pre-spawn: NoWriter error, lifecycle untouched.
        let mut rt = fresh_rt();
        let before = rt.state;
        let fx = reduce(&mut rt, &limits(), Event::Frame {
            conn: 9,
            role: ConnRole::AwaitingFirstFrame,
            frame: &Frame::Kill,
        });
        assert_eq!(rt.state, before);
        assert!(matches!(frames_of(&fx).first(), Some(Frame::Error { code: 3, .. })));
        assert!(!fx.iter().any(|e| matches!(e, Effect::BeginKill)));

        // Running with a writer: deferred BeginKill only.
        let mut rt = running_with_writer(1);
        let fx = reduce(&mut rt, &limits(), Event::Frame {
            conn: 9,
            role: ConnRole::AwaitingFirstFrame,
            frame: &Frame::Kill,
        });
        assert_eq!(rt.state.lifecycle, Lifecycle::Running, "no terminal jump");
        assert!(fx.iter().any(|e| matches!(e, Effect::BeginKill)));
        assert!(
            !fx.iter().any(|e| {
                matches!(e, Effect::CloseAfterFlush { .. }) || matches!(e, Effect::CloseNow { .. })
            }),
            "control client stays open awaiting Exit"
        );

        // Running with NO writer: still BeginKill.
        let mut rt = running_with_writer(1);
        rt.state = rt.state.revoke_writer().expect("revoke");
        let fx = reduce(&mut rt, &limits(), Event::Frame {
            conn: 9,
            role: ConnRole::AwaitingFirstFrame,
            frame: &Frame::Kill,
        });
        assert!(fx.iter().any(|e| matches!(e, Effect::BeginKill)));
    }

    #[test]
    fn disconnect_revoke_and_observer_leave() {
        let mut rt = running_with_writer(1);
        rt.observers.join(3);
        reduce(&mut rt, &limits(), Event::Disconnected { role: ConnRole::Writer { client_id: 1 } });
        assert_eq!(rt.state.ownership, Ownership::NoWriter);
        reduce(
            &mut rt,
            &limits(),
            Event::Disconnected {
                role: ConnRole::Observer { client_id: 3 },
            },
        );
        assert!(!rt.observers.contains(3));
        // A stale writer disconnect must not revoke the new writer.
        let mut rt = running_with_writer(2);
        reduce(&mut rt, &limits(), Event::Disconnected { role: ConnRole::Writer { client_id: 1 } });
        assert_eq!(rt.state.ownership, Ownership::Writer(2));
    }

    #[test]
    fn deadline_events_close_now() {
        let mut rt = fresh_rt();
        for ev in [
            Event::IncompleteFrameExpired { conn: 4 },
            Event::ReplyDeadlineExpired { conn: 4 },
        ] {
            let fx = reduce(&mut rt, &limits(), ev);
            assert!(
                matches!(fx.as_slice(), [Effect::CloseNow { conn: 4 }]),
                "unexpected effects: {fx:?}"
            );
        }
    }

    #[test]
    fn startup_deadline_fails_and_shuts_down() {
        let mut rt = fresh_rt();
        let fx = reduce(&mut rt, &limits(), Event::StartupDeadlineExpired);
        assert_eq!(rt.state.lifecycle, Lifecycle::Failed);
        assert!(
            matches!(fx.as_slice(), [Effect::Shutdown]),
            "unexpected effects: {fx:?}"
        );
    }

    #[test]
    fn id_exhaustion_rejects_only_the_attempted_grant() {
        let mut rt = running_with_writer(1);
        rt.next_client_id = u32::MAX;
        // A takeover attempt peeks an id, finds exhaustion, and refuses
        // with ResourceLimit while the existing writer is untouched.
        // (A no-takeover attempt is Busy — which never peeks an id at
        // all, as its own test pins.)
        let fx = reduce(&mut rt, &limits(), Event::Frame {
            conn: 5,
            role: ConnRole::AwaitingFirstFrame,
            frame: &hello(WireRole::Writer, true, 24, 80),
        });
        assert!(matches!(frames_of(&fx).first(), Some(Frame::Error { code: 4, .. })));
        assert_eq!(rt.state.ownership, Ownership::Writer(1), "existing clients unaffected");
    }

    #[test]
    fn error_frame_text_is_bounded_static_utf8() {
        let mut narrow = limits();
        narrow.error_text_max = 3;
        let f = error_frame(ErrorCode::Protocol, "protocol error", &narrow);
        assert!(matches!(f, Frame::Error { code: 1, ref text } if text.len() <= 3));
        // Multi-byte boundary: 3 bytes would split this 2-byte char.
        let f = error_frame(ErrorCode::Protocol, "éée", &narrow);
        assert!(matches!(f, Frame::Error { ref text, .. } if text.len() == 2));
        // A tiny frame cap bounds the text through the payload
        // headroom even when error_text_max is generous: body = 2 + 4
        // + text ≤ frame_max_body → text ≤ frame_max_body - 6.
        let mut tiny = limits();
        tiny.frame_max_body = 10;
        let f = error_frame(ErrorCode::Protocol, "protocol error", &tiny);
        assert!(matches!(f, Frame::Error { ref text, .. } if text.len() <= 4));
    }
}
