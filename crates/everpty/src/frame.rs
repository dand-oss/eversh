//! Versioned length-prefixed local frame codec (design 5.2, 4).
//!
//! Wire format: `u32 body_length (BE) | u8 protocol_version | u8
//! message_kind | payload[]`. All integers big-endian. The header is
//! validated against the configured cap BEFORE any payload buffer is
//! allocated. Raw PTY bytes occur only in `Input`/`Output`.

use crate::error::Error;
use crate::limits::Limits;

pub const PROTOCOL_VERSION: u8 = 1;
pub const HEADER_LEN: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Hello = 1,
    HelloAck = 2,
    Busy = 3,
    Input = 4,
    Output = 5,
    Resize = 6,
    Ownership = 7,
    DetachWriter = 8,
    Kill = 9,
    Ping = 10,
    Pong = 11,
    Exit = 12,
    Error = 13,
    Signal = 14,
    GatewayHello = 15,
    Lease = 16,
}

impl Kind {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Hello,
            2 => Self::HelloAck,
            3 => Self::Busy,
            4 => Self::Input,
            5 => Self::Output,
            6 => Self::Resize,
            7 => Self::Ownership,
            8 => Self::DetachWriter,
            9 => Self::Kill,
            10 => Self::Ping,
            11 => Self::Pong,
            12 => Self::Exit,
            13 => Self::Error,
            14 => Self::Signal,
            15 => Self::GatewayHello,
            16 => Self::Lease,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// `u8 role | u8 take_over | u16 name_len | name | u16 rows | u16 cols`
    Hello {
        role: Role,
        take_over: bool,
        name: String,
        rows: u16,
        cols: u16,
    },
    /// Fast-path writer hello. The broker additionally binds the current
    /// same-UID peer credentials to `pid` and `/proc/<pid>/stat` start time
    /// before considering a PTY lease.
    ///
    /// `u8 take_over | u16 name_len | name | u16 rows | u16 cols |
    ///  [u8;16] gateway_generation | u32 pid | u64 start_ticks`
    GatewayHello {
        take_over: bool,
        name: String,
        rows: u16,
        cols: u16,
        generation: [u8; 16],
        pid: u32,
        start_ticks: u64,
    },
    /// `u32 client_id | u8 broker_protocol_version | u8 status`
    HelloAck {
        client_id: u32,
        broker_protocol_version: u8,
        status: AttachStatus,
    },
    /// `u32 current_writer_id`
    Busy {
        current_writer_id: u32,
    },
    /// Raw input bytes (arbitrary; never UTF-8-assumed).
    Input(Vec<u8>),
    /// Raw PTY output bytes.
    Output(Vec<u8>),
    /// `u16 rows | u16 cols`
    Resize {
        rows: u16,
        cols: u16,
    },
    /// `u8 signal`; allow-listed process-group signal for the current writer.
    Signal {
        signal: u8,
    },
    /// Fixed-size fast-path lease state. The duplicated PTY descriptor is
    /// ancillary to `Grant`; no descriptor is represented in these bytes.
    Lease {
        action: LeaseAction,
        generation: [u8; 16],
        lease_id: u64,
    },
    /// `u8 event`
    Ownership(OwnershipEvent),
    DetachWriter,
    Kill,
    Ping,
    Pong,
    /// `u8 kind | u32 value`
    Exit {
        signal: bool,
        value: u32,
    },
    /// `u16 code | u16 len | UTF-8 bytes`
    Error {
        code: u16,
        text: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    Writer = 1,
    Observer = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AttachStatus {
    WriterGranted = 1,
    ObserverAccepted = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OwnershipEvent {
    Granted = 1,
    Revoked = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LeaseAction {
    Grant = 1,
    Commit = 2,
    Committed = 3,
    Release = 4,
    Released = 5,
    Revoke = 6,
    Unavailable = 7,
    Barrier = 8,
    BarrierAck = 9,
}

impl LeaseAction {
    fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::Grant,
            2 => Self::Commit,
            3 => Self::Committed,
            4 => Self::Release,
            5 => Self::Released,
            6 => Self::Revoke,
            7 => Self::Unavailable,
            8 => Self::Barrier,
            9 => Self::BarrierAck,
            _ => return None,
        })
    }
}

#[derive(Debug)]
pub enum FrameError {
    /// Header length exceeds the configured cap — detected before any
    /// payload allocation.
    BodyTooLarge {
        declared: u32,
        cap: usize,
    },
    UnsupportedVersion {
        got: u8,
    },
    UnknownKind {
        got: u8,
    },
    Truncated,
    Malformed(&'static str),
    NameInvalid,
    TextNotUtf8,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BodyTooLarge { declared, cap } => {
                write!(f, "frame body {declared} exceeds cap {cap}")
            }
            Self::UnsupportedVersion { got } => write!(f, "unsupported protocol version {got}"),
            Self::UnknownKind { got } => write!(f, "unknown message kind {got}"),
            Self::Truncated => write!(f, "truncated frame"),
            Self::Malformed(m) => write!(f, "malformed frame: {m}"),
            Self::NameInvalid => write!(f, "invalid session name"),
            Self::TextNotUtf8 => write!(f, "control text is not UTF-8"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<FrameError> for Error {
    fn from(e: FrameError) -> Self {
        Self::Io(std::io::Error::other(e))
    }
}

/// Validate a session name: 1..=name_max bytes, `[A-Za-z0-9._-]`, first
/// byte alphanumeric. Never a shell fragment.
pub fn validate_name(name: &str, limits: &Limits) -> bool {
    let b = name.as_bytes();
    if b.is_empty() || b.len() > limits.name_max {
        return false;
    }
    if !b[0].is_ascii_alphanumeric() {
        return false;
    }
    b.iter()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

impl Frame {
    pub fn kind(&self) -> Kind {
        match self {
            Self::Hello { .. } => Kind::Hello,
            Self::GatewayHello { .. } => Kind::GatewayHello,
            Self::HelloAck { .. } => Kind::HelloAck,
            Self::Busy { .. } => Kind::Busy,
            Self::Input(_) => Kind::Input,
            Self::Output(_) => Kind::Output,
            Self::Resize { .. } => Kind::Resize,
            Self::Signal { .. } => Kind::Signal,
            Self::Lease { .. } => Kind::Lease,
            Self::Ownership(_) => Kind::Ownership,
            Self::DetachWriter => Kind::DetachWriter,
            Self::Kill => Kind::Kill,
            Self::Ping => Kind::Ping,
            Self::Pong => Kind::Pong,
            Self::Exit { .. } => Kind::Exit,
            Self::Error { .. } => Kind::Error,
        }
    }

    /// Encode into an existing buffer (header + payload).
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        let mut payload = Vec::new();
        match self {
            Self::Hello {
                role,
                take_over,
                name,
                rows,
                cols,
            } => {
                payload.push(*role as u8);
                payload.push(u8::from(*take_over));
                put_u16(&mut payload, name.len() as u16);
                payload.extend_from_slice(name.as_bytes());
                put_u16(&mut payload, *rows);
                put_u16(&mut payload, *cols);
            }
            Self::GatewayHello {
                take_over,
                name,
                rows,
                cols,
                generation,
                pid,
                start_ticks,
            } => {
                payload.push(u8::from(*take_over));
                put_u16(&mut payload, name.len() as u16);
                payload.extend_from_slice(name.as_bytes());
                put_u16(&mut payload, *rows);
                put_u16(&mut payload, *cols);
                payload.extend_from_slice(generation);
                put_u32(&mut payload, *pid);
                put_u64(&mut payload, *start_ticks);
            }
            Self::HelloAck {
                client_id,
                broker_protocol_version,
                status,
            } => {
                put_u32(&mut payload, *client_id);
                payload.push(*broker_protocol_version);
                payload.push(*status as u8);
            }
            Self::Busy { current_writer_id } => put_u32(&mut payload, *current_writer_id),
            Self::Input(b) | Self::Output(b) => payload.extend_from_slice(b),
            Self::Resize { rows, cols } => {
                put_u16(&mut payload, *rows);
                put_u16(&mut payload, *cols);
            }
            Self::Signal { signal } => payload.push(*signal),
            Self::Lease {
                action,
                generation,
                lease_id,
            } => {
                payload.push(*action as u8);
                payload.extend_from_slice(generation);
                put_u64(&mut payload, *lease_id);
            }
            Self::Ownership(e) => payload.push(*e as u8),
            Self::DetachWriter | Self::Kill | Self::Ping | Self::Pong => {}
            Self::Exit { signal, value } => {
                payload.push(u8::from(*signal));
                put_u32(&mut payload, *value);
            }
            Self::Error { code, text } => {
                put_u16(&mut payload, *code);
                put_u16(&mut payload, text.len() as u16);
                payload.extend_from_slice(text.as_bytes());
            }
        }
        out.reserve(HEADER_LEN + payload.len());
        put_u32(out, (payload.len() + 2) as u32); // version + kind + payload
        out.push(PROTOCOL_VERSION);
        out.push(self.kind() as u8);
        out.extend_from_slice(&payload);
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::new();
        self.encode_into(&mut v);
        v
    }

    /// Validate a header (first HEADER_LEN bytes) against the cap. Returns
    /// the total frame length on success. This is the ONLY gate that must
    /// run before any payload-sized allocation.
    pub fn validate_header(header: &[u8], limits: &Limits) -> Result<usize, FrameError> {
        if header.len() < HEADER_LEN {
            return Err(FrameError::Truncated);
        }
        let body = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
        if header[4] != PROTOCOL_VERSION {
            return Err(FrameError::UnsupportedVersion { got: header[4] });
        }
        if Kind::from_u8(header[5]).is_none() {
            return Err(FrameError::UnknownKind { got: header[5] });
        }
        if body < 2 || body > limits.frame_max_body {
            return Err(FrameError::BodyTooLarge {
                declared: body as u32,
                cap: limits.frame_max_body,
            });
        }
        Ok(HEADER_LEN + body - 2)
    }

    /// Decode one frame from a complete buffer, consuming it. `limits`
    /// bounds are re-checked; the caller must have validated the header
    /// (or rely on the internal checks, which are total).
    pub fn decode(buf: &[u8], limits: &Limits) -> Result<(Self, usize), FrameError> {
        let total = Self::validate_header(buf, limits)?;
        if buf.len() < total {
            return Err(FrameError::Truncated);
        }
        let body = &buf[HEADER_LEN..total];
        let kind = Kind::from_u8(buf[5]).expect("validated above");
        let frame = match kind {
            Kind::Hello => {
                if body.len() < 8 {
                    return Err(FrameError::Malformed("hello too short"));
                }
                let role = match body[0] {
                    1 => Role::Writer,
                    2 => Role::Observer,
                    _ => return Err(FrameError::Malformed("bad role")),
                };
                let take_over = match body[1] {
                    0 => false,
                    1 => true,
                    _ => return Err(FrameError::Malformed("bad take_over")),
                };
                let name_len = u16::from_be_bytes([body[2], body[3]]) as usize;
                if 4 + name_len + 4 > body.len() {
                    return Err(FrameError::Truncated);
                }
                if 4 + name_len + 4 < body.len() {
                    return Err(FrameError::Malformed("hello trailing bytes"));
                }
                let name = std::str::from_utf8(&body[4..4 + name_len])
                    .map_err(|_| FrameError::TextNotUtf8)?
                    .to_owned();
                if !validate_name(&name, limits) {
                    return Err(FrameError::NameInvalid);
                }
                let rows = u16::from_be_bytes([body[4 + name_len], body[5 + name_len]]);
                let cols = u16::from_be_bytes([body[6 + name_len], body[7 + name_len]]);
                Self::Hello {
                    role,
                    take_over,
                    name,
                    rows,
                    cols,
                }
            }
            Kind::GatewayHello => {
                if body.len() < 35 {
                    return Err(FrameError::Malformed("gateway hello too short"));
                }
                let take_over = match body[0] {
                    0 => false,
                    1 => true,
                    _ => return Err(FrameError::Malformed("bad gateway take_over")),
                };
                let name_len = u16::from_be_bytes([body[1], body[2]]) as usize;
                let expected = 35_usize
                    .checked_add(name_len)
                    .ok_or(FrameError::Malformed("gateway hello length"))?;
                if body.len() != expected {
                    return Err(FrameError::Malformed("gateway hello length"));
                }
                let name_end = 3 + name_len;
                let name = std::str::from_utf8(&body[3..name_end])
                    .map_err(|_| FrameError::TextNotUtf8)?
                    .to_owned();
                if !validate_name(&name, limits) {
                    return Err(FrameError::NameInvalid);
                }
                let rows = u16::from_be_bytes([body[name_end], body[name_end + 1]]);
                let cols = u16::from_be_bytes([body[name_end + 2], body[name_end + 3]]);
                let generation_start = name_end + 4;
                let mut generation = [0_u8; 16];
                generation.copy_from_slice(&body[generation_start..generation_start + 16]);
                let pid_start = generation_start + 16;
                let pid = u32::from_be_bytes(
                    body[pid_start..pid_start + 4]
                        .try_into()
                        .expect("fixed checked slice"),
                );
                let ticks_start = pid_start + 4;
                let start_ticks = u64::from_be_bytes(
                    body[ticks_start..ticks_start + 8]
                        .try_into()
                        .expect("fixed checked slice"),
                );
                if generation == [0; 16] || pid == 0 || start_ticks == 0 {
                    return Err(FrameError::Malformed("invalid gateway identity"));
                }
                Self::GatewayHello {
                    take_over,
                    name,
                    rows,
                    cols,
                    generation,
                    pid,
                    start_ticks,
                }
            }
            Kind::HelloAck => {
                if body.len() != 6 {
                    return Err(FrameError::Malformed("helloack length"));
                }
                Self::HelloAck {
                    client_id: u32::from_be_bytes([body[0], body[1], body[2], body[3]]),
                    broker_protocol_version: body[4],
                    status: match body[5] {
                        1 => AttachStatus::WriterGranted,
                        2 => AttachStatus::ObserverAccepted,
                        _ => return Err(FrameError::Malformed("bad status")),
                    },
                }
            }
            Kind::Busy => {
                if body.len() != 4 {
                    return Err(FrameError::Malformed("busy length"));
                }
                Self::Busy {
                    current_writer_id: u32::from_be_bytes([body[0], body[1], body[2], body[3]]),
                }
            }
            Kind::Input | Kind::Output => {
                let mut b = Vec::with_capacity(body.len().saturating_sub(2));
                b.extend_from_slice(body);
                if kind == Kind::Input {
                    Self::Input(b)
                } else {
                    Self::Output(b)
                }
            }
            Kind::Resize => {
                if body.len() != 4 {
                    return Err(FrameError::Malformed("resize length"));
                }
                Self::Resize {
                    rows: u16::from_be_bytes([body[0], body[1]]),
                    cols: u16::from_be_bytes([body[2], body[3]]),
                }
            }
            Kind::Signal => {
                if body.len() != 1 || !signal_is_allowed(body[0]) {
                    return Err(FrameError::Malformed("invalid process-group signal"));
                }
                Self::Signal { signal: body[0] }
            }
            Kind::Lease => {
                if body.len() != 25 {
                    return Err(FrameError::Malformed("lease length"));
                }
                let action =
                    LeaseAction::from_u8(body[0]).ok_or(FrameError::Malformed("lease action"))?;
                let mut generation = [0_u8; 16];
                generation.copy_from_slice(&body[1..17]);
                let lease_id =
                    u64::from_be_bytes(body[17..25].try_into().expect("fixed checked slice"));
                let valid_id = match action {
                    LeaseAction::Unavailable => lease_id == 0,
                    _ => lease_id != 0,
                };
                if generation == [0; 16] || !valid_id {
                    return Err(FrameError::Malformed("invalid lease identity"));
                }
                Self::Lease {
                    action,
                    generation,
                    lease_id,
                }
            }
            Kind::Ownership => {
                if body.len() != 1 {
                    return Err(FrameError::Malformed("ownership length"));
                }
                Self::Ownership(match body[0] {
                    1 => OwnershipEvent::Granted,
                    2 => OwnershipEvent::Revoked,
                    _ => return Err(FrameError::Malformed("bad ownership event")),
                })
            }
            Kind::DetachWriter => empty(body, Self::DetachWriter)?,
            Kind::Kill => empty(body, Self::Kill)?,
            Kind::Ping => empty(body, Self::Ping)?,
            Kind::Pong => empty(body, Self::Pong)?,
            Kind::Exit => {
                if body.len() != 5 {
                    return Err(FrameError::Malformed("exit length"));
                }
                let signal = match body[0] {
                    0 => false,
                    1 => true,
                    _ => return Err(FrameError::Malformed("bad exit signal")),
                };
                Self::Exit {
                    signal,
                    value: u32::from_be_bytes([body[1], body[2], body[3], body[4]]),
                }
            }
            Kind::Error => {
                if body.len() < 4 {
                    return Err(FrameError::Malformed("error too short"));
                }
                let code = u16::from_be_bytes([body[0], body[1]]);
                let len = u16::from_be_bytes([body[2], body[3]]) as usize;
                if 4 + len != body.len() || len > limits.error_text_max {
                    return Err(FrameError::Malformed("error text length"));
                }
                let text = std::str::from_utf8(&body[4..])
                    .map_err(|_| FrameError::TextNotUtf8)?
                    .to_owned();
                Self::Error { code, text }
            }
        };
        Ok((frame, total))
    }
}

/// Stable allow-list shared with the direct-QUIC input protocol. Values are
/// POSIX/Linux signal numbers carried on the local same-UID broker socket.
pub const fn signal_is_allowed(signal: u8) -> bool {
    matches!(signal, 1 | 2 | 3 | 15 | 18 | 20)
}

fn empty(body: &[u8], f: Frame) -> Result<Frame, FrameError> {
    if body.is_empty() {
        Ok(f)
    } else {
        Err(FrameError::Malformed("payload must be empty"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn typed_frames() -> Vec<Frame> {
        vec![
            Frame::Hello {
                role: Role::Writer,
                take_over: true,
                name: "s1".into(),
                rows: 252,
                cols: 206,
            },
            Frame::Hello {
                role: Role::Observer,
                take_over: false,
                name: "a.b-_c9".into(),
                rows: 1,
                cols: 2,
            },
            Frame::GatewayHello {
                take_over: true,
                name: "lease-1".into(),
                rows: 41,
                cols: 132,
                generation: [0x5a; 16],
                pid: 4242,
                start_ticks: 987_654,
            },
            Frame::HelloAck {
                client_id: 7,
                broker_protocol_version: PROTOCOL_VERSION,
                status: AttachStatus::ObserverAccepted,
            },
            Frame::Busy {
                current_writer_id: 42,
            },
            Frame::Resize {
                rows: 80,
                cols: 240,
            },
            Frame::Signal { signal: 2 },
            Frame::Lease {
                action: LeaseAction::Grant,
                generation: [0xa5; 16],
                lease_id: 1,
            },
            Frame::Lease {
                action: LeaseAction::Unavailable,
                generation: [0xa5; 16],
                lease_id: 0,
            },
            Frame::Ownership(OwnershipEvent::Granted),
            Frame::Ownership(OwnershipEvent::Revoked),
            Frame::DetachWriter,
            Frame::Kill,
            Frame::Ping,
            Frame::Pong,
            Frame::Exit {
                signal: true,
                value: 9,
            },
            Frame::Exit {
                signal: false,
                value: 3,
            },
            Frame::Error {
                code: 513,
                text: "boom".into(),
            },
        ]
    }

    /// A canonical encoding of `frame` with `extra` bytes appended to the
    /// payload and the header body length patched to match.
    fn with_trailing(frame: &Frame, extra: &[u8]) -> Vec<u8> {
        let mut b = frame.encode();
        let body = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        b[..4].copy_from_slice(&(body + extra.len() as u32).to_be_bytes());
        b.extend_from_slice(extra);
        b
    }

    #[test]
    fn typed_kinds_reject_trailing_bytes() {
        let l = Limits::default();
        for f in typed_frames() {
            // The exact-length body still decodes and re-encodes
            // byte-identically.
            let pristine = f.encode();
            let (back, used) = match Frame::decode(&pristine, &l) {
                Ok(ok) => ok,
                Err(e) => panic!("{:?} must decode, got {e:?}", f.kind()),
            };
            assert_eq!(used, pristine.len());
            assert_eq!(back.encode(), pristine);
            // One trailing byte must never be accepted silently.
            let padded = with_trailing(&f, &[0x00]);
            assert!(
                Frame::decode(&padded, &l).is_err(),
                "{:?} must reject a trailing byte",
                f.kind()
            );
        }
    }

    #[test]
    fn hello_rejects_trailing_garbage_shapes() {
        // The 20260902 fuzz_frame crash shape: a valid Hello whose parsed
        // fields end early, here 1, 2, and 27 trailing bytes.
        let l = Limits::default();
        let hello = Frame::Hello {
            role: Role::Writer,
            take_over: false,
            name: "1".into(),
            rows: 0x00fc,
            cols: 0x00ce,
        };
        for extra in [&[0xce][..], &[0xce, 0xce][..], &[0x2au8; 27][..]] {
            let padded = with_trailing(&hello, extra);
            match Frame::decode(&padded, &l) {
                Err(FrameError::Malformed(m)) => assert_eq!(m, "hello trailing bytes"),
                other => panic!("expected Malformed, got {other:?}"),
            }
        }
    }

    #[test]
    fn exit_signal_byte_must_be_canonical() {
        let l = Limits::default();
        for (byte, signal) in [(0u8, false), (1u8, true)] {
            let mut b = Frame::Exit {
                signal,
                value: 0x0102_0304,
            }
            .encode();
            b[HEADER_LEN] = byte;
            let (back, _) = Frame::decode(&b, &l).expect("canonical signal decodes");
            assert_eq!(back.encode(), b, "round-trips byte-identically");
        }
        for byte in 2..=255u8 {
            let mut b = Frame::Exit {
                signal: true,
                value: 7,
            }
            .encode();
            b[HEADER_LEN] = byte;
            match Frame::decode(&b, &l) {
                Err(FrameError::Malformed(m)) => assert_eq!(m, "bad exit signal"),
                other => panic!("signal byte {byte}: expected Malformed, got {other:?}"),
            }
        }
    }

    #[test]
    fn process_group_signal_is_exact_and_allow_listed() {
        let limits = Limits::default();
        for signal in [1, 2, 3, 15, 18, 20] {
            let encoded = Frame::Signal { signal }.encode();
            assert_eq!(
                Frame::decode(&encoded, &limits).expect("allowed signal").0,
                Frame::Signal { signal }
            );
        }
        for signal in [0, 4, 9, 19, 255] {
            let mut encoded = Frame::Signal { signal: 2 }.encode();
            encoded[HEADER_LEN] = signal;
            assert!(matches!(
                Frame::decode(&encoded, &limits),
                Err(FrameError::Malformed("invalid process-group signal"))
            ));
        }
    }

    #[test]
    fn gateway_and_lease_identity_fields_are_canonical() {
        let limits = Limits::default();
        let hello = Frame::GatewayHello {
            take_over: false,
            name: "fast".to_owned(),
            rows: 24,
            cols: 80,
            generation: [7; 16],
            pid: 123,
            start_ticks: 456,
        };
        let encoded = hello.encode();
        assert_eq!(Frame::decode(&encoded, &limits).expect("hello").0, hello);

        let mut last = Vec::new();
        for action in [
            LeaseAction::Grant,
            LeaseAction::Commit,
            LeaseAction::Committed,
            LeaseAction::Release,
            LeaseAction::Released,
            LeaseAction::Revoke,
            LeaseAction::Barrier,
            LeaseAction::BarrierAck,
        ] {
            let lease = Frame::Lease {
                action,
                generation: [9; 16],
                lease_id: 73,
            };
            last = lease.encode();
            assert_eq!(Frame::decode(&last, &limits).expect("lease").0, lease);
        }

        last[HEADER_LEN + 1..HEADER_LEN + 17].fill(0);
        assert!(matches!(
            Frame::decode(&last, &limits),
            Err(FrameError::Malformed("invalid lease identity"))
        ));
    }

    #[test]
    fn opaque_payload_kinds_stay_length_agnostic() {
        // Input/Output bodies are raw payload: any length is canonical by
        // construction and must keep round-tripping byte-identically.
        let l = Limits::default();
        for len in [0usize, 1, 2, 255, 4096] {
            let f = Frame::Input(vec![0xa5; len]);
            let b = f.encode();
            let (back, used) = Frame::decode(&b, &l).expect("decodes");
            assert_eq!(used, b.len());
            assert_eq!(back, f);
            assert_eq!(back.encode(), b);
        }
    }

    #[test]
    fn fuzz_frame_crash_artifact_is_rejected() {
        // Artifact crash-204953801670d4f3ff571d8e8f687c803106aceb from the
        // 20260902T051552Z-0a087c1ac915 campaign, verbatim: a Hello whose
        // parsed fields span 9 body bytes inside a 36-byte body (27
        // trailing bytes). Must be rejected, never decoded-and-reencoded
        // with a different length (the fuzz harness canonicality assert).
        let artifact: &[u8] = &[
            0x00, 0x00, 0x00, 0x26, // body length 38
            0x01, // protocol version 1
            0x01, // kind Hello
            0x01, 0x00, 0x00, 0x01, 0x31, 0x00, 0xfc, 0x00, 0xce, // parsed fields
            0xce, 0xce, 0x01, 0x00, 0xce, 0xce, 0xff, 0xff, 0xff, 0x2a, 0x2a, 0xff, 0x01, 0x0a,
            0x31, 0x29, 0x00, 0x2a, 0x01, 0x2a, 0x0a, 0xff, 0x2a, 0xff, 0xff, 0xff,
            0xff, // 27 trailing garbage bytes
        ];
        assert_eq!(artifact.len(), 42);
        let l = Limits::default();
        assert!(matches!(Frame::validate_header(artifact, &l), Ok(42)));
        match Frame::decode(artifact, &l) {
            Err(FrameError::Malformed(m)) => assert_eq!(m, "hello trailing bytes"),
            other => panic!("expected Malformed, got {other:?}"),
        }
    }
}
