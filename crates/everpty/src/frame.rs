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

impl Frame {
    pub fn kind(&self) -> Kind {
        match self {
            Self::Hello { .. } => Kind::Hello,
            Self::HelloAck { .. } => Kind::HelloAck,
            Self::Busy { .. } => Kind::Busy,
            Self::Input(_) => Kind::Input,
            Self::Output(_) => Kind::Output,
            Self::Resize { .. } => Kind::Resize,
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
