//! Bounded remote-control request encoding (design 7).
//!
//! Two layers live here. `RemoteRequest` is the M1 generic argument-vector
//! wire (`u8 version=1 | u16 arg_count(BE) | repeated[u32 arg_len(BE) |
//! bytes]`). `ControlRequest` is the M4 typed child-argument request carried
//! over SSH as one unpadded base64url token: `u8 version=1 | u8 flags |
//! u16 origin_count(BE) | repeated[u16 len(BE) | UTF-8] | u16 argv_count(BE)
//! | repeated[u32 len(BE) | bytes]`. Both are capped at `remote_control_max`
//! bytes before decoding, reject NUL inside Unix argv elements, and are never
//! evaluated as shell source.

use crate::error::Error;
use crate::limits::Limits;

pub const REQUEST_VERSION: u8 = 1;
pub const CONTROL_VERSION: u8 = 1;
const FLAG_TAKE_OVER: u8 = 0b0000_0001;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteRequest {
    pub version: u8,
    /// Arbitrary argument bytes; NUL-free by construction; never evaluated
    /// as shell syntax.
    pub args: Vec<Vec<u8>>,
}

fn be16(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}
fn be32(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

impl RemoteRequest {
    /// Encode. Panics never: oversized input returns a typed error first.
    pub fn encode(&self, limits: &Limits) -> Result<Vec<u8>, Error> {
        if self.version != REQUEST_VERSION {
            return Err(Error::VersionUnsupported);
        }
        if self.args.len() > limits.arg_count_max {
            return Err(Error::ArgCountExceeded);
        }
        let mut out = Vec::with_capacity(3);
        out.push(REQUEST_VERSION);
        out.extend_from_slice(&be16(self.args.len() as u16));
        for a in &self.args {
            if a.contains(&0) {
                return Err(Error::NullInArg);
            }
            if a.len() > u32::MAX as usize {
                return Err(Error::RequestTooLarge);
            }
            out.extend_from_slice(&be32(a.len() as u32));
            out.extend_from_slice(a);
        }
        if out.len() > limits.remote_control_max {
            return Err(Error::RequestTooLarge);
        }
        Ok(out)
    }

    /// Decode with the size cap checked BEFORE any argument allocation.
    pub fn decode(buf: &[u8], limits: &Limits) -> Result<Self, Error> {
        if buf.len() > limits.remote_control_max {
            return Err(Error::RequestTooLarge);
        }
        if buf.len() < 3 || buf[0] != REQUEST_VERSION {
            return Err(if buf.len() < 3 {
                Error::RequestTooLarge
            } else {
                Error::VersionUnsupported
            });
        }
        let count = u16::from_be_bytes([buf[1], buf[2]]) as usize;
        if count > limits.arg_count_max {
            return Err(Error::ArgCountExceeded);
        }
        let mut args = Vec::with_capacity(count.min(16)); // bounded pre-size
        let mut rest = &buf[3..];
        for _ in 0..count {
            if rest.len() < 4 {
                return Err(Error::RequestTooLarge);
            }
            let len = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
            if rest.len() - 4 < len {
                return Err(Error::RequestTooLarge);
            }
            let a = &rest[4..4 + len];
            if a.contains(&0) {
                return Err(Error::NullInArg);
            }
            args.push(a.to_vec());
            rest = &rest[4 + len..];
        }
        if !rest.is_empty() {
            return Err(Error::RequestTooLarge);
        }
        Ok(Self {
            version: REQUEST_VERSION,
            args,
        })
    }
}

/// Typed M4 control request: takeover intent, generated origin labels, and
/// an arbitrary NUL-free child argument vector. Decoded bytes are handed to
/// process creation as a plain argv and never to a shell.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ControlRequest {
    pub take_over: bool,
    pub origins: Vec<String>,
    pub child_argv: Vec<Vec<u8>>,
}

impl ControlRequest {
    pub fn encode(&self, limits: &Limits) -> Result<Vec<u8>, Error> {
        if self.origins.len() > limits.origin_count_max {
            return Err(Error::OriginInvalid);
        }
        if self.child_argv.len() > limits.arg_count_max {
            return Err(Error::ArgCountExceeded);
        }
        let mut out = Vec::with_capacity(16);
        out.push(CONTROL_VERSION);
        out.push(if self.take_over { FLAG_TAKE_OVER } else { 0 });
        out.extend_from_slice(&be16(self.origins.len() as u16));
        for origin in &self.origins {
            validate_origin_label(origin, limits)?;
            out.extend_from_slice(&be16(origin.len() as u16));
            out.extend_from_slice(origin.as_bytes());
        }
        out.extend_from_slice(&be16(self.child_argv.len() as u16));
        for arg in &self.child_argv {
            if arg.contains(&0) {
                return Err(Error::NullInArg);
            }
            if arg.len() > u32::MAX as usize {
                return Err(Error::RequestTooLarge);
            }
            out.extend_from_slice(&be32(arg.len() as u32));
            out.extend_from_slice(arg);
        }
        if out.len() > limits.remote_control_max {
            return Err(Error::RequestTooLarge);
        }
        Ok(out)
    }

    /// Decode with the size cap checked BEFORE any allocation and every
    /// declared length checked against the remaining buffer.
    pub fn decode(buf: &[u8], limits: &Limits) -> Result<Self, Error> {
        if buf.len() > limits.remote_control_max {
            return Err(Error::RequestTooLarge);
        }
        if buf.len() < 6 {
            return Err(Error::RequestTooLarge);
        }
        if buf[0] != CONTROL_VERSION {
            return Err(Error::VersionUnsupported);
        }
        let flags = buf[1];
        if flags & !FLAG_TAKE_OVER != 0 {
            return Err(Error::FlagsInvalid);
        }
        let mut rest = &buf[2..];
        let origin_count = u16::from_be_bytes([rest[0], rest[1]]) as usize;
        rest = &rest[2..];
        if origin_count > limits.origin_count_max {
            return Err(Error::OriginInvalid);
        }
        let mut origins = Vec::with_capacity(origin_count.min(8));
        for _ in 0..origin_count {
            if rest.len() < 2 {
                return Err(Error::RequestTooLarge);
            }
            let len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
            if rest.len() - 2 < len {
                return Err(Error::RequestTooLarge);
            }
            let label = std::str::from_utf8(&rest[2..2 + len]).map_err(|_| Error::OriginInvalid)?;
            validate_origin_label(label, limits)?;
            origins.push(label.to_owned());
            rest = &rest[2 + len..];
        }
        if rest.len() < 2 {
            return Err(Error::RequestTooLarge);
        }
        let argv_count = u16::from_be_bytes([rest[0], rest[1]]) as usize;
        rest = &rest[2..];
        if argv_count > limits.arg_count_max {
            return Err(Error::ArgCountExceeded);
        }
        let mut child_argv = Vec::with_capacity(argv_count.min(16));
        for _ in 0..argv_count {
            if rest.len() < 4 {
                return Err(Error::RequestTooLarge);
            }
            let len = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
            if rest.len() - 4 < len {
                return Err(Error::RequestTooLarge);
            }
            let arg = &rest[4..4 + len];
            if arg.contains(&0) {
                return Err(Error::NullInArg);
            }
            child_argv.push(arg.to_vec());
            rest = &rest[4 + len..];
        }
        if !rest.is_empty() {
            return Err(Error::RequestTooLarge);
        }
        Ok(Self {
            take_over: flags & FLAG_TAKE_OVER != 0,
            origins,
            child_argv,
        })
    }
}

/// Origin labels are bounded printable ASCII without spaces or quotes:
/// discovery metadata only, safe for terminals and list output.
pub fn validate_origin_label(label: &str, limits: &Limits) -> Result<(), Error> {
    if label.is_empty()
        || label.len() > limits.origin_label_max
        || !label.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'@')
        })
    {
        return Err(Error::OriginInvalid);
    }
    Ok(())
}

/// Deterministically sanitize a local host name into an origin label
/// component: every byte outside the conservative set becomes `-` and the
/// result is capped. Both the connect-time generator and the list/resume
/// matchers use this one function so labels always compare equal.
pub fn sanitize_host_label(raw: &str) -> String {
    const LABEL_CAP: usize = 32;
    let mut label: String = raw
        .chars()
        .take(LABEL_CAP)
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
                character
            } else {
                '-'
            }
        })
        .collect();
    if label.is_empty() {
        label.push_str("unknown");
    }
    label
}

/// The generated origin label for sessions created by this supervisor.
pub fn origin_label(local_host: &str) -> String {
    format!("eversh:{}", sanitize_host_label(local_host))
}

const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Unpadded base64url (RFC 4648 section 5 without `=`), the only encoding
/// permitted inside remote command strings.
pub fn base64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let group = (b0 << 16) | (b1 << 8) | b2;
        out.push(BASE64URL[(group >> 18) as usize & 63] as char);
        out.push(BASE64URL[(group >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(BASE64URL[(group >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(BASE64URL[group as usize & 63] as char);
        }
    }
    out
}

fn base64url_value(byte: u8) -> Result<u32, Error> {
    match byte {
        b'A'..=b'Z' => Ok((byte - b'A') as u32),
        b'a'..=b'z' => Ok((byte - b'a' + 26) as u32),
        b'0'..=b'9' => Ok((byte - b'0' + 52) as u32),
        b'-' => Ok(62),
        b'_' => Ok(63),
        _ => Err(Error::Base64Malformed),
    }
}

/// Strict decoder: rejects padding, whitespace, invalid alphabet, impossible
/// lengths, and non-canonical trailing bits. `max_decoded` bounds allocation
/// before any work.
pub fn base64url_decode(text: &str, max_decoded: usize) -> Result<Vec<u8>, Error> {
    let bytes = text.as_bytes();
    let full = bytes.len() / 4;
    let tail = bytes.len() % 4;
    if tail == 1 {
        return Err(Error::Base64Malformed);
    }
    let decoded_len = full * 3
        + match tail {
            0 => 0,
            2 => 1,
            _ => 2,
        };
    if decoded_len > max_decoded {
        return Err(Error::RequestTooLarge);
    }
    let mut out = Vec::with_capacity(decoded_len);
    for chunk in bytes.chunks(4) {
        let mut group: u32 = 0;
        for &byte in chunk {
            group = (group << 6) | base64url_value(byte)?;
        }
        match chunk.len() {
            4 => {
                out.push((group >> 16) as u8);
                out.push((group >> 8) as u8);
                out.push(group as u8);
            }
            3 => {
                // 18 significant bits; the low 2 must be zero (canonical).
                if group & 0b11 != 0 {
                    return Err(Error::Base64Malformed);
                }
                out.push((group >> 10) as u8);
                out.push((group >> 2) as u8);
            }
            2 => {
                // 12 significant bits; the low 4 must be zero (canonical).
                if group & 0b1111 != 0 {
                    return Err(Error::Base64Malformed);
                }
                out.push((group >> 4) as u8);
            }
            _ => return Err(Error::Base64Malformed),
        }
    }
    Ok(out)
}

/// Conservative SSH destination validation: `[user@]host` where the host may
/// be a name, IPv4, or bracketed/plain IPv6 literal. Everything outside the
/// safe set is rejected so the token can appear single-quoted inside a
/// ProxyCommand string and as a plain argv word without shell interpretation.
pub fn validate_host(destination: &str) -> Result<(), Error> {
    const HOST_MAX: usize = 1024;
    if destination.is_empty()
        || destination.len() > HOST_MAX
        || destination.starts_with('-')
        || !destination.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'-' | b':' | b'@' | b'[' | b']' | b'%')
        })
    {
        return Err(Error::HostInvalid);
    }
    Ok(())
}

/// Session-name validation identical to everpty's rules; validated before
/// any path construction and never interpolated as shell source.
pub fn validate_name(name: &str, limits: &Limits) -> bool {
    let b = name.as_bytes();
    if b.is_empty() || b.len() > limits.name_max || !b[0].is_ascii_alphanumeric() {
        return false;
    }
    b.iter()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

/// Check a Unix socket pathname against the kernel limit (107 bytes + NUL)
/// before bind. Near-limit paths are typed errors, never truncation.
pub fn check_socket_path(path: &str, limits: &Limits) -> Result<(), Error> {
    if path.len() > limits.unix_path_max {
        Err(Error::PathTooLong)
    } else {
        Ok(())
    }
}
