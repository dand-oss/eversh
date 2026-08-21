//! Bounded remote-control request encoding (design 7).
//!
//! Wire: `u8 version=1 | u16 arg_count(BE) | repeated[u32 arg_len(BE) |
//! bytes]`, capped at `remote_control_max` bytes before decoding. Decoding
//! rejects NUL inside any argument and never treats bytes as shell source;
//! the decoded form is a plain argument vector used with fixed command words.

use crate::error::Error;
use crate::limits::Limits;

pub const REQUEST_VERSION: u8 = 1;

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
