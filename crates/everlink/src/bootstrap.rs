//! Bootstrap record and authentication-frame codecs (design 6.1, 6.2, 4).
//!
//! The bootstrap record is one newline-terminated line delivered over the
//! authenticated SSH channel, capped at `bootstrap_record_max` bytes before
//! parsing. The auth frame is exactly 35 bytes opening the single
//! bidirectional QUIC stream. All integers big-endian.

use crate::error::Error;
use crate::limits::Limits;
use std::net::IpAddr;

pub const BOOTSTRAP_VERSION: u8 = 1;
pub const AUTH_VERSION: u8 = 1;
pub const ALPN: &[&[u8]] = &[b"eversh-link/1"];

/// `everlink v1 HOST PORT SPKI_HEX TOKEN_HEX PID\n`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapRecord {
    pub version: u8,
    pub udp_endpoint: IpAddr,
    pub udp_port: u16,
    /// SHA-256 over the server certificate's SubjectPublicKeyInfo DER.
    pub spki_sha256: [u8; 32],
    /// One-use 256-bit token (constant-time compared; never logged).
    pub token: [u8; 32],
    /// Diagnostics-safe process identity of the one-shot server child.
    pub pid: u32,
}

fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, c) in s.as_bytes().chunks(2).enumerate() {
        let hi = (c[0] as char).to_digit(16)?;
        let lo = (c[1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

pub fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl BootstrapRecord {
    pub fn encode(&self) -> String {
        format!(
            "everlink v{} {} {} {} {} {}\n",
            self.version,
            self.udp_endpoint,
            self.udp_port,
            hex32(&self.spki_sha256),
            hex32(&self.token),
            self.pid
        )
    }

    /// Parse one full line (without the newline). Total: every byte position
    /// validated; `input.len()` is checked against the cap FIRST.
    pub fn parse(line: &str, limits: &Limits) -> Result<Self, Error> {
        if line.len() + 1 > limits.bootstrap_record_max {
            return Err(Error::BootstrapMalformed);
        }
        let mut parts = line.split(' ');
        match (parts.next(), parts.next()) {
            (Some("everlink"), Some("v1")) => {}
            _ => return Err(Error::BootstrapMalformed),
        }
        let host = parts.next().ok_or(Error::BootstrapMalformed)?;
        let udp_endpoint: IpAddr = host.parse().map_err(|_| Error::BootstrapMalformed)?; // literal only, no resolution
        let udp_port: u16 = parts
            .next()
            .and_then(|p| p.parse().ok())
            .ok_or(Error::BootstrapMalformed)?;
        let spki = decode_hex32(parts.next().ok_or(Error::BootstrapMalformed)?)
            .ok_or(Error::BootstrapMalformed)?;
        let token = decode_hex32(parts.next().ok_or(Error::BootstrapMalformed)?)
            .ok_or(Error::BootstrapMalformed)?;
        let pid: u32 = parts
            .next()
            .and_then(|p| p.parse().ok())
            .ok_or(Error::BootstrapMalformed)?;
        if parts.next().is_some() || token.len() != limits.token_len {
            return Err(Error::BootstrapMalformed);
        }
        Ok(Self {
            version: BOOTSTRAP_VERSION,
            udp_endpoint,
            udp_port,
            spki_sha256: spki,
            token,
            pid,
        })
    }
}

/// `u8 version | token[32] | u16 target_port(BE)` — exactly 35 bytes.
pub fn encode_auth_frame(token: &[u8; 32], target_port: u16, limits: &Limits) -> Vec<u8> {
    debug_assert_eq!(limits.auth_frame_len, 35);
    let mut f = Vec::with_capacity(35);
    f.push(AUTH_VERSION);
    f.extend_from_slice(token);
    f.extend_from_slice(&target_port.to_be_bytes());
    f
}

pub fn decode_auth_frame(frame: &[u8], limits: &Limits) -> Result<([u8; 32], u16), Error> {
    if frame.len() != limits.auth_frame_len {
        return Err(Error::AuthRejected);
    }
    if frame[0] != AUTH_VERSION {
        return Err(Error::VersionUnsupported);
    }
    let mut token = [0u8; 32];
    token.copy_from_slice(&frame[1..33]);
    let port = u16::from_be_bytes([frame[33], frame[34]]);
    Ok((token, port))
}

/// Constant-time equality for token/pin comparison.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// SHA-256 via ring (the same provider as the noq rustls path).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use ring::digest::{digest, SHA256};
    let d = digest(&SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}
