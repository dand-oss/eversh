//! Disposable spike wire formats.
//!
//! Bootstrap record (one newline-terminated line over authenticated SSH stdout):
//!   `m0 v1 <udp_port> <spki_sha256_hex> <token_hex> <pid>`
//!
//! Authentication frame (exactly `Limits::auth_frame_len` bytes, first bytes of
//! the first bidirectional stream, client -> server):
//!   version(1) | token(32) | target_port_be(2)
//!
//! After authentication the stream carries opaque SSH bytes.

use crate::PROTOCOL_VERSION;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapRecord {
    pub version: u8,
    pub udp_port: u16,
    /// SHA-256 of the server certificate's SubjectPublicKeyInfo (DER).
    pub spki_sha256: [u8; 32],
    /// One-use 256-bit token.
    pub token: [u8; 32],
    /// Diagnostics-safe process identity of the detached server child.
    pub pid: u32,
}

#[derive(Debug)]
pub struct ProtocolError(pub &'static str);

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "spike protocol error: {}", self.0)
    }
}
impl std::error::Error for ProtocolError {}

fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

impl BootstrapRecord {
    pub fn encode(&self) -> String {
        format!(
            "m0 v{} {} {} {} {}\n",
            self.version,
            self.udp_port,
            hex(&self.spki_sha256),
            hex(&self.token),
            self.pid
        )
    }

    pub fn parse(line: &str, max_len: usize) -> Result<Self, ProtocolError> {
        if line.len() + 1 > max_len {
            return Err(ProtocolError("bootstrap record too large"));
        }
        let mut parts = line.split(' ');
        match (parts.next(), parts.next()) {
            (Some("m0"), Some("v1")) => {}
            _ => return Err(ProtocolError("bad record magic/version")),
        }
        let port: u16 = parts
            .next()
            .and_then(|p| p.parse().ok())
            .ok_or(ProtocolError("bad udp port"))?;
        let spki = decode_hex32(parts.next().ok_or(ProtocolError("missing spki"))?)
            .ok_or(ProtocolError("bad spki hex"))?;
        let token = decode_hex32(parts.next().ok_or(ProtocolError("missing token"))?)
            .ok_or(ProtocolError("bad token hex"))?;
        let pid: u32 = parts
            .next()
            .and_then(|p| p.parse().ok())
            .ok_or(ProtocolError("bad pid"))?;
        if parts.next().is_some() {
            return Err(ProtocolError("trailing fields"));
        }
        Ok(BootstrapRecord {
            version: PROTOCOL_VERSION,
            udp_port: port,
            spki_sha256: spki,
            token,
            pid,
        })
    }
}

pub fn encode_auth_frame(token: &[u8; 32], target_port: u16) -> Vec<u8> {
    let mut f = Vec::with_capacity(35);
    f.push(PROTOCOL_VERSION);
    f.extend_from_slice(token);
    f.extend_from_slice(&target_port.to_be_bytes());
    f
}

pub fn decode_auth_frame(frame: &[u8]) -> Result<(u8, [u8; 32], u16), ProtocolError> {
    if frame.len() != 35 {
        return Err(ProtocolError("bad auth frame length"));
    }
    let version = frame[0];
    let mut token = [0u8; 32];
    token.copy_from_slice(&frame[1..33]);
    let port = u16::from_be_bytes([frame[33], frame[34]]);
    Ok((version, token, port))
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_roundtrip() {
        let r = BootstrapRecord {
            version: 1,
            udp_port: 4433,
            spki_sha256: [7; 32],
            token: [9; 32],
            pid: 4242,
        };
        let line = r.encode();
        assert!(line.ends_with('\n'));
        let parsed = BootstrapRecord::parse(line.trim_end(), 4096).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn record_rejects_garbage() {
        assert!(BootstrapRecord::parse("m0 v2 1 aa bb 2", 4096).is_err());
        assert!(BootstrapRecord::parse("", 4096).is_err());
        assert!(BootstrapRecord::parse(
            &format!("m0 v1 1 {} {} 2 extra", "a".repeat(64), "b".repeat(64)),
            4096
        )
        .is_err());
        assert!(BootstrapRecord::parse("m0 v1 1 xx yy 2", 4096).is_err());
    }

    #[test]
    fn auth_frame_roundtrip() {
        let f = encode_auth_frame(&[3; 32], 2222);
        assert_eq!(f.len(), 35);
        let (v, t, p) = decode_auth_frame(&f).unwrap();
        assert_eq!((v, t.as_ref(), p), (1u8, &[3u8; 32][..], 2222u16));
        assert!(decode_auth_frame(&f[..34]).is_err());
    }

    #[test]
    fn ct_eq_is_order_insensitive() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}
