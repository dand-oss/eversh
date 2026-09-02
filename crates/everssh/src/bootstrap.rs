//! Secret-owning bootstrap and frozen authentication-prefix codecs.
//!
//! The bootstrap record is one newline-terminated line delivered over the
//! authenticated SSH channel. The authentication prefix remains exactly
//! `u8 version | token[32] | u16 target_port(BE)`.

use crate::error::Error;
use crate::limits::Limits;
use std::net::IpAddr;
use zeroize::Zeroize;

pub const BOOTSTRAP_VERSION: u8 = 1;
pub const AUTH_VERSION: u8 = 1;
pub const TOKEN_LEN: usize = 32;
pub const AUTH_FRAME_LEN: usize = 35;
pub const ALPN: &[&[u8]] = &[b"eversh-link/1"];
const BOOTSTRAP_WIRE_MAX: usize = 199;

/// A token whose bytes are deliberately unavailable to `Debug` and scrubbed
/// when ownership ends.
pub struct SecretToken([u8; TOKEN_LEN]);

impl SecretToken {
    pub fn from_bytes(bytes: [u8; TOKEN_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; TOKEN_LEN] {
        &self.0
    }

    fn zeroed() -> Self {
        Self([0; TOKEN_LEN])
    }
}

impl Clone for SecretToken {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl std::fmt::Debug for SecretToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretToken(<REDACTED>)")
    }
}

impl PartialEq for SecretToken {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(self.as_bytes(), other.as_bytes())
    }
}

impl Eq for SecretToken {}

impl Zeroize for SecretToken {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SecretToken {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// The one bootstrap wire line. Debug formatting is deliberately opaque and
/// the complete allocation is scrubbed on drop because it contains the token.
pub struct BootstrapLine(String);

impl BootstrapLine {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for BootstrapLine {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl AsRef<str> for BootstrapLine {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl std::fmt::Debug for BootstrapLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BootstrapLine(<REDACTED>)")
    }
}

impl PartialEq for BootstrapLine {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(self.0.as_bytes(), other.0.as_bytes())
    }
}

impl Eq for BootstrapLine {}

impl Drop for BootstrapLine {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// `everssh v1 HOST PORT SPKI_HEX TOKEN_HEX PID\n`.
pub struct BootstrapRecord {
    pub version: u8,
    pub udp_endpoint: IpAddr,
    pub udp_port: u16,
    /// SHA-256 over the server certificate's SubjectPublicKeyInfo DER.
    pub spki_sha256: [u8; 32],
    token: SecretToken,
    /// Diagnostics-safe process identity of the one-shot server child.
    pub pid: u32,
}

impl BootstrapRecord {
    pub fn new(
        udp_endpoint: IpAddr,
        udp_port: u16,
        spki_sha256: [u8; 32],
        token: SecretToken,
        pid: u32,
    ) -> Result<Self, Error> {
        if udp_port == 0 || unusable_ip(udp_endpoint) {
            return Err(Error::BootstrapMalformed);
        }
        Ok(Self {
            version: BOOTSTRAP_VERSION,
            udp_endpoint,
            udp_port,
            spki_sha256,
            token,
            pid,
        })
    }

    pub fn token(&self) -> &SecretToken {
        &self.token
    }

    pub fn encode(&self) -> BootstrapLine {
        // Reserve the full maximum representation up front. In particular,
        // never reallocate after token bytes enter the buffer, because the
        // allocator cannot scrub the abandoned allocation for us.
        let mut line = String::with_capacity(BOOTSTRAP_WIRE_MAX);
        line.push_str("everssh v1 ");
        line.push_str(&self.udp_endpoint.to_string());
        line.push(' ');
        line.push_str(&self.udp_port.to_string());
        line.push(' ');
        encode_hex_into(&self.spki_sha256, &mut line);
        line.push(' ');
        encode_hex_into(self.token.as_bytes(), &mut line);
        line.push(' ');
        line.push_str(&self.pid.to_string());
        line.push('\n');
        BootstrapLine(line)
    }

    /// Parse one full line without its newline. The cap is checked before any
    /// field parsing or allocation.
    pub fn parse(line: &str, limits: &Limits) -> Result<Self, Error> {
        limits.validate()?;
        let encoded_len = line.len().checked_add(1).ok_or(Error::BootstrapMalformed)?;
        if encoded_len > limits.bootstrap_record_max {
            return Err(Error::BootstrapMalformed);
        }
        let mut parts = line.split(' ');
        match (parts.next(), parts.next()) {
            (Some("everssh"), Some("v1")) => {}
            _ => return Err(Error::BootstrapMalformed),
        }
        let udp_endpoint: IpAddr = parts
            .next()
            .ok_or(Error::BootstrapMalformed)?
            .parse()
            .map_err(|_| Error::BootstrapMalformed)?;
        let udp_port = parts
            .next()
            .and_then(|part| part.parse::<u16>().ok())
            .ok_or(Error::BootstrapMalformed)?;
        let spki_sha256 = decode_hex32(parts.next().ok_or(Error::BootstrapMalformed)?)
            .ok_or(Error::BootstrapMalformed)?;
        let token = decode_secret_hex32(parts.next().ok_or(Error::BootstrapMalformed)?)
            .ok_or(Error::BootstrapMalformed)?;
        let pid = parts
            .next()
            .and_then(|part| part.parse::<u32>().ok())
            .ok_or(Error::BootstrapMalformed)?;
        if parts.next().is_some() {
            return Err(Error::BootstrapMalformed);
        }
        Self::new(udp_endpoint, udp_port, spki_sha256, token, pid)
    }
}

impl Clone for BootstrapRecord {
    fn clone(&self) -> Self {
        Self {
            version: self.version,
            udp_endpoint: self.udp_endpoint,
            udp_port: self.udp_port,
            spki_sha256: self.spki_sha256,
            token: self.token.clone(),
            pid: self.pid,
        }
    }
}

impl std::fmt::Debug for BootstrapRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapRecord")
            .field("version", &self.version)
            .field("udp_endpoint", &self.udp_endpoint)
            .field("udp_port", &self.udp_port)
            .field("spki_sha256", &self.spki_sha256)
            .field("token", &"<REDACTED>")
            .field("pid", &self.pid)
            .finish()
    }
}

impl PartialEq for BootstrapRecord {
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version
            && self.udp_endpoint == other.udp_endpoint
            && self.udp_port == other.udp_port
            && self.spki_sha256 == other.spki_sha256
            && self.token == other.token
            && self.pid == other.pid
    }
}

impl Eq for BootstrapRecord {}

/// Secret-owning frozen authentication prefix.
pub struct SecretAuthFrame([u8; AUTH_FRAME_LEN]);

impl SecretAuthFrame {
    pub(crate) fn take_bytes(bytes: &mut [u8; AUTH_FRAME_LEN]) -> Self {
        Self(std::mem::replace(bytes, [0; AUTH_FRAME_LEN]))
    }
}

impl std::ops::Deref for SecretAuthFrame {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for SecretAuthFrame {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl PartialEq<&[u8]> for SecretAuthFrame {
    fn eq(&self, other: &&[u8]) -> bool {
        ct_eq(self.as_ref(), other)
    }
}

impl std::fmt::Debug for SecretAuthFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretAuthFrame(<REDACTED>)")
    }
}

impl Drop for SecretAuthFrame {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Encode the frozen wire prefix. This compatibility surface is infallible
/// because its output always has the contract length; production transport
/// uses [`try_encode_auth_frame`] to reject an invalid selector or limits.
pub fn encode_auth_frame(
    token: &SecretToken,
    target_port: u16,
    _limits: &Limits,
) -> SecretAuthFrame {
    let mut frame = SecretAuthFrame([0; AUTH_FRAME_LEN]);
    frame.0[0] = AUTH_VERSION;
    frame.0[1..33].copy_from_slice(token.as_bytes());
    frame.0[33..].copy_from_slice(&target_port.to_be_bytes());
    frame
}

pub fn try_encode_auth_frame(
    token: &SecretToken,
    target_port: u16,
    limits: &Limits,
) -> Result<SecretAuthFrame, Error> {
    limits.validate()?;
    if target_port == 0 {
        return Err(Error::TargetUnauthorized);
    }
    Ok(encode_auth_frame(token, target_port, limits))
}

pub fn decode_auth_frame(frame: &[u8], limits: &Limits) -> Result<(SecretToken, u16), Error> {
    limits.validate()?;
    if frame.len() != AUTH_FRAME_LEN {
        return Err(Error::AuthRejected);
    }
    if frame[0] != AUTH_VERSION {
        return Err(Error::VersionUnsupported);
    }
    let mut token = SecretToken::zeroed();
    token.0.copy_from_slice(&frame[1..33]);
    let port = u16::from_be_bytes([frame[33], frame[34]]);
    if port == 0 {
        return Err(Error::TargetUnauthorized);
    }
    Ok((token, port))
}

/// Constant-time equality without exposing either operand through formatting.
pub fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    use subtle::ConstantTimeEq;

    left.len() == right.len() && bool::from(left.ct_eq(right))
}

/// SHA-256 via ring, shared by identity generation and pin verification.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use ring::digest::{digest, SHA256};
    let digest = digest(&SHA256, data);
    let mut output = [0; 32];
    output.copy_from_slice(digest.as_ref());
    output
}

fn unusable_ip(ip: IpAddr) -> bool {
    ip.is_unspecified() || ip.is_multicast() || ip == IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
}

fn decode_hex32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut output = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(output)
}

fn decode_secret_hex32(value: &str) -> Option<SecretToken> {
    if value.len() != 64 {
        return None;
    }
    let mut output = SecretToken::zeroed();
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output.0[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(output)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn encode_hex_into(bytes: &[u8], output: &mut String) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn explicit_zeroize_clears_secret_storage() {
        let mut token = SecretToken::from_bytes([0xa5; TOKEN_LEN]);
        token.zeroize();
        assert_eq!(token.as_bytes(), &[0; TOKEN_LEN]);
    }
}
