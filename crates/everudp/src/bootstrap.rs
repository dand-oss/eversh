//! Exact SSH bootstrap record for locating and authenticating a gateway.

use crate::admission::GatewayGeneration;
use crate::limits::Limits;
use crate::LimitViolation;
use everssh::association::AssociationId;
use everssh::bootstrap::{ct_eq, SecretToken};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use zeroize::Zeroize;

const BOOTSTRAP_WIRE_MAX: usize = 320;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapError {
    InvalidLimits(LimitViolation),
    Endpoint,
    Process,
    Malformed,
}

impl fmt::Display for BootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits(error) => write!(formatter, "{error}"),
            Self::Endpoint => formatter.write_str("invalid everudp bootstrap endpoint"),
            Self::Process => formatter.write_str("invalid everudp gateway process identity"),
            Self::Malformed => formatter.write_str("malformed everudp bootstrap record"),
        }
    }
}

impl std::error::Error for BootstrapError {}

impl From<LimitViolation> for BootstrapError {
    fn from(value: LimitViolation) -> Self {
        Self::InvalidLimits(value)
    }
}

pub struct BootstrapLine(String);

impl BootstrapLine {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for BootstrapLine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BootstrapLine(<REDACTED>)")
    }
}

impl Drop for BootstrapLine {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub struct BootstrapRecord {
    endpoint: SocketAddr,
    server_spki_sha256: [u8; 32],
    token: SecretToken,
    association_id: AssociationId,
    generation: GatewayGeneration,
    pid: u32,
}

impl BootstrapRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint: SocketAddr,
        server_spki_sha256: [u8; 32],
        token: SecretToken,
        association_id: AssociationId,
        generation: GatewayGeneration,
        pid: u32,
    ) -> Result<Self, BootstrapError> {
        if !usable_endpoint(endpoint) {
            return Err(BootstrapError::Endpoint);
        }
        if pid == 0 {
            return Err(BootstrapError::Process);
        }
        Ok(Self {
            endpoint,
            server_spki_sha256,
            token,
            association_id,
            generation,
            pid,
        })
    }

    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    pub fn server_spki_sha256(&self) -> [u8; 32] {
        self.server_spki_sha256
    }

    pub fn token(&self) -> &SecretToken {
        &self.token
    }

    pub fn association_id(&self) -> AssociationId {
        self.association_id
    }

    pub fn generation(&self) -> GatewayGeneration {
        self.generation
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn encode(&self) -> BootstrapLine {
        let mut line = String::with_capacity(BOOTSTRAP_WIRE_MAX);
        line.push_str("everudp v1 ");
        line.push_str(&self.endpoint.ip().to_string());
        line.push(' ');
        line.push_str(&self.endpoint.port().to_string());
        line.push(' ');
        encode_hex_into(&self.server_spki_sha256, &mut line);
        line.push(' ');
        encode_hex_into(self.token.as_bytes(), &mut line);
        line.push(' ');
        encode_hex_into(self.association_id.as_bytes(), &mut line);
        line.push(' ');
        encode_hex_into(self.generation.as_bytes(), &mut line);
        line.push(' ');
        line.push_str(&self.pid.to_string());
        line.push('\n');
        debug_assert!(line.len() <= BOOTSTRAP_WIRE_MAX);
        BootstrapLine(line)
    }

    pub fn parse_line(line: &str, limits: &Limits) -> Result<Self, BootstrapError> {
        limits.validate()?;
        if line.len() > limits.bootstrap_record_max
            || !line.ends_with('\n')
            || line[..line.len() - 1].contains('\n')
            || line.contains('\r')
        {
            return Err(BootstrapError::Malformed);
        }
        let bare = &line[..line.len() - 1];
        let fields: Vec<&str> = bare.split(' ').collect();
        let [prefix, version, host, port, pin, token, association, generation, pid] =
            fields.as_slice()
        else {
            return Err(BootstrapError::Malformed);
        };
        if *prefix != "everudp" || *version != "v1" {
            return Err(BootstrapError::Malformed);
        }
        let ip: IpAddr = host.parse().map_err(|_| BootstrapError::Malformed)?;
        let port = parse_canonical_u16(port)?;
        let endpoint = SocketAddr::new(ip, port);
        let pin = decode_hex_exact::<32>(pin)?;
        let token = SecretToken::from_bytes(decode_hex_exact::<32>(token)?);
        let association_id = AssociationId::from_bytes(decode_hex_exact::<16>(association)?)
            .map_err(|_| BootstrapError::Malformed)?;
        let generation = GatewayGeneration::from_bytes(decode_hex_exact::<16>(generation)?)
            .map_err(|_| BootstrapError::Malformed)?;
        let pid = parse_canonical_u32(pid)?;
        let record = Self::new(endpoint, pin, token, association_id, generation, pid)?;
        if record.encode().as_str() != line {
            return Err(BootstrapError::Malformed);
        }
        Ok(record)
    }
}

impl fmt::Debug for BootstrapRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BootstrapRecord")
            .field("endpoint", &self.endpoint)
            .field("server_spki_sha256", &self.server_spki_sha256)
            .field("token", &"<REDACTED>")
            .field("association_id", &self.association_id)
            .field("generation", &self.generation)
            .field("pid", &self.pid)
            .finish()
    }
}

impl PartialEq for BootstrapRecord {
    fn eq(&self, other: &Self) -> bool {
        self.endpoint == other.endpoint
            && ct_eq(&self.server_spki_sha256, &other.server_spki_sha256)
            && self.token == other.token
            && self.association_id == other.association_id
            && self.generation == other.generation
            && self.pid == other.pid
    }
}

impl Eq for BootstrapRecord {}

fn usable_endpoint(endpoint: SocketAddr) -> bool {
    if endpoint.port() == 0 {
        return false;
    }
    match endpoint.ip() {
        IpAddr::V4(ip) => !ip.is_unspecified() && !ip.is_multicast() && ip != Ipv4Addr::BROADCAST,
        IpAddr::V6(ip) => !ip.is_unspecified() && !ip.is_multicast(),
    }
}

fn encode_hex_into(bytes: &[u8], output: &mut String) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
}

fn decode_hex_exact<const N: usize>(encoded: &str) -> Result<[u8; N], BootstrapError> {
    if encoded.len() != N * 2 {
        return Err(BootstrapError::Malformed);
    }
    let mut output = [0_u8; N];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (decode_nibble(pair[0])? << 4) | decode_nibble(pair[1])?;
    }
    Ok(output)
}

fn decode_nibble(byte: u8) -> Result<u8, BootstrapError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(BootstrapError::Malformed),
    }
}

fn parse_canonical_u16(value: &str) -> Result<u16, BootstrapError> {
    let parsed = value
        .parse::<u16>()
        .map_err(|_| BootstrapError::Malformed)?;
    if parsed == 0 || parsed.to_string() != value {
        return Err(BootstrapError::Malformed);
    }
    Ok(parsed)
}

fn parse_canonical_u32(value: &str) -> Result<u32, BootstrapError> {
    let parsed = value
        .parse::<u32>()
        .map_err(|_| BootstrapError::Malformed)?;
    if parsed == 0 || parsed.to_string() != value {
        return Err(BootstrapError::Malformed);
    }
    Ok(parsed)
}
