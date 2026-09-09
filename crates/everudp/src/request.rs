//! Canonical client-to-SSH-bootstrap request.

use crate::wire::ConnectionRole;
use everssh::association::AssociationId;
use std::fmt;

const MAGIC: &[u8; 4] = b"EUR1";
const MAX_WIRE: usize = 1_536;
const MAX_SESSION: usize = 64;
const MAX_ORIGIN: usize = 64;
const MAX_ARGUMENTS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapOperation {
    Connect,
    Attach,
    Observe,
}

impl BootstrapOperation {
    fn byte(self) -> u8 {
        match self {
            Self::Connect => 1,
            Self::Attach => 2,
            Self::Observe => 3,
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Connect),
            2 => Some(Self::Attach),
            3 => Some(Self::Observe),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestError {
    Malformed,
    TooLarge,
    InvalidSession,
    InvalidOrigin,
    InvalidRole,
    InvalidDimensions,
    InvalidTakeover,
    InvalidCommand,
}

impl fmt::Display for RequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => formatter.write_str("malformed everudp bootstrap request"),
            Self::TooLarge => formatter.write_str("everudp bootstrap request exceeds its cap"),
            Self::InvalidSession => formatter.write_str("invalid everudp session name"),
            Self::InvalidOrigin => formatter.write_str("invalid everudp origin label"),
            Self::InvalidRole => formatter.write_str("invalid everudp bootstrap role"),
            Self::InvalidDimensions => formatter.write_str("invalid everudp terminal dimensions"),
            Self::InvalidTakeover => formatter.write_str("invalid everudp takeover request"),
            Self::InvalidCommand => formatter.write_str("invalid everudp child command"),
        }
    }
}

impl std::error::Error for RequestError {}

pub struct BootstrapRequest {
    operation: BootstrapOperation,
    session: String,
    role: ConnectionRole,
    take_over: bool,
    rows: u16,
    columns: u16,
    association_id: AssociationId,
    client_spki_sha256: [u8; 32],
    origin: String,
    command: Vec<Vec<u8>>,
}

impl BootstrapRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation: BootstrapOperation,
        session: String,
        role: ConnectionRole,
        take_over: bool,
        rows: u16,
        columns: u16,
        association_id: AssociationId,
        client_spki_sha256: [u8; 32],
        origin: String,
        command: Vec<Vec<u8>>,
    ) -> Result<Self, RequestError> {
        let request = Self {
            operation,
            session,
            role,
            take_over,
            rows,
            columns,
            association_id,
            client_spki_sha256,
            origin,
            command,
        };
        request.validate()?;
        if request.encode_wire()?.len() > MAX_WIRE {
            return Err(RequestError::TooLarge);
        }
        Ok(request)
    }

    pub fn operation(&self) -> BootstrapOperation {
        self.operation
    }

    pub fn session(&self) -> &str {
        &self.session
    }

    pub fn role(&self) -> ConnectionRole {
        self.role
    }

    pub fn take_over(&self) -> bool {
        self.take_over
    }

    pub fn rows(&self) -> u16 {
        self.rows
    }

    pub fn columns(&self) -> u16 {
        self.columns
    }

    pub fn association_id(&self) -> AssociationId {
        self.association_id
    }

    pub fn client_spki_sha256(&self) -> [u8; 32] {
        self.client_spki_sha256
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    pub fn command(&self) -> &[Vec<u8>] {
        &self.command
    }

    pub fn encode_token(&self) -> Result<String, RequestError> {
        let wire = self.encode_wire()?;
        let mut token = String::with_capacity(wire.len() * 2);
        for byte in wire {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            token.push(HEX[(byte >> 4) as usize] as char);
            token.push(HEX[(byte & 0x0f) as usize] as char);
        }
        Ok(token)
    }

    pub fn decode_token(token: &str) -> Result<Self, RequestError> {
        if token.is_empty() || token.len() > MAX_WIRE * 2 || token.len() & 1 != 0 {
            return Err(RequestError::Malformed);
        }
        let mut wire = Vec::new();
        wire.try_reserve_exact(token.len() / 2)
            .map_err(|_| RequestError::TooLarge)?;
        for pair in token.as_bytes().chunks_exact(2) {
            wire.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
        }
        let request = Self::decode_wire(&wire)?;
        if request.encode_token()? != token {
            return Err(RequestError::Malformed);
        }
        Ok(request)
    }

    fn encode_wire(&self) -> Result<Vec<u8>, RequestError> {
        self.validate()?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(MAX_WIRE)
            .map_err(|_| RequestError::TooLarge)?;
        output.extend_from_slice(MAGIC);
        output.push(self.operation.byte());
        output.push(u8::from(self.take_over));
        output.extend_from_slice(&self.rows.to_be_bytes());
        output.extend_from_slice(&self.columns.to_be_bytes());
        output.extend_from_slice(self.association_id.as_bytes());
        output.extend_from_slice(&self.client_spki_sha256);
        output.push(u8::try_from(self.session.len()).map_err(|_| RequestError::InvalidSession)?);
        output.push(u8::try_from(self.origin.len()).map_err(|_| RequestError::InvalidOrigin)?);
        output.push(u8::try_from(self.command.len()).map_err(|_| RequestError::InvalidCommand)?);
        output.extend_from_slice(self.session.as_bytes());
        output.extend_from_slice(self.origin.as_bytes());
        for argument in &self.command {
            let length = u16::try_from(argument.len()).map_err(|_| RequestError::InvalidCommand)?;
            output.extend_from_slice(&length.to_be_bytes());
            output.extend_from_slice(argument);
        }
        if output.len() > MAX_WIRE {
            return Err(RequestError::TooLarge);
        }
        Ok(output)
    }

    fn decode_wire(input: &[u8]) -> Result<Self, RequestError> {
        const FIXED: usize = 61;
        if input.len() < FIXED || &input[..4] != MAGIC {
            return Err(RequestError::Malformed);
        }
        let operation = BootstrapOperation::from_byte(input[4]).ok_or(RequestError::Malformed)?;
        let take_over = match input[5] {
            0 => false,
            1 => true,
            _ => return Err(RequestError::Malformed),
        };
        let rows = u16::from_be_bytes([input[6], input[7]]);
        let columns = u16::from_be_bytes([input[8], input[9]]);
        let mut association = [0_u8; 16];
        association.copy_from_slice(&input[10..26]);
        let association_id =
            AssociationId::from_bytes(association).map_err(|_| RequestError::Malformed)?;
        let mut client_spki_sha256 = [0_u8; 32];
        client_spki_sha256.copy_from_slice(&input[26..58]);
        let session_length = usize::from(input[58]);
        let origin_length = usize::from(input[59]);
        let argument_count = usize::from(input[60]);
        let mut offset = FIXED;
        let session_end = offset
            .checked_add(session_length)
            .ok_or(RequestError::Malformed)?;
        let session = std::str::from_utf8(
            input
                .get(offset..session_end)
                .ok_or(RequestError::Malformed)?,
        )
        .map_err(|_| RequestError::Malformed)?
        .to_owned();
        offset = session_end;
        let origin_end = offset
            .checked_add(origin_length)
            .ok_or(RequestError::Malformed)?;
        let origin = std::str::from_utf8(
            input
                .get(offset..origin_end)
                .ok_or(RequestError::Malformed)?,
        )
        .map_err(|_| RequestError::Malformed)?
        .to_owned();
        offset = origin_end;
        if argument_count > MAX_ARGUMENTS {
            return Err(RequestError::InvalidCommand);
        }
        let mut command = Vec::new();
        command
            .try_reserve_exact(argument_count)
            .map_err(|_| RequestError::TooLarge)?;
        for _ in 0..argument_count {
            let length_bytes: [u8; 2] = input
                .get(offset..offset + 2)
                .ok_or(RequestError::Malformed)?
                .try_into()
                .map_err(|_| RequestError::Malformed)?;
            offset += 2;
            let length = usize::from(u16::from_be_bytes(length_bytes));
            let end = offset.checked_add(length).ok_or(RequestError::Malformed)?;
            command.push(
                input
                    .get(offset..end)
                    .ok_or(RequestError::Malformed)?
                    .to_vec(),
            );
            offset = end;
        }
        if offset != input.len() {
            return Err(RequestError::Malformed);
        }
        Self::new(
            operation,
            session,
            match operation {
                BootstrapOperation::Observe => ConnectionRole::Observer,
                BootstrapOperation::Connect | BootstrapOperation::Attach => ConnectionRole::Writer,
            },
            take_over,
            rows,
            columns,
            association_id,
            client_spki_sha256,
            origin,
            command,
        )
    }

    fn validate(&self) -> Result<(), RequestError> {
        if self.session.is_empty()
            || self.session.len() > MAX_SESSION
            || !self.session.as_bytes()[0].is_ascii_alphanumeric()
            || !self
                .session
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(RequestError::InvalidSession);
        }
        if self.origin.len() > MAX_ORIGIN
            || !self.origin.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'@')
            })
        {
            return Err(RequestError::InvalidOrigin);
        }
        let writer = self.role == ConnectionRole::Writer;
        match self.operation {
            BootstrapOperation::Connect if !writer => return Err(RequestError::InvalidRole),
            BootstrapOperation::Attach if !writer => return Err(RequestError::InvalidRole),
            BootstrapOperation::Observe if writer => return Err(RequestError::InvalidRole),
            _ => {}
        }
        if writer && (self.rows == 0 || self.columns == 0) {
            return Err(RequestError::InvalidDimensions);
        }
        if !writer && (self.rows != 0 || self.columns != 0) {
            return Err(RequestError::InvalidDimensions);
        }
        if self.take_over && !writer {
            return Err(RequestError::InvalidTakeover);
        }
        if self.command.len() > MAX_ARGUMENTS
            || (self.operation != BootstrapOperation::Connect && !self.command.is_empty())
            || self
                .command
                .iter()
                .any(|argument| argument.is_empty() || argument.contains(&0))
        {
            return Err(RequestError::InvalidCommand);
        }
        Ok(())
    }
}

impl fmt::Debug for BootstrapRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BootstrapRequest")
            .field("operation", &self.operation)
            .field("session", &self.session)
            .field("role", &self.role)
            .field("take_over", &self.take_over)
            .field("rows", &self.rows)
            .field("columns", &self.columns)
            .field("association_id", &self.association_id)
            .field("client_spki_sha256", &"<REDACTED>")
            .field("origin", &self.origin)
            .field("command_arguments", &self.command.len())
            .finish()
    }
}

fn nibble(byte: u8) -> Result<u8, RequestError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(RequestError::Malformed),
    }
}
