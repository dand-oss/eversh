//! Canonical association handshake payloads carried in control records.

use crate::admission::GatewayGeneration;
use crate::wire::ConnectionRole;
use everssh::association::AssociationId;
use everssh::bootstrap::SecretToken;
use std::fmt;

const INITIAL_MODE: u8 = 1;
const RESUME_MODE: u8 = 2;
const WRITER_ROLE: u8 = 1;
const OBSERVER_ROLE: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeError {
    InvalidLength,
    OutputTooSmall,
    UnknownHelloMode(u8),
    UnknownRole(u8),
    InvalidAssociation,
    InvalidGeneration,
    InitialPositionNotZero,
    AckAheadOfSequence,
    InvalidGapFlag(u8),
    InvalidGapEpochs,
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLength => "invalid everudp handshake length",
            Self::OutputTooSmall => "everudp handshake output buffer is too small",
            Self::UnknownHelloMode(_) => "unknown everudp hello mode",
            Self::UnknownRole(_) => "unknown everudp connection role",
            Self::InvalidAssociation => "invalid everudp association identity",
            Self::InvalidGeneration => "invalid everudp gateway generation",
            Self::InitialPositionNotZero => "initial everudp position is not zero",
            Self::AckAheadOfSequence => "everudp acknowledgement is ahead of output sequence",
            Self::InvalidGapFlag(_) => "invalid everudp pending-gap flag",
            Self::InvalidGapEpochs => "invalid everudp pending-gap epochs",
        })
    }
}

impl std::error::Error for HandshakeError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResumePosition {
    pub input_epoch: u64,
    pub next_input: u64,
    pub output_epoch: u64,
    pub next_output: u64,
    pub delivered_output_ack: u64,
}

impl ResumePosition {
    fn validate(self) -> Result<Self, HandshakeError> {
        if self.delivered_output_ack > self.next_output {
            return Err(HandshakeError::AckAheadOfSequence);
        }
        Ok(self)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum ClientHello {
    Initial {
        association_id: AssociationId,
        generation: GatewayGeneration,
        role: ConnectionRole,
        position: ResumePosition,
        token: SecretToken,
    },
    Resume {
        association_id: AssociationId,
        generation: GatewayGeneration,
        role: ConnectionRole,
        position: ResumePosition,
    },
}

impl ClientHello {
    pub const RESUME_ENCODED_LEN: usize = 74;
    pub const INITIAL_ENCODED_LEN: usize = Self::RESUME_ENCODED_LEN + 32;
    pub const MAX_ENCODED_LEN: usize = Self::INITIAL_ENCODED_LEN;

    pub fn initial(
        association_id: AssociationId,
        generation: GatewayGeneration,
        role: ConnectionRole,
        position: ResumePosition,
        token: SecretToken,
    ) -> Result<Self, HandshakeError> {
        if position
            != (ResumePosition {
                input_epoch: 0,
                next_input: 0,
                output_epoch: 0,
                next_output: 0,
                delivered_output_ack: 0,
            })
        {
            return Err(HandshakeError::InitialPositionNotZero);
        }
        Ok(Self::Initial {
            association_id,
            generation,
            role,
            position: position.validate()?,
            token,
        })
    }

    pub fn resume(
        association_id: AssociationId,
        generation: GatewayGeneration,
        role: ConnectionRole,
        position: ResumePosition,
    ) -> Result<Self, HandshakeError> {
        Ok(Self::Resume {
            association_id,
            generation,
            role,
            position: position.validate()?,
        })
    }

    pub fn association_id(&self) -> AssociationId {
        match self {
            Self::Initial { association_id, .. } | Self::Resume { association_id, .. } => {
                *association_id
            }
        }
    }

    pub fn generation(&self) -> GatewayGeneration {
        match self {
            Self::Initial { generation, .. } | Self::Resume { generation, .. } => *generation,
        }
    }

    pub fn role(&self) -> ConnectionRole {
        match self {
            Self::Initial { role, .. } | Self::Resume { role, .. } => *role,
        }
    }

    pub fn position(&self) -> ResumePosition {
        match self {
            Self::Initial { position, .. } | Self::Resume { position, .. } => *position,
        }
    }

    pub fn token(&self) -> Option<&SecretToken> {
        match self {
            Self::Initial { token, .. } => Some(token),
            Self::Resume { .. } => None,
        }
    }

    pub const fn encoded_len(&self) -> usize {
        match self {
            Self::Initial { .. } => Self::INITIAL_ENCODED_LEN,
            Self::Resume { .. } => Self::RESUME_ENCODED_LEN,
        }
    }

    pub fn encode_into(&self, output: &mut [u8]) -> Result<usize, HandshakeError> {
        let length = self.encoded_len();
        if output.len() < length {
            return Err(HandshakeError::OutputTooSmall);
        }
        let (mode, token) = match self {
            Self::Initial { token, .. } => (INITIAL_MODE, Some(token)),
            Self::Resume { .. } => (RESUME_MODE, None),
        };
        output[0] = mode;
        output[1..17].copy_from_slice(self.association_id().as_bytes());
        output[17..33].copy_from_slice(self.generation().as_bytes());
        output[33] = encode_role(self.role());
        encode_position(self.position(), &mut output[34..74]);
        if let Some(token) = token {
            output[74..106].copy_from_slice(token.as_bytes());
        }
        Ok(length)
    }

    pub fn decode_exact(input: &[u8]) -> Result<Self, HandshakeError> {
        if input.len() != Self::RESUME_ENCODED_LEN && input.len() != Self::INITIAL_ENCODED_LEN {
            return Err(HandshakeError::InvalidLength);
        }
        let mode = input[0];
        if (mode == INITIAL_MODE) != (input.len() == Self::INITIAL_ENCODED_LEN) {
            return if mode == RESUME_MODE || mode == INITIAL_MODE {
                Err(HandshakeError::InvalidLength)
            } else {
                Err(HandshakeError::UnknownHelloMode(mode))
            };
        }
        if mode != INITIAL_MODE && mode != RESUME_MODE {
            return Err(HandshakeError::UnknownHelloMode(mode));
        }
        let association_id = decode_association(&input[1..17])?;
        let generation = decode_generation(&input[17..33])?;
        let role = decode_role(input[33])?;
        let position = decode_position(&input[34..74])?.validate()?;
        if mode == INITIAL_MODE {
            let mut token = [0_u8; 32];
            token.copy_from_slice(&input[74..106]);
            Self::initial(
                association_id,
                generation,
                role,
                position,
                SecretToken::from_bytes(token),
            )
        } else {
            Self::resume(association_id, generation, role, position)
        }
    }
}

impl fmt::Debug for ClientHello {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct(match self {
            Self::Initial { .. } => "ClientHello::Initial",
            Self::Resume { .. } => "ClientHello::Resume",
        });
        debug
            .field("association_id", &self.association_id())
            .field("generation", &self.generation())
            .field("role", &self.role())
            .field("position", &self.position());
        if matches!(self, Self::Initial { .. }) {
            debug.field("token", &"<REDACTED>");
        }
        debug.finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerHello {
    association_id: AssociationId,
    generation: GatewayGeneration,
    role: ConnectionRole,
    pub input_epoch: u64,
    pub accepted_input_ack: u64,
    pub output_epoch: u64,
    pub next_output: u64,
    pub pending_gap: Option<(u64, u64)>,
}

impl ServerHello {
    pub const ENCODED_LEN: usize = 82;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        association_id: AssociationId,
        generation: GatewayGeneration,
        role: ConnectionRole,
        input_epoch: u64,
        accepted_input_ack: u64,
        output_epoch: u64,
        next_output: u64,
        pending_gap: Option<(u64, u64)>,
    ) -> Result<Self, HandshakeError> {
        if pending_gap.is_some_and(|(abandoned, replacement)| replacement <= abandoned) {
            return Err(HandshakeError::InvalidGapEpochs);
        }
        Ok(Self {
            association_id,
            generation,
            role,
            input_epoch,
            accepted_input_ack,
            output_epoch,
            next_output,
            pending_gap,
        })
    }

    pub fn association_id(&self) -> AssociationId {
        self.association_id
    }

    pub fn generation(&self) -> GatewayGeneration {
        self.generation
    }

    pub fn role(&self) -> ConnectionRole {
        self.role
    }

    pub fn encode_into(&self, output: &mut [u8]) -> Result<usize, HandshakeError> {
        if output.len() < Self::ENCODED_LEN {
            return Err(HandshakeError::OutputTooSmall);
        }
        output[0..16].copy_from_slice(self.association_id.as_bytes());
        output[16..32].copy_from_slice(self.generation.as_bytes());
        output[32] = encode_role(self.role);
        output[33..41].copy_from_slice(&self.input_epoch.to_be_bytes());
        output[41..49].copy_from_slice(&self.accepted_input_ack.to_be_bytes());
        output[49..57].copy_from_slice(&self.output_epoch.to_be_bytes());
        output[57..65].copy_from_slice(&self.next_output.to_be_bytes());
        match self.pending_gap {
            Some((abandoned, replacement)) => {
                output[65] = 1;
                output[66..74].copy_from_slice(&abandoned.to_be_bytes());
                output[74..82].copy_from_slice(&replacement.to_be_bytes());
            }
            None => {
                output[65..82].fill(0);
            }
        }
        Ok(Self::ENCODED_LEN)
    }

    pub fn decode_exact(input: &[u8]) -> Result<Self, HandshakeError> {
        if input.len() != Self::ENCODED_LEN {
            return Err(HandshakeError::InvalidLength);
        }
        let association_id = decode_association(&input[0..16])?;
        let generation = decode_generation(&input[16..32])?;
        let role = decode_role(input[32])?;
        let pending_gap = match input[65] {
            0 => {
                if input[66..82].iter().any(|byte| *byte != 0) {
                    return Err(HandshakeError::InvalidGapEpochs);
                }
                None
            }
            1 => Some((read_u64(&input[66..74]), read_u64(&input[74..82]))),
            other => return Err(HandshakeError::InvalidGapFlag(other)),
        };
        Self::new(
            association_id,
            generation,
            role,
            read_u64(&input[33..41]),
            read_u64(&input[41..49]),
            read_u64(&input[49..57]),
            read_u64(&input[57..65]),
            pending_gap,
        )
    }
}

fn encode_role(role: ConnectionRole) -> u8 {
    match role {
        ConnectionRole::Writer => WRITER_ROLE,
        ConnectionRole::Observer => OBSERVER_ROLE,
    }
}

fn decode_role(encoded: u8) -> Result<ConnectionRole, HandshakeError> {
    match encoded {
        WRITER_ROLE => Ok(ConnectionRole::Writer),
        OBSERVER_ROLE => Ok(ConnectionRole::Observer),
        other => Err(HandshakeError::UnknownRole(other)),
    }
}

fn encode_position(position: ResumePosition, output: &mut [u8]) {
    output[0..8].copy_from_slice(&position.input_epoch.to_be_bytes());
    output[8..16].copy_from_slice(&position.next_input.to_be_bytes());
    output[16..24].copy_from_slice(&position.output_epoch.to_be_bytes());
    output[24..32].copy_from_slice(&position.next_output.to_be_bytes());
    output[32..40].copy_from_slice(&position.delivered_output_ack.to_be_bytes());
}

fn decode_position(input: &[u8]) -> Result<ResumePosition, HandshakeError> {
    if input.len() != 40 {
        return Err(HandshakeError::InvalidLength);
    }
    Ok(ResumePosition {
        input_epoch: read_u64(&input[0..8]),
        next_input: read_u64(&input[8..16]),
        output_epoch: read_u64(&input[16..24]),
        next_output: read_u64(&input[24..32]),
        delivered_output_ack: read_u64(&input[32..40]),
    })
}

fn decode_association(input: &[u8]) -> Result<AssociationId, HandshakeError> {
    let bytes: [u8; 16] = input
        .try_into()
        .map_err(|_| HandshakeError::InvalidLength)?;
    AssociationId::from_bytes(bytes).map_err(|_| HandshakeError::InvalidAssociation)
}

fn decode_generation(input: &[u8]) -> Result<GatewayGeneration, HandshakeError> {
    let bytes: [u8; 16] = input
        .try_into()
        .map_err(|_| HandshakeError::InvalidLength)?;
    GatewayGeneration::from_bytes(bytes).map_err(|_| HandshakeError::InvalidGeneration)
}

fn read_u64(input: &[u8]) -> u64 {
    u64::from_be_bytes(input.try_into().expect("fixed handshake field"))
}
