//! Bounded, one-use invitations for a persistent per-session gateway.
//!
//! The SSH bootstrap returns an invitation to exactly one association, role,
//! session, gateway generation, and client certificate SPKI.  Failed binding
//! checks never consume the invitation.  Successful claims retain only a
//! bounded SHA-256 verifier so immediate token replay can be distinguished
//! from an unknown token without retaining the secret itself.

use crate::limits::Limits;
use crate::wire::ConnectionRole;
use crate::LimitViolation;
use everssh::association::AssociationId;
use everssh::bootstrap::{ct_eq, sha256, SecretToken};
use ring::rand::{SecureRandom, SystemRandom};
use std::array;
use std::fmt;

const GENERATION_BYTES: usize = 16;
const INVITATION_BYTES: usize = 32;
const INVITATION_SLOTS: usize = 8;
const CONSUMED_SLOTS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GatewayGeneration([u8; GENERATION_BYTES]);

impl GatewayGeneration {
    pub fn generate() -> Result<Self, AdmissionError> {
        let random = SystemRandom::new();
        for _ in 0..4 {
            let mut bytes = [0_u8; GENERATION_BYTES];
            random
                .fill(&mut bytes)
                .map_err(|_| AdmissionError::Randomness)?;
            if let Ok(generation) = Self::from_bytes(bytes) {
                return Ok(generation);
            }
        }
        Err(AdmissionError::Randomness)
    }

    pub fn from_bytes(bytes: [u8; GENERATION_BYTES]) -> Result<Self, AdmissionError> {
        if bytes == [0; GENERATION_BYTES] {
            return Err(AdmissionError::InvalidGeneration);
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; GENERATION_BYTES] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionError {
    InvalidLimits(LimitViolation),
    InvalidSession,
    InvalidGeneration,
    Randomness,
    ClockOverflow,
    InvitationCapacity,
    TokenRejected,
    BindingMismatch,
    InvitationExpired,
    TokenReuse,
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits(error) => write!(formatter, "{error}"),
            Self::InvalidSession => formatter.write_str("invalid everudp session name"),
            Self::InvalidGeneration => formatter.write_str("invalid everudp gateway generation"),
            Self::Randomness => formatter.write_str("secure randomness is unavailable"),
            Self::ClockOverflow => formatter.write_str("invitation expiration overflowed"),
            Self::InvitationCapacity => {
                formatter.write_str("everudp invitation capacity is exhausted")
            }
            Self::TokenRejected => formatter.write_str("everudp invitation was rejected"),
            Self::BindingMismatch => {
                formatter.write_str("everudp invitation binding does not match")
            }
            Self::InvitationExpired => formatter.write_str("everudp invitation expired"),
            Self::TokenReuse => formatter.write_str("everudp invitation was already used"),
        }
    }
}

impl std::error::Error for AdmissionError {}

impl From<LimitViolation> for AdmissionError {
    fn from(value: LimitViolation) -> Self {
        Self::InvalidLimits(value)
    }
}

pub struct InvitationTicket {
    token: SecretToken,
    association_id: AssociationId,
    role: ConnectionRole,
    client_spki_sha256: [u8; 32],
    take_over: bool,
    expires_at_ms: u64,
}

impl InvitationTicket {
    pub fn token(&self) -> &SecretToken {
        &self.token
    }

    pub fn association_id(&self) -> AssociationId {
        self.association_id
    }

    pub fn role(&self) -> ConnectionRole {
        self.role
    }

    pub fn client_spki_sha256(&self) -> &[u8; 32] {
        &self.client_spki_sha256
    }

    pub fn take_over(&self) -> bool {
        self.take_over
    }

    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

impl fmt::Debug for InvitationTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InvitationTicket")
            .field("token", &"<REDACTED>")
            .field("association_id", &self.association_id)
            .field("role", &self.role)
            .field("take_over", &self.take_over)
            .field("client_spki_sha256", &"<REDACTED>")
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

impl PartialEq for InvitationTicket {
    fn eq(&self, other: &Self) -> bool {
        self.token == other.token
            && self.association_id == other.association_id
            && self.role == other.role
            && self.take_over == other.take_over
            && ct_eq(&self.client_spki_sha256, &other.client_spki_sha256)
            && self.expires_at_ms == other.expires_at_ms
    }
}

impl Eq for InvitationTicket {}

struct Invitation {
    token: SecretToken,
    association_id: AssociationId,
    role: ConnectionRole,
    client_spki_sha256: [u8; 32],
    take_over: bool,
    expires_at_ms: u64,
}

#[derive(Clone, Copy)]
struct ConsumedInvitation {
    token_sha256: [u8; 32],
    expires_at_ms: u64,
}

pub struct InvitationStore {
    session: String,
    generation: GatewayGeneration,
    invitation_lifetime_ms: u64,
    invitations: [Option<Invitation>; INVITATION_SLOTS],
    consumed: [Option<ConsumedInvitation>; CONSUMED_SLOTS],
}

impl InvitationStore {
    pub fn new(
        session: &str,
        generation: GatewayGeneration,
        limits: &Limits,
    ) -> Result<Self, AdmissionError> {
        limits.validate()?;
        if !everpty::frame::validate_name(session, &everpty::Limits::default()) {
            return Err(AdmissionError::InvalidSession);
        }
        Ok(Self {
            session: session.to_owned(),
            generation,
            invitation_lifetime_ms: limits.invitation_lifetime_ms,
            invitations: array::from_fn(|_| None),
            consumed: [None; CONSUMED_SLOTS],
        })
    }

    pub fn session(&self) -> &str {
        &self.session
    }

    pub fn generation(&self) -> GatewayGeneration {
        self.generation
    }

    pub fn issue(
        &mut self,
        association_id: AssociationId,
        role: ConnectionRole,
        client_spki_sha256: [u8; 32],
        now_ms: u64,
    ) -> Result<InvitationTicket, AdmissionError> {
        self.issue_with_takeover(association_id, role, client_spki_sha256, false, now_ms)
    }

    pub fn issue_with_takeover(
        &mut self,
        association_id: AssociationId,
        role: ConnectionRole,
        client_spki_sha256: [u8; 32],
        take_over: bool,
        now_ms: u64,
    ) -> Result<InvitationTicket, AdmissionError> {
        if take_over && role != ConnectionRole::Writer {
            return Err(AdmissionError::BindingMismatch);
        }
        self.expire_before(now_ms);
        let slot = self
            .invitations
            .iter()
            .position(Option::is_none)
            .ok_or(AdmissionError::InvitationCapacity)?;
        let expires_at_ms = now_ms
            .checked_add(self.invitation_lifetime_ms)
            .ok_or(AdmissionError::ClockOverflow)?;
        let token = generate_token()?;
        let ticket = InvitationTicket {
            token: token.clone(),
            association_id,
            role,
            client_spki_sha256,
            take_over,
            expires_at_ms,
        };
        self.invitations[slot] = Some(Invitation {
            token,
            association_id,
            role,
            client_spki_sha256,
            take_over,
            expires_at_ms,
        });
        Ok(ticket)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn claim(
        &mut self,
        token: &[u8],
        association_id: AssociationId,
        session: &str,
        generation: GatewayGeneration,
        role: ConnectionRole,
        client_spki_sha256: [u8; 32],
        now_ms: u64,
    ) -> Result<bool, AdmissionError> {
        if token.len() != INVITATION_BYTES {
            return Err(AdmissionError::TokenRejected);
        }

        self.expire_consumed_before(now_ms);
        let token_sha256 = sha256(token);
        if self
            .consumed
            .iter()
            .flatten()
            .any(|entry| entry.expires_at_ms > now_ms && ct_eq(&entry.token_sha256, &token_sha256))
        {
            return Err(AdmissionError::TokenReuse);
        }

        let mut matched_slot = None;
        for (index, entry) in self.invitations.iter().enumerate() {
            if let Some(entry) = entry {
                if ct_eq(entry.token.as_bytes(), token) {
                    matched_slot = Some(index);
                }
            }
        }
        let slot = matched_slot.ok_or(AdmissionError::TokenRejected)?;
        let entry = self.invitations[slot]
            .as_ref()
            .expect("matched invitation slot is populated");

        if now_ms >= entry.expires_at_ms {
            self.invitations[slot] = None;
            return Err(AdmissionError::InvitationExpired);
        }
        if entry.association_id != association_id
            || self.session != session
            || self.generation != generation
            || entry.role != role
            || !ct_eq(&entry.client_spki_sha256, &client_spki_sha256)
        {
            return Err(AdmissionError::BindingMismatch);
        }

        let claimed = self.invitations[slot]
            .take()
            .expect("matched invitation slot is populated");
        self.remember_consumed(token_sha256, claimed.expires_at_ms);
        Ok(claimed.take_over)
    }

    fn expire_before(&mut self, now_ms: u64) {
        for entry in &mut self.invitations {
            if entry
                .as_ref()
                .is_some_and(|invitation| invitation.expires_at_ms <= now_ms)
            {
                *entry = None;
            }
        }
        self.expire_consumed_before(now_ms);
    }

    fn expire_consumed_before(&mut self, now_ms: u64) {
        for entry in &mut self.consumed {
            if entry
                .as_ref()
                .is_some_and(|consumed| consumed.expires_at_ms <= now_ms)
            {
                *entry = None;
            }
        }
    }

    fn remember_consumed(&mut self, token_sha256: [u8; 32], expires_at_ms: u64) {
        let slot = self
            .consumed
            .iter()
            .position(Option::is_none)
            .or_else(|| {
                self.consumed
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, entry)| {
                        entry
                            .as_ref()
                            .map_or(u64::MIN, |consumed| consumed.expires_at_ms)
                    })
                    .map(|(index, _)| index)
            })
            .expect("consumed invitation store has a fixed nonzero size");
        self.consumed[slot] = Some(ConsumedInvitation {
            token_sha256,
            expires_at_ms,
        });
    }
}

impl fmt::Debug for InvitationStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InvitationStore")
            .field("session", &self.session)
            .field("generation", &self.generation)
            .field("invitations", &"<REDACTED>")
            .field("consumed", &"<REDACTED>")
            .finish()
    }
}

fn generate_token() -> Result<SecretToken, AdmissionError> {
    let random = SystemRandom::new();
    for _ in 0..4 {
        let mut bytes = [0_u8; INVITATION_BYTES];
        random
            .fill(&mut bytes)
            .map_err(|_| AdmissionError::Randomness)?;
        if bytes != [0; INVITATION_BYTES] {
            return Ok(SecretToken::from_bytes(bytes));
        }
    }
    Err(AdmissionError::Randomness)
}
