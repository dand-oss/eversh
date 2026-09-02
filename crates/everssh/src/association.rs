//! Bootstrap-bound v2 association identity and exact handshake records.

use crate::admission::OneUseToken;
use crate::bootstrap::SecretToken;
use crate::error::Error;
use crate::pinning::extract_spki;
use noq::rustls::client::danger::HandshakeSignatureValid;
use noq::rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use noq::rustls::pki_types::{CertificateDer, UnixTime};
use noq::rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use noq::rustls::{DigitallySignedStruct, DistinguishedName};
use noq::Connection;
use ring::rand::{SecureRandom, SystemRandom};
use std::sync::Arc;
use zeroize::Zeroizing;

pub const HANDSHAKE_VERSION: u8 = 2;
pub const ASSOCIATION_ID_LEN: usize = 16;
pub const CLIENT_HELLO_INITIAL_LEN: usize = 60;
pub const CLIENT_HELLO_RESUME_LEN: usize = 26;
pub const SERVER_HELLO_LEN: usize = 26;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AssociationId([u8; ASSOCIATION_ID_LEN]);

impl AssociationId {
    pub fn generate() -> Result<Self, Error> {
        let mut bytes = [0_u8; ASSOCIATION_ID_LEN];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| Error::IdentityRandomness)?;
        Self::from_bytes(bytes)
    }

    pub fn from_bytes(bytes: [u8; ASSOCIATION_ID_LEN]) -> Result<Self, Error> {
        if bytes == [0_u8; ASSOCIATION_ID_LEN] {
            return Err(Error::AssociationIdMalformed);
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; ASSOCIATION_ID_LEN] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientHelloKind {
    Initial = 1,
    Resume = 2,
}

/// The first or reconnecting client record on one association stream.
#[derive(Clone, PartialEq, Eq)]
pub enum ClientHello {
    Initial {
        association_id: AssociationId,
        delivered_ack: u64,
        token: SecretToken,
        target_port: u16,
    },
    Resume {
        association_id: AssociationId,
        delivered_ack: u64,
    },
}

impl ClientHello {
    pub fn initial(
        association_id: AssociationId,
        delivered_ack: u64,
        token: SecretToken,
        target_port: u16,
    ) -> Result<Self, Error> {
        if target_port == 0 {
            return Err(Error::TargetUnauthorized);
        }
        Ok(Self::Initial {
            association_id,
            delivered_ack,
            token,
            target_port,
        })
    }

    pub fn resume(association_id: AssociationId, delivered_ack: u64) -> Result<Self, Error> {
        Ok(Self::Resume {
            association_id,
            delivered_ack,
        })
    }

    pub fn association_id(&self) -> AssociationId {
        match self {
            Self::Initial { association_id, .. } | Self::Resume { association_id, .. } => {
                *association_id
            }
        }
    }

    pub fn delivered_ack(&self) -> u64 {
        match self {
            Self::Initial { delivered_ack, .. } | Self::Resume { delivered_ack, .. } => {
                *delivered_ack
            }
        }
    }

    pub fn encoded_len(&self) -> usize {
        match self {
            Self::Initial { .. } => CLIENT_HELLO_INITIAL_LEN,
            Self::Resume { .. } => CLIENT_HELLO_RESUME_LEN,
        }
    }

    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut wire = Zeroizing::new(vec![0_u8; self.encoded_len()]);
        let bytes: &mut [u8] = &mut wire;
        bytes[0] = HANDSHAKE_VERSION;
        bytes[2..18].copy_from_slice(self.association_id().as_bytes());
        bytes[18..26].copy_from_slice(&self.delivered_ack().to_be_bytes());
        match self {
            Self::Initial {
                token, target_port, ..
            } => {
                bytes[1] = ClientHelloKind::Initial as u8;
                bytes[26..58].copy_from_slice(token.as_bytes());
                bytes[58..60].copy_from_slice(&target_port.to_be_bytes());
            }
            Self::Resume { .. } => {
                bytes[1] = ClientHelloKind::Resume as u8;
            }
        }
        wire
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, Error> {
        match bytes.len() {
            CLIENT_HELLO_INITIAL_LEN | CLIENT_HELLO_RESUME_LEN => {}
            _ => return Err(Error::HandshakeMalformed),
        }
        if bytes[0] != HANDSHAKE_VERSION {
            return Err(Error::VersionUnsupported);
        }
        let mut association_id_bytes = [0_u8; ASSOCIATION_ID_LEN];
        association_id_bytes.copy_from_slice(&bytes[2..18]);
        let association_id = AssociationId::from_bytes(association_id_bytes)?;
        let delivered_ack = u64::from_be_bytes(
            bytes[18..26]
                .try_into()
                .map_err(|_| Error::HandshakeMalformed)?,
        );
        match (bytes[1], bytes.len()) {
            (kind, CLIENT_HELLO_INITIAL_LEN) if kind == ClientHelloKind::Initial as u8 => {
                let mut token = [0_u8; crate::bootstrap::TOKEN_LEN];
                token.copy_from_slice(&bytes[26..58]);
                let target_port = u16::from_be_bytes(
                    bytes[58..60]
                        .try_into()
                        .map_err(|_| Error::HandshakeMalformed)?,
                );
                Self::initial(
                    association_id,
                    delivered_ack,
                    SecretToken::from_bytes(token),
                    target_port,
                )
            }
            (kind, CLIENT_HELLO_RESUME_LEN) if kind == ClientHelloKind::Resume as u8 => {
                Self::resume(association_id, delivered_ack)
            }
            _ => Err(Error::HandshakeMalformed),
        }
    }
}

impl std::fmt::Debug for ClientHello {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientHello")
            .field("association_id", &self.association_id())
            .field("delivered_ack", &self.delivered_ack())
            .field(
                "kind",
                &match self {
                    Self::Initial { .. } => "Initial(<TOKEN-REDACTED>)",
                    Self::Resume { .. } => "Resume",
                },
            )
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ServerHello {
    association_id: AssociationId,
    delivered_ack: u64,
}

impl ServerHello {
    pub fn new(association_id: AssociationId, delivered_ack: u64) -> Self {
        Self {
            association_id,
            delivered_ack,
        }
    }

    pub fn association_id(&self) -> AssociationId {
        self.association_id
    }

    pub fn delivered_ack(&self) -> u64 {
        self.delivered_ack
    }

    pub fn encode(&self) -> [u8; SERVER_HELLO_LEN] {
        let mut bytes = [0_u8; SERVER_HELLO_LEN];
        bytes[0] = HANDSHAKE_VERSION;
        bytes[1] = 3;
        bytes[2..18].copy_from_slice(self.association_id.as_bytes());
        bytes[18..].copy_from_slice(&self.delivered_ack.to_be_bytes());
        bytes
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != SERVER_HELLO_LEN {
            return Err(Error::HandshakeMalformed);
        }
        if bytes[0] != HANDSHAKE_VERSION {
            return Err(Error::VersionUnsupported);
        }
        if bytes[1] != 3 {
            return Err(Error::HandshakeMalformed);
        }
        let mut association_id_bytes = [0_u8; ASSOCIATION_ID_LEN];
        association_id_bytes.copy_from_slice(&bytes[2..18]);
        Ok(Self {
            association_id: AssociationId::from_bytes(association_id_bytes)?,
            delivered_ack: u64::from_be_bytes(
                bytes[18..]
                    .try_into()
                    .map_err(|_| Error::HandshakeMalformed)?,
            ),
        })
    }
}

impl std::fmt::Debug for ServerHello {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerHello")
            .field("association_id", &self.association_id)
            .field("delivered_ack", &self.delivered_ack)
            .finish()
    }
}

/// Require one parseable self-signed client certificate and no intermediates.
///
/// TLS proves possession of the certificate key; everssh binds its SPKI to the
/// one-use authenticated bootstrap association before allowing reconnect.
#[derive(Debug)]
pub struct BootstrapClientCertVerifier {
    provider: Arc<CryptoProvider>,
}

/// Server-side authorization state for one bootstrap-bound association.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssociationAuthorization {
    association_id: AssociationId,
    client_spki_sha256: [u8; 32],
    target_port: u16,
}

pub(crate) fn client_spki_from_connection(connection: &Connection) -> Result<[u8; 32], Error> {
    let identity = connection.peer_identity().ok_or(Error::AuthRejected)?;
    let certificates = identity
        .downcast_ref::<Vec<CertificateDer<'_>>>()
        .ok_or(Error::AuthRejected)?;
    let [certificate] = certificates.as_slice() else {
        return Err(Error::AuthRejected);
    };
    let spki = extract_spki(certificate).ok_or(Error::AuthRejected)?;
    Ok(crate::bootstrap::sha256(spki))
}

impl AssociationAuthorization {
    pub fn establish(
        expected_id: AssociationId,
        expected_target_port: u16,
        client_spki_sha256: [u8; 32],
        hello: ClientHello,
        token: &OneUseToken,
    ) -> Result<Self, Error> {
        let ClientHello::Initial {
            association_id,
            delivered_ack,
            token: candidate,
            target_port,
        } = hello
        else {
            return Err(Error::AuthRejected);
        };
        if association_id != expected_id || delivered_ack != 0 {
            return Err(Error::HandshakeMalformed);
        }
        if target_port != expected_target_port {
            return Err(Error::TargetUnauthorized);
        }
        token.claim(candidate.as_bytes())?;
        Ok(Self {
            association_id,
            client_spki_sha256,
            target_port,
        })
    }

    pub fn authorize_resume(
        &self,
        client_spki_sha256: [u8; 32],
        hello: ClientHello,
        last_assigned: u64,
    ) -> Result<u64, Error> {
        let ClientHello::Resume {
            association_id,
            delivered_ack,
        } = hello
        else {
            return Err(Error::AuthRejected);
        };
        if association_id != self.association_id
            || client_spki_sha256 != self.client_spki_sha256
            || self.target_port == 0
        {
            return Err(Error::AuthRejected);
        }
        if delivered_ack > last_assigned {
            return Err(Error::ResumeSequenceInvalid);
        }
        Ok(delivered_ack)
    }

    pub fn association_id(&self) -> AssociationId {
        self.association_id
    }

    pub fn client_spki_sha256(&self) -> [u8; 32] {
        self.client_spki_sha256
    }

    pub fn target_port(&self) -> u16 {
        self.target_port
    }
}

impl BootstrapClientCertVerifier {
    pub fn new(provider: Arc<CryptoProvider>) -> Self {
        Self { provider }
    }
}

impl ClientCertVerifier for BootstrapClientCertVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, noq::rustls::Error> {
        if !intermediates.is_empty() || extract_spki(end_entity).is_none() {
            return Err(noq::rustls::Error::InvalidCertificate(
                noq::rustls::CertificateError::BadEncoding,
            ));
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, noq::rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, noq::rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<noq::rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::identity::EphemeralClientIdentity;

    fn association_id() -> AssociationId {
        AssociationId::from_bytes([0x51; ASSOCIATION_ID_LEN]).unwrap()
    }

    #[test]
    fn association_ids_are_random_nonzero_and_fail_closed() {
        let first = AssociationId::generate().unwrap();
        let second = AssociationId::generate().unwrap();
        assert_ne!(first, second);
        assert!(AssociationId::from_bytes([0; ASSOCIATION_ID_LEN]).is_err());
    }

    #[test]
    fn initial_and_resume_client_hellos_are_exact_and_secret() {
        let token = SecretToken::from_bytes([0x5a; crate::bootstrap::TOKEN_LEN]);
        let initial = ClientHello::initial(
            association_id(),
            0x0102_0304_0506_0708,
            token.clone(),
            0x1234,
        )
        .unwrap();
        let wire = initial.encode();
        assert_eq!(wire.len(), CLIENT_HELLO_INITIAL_LEN);
        assert_eq!(wire[0], HANDSHAKE_VERSION);
        assert_eq!(wire[1], 1);
        assert_eq!(&wire[2..18], association_id().as_bytes());
        assert_eq!(&wire[18..26], &0x0102_0304_0506_0708_u64.to_be_bytes());
        assert_eq!(&wire[26..58], &[0x5a; crate::bootstrap::TOKEN_LEN]);
        assert_eq!(&wire[58..], &[0x12, 0x34]);
        assert_eq!(ClientHello::decode_exact(&wire).unwrap(), initial);
        assert!(!format!("{initial:?}").contains(&"5a".repeat(32)));

        let resume = ClientHello::resume(association_id(), 9).unwrap();
        let resume_wire = resume.encode();
        assert_eq!(resume_wire.len(), CLIENT_HELLO_RESUME_LEN);
        assert_eq!(resume_wire[1], 2);
        assert_eq!(&resume_wire[18..], &9_u64.to_be_bytes());
        assert_eq!(ClientHello::decode_exact(&resume_wire).unwrap(), resume);
        assert!(ClientHello::initial(association_id(), 0, token.clone(), 0).is_err());
    }

    #[test]
    fn server_hello_is_exact() {
        let hello = ServerHello::new(association_id(), 0x1122_3344_5566_7788);
        let wire = hello.encode();
        assert_eq!(wire.len(), SERVER_HELLO_LEN);
        assert_eq!(wire[0], HANDSHAKE_VERSION);
        assert_eq!(wire[1], 3);
        assert_eq!(&wire[2..18], association_id().as_bytes());
        assert_eq!(&wire[18..], &0x1122_3344_5566_7788_u64.to_be_bytes());
        assert_eq!(ServerHello::decode_exact(&wire).unwrap(), hello);
    }

    #[test]
    fn every_handshake_truncation_and_noncanonical_shape_fails() {
        let token = SecretToken::from_bytes([3; crate::bootstrap::TOKEN_LEN]);
        let initial = ClientHello::initial(association_id(), 1, token, 22).unwrap();
        let initial_wire = initial.encode();
        let resume = ClientHello::resume(association_id(), 1).unwrap();
        let resume_wire = resume.encode();
        let server = ServerHello::new(association_id(), 1).encode();

        for wire in [
            initial_wire.as_slice(),
            resume_wire.as_slice(),
            server.as_slice(),
        ] {
            for cut in 0..wire.len() {
                assert!(ClientHello::decode_exact(&wire[..cut]).is_err());
                assert!(ServerHello::decode_exact(&wire[..cut]).is_err());
            }
            let mut trailing = wire.to_vec();
            trailing.push(0);
            assert!(ClientHello::decode_exact(&trailing).is_err());
            assert!(ServerHello::decode_exact(&trailing).is_err());
        }

        let mut bad_version = initial_wire.clone();
        bad_version[0] = 1;
        assert!(matches!(
            ClientHello::decode_exact(&bad_version),
            Err(Error::VersionUnsupported)
        ));
        assert!(matches!(
            ServerHello::decode_exact(&bad_version[..SERVER_HELLO_LEN]),
            Err(Error::VersionUnsupported)
        ));

        let mut bad_kind = initial_wire.clone();
        bad_kind[1] = 3;
        assert!(matches!(
            ClientHello::decode_exact(&bad_kind),
            Err(Error::HandshakeMalformed)
        ));

        let mut zero_id = initial_wire.clone();
        zero_id[2..18].fill(0);
        assert!(matches!(
            ClientHello::decode_exact(&zero_id),
            Err(Error::AssociationIdMalformed)
        ));
    }

    #[test]
    fn bootstrap_client_verifier_accepts_one_generated_certificate_only() {
        let identity = EphemeralClientIdentity::generate().unwrap();
        let other = EphemeralClientIdentity::generate().unwrap();
        let verifier = BootstrapClientCertVerifier::new(Arc::new(
            noq::rustls::crypto::ring::default_provider(),
        ));
        assert!(verifier
            .verify_client_cert(identity.certificate_der(), &[], UnixTime::now())
            .is_ok());
        assert!(verifier
            .verify_client_cert(
                identity.certificate_der(),
                &[other.certificate_der().clone()],
                UnixTime::now()
            )
            .is_err());
        let invalid = CertificateDer::from(vec![1, 2, 3]);
        assert!(verifier
            .verify_client_cert(&invalid, &[], UnixTime::now())
            .is_err());
    }

    #[test]
    fn one_use_bootstrap_binds_association_and_client_spki() {
        let id = association_id();
        let wrong_id = AssociationId::from_bytes([0x77; ASSOCIATION_ID_LEN]).unwrap();
        let token = SecretToken::from_bytes([0x31; crate::bootstrap::TOKEN_LEN]);
        let owner = OneUseToken::new(token.clone());
        let client_key = [0x61; 32];
        let hello = ClientHello::initial(id, 0, token.clone(), 22).unwrap();
        let authorization =
            AssociationAuthorization::establish(id, 22, client_key, hello.clone(), &owner).unwrap();
        assert_eq!(authorization.association_id(), id);
        assert_eq!(authorization.client_spki_sha256(), client_key);
        assert_eq!(authorization.target_port(), 22);

        let resume = ClientHello::resume(id, 0).unwrap();
        assert_eq!(
            authorization
                .authorize_resume(client_key, resume.clone(), 0)
                .unwrap(),
            0
        );
        assert!(authorization
            .authorize_resume([0x62; 32], resume.clone(), 0)
            .is_err());
        assert!(authorization
            .authorize_resume(client_key, ClientHello::resume(wrong_id, 0).unwrap(), 0)
            .is_err());
        assert!(authorization
            .authorize_resume(client_key, ClientHello::resume(id, 1).unwrap(), 0)
            .is_err());
        assert!(authorization
            .authorize_resume(client_key, hello.clone(), 0)
            .is_err());

        assert!(AssociationAuthorization::establish(
            wrong_id,
            22,
            client_key,
            ClientHello::initial(id, 0, token.clone(), 22).unwrap(),
            &owner
        )
        .is_err());
        assert!(AssociationAuthorization::establish(
            id,
            23,
            client_key,
            ClientHello::initial(id, 0, token.clone(), 22).unwrap(),
            &owner
        )
        .is_err());
        assert!(AssociationAuthorization::establish(
            id,
            22,
            client_key,
            ClientHello::initial(id, 1, token.clone(), 22).unwrap(),
            &owner
        )
        .is_err());
        assert!(AssociationAuthorization::establish(
            id,
            22,
            client_key,
            ClientHello::initial(id, 0, SecretToken::from_bytes([0x63; 32]), 22).unwrap(),
            &owner
        )
        .is_err());
        assert!(matches!(
            AssociationAuthorization::establish(
                id,
                22,
                client_key,
                ClientHello::initial(id, 0, token, 22).unwrap(),
                &owner
            ),
            Err(Error::TokenReuse)
        ));
    }
}
