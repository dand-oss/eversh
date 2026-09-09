//! Ephemeral gateway and client identities for bootstrap-pinned TLS.
//!
//! This follows the hardened key-generation path proven by `everssh`, but
//! omits its one-shot server token because one persistent gateway issues many
//! independently bounded invitations. Application copies of PKCS#8 bytes are
//! scrubbed as soon as the ring signing key has been constructed.

use everssh::bootstrap::sha256;
use everssh::pinning::extract_spki;
use noq::rustls::crypto::ring::sign::any_supported_type;
use noq::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use noq::rustls::sign::CertifiedKey;
use rcgen::{CertificateParams, KeyPair};
use std::fmt;
use std::sync::Arc;
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityError {
    KeyGeneration,
    CertificateGeneration,
    CertificateMalformed,
    SigningKey,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::KeyGeneration => "failed to generate an everudp identity key",
            Self::CertificateGeneration => "failed to generate an everudp certificate",
            Self::CertificateMalformed => "generated everudp certificate has no valid SPKI",
            Self::SigningKey => "everudp certificate and signing key do not match",
        })
    }
}

impl std::error::Error for IdentityError {}

pub struct GatewayIdentity(GeneratedIdentity);

impl GatewayIdentity {
    pub fn generate() -> Result<Self, IdentityError> {
        GeneratedIdentity::generate().map(Self)
    }

    pub fn certificate_der(&self) -> &CertificateDer<'static> {
        &self.0.certificate
    }

    pub fn spki_sha256(&self) -> [u8; 32] {
        self.0.spki_sha256
    }

    pub(crate) fn certified_key(&self) -> Arc<CertifiedKey> {
        self.0.certified_key.clone()
    }
}

impl fmt::Debug for GatewayIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayIdentity")
            .field("certificate_len", &self.0.certificate.as_ref().len())
            .field("spki_sha256", &self.0.spki_sha256)
            .field("private_key", &"<REDACTED>")
            .finish()
    }
}

pub struct ClientIdentity(GeneratedIdentity);

impl ClientIdentity {
    pub fn generate() -> Result<Self, IdentityError> {
        GeneratedIdentity::generate().map(Self)
    }

    pub fn certificate_der(&self) -> &CertificateDer<'static> {
        &self.0.certificate
    }

    pub fn spki_sha256(&self) -> [u8; 32] {
        self.0.spki_sha256
    }

    pub(crate) fn certified_key(&self) -> Arc<CertifiedKey> {
        self.0.certified_key.clone()
    }
}

impl fmt::Debug for ClientIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientIdentity")
            .field("certificate_len", &self.0.certificate.as_ref().len())
            .field("spki_sha256", &self.0.spki_sha256)
            .field("private_key", &"<REDACTED>")
            .finish()
    }
}

struct GeneratedIdentity {
    certificate: CertificateDer<'static>,
    certified_key: Arc<CertifiedKey>,
    spki_sha256: [u8; 32],
}

impl GeneratedIdentity {
    fn generate() -> Result<Self, IdentityError> {
        let key_pair = KeyPair::generate().map_err(|_| IdentityError::KeyGeneration)?;
        let key_pair = ZeroizingKeyPair(key_pair);
        let parameters = CertificateParams::new(vec!["localhost".to_owned()])
            .map_err(|_| IdentityError::CertificateGeneration)?;
        let certificate = parameters
            .self_signed(&key_pair.0)
            .map_err(|_| IdentityError::CertificateGeneration)?
            .der()
            .clone();
        let spki = extract_spki(&certificate).ok_or(IdentityError::CertificateMalformed)?;
        let spki_sha256 = sha256(spki);
        let signing_key = parse_signing_key(key_pair.0.serialized_der())?;
        let certified_key = CertifiedKey::new(vec![certificate.clone()], signing_key);
        certified_key
            .keys_match()
            .map_err(|_| IdentityError::SigningKey)?;
        Ok(Self {
            certificate,
            certified_key: Arc::new(certified_key),
            spki_sha256,
        })
    }
}

fn parse_signing_key(
    key_der: &[u8],
) -> Result<Arc<dyn noq::rustls::sign::SigningKey>, IdentityError> {
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
    any_supported_type(&key).map_err(|_| IdentityError::SigningKey)
}

struct ZeroizingKeyPair(KeyPair);

impl Drop for ZeroizingKeyPair {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_private_key_is_typed() {
        assert!(matches!(
            parse_signing_key(&[1, 2, 3]),
            Err(IdentityError::SigningKey)
        ));
    }
}
