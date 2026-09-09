//! Ring-backed ephemeral certificate, signing key, and one-use token.

use crate::admission::OneUseToken;
use crate::bootstrap::{sha256, SecretToken, TOKEN_LEN};
use crate::error::Error;
use crate::pinning::extract_spki;
use noq::rustls::crypto::ring::sign::any_supported_type;
use noq::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use noq::rustls::sign::CertifiedKey;
use rcgen::{CertificateParams, KeyPair};
use ring::rand::{SecureRandom, SystemRandom};
use std::sync::{Arc, Mutex};
use zeroize::{Zeroize, Zeroizing};

/// Complete server identity without any diagnostic path to its private state.
pub struct EphemeralIdentity {
    certificate: CertificateDer<'static>,
    certified_key: Arc<CertifiedKey>,
    spki_sha256: [u8; 32],
    bootstrap_token: Mutex<Option<SecretToken>>,
    token_owner: Arc<OneUseToken>,
}

impl EphemeralIdentity {
    pub fn generate() -> Result<Self, Error> {
        generate_with(&RingTokenRandom, || {
            KeyPair::generate().map_err(|_| Error::IdentityKeyGeneration)
        })
    }

    pub fn certificate_der(&self) -> &CertificateDer<'static> {
        &self.certificate
    }

    pub fn spki_sha256(&self) -> [u8; 32] {
        self.spki_sha256
    }

    /// Move the only bootstrap-record copy out exactly once.
    pub fn take_bootstrap_token(&self) -> Result<SecretToken, Error> {
        self.bootstrap_token
            .lock()
            .map_err(|_| Error::IdentityUnavailable)?
            .take()
            .ok_or(Error::IdentityUnavailable)
    }

    pub(crate) fn certified_key(&self) -> Arc<CertifiedKey> {
        self.certified_key.clone()
    }

    pub(crate) fn token_owner(&self) -> Arc<OneUseToken> {
        self.token_owner.clone()
    }
}

impl std::fmt::Debug for EphemeralIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EphemeralIdentity")
            .field("certificate_len", &self.certificate.as_ref().len())
            .field("spki_sha256", &self.spki_sha256)
            .field("private_key", &"<REDACTED>")
            .field("token", &"<REDACTED>")
            .finish()
    }
}

/// Ephemeral client identity used by the v2 association ProxyCommand.
///
/// The certificate is intentionally self-signed: TLS proves possession of the
/// private key, while the one-use bootstrap authentication binds its SPKI to
/// one server association. No CA trust or long-lived identity is introduced.
pub struct EphemeralClientIdentity {
    certificate: CertificateDer<'static>,
    private_key_der: Zeroizing<Vec<u8>>,
    spki_sha256: [u8; 32],
}

impl EphemeralClientIdentity {
    pub fn generate() -> Result<Self, Error> {
        generate_client_with(|| KeyPair::generate().map_err(|_| Error::IdentityKeyGeneration))
    }

    pub fn certificate_der(&self) -> &CertificateDer<'static> {
        &self.certificate
    }

    pub fn spki_sha256(&self) -> [u8; 32] {
        self.spki_sha256
    }

    pub(crate) fn private_key_der(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.private_key_der.to_vec()))
    }
}

impl std::fmt::Debug for EphemeralClientIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EphemeralClientIdentity")
            .field("certificate_len", &self.certificate.as_ref().len())
            .field("spki_sha256", &self.spki_sha256)
            .field("private_key", &"<REDACTED>")
            .finish()
    }
}

trait TokenRandom {
    fn fill(&self, destination: &mut [u8]) -> Result<(), ()>;
}

struct RingTokenRandom;

impl TokenRandom for RingTokenRandom {
    fn fill(&self, destination: &mut [u8]) -> Result<(), ()> {
        SystemRandom::new().fill(destination).map_err(|_| ())
    }
}

fn generate_with<R, K>(random: &R, key_source: K) -> Result<EphemeralIdentity, Error>
where
    R: TokenRandom,
    K: FnOnce() -> Result<KeyPair, Error>,
{
    let mut token_bytes = Zeroizing::new([0; TOKEN_LEN]);
    random
        .fill(&mut token_bytes[..])
        .map_err(|()| Error::IdentityRandomness)?;
    let bootstrap_token = SecretToken::from_bytes(*token_bytes);
    let token_owner = Arc::new(OneUseToken::new(bootstrap_token.clone()));

    let key_pair = ZeroizingKeyPair(key_source()?);
    let parameters = CertificateParams::new(vec!["localhost".to_owned()])
        .map_err(|_| Error::IdentityCertificateGeneration)?;
    let certificate = parameters
        .self_signed(&key_pair.0)
        .map_err(|_| Error::IdentityCertificateGeneration)?;
    let certificate = certificate.der().clone();
    let spki = extract_spki(&certificate).ok_or(Error::IdentityCertificateMalformed)?;
    let spki_sha256 = sha256(spki);

    let signing_key = parse_signing_key(key_pair.0.serialized_der())?;
    let certified_key = CertifiedKey::new(vec![certificate.clone()], signing_key);
    certified_key
        .keys_match()
        .map_err(|_| Error::IdentitySigningKey)?;

    Ok(EphemeralIdentity {
        certificate,
        certified_key: Arc::new(certified_key),
        spki_sha256,
        bootstrap_token: Mutex::new(Some(bootstrap_token)),
        token_owner,
    })
}

fn generate_client_with<K>(key_source: K) -> Result<EphemeralClientIdentity, Error>
where
    K: FnOnce() -> Result<KeyPair, Error>,
{
    let key_pair = ZeroizingKeyPair(key_source()?);
    let parameters = CertificateParams::new(vec!["localhost".to_owned()])
        .map_err(|_| Error::IdentityCertificateGeneration)?;
    let certificate = parameters
        .self_signed(&key_pair.0)
        .map_err(|_| Error::IdentityCertificateGeneration)?;
    let certificate = certificate.der().clone();
    let spki = extract_spki(&certificate).ok_or(Error::IdentityCertificateMalformed)?;
    let spki_sha256 = sha256(spki);
    let private_key_der = Zeroizing::new(key_pair.0.serialized_der().to_vec());
    let signing_key = parse_signing_key(&private_key_der)?;
    let certified_key = CertifiedKey::new(vec![certificate.clone()], signing_key);
    certified_key
        .keys_match()
        .map_err(|_| Error::IdentitySigningKey)?;
    drop(certified_key);

    Ok(EphemeralClientIdentity {
        certificate,
        private_key_der,
        spki_sha256,
    })
}

fn parse_signing_key(key_der: &[u8]) -> Result<Arc<dyn noq::rustls::sign::SigningKey>, Error> {
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
    any_supported_type(&key).map_err(|_| Error::IdentitySigningKey)
}

struct ZeroizingKeyPair(KeyPair);

impl Drop for ZeroizingKeyPair {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    struct FailingRandom;

    impl TokenRandom for FailingRandom {
        fn fill(&self, _destination: &mut [u8]) -> Result<(), ()> {
            Err(())
        }
    }

    #[test]
    fn injected_generation_failures_are_typed() {
        assert!(matches!(
            generate_with(&FailingRandom, || {
                KeyPair::generate().map_err(|_| Error::IdentityKeyGeneration)
            }),
            Err(Error::IdentityRandomness)
        ));
        assert!(matches!(
            generate_with(&RingTokenRandom, || Err(Error::IdentityKeyGeneration)),
            Err(Error::IdentityKeyGeneration)
        ));
        assert!(matches!(
            parse_signing_key(&[1, 2, 3]),
            Err(Error::IdentitySigningKey)
        ));
    }

    #[test]
    fn rcgen_application_der_copy_is_explicitly_scrubbed() {
        let mut key_pair = KeyPair::generate().map_err(|_| ()).ok();
        assert!(key_pair.is_some());
        if let Some(key_pair) = &mut key_pair {
            assert!(key_pair.serialized_der().iter().any(|byte| *byte != 0));
            key_pair.zeroize();
            assert!(key_pair.serialized_der().iter().all(|byte| *byte == 0));
        }
    }
}
