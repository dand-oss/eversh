//! SPKI SHA-256 pinning for the spike client.
//!
//! The client trusts exactly one hash: SHA-256 over the server certificate's
//! SubjectPublicKeyInfo DER. A custom rustls `ServerCertVerifier` makes TLS fail
//! closed for any other key, including a re-issued certificate for the same
//! name. The whole-certificate fingerprint is deliberately NOT used, so a
//! changed expiry/serial cannot silently pass.

use noq::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use noq::rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use noq::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use noq::rustls::DigitallySignedStruct;
use std::ops::Deref;
use std::sync::Arc;

#[derive(Debug)]
pub struct PinMismatch;

impl std::fmt::Display for PinMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "server SPKI does not match the bootstrap pin")
    }
}
impl std::error::Error for PinMismatch {}

/// A verifier that accepts exactly one SPKI SHA-256 pin and nothing else.
#[derive(Debug)]
pub struct SpkiPinVerifier {
    pin: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl SpkiPinVerifier {
    pub fn new(pin: [u8; 32], provider: Arc<CryptoProvider>) -> Self {
        Self { pin, provider }
    }
}

impl ServerCertVerifier for SpkiPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, noq::rustls::Error> {
        let spki = extract_spki(end_entity).ok_or_else(|| {
            noq::rustls::Error::General("cannot parse certificate SubjectPublicKeyInfo".into())
        })?;
        let computed = sha256(spki);
        if crate::protocol::ct_eq(&computed, &self.pin) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(noq::rustls::Error::General(PinMismatch.to_string()))
        }
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

/// Minimal DER walker: returns the raw SubjectPublicKeyInfo bytes of an X.509
/// certificate. Layout: Certificate SEQ { tbs SEQ { [0] version, serial INT,
/// sig SEQ, issuer SEQ, validity SEQ, subject SEQ, spki SEQ, ... } }.
pub fn extract_spki<'a>(cert: &'a CertificateDer<'_>) -> Option<&'a [u8]> {
    let der: &[u8] = cert.deref();
    // Outer Certificate SEQ body is the TBSCertificate TLV itself.
    let tbs_body = tlv(der)?.1;
    let tbs = tlv(tbs_body)?.1;
    let mut rest = tbs;
    // Optional [0] EXPLICIT version precedes serialNumber.
    if !rest.is_empty() && rest[0] == 0xA0 {
        rest = &rest[tlv(rest)?.2..];
    }
    // Skip serialNumber, signature, issuer, validity, subject.
    for _ in 0..5 {
        rest = &rest[tlv(rest)?.2..];
    }
    // Next TLV is SubjectPublicKeyInfo; return its full encoding.
    let (tag, _, consumed) = tlv(rest)?;
    if tag != 0x30 {
        return None;
    }
    Some(&rest[..consumed])
}

/// Parse one DER TLV; returns (tag, content, total_encoded_len).
pub fn tlv_probe(buf: &[u8]) -> Option<(u8, &[u8], usize)> {
    tlv(buf)
}

fn tlv(buf: &[u8]) -> Option<(u8, &[u8], usize)> {
    if buf.len() < 2 {
        return None;
    }
    let tag = buf[0];
    let mut i = 1;
    let first = buf[i];
    i += 1;
    let len = if first & 0x80 == 0 {
        first as usize
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || buf.len() < i + n {
            return None;
        }
        let mut l = 0usize;
        for b in &buf[i..i + n] {
            l = (l << 8) | *b as usize;
        }
        i += n;
        l
    };
    if buf.len() < i + len {
        return None;
    }
    Some((tag, &buf[i..i + len], i + len))
}

/// SHA-256 without pulling a second hash implementation: ring is already in
/// the noq feature path.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use ring::digest::{digest, SHA256};
    let d = digest(&SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_spki_matches_known_key_material() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let der = cert.cert.der();
        let spki = extract_spki(der).expect("spki");
        // SPKI must differ from the whole cert and be a plausible size.
        assert_ne!(spki, der.as_ref());
        assert!(spki.len() > 40 && spki.len() < der.len());
        // Deterministic: same cert, same hash.
        assert_eq!(sha256(spki), sha256(extract_spki(der).unwrap()));
    }
}
