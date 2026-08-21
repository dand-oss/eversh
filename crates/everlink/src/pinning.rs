//! SPKI extraction and pinning verifier (M0-proven path).
//!
//! `extract_spki` walks the certificate DER read-only to return the raw
//! SubjectPublicKeyInfo bytes; this is parsing, not certificate generation
//! (rcgen, pinned =0.13.2 with only `ring`, generates the ephemeral
//! certificate in M3). The verifier accepts exactly one SPKI SHA-256 pin
//! and fails closed for any other key.

use noq::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use noq::rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use noq::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use noq::rustls::DigitallySignedStruct;
use std::sync::Arc;

/// A verifier that accepts exactly one SPKI SHA-256 pin and nothing else.
/// The whole-certificate fingerprint is deliberately NOT used.
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
        if crate::bootstrap::ct_eq(&crate::bootstrap::sha256(spki), &self.pin) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(noq::rustls::Error::General(
                crate::Error::PinMismatch.to_string(),
            ))
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

/// Read-only DER walk: returns the raw SubjectPublicKeyInfo encoding of an
/// X.509 certificate: Certificate SEQ { tbs SEQ { [0] version?, serial, sig,
/// issuer, validity, subject, spki SEQ, ... } }.
pub fn extract_spki<'a>(cert: &'a CertificateDer<'_>) -> Option<&'a [u8]> {
    let der: &[u8] = std::ops::Deref::deref(cert);
    let tbs_body = tlv(der)?.1;
    let tbs = tlv(tbs_body)?.1;
    let mut rest = tbs;
    if !rest.is_empty() && rest[0] == 0xA0 {
        rest = &rest[tlv(rest)?.2..];
    }
    // Skip serialNumber, signature, issuer, validity, subject.
    for _ in 0..5 {
        rest = &rest[tlv(rest)?.2..];
    }
    let (tag, _, consumed) = tlv(rest)?;
    if tag != 0x30 {
        return None;
    }
    Some(&rest[..consumed])
}

/// Parse one DER TLV; returns (tag, content, total_encoded_len).
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
