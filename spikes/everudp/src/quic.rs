//! Minimal noq endpoint helpers for the spike. The TLS 1.3 handshake with
//! one pinned SPKI is the spike's authenticated key establishment.

use noq::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use noq::rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use noq::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use noq::rustls::ClientConfig as RustlsClientConfig;
use noq::rustls::DigitallySignedStruct;
use noq::{ClientConfig, Endpoint, ServerConfig, TransportConfig, VarInt};
use std::net::SocketAddr;
use std::sync::Arc;

pub const SPIKE_ALPN: &[&[u8]] = &[b"everudp-spike/1"];

pub struct Identity {
    pub cert: CertificateDer<'static>,
    pub key: PrivateKeyDer<'static>,
    pub spki_sha256: [u8; 32],
}

pub fn generate_identity() -> Identity {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("identity");
    let spki = extract_spki(ck.cert.der()).expect("generated cert has spki");
    Identity {
        cert: ck.cert.der().clone(),
        key: PrivateKeyDer::Pkcs8(noq::rustls::pki_types::PrivatePkcs8KeyDer::from(
            ck.key_pair.serialize_der(),
        )),
        spki_sha256: sha256(spki),
    }
}

pub fn server_endpoint(id: &Identity, bind: SocketAddr) -> std::io::Result<Endpoint> {
    let mut rc = noq::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![id.cert.clone()], id.key.clone_key())
        .map_err(std::io::Error::other)?;
    rc.alpn_protocols = SPIKE_ALPN.iter().map(|p| p.to_vec()).collect();
    let quic_server = noq::crypto::rustls::QuicServerConfig::try_from(Arc::new(rc))
        .map_err(std::io::Error::other)?;
    let mut sc = ServerConfig::with_crypto(Arc::new(quic_server));
    sc.transport_config(transport_config());
    Endpoint::server(sc, bind)
}

pub fn client_endpoint(pin: [u8; 32], bind: SocketAddr) -> std::io::Result<Endpoint> {
    let rustls_provider = Arc::new(noq::rustls::crypto::ring::default_provider());
    let mut rc = RustlsClientConfig::builder_with_provider(rustls_provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(std::io::Error::other)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SpkiPin::new(pin, rustls_provider)))
        .with_no_client_auth();
    rc.alpn_protocols = SPIKE_ALPN.iter().map(|p| p.to_vec()).collect();
    rc.resumption = noq::rustls::client::Resumption::disabled();
    let quic_client = noq::crypto::rustls::QuicClientConfig::try_from(Arc::new(rc))
        .map_err(std::io::Error::other)?;
    let mut cc = ClientConfig::new(Arc::new(quic_client));
    cc.transport_config(transport_config());
    let ep = Endpoint::client(bind)?;
    ep.set_default_client_config(cc);
    Ok(ep)
}

fn transport_config() -> Arc<TransportConfig> {
    let mut t = TransportConfig::default();
    t.max_concurrent_bidi_streams(VarInt::from_u32(0));
    t.max_concurrent_uni_streams(VarInt::from_u32(0));
    t.datagram_receive_buffer_size(Some(64 * 1024));
    Arc::new(t)
}

/// Minimal DER walker copied from the noq-m0 precedent: returns the raw
/// SubjectPublicKeyInfo bytes of an X.509 certificate.
pub fn extract_spki<'a>(cert: &'a CertificateDer<'_>) -> Option<&'a [u8]> {
    let der: &[u8] = cert.as_ref();
    let tbs_body = tlv(der)?.1;
    let tbs = tlv(tbs_body)?.1;
    let mut rest = tbs;
    if !rest.is_empty() && rest[0] == 0xA0 {
        rest = &rest[tlv(rest)?.2..];
    }
    for _ in 0..5 {
        rest = &rest[tlv(rest)?.2..];
    }
    let (tag, _, consumed) = tlv(rest)?;
    if tag != 0x30 {
        return None;
    }
    Some(&rest[..consumed])
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

fn sha256(data: &[u8]) -> [u8; 32] {
    use ring::digest::{digest, SHA256};
    let d = digest(&SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

#[derive(Debug)]
struct SpkiPin {
    pin: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl SpkiPin {
    fn new(pin: [u8; 32], provider: Arc<CryptoProvider>) -> Self {
        Self { pin, provider }
    }
}

impl ServerCertVerifier for SpkiPin {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, noq::rustls::Error> {
        let spki = extract_spki(end_entity)
            .ok_or_else(|| noq::rustls::Error::General("cannot parse certificate SPKI".into()))?;
        if sha256(spki) == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(noq::rustls::Error::General("SPKI pin mismatch".into()))
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
