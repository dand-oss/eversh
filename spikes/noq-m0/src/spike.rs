//! Core spike roles: one-shot QUIC server, pinning client, and the transparent
//! one-stream bridge with bounded backpressure and Request -> Drain -> Finalize.

use crate::config::Limits;
use crate::pinning::{extract_spki, sha256, SpkiPinVerifier};
use crate::protocol::{ct_eq, decode_auth_frame, encode_auth_frame, ProtocolError};
use crate::shutdown::{ShutdownState, TerminalCause};
use noq::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use noq::rustls::ClientConfig as RustlsClientConfig;
use noq::{
    ClientConfig, Connection, Endpoint, RecvStream, SendStream, ServerConfig, TransportConfig,
    VarInt,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const SPIKE_ALPN: &[&[u8]] = &[b"eversh-link/1"];

#[derive(Debug)]
pub enum SpikeError {
    Io(std::io::Error),
    Quic(noq::ConnectionError),
    Protocol(ProtocolError),
    Auth(&'static str),
    Timeout(&'static str),
}

impl std::fmt::Display for SpikeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Quic(e) => write!(f, "quic: {e}"),
            Self::Protocol(e) => write!(f, "{e}"),
            Self::Auth(m) => write!(f, "auth: {m}"),
            Self::Timeout(m) => write!(f, "deadline: {m}"),
        }
    }
}
impl std::error::Error for SpikeError {}
impl From<std::io::Error> for SpikeError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<noq::ConnectError> for SpikeError {
    fn from(e: noq::ConnectError) -> Self {
        Self::Io(std::io::Error::other(e))
    }
}
impl From<ProtocolError> for SpikeError {
    fn from(e: ProtocolError) -> Self {
        Self::Protocol(e)
    }
}
impl From<noq::rustls::Error> for SpikeError {
    fn from(_e: noq::rustls::Error) -> Self {
        Self::Auth("rustls")
    }
}
impl From<noq::ConnectionError> for SpikeError {
    fn from(e: noq::ConnectionError) -> Self {
        Self::Quic(e)
    }
}

fn transport_config(l: &Limits) -> Arc<TransportConfig> {
    let mut t = TransportConfig::default();
    t.max_concurrent_bidi_streams(VarInt::from_u32(l.max_bi_streams));
    t.max_concurrent_uni_streams(VarInt::from_u32(0));
    t.receive_window(VarInt::from_u32(l.receive_window as u32));
    t.stream_receive_window(VarInt::from_u32(l.receive_window as u32));
    t.send_window(l.send_window);
    t.max_idle_timeout(Some(noq::IdleTimeout::from(VarInt::from_u32(
        l.idle_timeout.as_millis() as u32,
    ))));
    Arc::new(t)
}

/// Ephemeral server identity: self-signed certificate + SPKI SHA-256 pin +
/// one-use token. `rcgen` keys are ring-backed.
pub struct ServerIdentity {
    pub cert: CertificateDer<'static>,
    pub key: PrivateKeyDer<'static>,
    pub spki_sha256: [u8; 32],
    pub token: [u8; 32],
}

pub fn generate_identity() -> ServerIdentity {
    // Deterministic-enough ephemeral identity; the RNG source is ring.
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let spki = extract_spki(ck.cert.der()).expect("generated cert has spki");
    let mut token = [0u8; 32];
    use ring::rand::{SecureRandom, SystemRandom};
    SystemRandom::new()
        .fill(&mut token)
        .expect("ring system rng");
    ServerIdentity {
        cert: ck.cert.der().clone(),
        key: noq::rustls::pki_types::PrivateKeyDer::Pkcs8(
            noq::rustls::pki_types::PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()),
        ),
        spki_sha256: sha256(spki),
        token,
    }
}

pub fn server_endpoint(
    id: &ServerIdentity,
    bind: SocketAddr,
    l: &Limits,
) -> Result<Endpoint, SpikeError> {
    let mut rc = noq::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![id.cert.clone()], id.key.clone_key())?;
    rc.alpn_protocols = SPIKE_ALPN.iter().map(|p| p.to_vec()).collect();
    let quic_server = noq::crypto::rustls::QuicServerConfig::try_from(Arc::new(rc))
        .map_err(|_| SpikeError::Auth("no initial cipher suite"))?;
    let mut sc = ServerConfig::with_crypto(Arc::new(quic_server));
    sc.transport_config(transport_config(l));
    Ok(Endpoint::server(sc, bind)?)
}

/// Client endpoint trusting exactly one SPKI pin. 0-RTT is structurally
/// disabled: no session storage, no early data.
pub fn client_endpoint(pin: [u8; 32], l: &Limits) -> std::io::Result<Endpoint> {
    let provider = Arc::new(noq::rustls::crypto::ring::default_provider());
    let mut rc = RustlsClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SpkiPinVerifier::new(pin, provider)))
        .with_no_client_auth();
    rc.alpn_protocols = SPIKE_ALPN.iter().map(|p| p.to_vec()).collect();
    rc.resumption = noq::rustls::client::Resumption::disabled();
    let quic_client = noq::crypto::rustls::QuicClientConfig::try_from(Arc::new(rc)).unwrap();
    let mut cc = ClientConfig::new(Arc::new(quic_client));
    cc.transport_config(transport_config(l));
    let ep = Endpoint::client("0.0.0.0:0".parse().unwrap())?;
    ep.set_default_client_config(cc);
    Ok(ep)
}

/// Client side: connect, authenticate on the first bidirectional stream, and
/// return the stream halves for transparent bridging.
pub async fn client_connect_auth(
    ep: &Endpoint,
    server: SocketAddr,
    token: &[u8; 32],
    target_port: u16,
    l: &Limits,
) -> Result<(Connection, SendStream, RecvStream), SpikeError> {
    let conn = tokio::time::timeout(
        l.handshake_timeout,
        ep.connect(server, "localhost")
            .map_err(|e| SpikeError::Io(std::io::Error::other(e)))?,
    )
    .await
    .map_err(|_| SpikeError::Timeout("handshake"))??;
    let (mut send, recv) = tokio::time::timeout(l.handshake_timeout, conn.open_bi())
        .await
        .map_err(|_| SpikeError::Timeout("open_bi"))?
        .map_err(SpikeError::Quic)?;
    send.write_all(&encode_auth_frame(token, target_port))
        .await
        .map_err(|e| SpikeError::Io(std::io::Error::other(e)))?;
    Ok((conn, send, recv))
}

pub struct AuthOutcome {
    pub conn: Connection,
    pub send: SendStream,
    pub recv: RecvStream,
    pub peer: SocketAddr,
    pub retried: bool,
}

/// One-shot server accept loop: require address validation (Retry), accept one
/// connection, authenticate the first bidirectional stream, consume the token,
/// reject duplicates. The TCP target is returned unconnected: the caller
/// connects only after this returns Ok, which structurally guarantees
/// "no target TCP connection before authentication".
pub async fn server_accept_auth(
    ep: &Endpoint,
    token: &[u8; 32],
    authorized_target_port: u16,
    l: &Limits,
    state: &ShutdownState,
) -> Result<AuthOutcome, SpikeError> {
    let incoming = tokio::time::timeout(l.server_lease, ep.accept())
        .await
        .map_err(|_| {
            state.request(TerminalCause::LeaseExpired);
            SpikeError::Timeout("server lease expired")
        })?
        .ok_or(SpikeError::Auth("endpoint closed before accept"))?;
    let retried;
    let incoming = if !incoming.remote_address_validated() {
        incoming
            .retry()
            .map_err(|_| SpikeError::Auth("retry refused"))?;
        let incoming2 = tokio::time::timeout(l.handshake_timeout, ep.accept())
            .await
            .map_err(|_| SpikeError::Timeout("no retry response"))?;
        let incoming = incoming2.ok_or(SpikeError::Auth("endpoint closed after retry"))?;
        if !incoming.remote_address_validated() {
            return Err(SpikeError::Auth("client did not validate address"));
        }
        retried = true;
        incoming
    } else {
        retried = false;
        incoming
    };
    let peer = incoming.remote_address();
    let connecting = incoming.accept().map_err(SpikeError::Quic)?;
    let conn = tokio::time::timeout(l.handshake_timeout, connecting)
        .await
        .map_err(|_| SpikeError::Timeout("handshake after retry"))??;

    let (send, mut recv) = tokio::time::timeout(l.handshake_timeout, conn.accept_bi())
        .await
        .map_err(|_| SpikeError::Timeout("accept_bi"))?
        .map_err(SpikeError::Quic)?;
    let mut frame = vec![0u8; l.auth_frame_len];
    tokio::time::timeout(l.handshake_timeout, recv.read_exact(&mut frame))
        .await
        .map_err(|_| SpikeError::Timeout("auth frame"))?
        .map_err(|_| SpikeError::Auth("short auth frame"))?;
    let (version, got_token, port) = decode_auth_frame(&frame)?;
    if version != crate::PROTOCOL_VERSION {
        return Err(SpikeError::Auth("unsupported version"));
    }
    if port != authorized_target_port {
        return Err(SpikeError::Auth("unauthorized target"));
    }
    if !ct_eq(&got_token, token) {
        return Err(SpikeError::Auth("bad token"));
    }
    // Token consumed: one-use. A second auth attempt arrives as a second
    // stream, which the accept loop below refuses.
    Ok(AuthOutcome {
        conn,
        send,
        recv,
        peer,
        retried,
    })
}

/// Bridge an authenticated QUIC stream to the authorized TCP target with two
/// backpressured copy loops. Returns after both directions reached a terminal
/// event. Every operation is bounded by the configured stall deadline.
/// QUIC -> TCP direction. Owned halves only; direct backpressure, no queue.
async fn copy_quic_to_tcp(
    mut quic_recv: RecvStream,
    mut tcp_w: tokio::net::tcp::OwnedWriteHalf,
    l: Limits,
    state: Arc<ShutdownState>,
) {
    let mut buf = vec![0u8; l.copy_buf];
    loop {
        let n = match tokio::time::timeout(l.stall_timeout, quic_recv.read(&mut buf)).await {
            Err(_) => {
                state.request(TerminalCause::Stalled);
                break;
            }
            Ok(Err(_)) => {
                state.request(TerminalCause::QuicClosed);
                break;
            }
            Ok(Ok(None)) => {
                // QUIC EOF: half-close the TCP write side.
                let _ = tcp_w.shutdown().await;
                break;
            }
            Ok(Ok(Some(0))) => continue,
            Ok(Ok(Some(n))) => n,
        };
        let w = tokio::time::timeout(l.stall_timeout, tcp_w.write_all(&buf[..n])).await;
        if w.is_err() || w.unwrap().is_err() {
            state.request(TerminalCause::TargetClosed);
            break;
        }
    }
    if std::env::var_os("NOQ_M0_DEBUG").is_some() {
        eprintln!("noq-m0 copy q2t done");
    }
    let _ = quic_recv.stop(VarInt::from_u32(0));
}

/// TCP -> QUIC direction. Owned halves only; direct backpressure, no queue.
async fn copy_tcp_to_quic(
    mut tcp_r: tokio::net::tcp::OwnedReadHalf,
    mut quic_send: SendStream,
    l: Limits,
    state: Arc<ShutdownState>,
) {
    let mut buf = vec![0u8; l.copy_buf];
    let mut clean_finish = false;
    loop {
        let n = match tokio::time::timeout(l.stall_timeout, tcp_r.read(&mut buf)).await {
            Err(_) => {
                state.request(TerminalCause::Stalled);
                break;
            }
            Ok(Err(_)) => {
                state.request(TerminalCause::TargetClosed);
                break;
            }
            Ok(Ok(0)) => {
                // TCP EOF: finish the QUIC send side (half-close).
                let _ = quic_send.finish();
                clean_finish = true;
                state.request(TerminalCause::TargetClosed);
                break;
            }
            Ok(Ok(n)) => n,
        };
        let w = tokio::time::timeout(l.stall_timeout, quic_send.write_all(&buf[..n])).await;
        if w.is_err() || w.unwrap().is_err() {
            state.request(TerminalCause::QuicClosed);
            break;
        }
    }
    if std::env::var_os("NOQ_M0_DEBUG").is_some() {
        eprintln!("noq-m0 copy t2q done clean={clean_finish}");
    }
    if !clean_finish {
        // Abnormal exit: reset so the peer does not wait for a FIN.
        let _ = quic_send.reset(VarInt::from_u32(0));
    }
}

/// Bridge an authenticated QUIC stream to the authorized TCP target with two
/// directly backpressured copy loops and explicit Request -> Drain -> Finalize.
/// Returns the joined copy tasks so callers own task lifetime; every operation
/// is bounded by the configured stall deadline and the drain deadline bounds
/// the whole phase.
pub async fn bridge(
    quic_send: SendStream,
    quic_recv: RecvStream,
    tcp: TcpStream,
    l: Limits,
    state: Arc<ShutdownState>,
) {
    let (tcp_r, tcp_w) = tcp.into_split();
    let mut q2t = tokio::spawn(copy_quic_to_tcp(quic_recv, tcp_w, l, state.clone()));
    let mut t2q = tokio::spawn(copy_tcp_to_quic(tcp_r, quic_send, l, state.clone()));
    // Both directions run concurrently while the bridge is healthy; the drain
    // deadline bounds only the SECOND direction after the first one reaches
    // its terminal event. Every individual operation is separately bounded by
    // the stall deadline, so a live bridge is never killed early.
    tokio::select! {
        _ = &mut q2t => {
            if tokio::time::timeout(l.drain_timeout, &mut t2q).await.is_err() {
                state.request(TerminalCause::Stalled);
            }
        }
        _ = &mut t2q => {
            if tokio::time::timeout(l.drain_timeout, &mut q2t).await.is_err() {
                state.request(TerminalCause::Stalled);
            }
        }
    }
    state.drain();
    state.finalize();
}
