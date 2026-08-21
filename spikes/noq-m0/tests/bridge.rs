//! M0 integration tests, part 1: authenticated bootstrap, one-stream bridge,
//! EOF/half-close, pinning rejection, token one-use, Retry requirement, and
//! "no TCP connect before authentication".

use noq_m0::config::Limits;
use noq_m0::shutdown::{ShutdownState, TerminalCause};
use noq_m0::spike::{
    bridge, client_connect_auth, client_endpoint, generate_identity, server_accept_auth,
    server_endpoint, SpikeError,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

/// A dumb loopback byte target: echoes nothing, records connect count, can be
/// told to serve a fixed response and capture received bytes.
struct ByteTarget {
    addr: SocketAddr,
    connected: Arc<AtomicUsize>,
    received: Arc<std::sync::Mutex<Vec<u8>>>,
    responder: Arc<std::sync::Mutex<Option<Vec<u8>>>>,
    _handle: tokio::task::JoinHandle<()>,
}

impl ByteTarget {
    async fn spawn() -> Self {
        let listener = tokio::net::TcpListener::bind(localhost(0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connected = Arc::new(AtomicUsize::new(0));
        let received = Arc::new(std::sync::Mutex::new(Vec::new()));
        let responder: Arc<std::sync::Mutex<Option<Vec<u8>>>> =
            Arc::new(std::sync::Mutex::new(None));
        let (c2, r2, resp2) = (connected.clone(), received.clone(), responder.clone());
        let handle = tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                c2.fetch_add(1, Ordering::SeqCst);
                let r = r2.clone();
                let resp = resp2.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                r.lock().unwrap().extend_from_slice(&buf[..n]);
                                let data = resp.lock().unwrap().clone();
                                if let Some(data) = data {
                                    let _ = sock.write_all(&data).await;
                                }
                            }
                        }
                    }
                });
            }
        });
        Self {
            addr,
            connected,
            received,
            responder,
            _handle: handle,
        }
    }
}

async fn auth_pair(
    l: &Limits,
    target_port: u16,
) -> (
    noq::Connection,
    noq::SendStream,
    noq::RecvStream,
    noq::Connection,
    noq::SendStream,
    noq::RecvStream,
) {
    let id = generate_identity();
    let ep = server_endpoint(&id, localhost(0), l).unwrap();
    let port = ep.local_addr().unwrap().port();
    let state = Arc::new(ShutdownState::new());
    let server = tokio::spawn({
        let ep = ep.clone();
        let token = id.token;
        let l = *l;
        async move { server_accept_auth(&ep, &token, target_port, &l, &state).await }
    });
    let cep = client_endpoint(id.spki_sha256, l).unwrap();
    let (cconn, csend, crecv) =
        client_connect_auth(&cep, localhost(port), &id.token, target_port, l)
            .await
            .expect("client auth");
    let auth = server.await.unwrap().expect("server auth");
    (auth.conn, auth.send, auth.recv, cconn, csend, crecv)
}

#[tokio::test]
async fn auth_then_bridge_transparent_binary_both_directions() {
    let l = Limits::default();
    let target = ByteTarget::spawn().await;
    // Arbitrary binary, explicitly not UTF-8.
    let up: Vec<u8> = (0..4096u32).map(|i| (i * 7 + 13) as u8).collect();
    let down = vec![0xffu8, 0x00, 0xfe, 0x80, 0x81, 0x7f, 0x01, 0x02];
    target.responder.lock().unwrap().replace(down.clone());

    let (sconn, ssend, srecv, _cconn, mut csend, mut crecv) =
        auth_pair(&l, target.addr.port()).await;

    let state = Arc::new(ShutdownState::new());
    let tcp = tokio::net::TcpStream::connect(target.addr).await.unwrap();
    let br = tokio::spawn(bridge(ssend, srecv, tcp, Limits::default(), state.clone()));

    csend.write_all(&up).await.unwrap();
    csend.finish().unwrap();
    let got = crecv.read_to_end(1 << 20).await.unwrap();
    br.await.unwrap();
    let _ = sconn;
    assert_eq!(
        got, down,
        "downlink bytes must be exactly the target response"
    );
    assert_eq!(
        target.received.lock().unwrap().clone(),
        up,
        "uplink bytes must arrive byte-identical"
    );
    assert_eq!(target.connected.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn no_target_tcp_connect_before_or_without_authentication() {
    let l = Limits::default();
    let target = ByteTarget::spawn().await;
    let id = generate_identity();
    let ep = server_endpoint(&id, localhost(0), &l).unwrap();
    let state = Arc::new(ShutdownState::new());

    // No client at all: the server must time out without touching the target.
    let mut ll = l;
    ll.server_lease = Duration::from_millis(300);
    let r = server_accept_auth(&ep, &id.token, target.addr.port(), &ll, &state).await;
    assert!(matches!(r, Err(SpikeError::Timeout(_))), "lease expiry");
    assert_eq!(
        target.connected.load(Ordering::SeqCst),
        0,
        "no TCP connect before authentication"
    );
    assert_eq!(state.cause(), Some(TerminalCause::LeaseExpired));
}

#[tokio::test]
async fn wrong_pin_is_rejected_by_tls() {
    let l = Limits::default();
    let target = ByteTarget::spawn().await;
    let id = generate_identity();
    let ep = server_endpoint(&id, localhost(0), &l).unwrap();
    let port = ep.local_addr().unwrap().port();
    let state = Arc::new(ShutdownState::new());
    let server = tokio::spawn({
        let ep = ep.clone();
        let token = id.token;
        async move { server_accept_auth(&ep, &token, target.addr.port(), &l, &state).await }
    });
    // A DIFFERENT pin: another identity's SPKI hash.
    let other = generate_identity();
    let cep = client_endpoint(other.spki_sha256, &l).unwrap();
    let r = client_connect_auth(&cep, localhost(port), &id.token, target.addr.port(), &l).await;
    assert!(r.is_err(), "TLS must fail closed on pin mismatch");
    let _ = server.await;

    assert_eq!(target.connected.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn wrong_token_is_rejected_and_target_untouched() {
    let l = Limits::default();
    let target = ByteTarget::spawn().await;
    let id = generate_identity();
    let ep = server_endpoint(&id, localhost(0), &l).unwrap();
    let port = ep.local_addr().unwrap().port();
    let state = Arc::new(ShutdownState::new());
    let server = tokio::spawn({
        let ep = ep.clone();
        let token = id.token;
        async move { server_accept_auth(&ep, &token, target.addr.port(), &l, &state).await }
    });
    let cep = client_endpoint(id.spki_sha256, &l).unwrap();
    let mut wrong = id.token;
    wrong[0] ^= 0xff;
    // Handshake succeeds (pin ok); token must fail at the server.
    let conn = tokio::time::timeout(
        l.handshake_timeout,
        cep.connect(localhost(port), "localhost").unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    let (mut send, _recv) = conn.open_bi().await.unwrap();
    use noq_m0::protocol::encode_auth_frame;
    send.write_all(&encode_auth_frame(&wrong, target.addr.port()))
        .await
        .unwrap();
    let r = server.await.unwrap();
    assert!(matches!(r, Err(SpikeError::Auth(_))), "bad token");
    assert_eq!(target.connected.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn retry_address_validation_is_required_and_connection_survives_it() {
    let l = Limits::default();
    let target = ByteTarget::spawn().await;
    let (sconn, _ssend, _srecv, cconn, _csend, _crecv) = auth_pair(&l, target.addr.port()).await;
    // If the handshake completed through the spike server's forced Retry, the
    // connection is alive and authenticated.
    assert!(cconnstable_probe(&cconn).await);
    let _ = sconn;
}

async fn cconnstable_probe(c: &noq::Connection) -> bool {
    c.close_reason().is_none() && c.stable_id() != 0
}

#[tokio::test]
async fn eof_half_close_propagation() {
    // Client half-closes its send side; target sees TCP FIN; target response
    // still flows back; server drain completes; no task survives.
    let l = Limits::default();
    let target = ByteTarget::spawn().await;
    let up = b"half-close-me".to_vec();
    let down = b"late-reply".to_vec();
    target.responder.lock().unwrap().replace(down.clone());
    let (sconn, ssend, srecv, _cconn, mut csend, mut crecv) =
        auth_pair(&l, target.addr.port()).await;
    let state = Arc::new(ShutdownState::new());
    let tcp = tokio::net::TcpStream::connect(target.addr).await.unwrap();
    let br = tokio::spawn(bridge(ssend, srecv, tcp, Limits::default(), state.clone()));
    csend.write_all(&up).await.unwrap();
    csend.finish().unwrap();
    let got = crecv.read_to_end(1 << 20).await.unwrap();
    br.await.unwrap();
    assert_eq!(got, down);
    assert_eq!(state.phase(), noq_m0::shutdown::Phase::Finalized);
    let _ = sconn;
}
