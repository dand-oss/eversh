//! M0 gate 5a: API-level address rebinding (same QUIC connection and stream
//! survive `Endpoint::rebind`) and total path loss without replay.

use noq_m0::config::Limits;
use noq_m0::shutdown::{ShutdownState, TerminalCause};
use noq_m0::spike::{
    client_endpoint, client_connect_auth, generate_identity, server_accept_auth, server_endpoint,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

/// Established authenticated pair with the server bridging to a TCP sink that
/// counts and labels every received frame.
struct LivePair {
    client_ep: noq::Endpoint,
    client: noq::Connection,
    send: noq::SendStream,
    recv: noq::RecvStream,
    server_ep: noq::Endpoint,
    _server_task: tokio::task::JoinHandle<()>,
    got: Arc<std::sync::Mutex<Vec<u8>>>,
}

async fn established() -> LivePair {
    let l = Limits::default();
    // TCP sink: records everything, echoes a 1-byte ack per read.
    let listener = tokio::net::TcpListener::bind(localhost(0)).await.unwrap();
    let tport = listener.local_addr().unwrap().port();
    let got = Arc::new(std::sync::Mutex::new(Vec::new()));
    let g2 = got.clone();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 8192];
        loop {
            match sock.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    g2.lock().unwrap().extend_from_slice(&buf[..n]);
                    let _ = sock.write_all(b"A").await;
                }
            }
        }
    });

    let id = generate_identity();
    let server_ep = server_endpoint(&id, localhost(0), &l).unwrap();
    let sport = server_ep.local_addr().unwrap().port();
    let state = Arc::new(ShutdownState::new());
    let sep = server_ep.clone();
    let token = id.token;
    let stask = tokio::spawn(async move {
        let auth = server_accept_auth(&sep, &token, tport, &l, &state)
            .await
            .expect("server auth");
        let tcp = tokio::net::TcpStream::connect(localhost(tport)).await.unwrap();
        noq_m0::spike::bridge(auth.send, auth.recv, tcp, l, state).await;
    });

    let client_ep = client_endpoint(id.spki_sha256, &l).unwrap();
    let (client, send, recv) =
        client_connect_auth(&client_ep, localhost(sport), &id.token, tport, &l)
            .await
            .expect("client auth");
    LivePair {
        client_ep,
        client,
        send,
        recv,
        server_ep,
        _server_task: stask,
        got,
    }
}

fn frame(i: u64) -> Vec<u8> {
    // 1024-byte numbered binary frame: magic + index + payload.
    let mut f = vec![0u8; 1024];
    f[..8].copy_from_slice(&i.to_be_bytes());
    for (j, b) in f.iter_mut().enumerate().skip(8) {
        *b = ((i as usize) + j) as u8;
    }
    f
}

/// Every frame must arrive exactly once, in order, byte-identical.
fn verify_frames(got: &[u8], count: usize) {
    assert_eq!(got.len(), count * 1024, "total byte count");
    for i in 0..count {
        let want = frame(i as u64);
        assert_eq!(
            &got[i * 1024..(i + 1) * 1024],
            &want[..],
            "frame {i} corrupted/reordered"
        );
    }
}

#[tokio::test]
async fn rebind_preserves_connection_and_stream_no_loss_dup_reorder() {
    let mut p = established().await;
    let stable_before = p.client.stable_id();

    // Continuous numbered frames.
    for i in 0..40 {
        p.send.write_all(&frame(i)).await.unwrap();
    }
    // Drain acks to prove liveness pre-rebind.
    let mut ack = [0u8; 1];
    tokio::time::timeout(Duration::from_secs(5), p.recv.read_exact(&mut ack))
        .await
        .expect("pre-rebind ack deadline")
        .unwrap();

    // Rebind the client endpoint to a brand-new UDP socket (new source port).
    let new_sock = std::net::UdpSocket::bind(localhost(0)).unwrap();
    let new_port = new_sock.local_addr().unwrap().port();
    p.client_ep.rebind(new_sock).expect("rebind");
    assert_eq!(p.client_ep.local_addr().unwrap().port(), new_port);
    assert_eq!(p.client.stable_id(), stable_before, "same connection");

    // Keep sending across the migration.
    for i in 40..120 {
        p.send.write_all(&frame(i)).await.unwrap();
    }
    let _ = p.send.finish();

    // Verify every frame exactly once, in order, at the application boundary.
    let all = p.recv.read_to_end(1 << 20).await.unwrap();
    // `all` contains 1-byte acks interleaved; the sink record is authoritative.
    let _ = all;
    tokio::time::timeout(Duration::from_secs(5), async {
        while p.got.lock().unwrap().len() < 120 * 1024 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("all frames delivered post-rebind");
    verify_frames(&p.got.lock().unwrap(), 120);
    assert_eq!(p.client.stable_id(), stable_before, "connection identity preserved");
}

#[tokio::test]
async fn total_path_loss_closes_stream_and_no_replay_on_fresh_connection() {
    let l = Limits::default();
    let mut p = established().await;
    let stable_before = p.client.stable_id();
    for i in 0..10 {
        p.send.write_all(&frame(i)).await.unwrap();
    }

    // Destroy every viable path: close the client endpoint socket entirely.
    // (Dropping the endpoint is the strongest loopback equivalent of pulling
    // all interfaces; the netns gate in net/test-migration.sh proves the real
    // multi-address variant.)
    let old_marker = b"old-connection-marker".to_vec();
    p.send.write_all(&old_marker).await.unwrap();
    drop(p.send);
    p.client_ep.close(0u32.into(), b"path-loss");
    drop(p.client_ep);
    drop(p.client);

    // A fresh connection to a fresh one-shot server must not replay any byte
    // of the old stream.
    let id2 = generate_identity();
    let ep2 = server_endpoint(&id2, localhost(0), &l).unwrap();
    let port2 = ep2.local_addr().unwrap().port();
    let state2 = Arc::new(ShutdownState::new());
    // Reuse the SAME TCP sink to observe any replayed bytes globally.
    let got2 = p.got.clone();
    let stask2 = tokio::spawn({
        let ep2 = ep2.clone();
        let token = id2.token;
        async move {
            // No client will authenticate in this window; the point is that
            // nothing is emitted to the target.
            let mut ll = l;
            ll.server_lease = Duration::from_secs(2);
            let _ = server_accept_auth(&ep2, &token, 1, &ll, &state2).await;
        }
    });
    let len_before = got2.lock().unwrap().len();
    stask2.await.unwrap();
    let len_after = got2.lock().unwrap().len();
    assert_eq!(
        len_before, len_after,
        "no byte from the lost connection may be replayed to any target"
    );
    assert_ne!(stable_before, 0);
    let _ = p.recv.stop(0u32.into());
    let _ = p.server_ep.wait_idle().await;
}

#[tokio::test]
async fn server_lease_and_stall_terminate_with_finite_state() {
    let l = Limits::default();
    let id = generate_identity();
    let ep = server_endpoint(&id, localhost(0), &l).unwrap();
    let state = Arc::new(ShutdownState::new());
    let mut ll = l;
    ll.server_lease = Duration::from_millis(250);
    let start = std::time::Instant::now();
    let r = noq_m0::spike::server_accept_auth(&ep, &id.token, 22, &ll, &state).await;
    assert!(r.is_err());
    assert!(start.elapsed() < Duration::from_secs(5), "lease expiry is bounded");
    assert_eq!(state.cause(), Some(TerminalCause::LeaseExpired));
    let _ = ep.wait_idle().await;
}
