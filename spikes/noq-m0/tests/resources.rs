//! M0 gate 7: bounded resources. Saturates stdin/stdout-equivalent (QUIC
//! stream), target TCP, and QUIC flow control independently, then samples
//! RSS/file descriptors across sustained transfer and a stalled phase,
//! requiring a plateau explained by the configured windows plus fixed buffers.

use noq_m0::config::Limits;
use noq_m0::shutdown::ShutdownState;
use noq_m0::spike::{
    bridge, client_connect_auth, client_endpoint, generate_identity, server_accept_auth,
    server_endpoint,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

fn rss_kb() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    for line in status.lines() {
        if let Some(v) = line.strip_prefix("VmRSS:") {
            return v.trim_end_matches(" kB").trim().parse().unwrap();
        }
    }
    0
}

fn fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

#[tokio::test(flavor = "multi_thread")]
async fn sustained_transfer_and_stall_remain_bounded() {
    let l = Limits::default();

    // Target that reads slowly and never blocks us into unbounded growth:
    // reads continuously but slowly (saturates the QUIC receive window).
    let listener = tokio::net::TcpListener::bind(localhost(0)).await.unwrap();
    let tport = listener.local_addr().unwrap().port();
    let read_total = Arc::new(AtomicUsize::new(0));
    let rt = read_total.clone();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut b = [0u8; 4096];
        loop {
            match tokio::time::timeout(Duration::from_secs(5), s.read(&mut b)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                Ok(Ok(n)) => {
                    rt.fetch_add(n, Ordering::SeqCst);
                    // Slow consumer: saturate QUIC flow control.
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }
        }
    });

    let id = generate_identity();
    let sep = server_endpoint(&id, localhost(0), &l).unwrap();
    let sport = sep.local_addr().unwrap().port();
    let state = Arc::new(ShutdownState::new());
    let stask = {
        let sep = sep.clone();
        let token = id.token;
        let state = state.clone();
        tokio::spawn(async move {
            let auth = server_accept_auth(&sep, &token, tport, &l, &state)
                .await
                .unwrap();
            let tcp = tokio::net::TcpStream::connect(localhost(tport))
                .await
                .unwrap();
            bridge(auth.send, auth.recv, tcp, l, state).await;
        })
    };
    let cep = client_endpoint(id.spki_sha256, &l).unwrap();
    let (_conn, mut send, mut recv) =
        client_connect_auth(&cep, localhost(sport), &id.token, tport, &l)
            .await
            .unwrap();

    // Sustained uplink: far more than the configured windows.
    let chunk = vec![0x5au8; 16 * 1024];
    let start = Instant::now();
    let mut samples_rss = Vec::new();
    let mut samples_fd = Vec::new();
    let mut sent = 0usize;
    while start.elapsed() < Duration::from_secs(6) {
        // Backpressure-aware writes: send blocks on flow control, so the
        // loop cannot outrun the configured windows.
        send.write_all(&chunk).await.unwrap();
        sent += chunk.len();
        if sent.is_multiple_of(16 * 1024 * 64) {
            samples_rss.push(rss_kb());
            samples_fd.push(fd_count());
        }
        // Downlink: target sends nothing; poll with a short timeout so the
        // loop never blocks on an empty downlink.
        let _ = tokio::time::timeout(Duration::from_millis(1), recv.read(&mut [0u8; 1])).await;
    }
    let _ = send.finish();
    drop(send);
    drop(recv);
    drop(cep);
    let _ = tokio::time::timeout(Duration::from_secs(35), stask).await;

    // Plateau: after warm-up, RSS spread must be small relative to the data
    // transferred (windows + fixed buffers, not proportional to bytes).
    let warm = &samples_rss[samples_rss.len() / 2..];
    let max = *warm.iter().max().unwrap();
    let min = *warm.iter().min().unwrap();
    println!(
        "sent={sent} bytes ({}x receive window), rss samples={samples_rss:?}, fd samples={samples_fd:?}",
        sent / l.receive_window as usize
    );
    assert!(
        sent > 4 * l.receive_window as usize,
        "test must push multiples of the configured window"
    );
    assert!(
        max - min < 8192,
        "RSS must plateau (windows + fixed buffers), spread {max}-{min} kB"
    );
    let fd_max = *samples_fd.iter().max().unwrap();
    assert!(fd_max < 64, "file descriptors bounded, got {fd_max}");
}
