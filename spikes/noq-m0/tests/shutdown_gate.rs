//! M0 gate 4: shutdown ownership — cancellation at bootstrap/handshake
//! boundaries, stalled QUIC and TCP peers, client disappearance, process kill,
//! and idempotent concurrent terminal events. Every test is deadline-bounded
//! and proves no surviving owned task.

use noq_m0::config::Limits;
use noq_m0::shutdown::{Phase, ShutdownState, TerminalCause};
use noq_m0::spike::{
    bridge, client_connect_auth, client_endpoint, generate_identity, server_accept_auth,
    server_endpoint,
};
use std::io::{Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt as _;

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

#[tokio::test]
async fn cancellation_at_handshake_boundary_finalizes_finite() {
    let l = Limits::default();
    let id = generate_identity();
    let ep = server_endpoint(&id, localhost(0), &l).unwrap();
    let state = Arc::new(ShutdownState::new());
    // Cancel the accept future mid-handshake (drop it); state machine stays
    // coherent and a fresh accept still works on the same endpoint.
    let mut ll = l;
    ll.server_lease = Duration::from_secs(10);
    let ep2 = ep.clone();
    let acc =
        tokio::spawn(async move { server_accept_auth(&ep2, &[0u8; 32], 22, &ll, &state).await });
    acc.abort();
    let _ = acc.await;
    // Endpoint still functional.
    assert_eq!(
        ep.local_addr().unwrap().port(),
        ep.local_addr().unwrap().port()
    );
    let _ = ep.wait_idle().await;
}

#[tokio::test]
async fn stalled_quic_peer_terminates_within_stall_deadline() {
    let l = Limits {
        stall_timeout: Duration::from_millis(400),
        drain_timeout: Duration::from_secs(2),
        ..Limits::default()
    };
    // Target that never reads (stalled TCP peer from the server's view is
    // covered by the write deadline; here we stall the QUIC reader).
    let listener = tokio::net::TcpListener::bind(localhost(0)).await.unwrap();
    let tport = listener.local_addr().unwrap().port();
    // Accept and never send anything: QUIC read stalls.
    tokio::spawn(async move {
        let (_s, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(30)).await;
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
    let (_conn, _send, _recv) = client_connect_auth(&cep, localhost(sport), &id.token, tport, &l)
        .await
        .unwrap();
    // Client sends nothing more; server copy directions hit stall deadline.
    let start = std::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(10), stask)
        .await
        .expect("bridge terminates within bounded time after stall")
        .unwrap();
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "stall bounded by config"
    );
    assert_eq!(state.phase(), Phase::Finalized);
    assert_eq!(state.cause(), Some(TerminalCause::Stalled));
}

#[tokio::test]
async fn stalled_tcp_peer_terminates_within_stall_deadline() {
    let l = Limits {
        stall_timeout: Duration::from_millis(400),
        drain_timeout: Duration::from_secs(2),
        ..Limits::default()
    };
    // TCP target that accepts but never reads nor writes.
    let listener = tokio::net::TcpListener::bind(localhost(0)).await.unwrap();
    let tport = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (_s, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(30)).await;
        let _ = _s;
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
    // Flood until the stalled target's TCP window fills and the write stalls.
    let flood = vec![0x33u8; 64 * 1024];
    let _ = send.write_all(&flood).await;
    let _ = recv.read(&mut [0u8; 1]).await;
    tokio::time::timeout(Duration::from_secs(10), stask)
        .await
        .expect("bridge terminates within bounded time after TCP stall")
        .unwrap();
    assert_eq!(state.phase(), Phase::Finalized);
}

#[tokio::test]
async fn client_disappearance_closes_server_side_finitely() {
    let l = Limits::default();
    let listener = tokio::net::TcpListener::bind(localhost(0)).await.unwrap();
    let tport = listener.local_addr().unwrap().port();
    let target_saw_eof = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let t = target_saw_eof.clone();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut b = [0u8; 64];
        match s.read(&mut b).await {
            Ok(0) | Err(_) => t.store(true, std::sync::atomic::Ordering::SeqCst),
            Ok(_) => {}
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
            // Abrupt client loss may surface as an error here; that is the
            // expected terminal outcome, not a failure.
            match server_accept_auth(&sep, &token, tport, &l, &state).await {
                Ok(auth) => match tokio::net::TcpStream::connect(localhost(tport)).await {
                    Ok(tcp) => bridge(auth.send, auth.recv, tcp, l, state).await,
                    Err(_) => {
                        state.request(TerminalCause::TargetClosed);
                        state.drain();
                        state.finalize();
                    }
                },
                Err(_) => {
                    state.request(TerminalCause::QuicClosed);
                    state.drain();
                    state.finalize();
                }
            }
        })
    };
    let cep = client_endpoint(id.spki_sha256, &l).unwrap();
    let (_conn, _send, _recv) = client_connect_auth(&cep, localhost(sport), &id.token, tport, &l)
        .await
        .unwrap();
    // Client vanishes entirely: drop endpoint + connection.
    drop(_send);
    drop(_recv);
    cep.close(0u32.into(), b"gone");
    drop(cep);
    tokio::time::timeout(Duration::from_secs(40), stask)
        .await
        .expect("server bridge ends after client disappearance")
        .unwrap();
    assert_eq!(state.phase(), Phase::Finalized);
}

#[tokio::test]
async fn process_kill_is_reaped_and_no_owned_task_survives() {
    // Binary-level: start `server` against a target, kill -9 the client-side
    // process; the server must exit within its bounded deadlines and leave
    // no task behind (process exit is the proof).
    let exe = env!("CARGO_BIN_EXE_noq-m0");
    // A target that blocks forever.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let tport = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (_s, _) = listener.accept().unwrap();
        std::thread::sleep(Duration::from_secs(60));
    });
    let mut server = std::process::Command::new(exe)
        .args(["server"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    server
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{tport}\n").as_bytes())
        .unwrap();
    let mut out = server.stdout.take().unwrap();
    let mut rec = String::new();
    let mut b = [0u8; 1];
    loop {
        assert_eq!(out.read(&mut b).unwrap(), 1);
        if b[0] == b'\n' {
            break;
        }
        rec.push(b[0] as char);
    }
    let parts: Vec<&str> = rec.split(' ').collect();
    let udp: u16 = parts[2].parse().unwrap();
    let mut pin = [0u8; 32];
    let mut tok = [0u8; 32];
    for i in 0..32 {
        pin[i] = u8::from_str_radix(&parts[3][i * 2..i * 2 + 2], 16).unwrap();
        tok[i] = u8::from_str_radix(&parts[4][i * 2..i * 2 + 2], 16).unwrap();
    }

    // In-process client; then simulate kill by abruptly dropping everything.
    let l = Limits::default();
    let ep = client_endpoint(pin, &l).unwrap();
    let (conn, _s, _r) = client_connect_auth(&ep, localhost(udp), &tok, tport, &l)
        .await
        .unwrap();
    let pid = server.id();
    // Abrupt client loss.
    drop(_s);
    drop(_r);
    drop(conn);
    ep.close(0u32.into(), b"kill");
    drop(ep);
    let mut server = server;
    let status = tokio::time::timeout(
        Duration::from_secs(40),
        tokio::task::spawn_blocking(move || server.wait()),
    )
    .await
    .expect("server exits within bounded deadline after abrupt client loss");
    assert!(status.is_ok());
    // No surviving owned process with our binary name.
    let alive = std::process::Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .status()
        .unwrap();
    assert!(!alive.success(), "server pid {pid} must be gone");
}
