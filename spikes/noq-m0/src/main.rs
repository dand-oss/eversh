//! noq-m0 spike binary. Private test roles only — nothing here is the public
//! eversh interface.
//!
//! Roles:
//!   bootstrap-parent  launched by `ssh` over the authenticated channel;
//!                     spawns the detached one-shot server child and relays
//!                     exactly one bootstrap record line on stdout.
//!   server            detached one-shot server child: binds UDP, waits for one
//!                     authenticated QUIC client, bridges to the authorized
//!                     loopback target, exits.
//!   record            test helper: run the full local bootstrap path and print
//!                     the record (used by harness scripts).
//!   proxy             client side: reads one bootstrap record on stdin
//!                     (exactly what ProxyCommand receives over the SSH
//!                     bootstrap), then bridges local stdin/stdout to the QUIC
//!                     stream. All diagnostics go to stderr.

use noq_m0::config::Limits;
use noq_m0::protocol::BootstrapRecord;
use noq_m0::shutdown::{ShutdownState, TerminalCause};
use noq_m0::spike::{
    bridge, client_connect_auth, client_endpoint, generate_identity, server_accept_auth,
    server_endpoint, SpikeError,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

fn main() {
    let role = std::env::args().nth(1).unwrap_or_default();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("one tokio runtime");
    let code = rt.block_on(async move {
        match role.as_str() {
            "bootstrap-parent" => run_bootstrap_parent().await,
            "server" => run_server().await,
            "record" => run_record().await,
            "proxy" => run_proxy().await,
            "proxy-peer" => run_proxy_peer().await,
            "migrate-client" => run_migrate_client().await,
            _ => {
                eprintln!("noq-m0: unknown or missing role (private spike binary)");
                2
            }
        }
    });
    std::process::exit(code);
}

/// Read exactly one newline-terminated record (bounded) from a buffered reader.
async fn read_record<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    l: &Limits,
) -> Result<BootstrapRecord, String> {
    let mut line = String::new();
    let n = tokio::time::timeout(l.bootstrap_timeout, reader.read_line(&mut line))
        .await
        .map_err(|_| "bootstrap record timeout".to_string())?
        .map_err(|e| e.to_string())?;
    if n == 0 || n + 1 > l.bootstrap_record_max {
        return Err("bad bootstrap record size".into());
    }
    BootstrapRecord::parse(line.trim_end_matches(['\n', '\r']), l.bootstrap_record_max)
        .map_err(|e| e.to_string())
}

/// The target the server may connect to: loopback only, port derived from the
/// bootstrap SSH_CONNECTION (remote port of the tunnelled sshd is not used;
/// the spike passes the authorized loopback port on the server's stdin record
/// channel, not argv or environment visible to other processes).
async fn authorized_target_port() -> Result<u16, String> {
    // Delivered by the bootstrap parent over the inherited pipe (stdin of the
    // detached child), never argv/environment.
    read_port_pipe().await
}

async fn read_port_pipe() -> Result<u16, String> {
    let mut buf = String::new();
    let mut reader = BufReader::new(tokio::io::stdin());
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        reader.read_line(&mut buf),
    )
    .await
    .map_err(|_| "pipe timeout".to_string())?
    .map_err(|e| e.to_string())?;
    buf.trim()
        .parse()
        .map_err(|_| "bad authorized port".to_string())
}

/// SSH-launched bootstrap parent. Spawns the detached one-shot server child,
/// relays exactly one record line to stdout, diagnostics to stderr.
async fn run_bootstrap_parent() -> i32 {
    let l = Limits::default();
    let authorized_port = match read_port_pipe().await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("noq-m0 bootstrap: {e}");
            return 3;
        }
    };
    let self_exe = std::env::current_exe()
        .expect("self exe path")
        .to_string_lossy()
        .to_string();

    let mut child = match tokio::process::Command::new(&self_exe)
        .arg("server")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("noq-m0 bootstrap: spawn server: {e}");
            return 3;
        }
    };
    // Authorized target port goes to the child over the inherited pipe only.
    let mut stdin = child.stdin.take().expect("child stdin");
    let _ = stdin
        .write_all(format!("{authorized_port}\n").as_bytes())
        .await;
    let _ = stdin.shutdown().await;
    drop(stdin);

    let mut stdout = child.stdout.take().expect("child stdout");
    let record = match read_record(&mut BufReader::new(&mut stdout), &l).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("noq-m0 bootstrap: {e}");
            let _ = child.kill().await;
            return 3;
        }
    };
    // Relay exactly one record line; the server child is now detached.
    let mut out = tokio::io::stdout();
    if out.write_all(record.encode().as_bytes()).await.is_err() {
        let _ = child.kill().await;
        return 3;
    }
    let _ = out.shutdown().await;
    // The parent exits; the server child keeps running detached.
    0
}

/// Detached one-shot server child. `authorized_target_port` arrives on stdin
/// (inherited pipe from the bootstrap parent), never argv/env.
async fn run_server() -> i32 {
    let l = Limits::default();
    let authorized_port = match authorized_target_port().await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("noq-m0 server: {e}");
            return 3;
        }
    };
    let id = generate_identity();
    // Loopback by default; the netns migration gate overrides with a
    // namespace-local address (never a secret).
    let bind_ip: IpAddr = std::env::var("NOQ_M0_BIND_ADDR")
        .ok()
        .and_then(|a| a.parse().ok())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let bind = SocketAddr::new(bind_ip, 0);
    let ep = match server_endpoint(&id, bind, &l) {
        Ok(ep) => ep,
        Err(e) => {
            eprintln!("noq-m0 server: {e}");
            return 3;
        }
    };
    let port = ep.local_addr().expect("bound").port();
    let record = BootstrapRecord {
        version: noq_m0::PROTOCOL_VERSION,
        udp_port: port,
        spki_sha256: id.spki_sha256,
        token: id.token,
        pid: std::process::id(),
    };
    {
        let mut out = tokio::io::stdout();
        let _ = out.write_all(record.encode().as_bytes()).await;
        let _ = out.shutdown().await;
    }
    // The record (with token) is not used past this point; it goes out of
    // scope when this block ends.

    let state = Arc::new(ShutdownState::new());
    let auth = match server_accept_auth(&ep, &id.token, authorized_port, &l, &state).await {
        Ok(a) => a,
        Err(SpikeError::Timeout(_)) => {
            eprintln!("noq-m0 server: lease expired");
            ep.close(0u32.into(), b"lease");
            ep.wait_idle().await;
            return 0;
        }
        Err(e) => {
            eprintln!("noq-m0 server: {e}");
            ep.close(0u32.into(), b"auth");
            ep.wait_idle().await;
            return 4;
        }
    };
    if std::env::var_os("NOQ_M0_DEBUG").is_some() {
        eprintln!(
            "noq-m0 server: auth ok (retried={}), stable_id={}",
            auth.retried,
            auth.conn.stable_id()
        );
    }
    // Target TCP connect happens only here, after authentication.
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), authorized_port);
    let tcp =
        match tokio::time::timeout(l.handshake_timeout, tokio::net::TcpStream::connect(target))
            .await
        {
            Ok(Ok(t)) => t,
            _ => {
                eprintln!("noq-m0 server: target connect failed");
                auth.conn.close(0u32.into(), b"target");
                ep.wait_idle().await;
                return 5;
            }
        };
    if std::env::var_os("NOQ_M0_DEBUG").is_some() {
        eprintln!("noq-m0 server: target connected, bridging");
    }
    let cause_before = state.cause();
    bridge(auth.send, auth.recv, tcp, l, state).await;
    if std::env::var_os("NOQ_M0_DEBUG").is_some() {
        eprintln!("noq-m0 server: bridge done cause={cause_before:?}");
    }
    ep.wait_idle().await;
    0
}

/// Test helper: print one bootstrap record for harness scripts (local path).
async fn run_record() -> i32 {
    // Same as bootstrap-parent but the child is not detached from our lifetime
    // management here; used only by scripts to inspect the record format.
    run_bootstrap_parent().await
}

/// M0 gate 5b role: connects, streams numbered frames, rebinds the endpoint
/// to a second local address mid-stream, and reports evidence. Arguments:
///   migrate-client SERVER_IP:PORT SECOND_LOCAL_IP FRAME_COUNT
/// The bootstrap record and target port arrive on stdin (2 lines).
async fn run_migrate_client() -> i32 {
    let l = Limits::default();
    let mut args = std::env::args().skip(2);
    let (server, second_ip, frames) = match (args.next(), args.next(), args.next()) {
        (Some(s), Some(i), Some(f)) => (s, i, f),
        _ => {
            eprintln!("noq-m0 migrate-client: usage: migrate-client SERVER_IP:PORT SECOND_LOCAL_IP FRAMES");
            return 2;
        }
    };
    let frames: u64 = frames.parse().unwrap_or(1000);
    let server: SocketAddr = match server.parse() {
        Ok(s) => s,
        Err(_) => {
            eprintln!("noq-m0 migrate-client: bad server addr");
            return 2;
        }
    };
    let mut reader = BufReader::new(tokio::io::stdin());
    let record = match read_record(&mut reader, &l).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("noq-m0 migrate-client: {e}");
            return 3;
        }
    };
    let mut port_line = String::new();
    if reader.read_line(&mut port_line).await.is_err() || port_line.trim().is_empty() {
        eprintln!("noq-m0 migrate-client: no port line");
        return 3;
    }
    let target_port: u16 = match port_line.trim().parse() {
        Ok(p) => p,
        Err(_) => return 3,
    };
    let ep = match client_endpoint(record.spki_sha256, &l) {
        Ok(ep) => ep,
        Err(e) => {
            eprintln!("noq-m0 migrate-client: {e}");
            return 3;
        }
    };
    let (conn, mut send, _recv) =
        match client_connect_auth(&ep, server, &record.token, target_port, &l).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("noq-m0 migrate-client: {e}");
                return 4;
            }
        };
    let stable_before = conn.stable_id();
    let old_local = ep.local_addr().unwrap();
    let mut frame = vec![0u8; 1024];
    for (j, b) in frame.iter_mut().enumerate() {
        *b = j as u8;
    }
    let rebind_at = frames / 2;
    let mut new_local = old_local;
    for i in 0..frames {
        if i == rebind_at {
            let addr = format!("{second_ip}:0");
            let sock = match std::net::UdpSocket::bind(&addr) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("noq-m0 migrate-client: bind {addr}: {e}");
                    return 5;
                }
            };
            new_local = sock.local_addr().unwrap();
            if let Err(e) = ep.rebind(sock) {
                eprintln!("noq-m0 migrate-client: rebind: {e}");
                return 5;
            }
            eprintln!("noq-m0 migrate-client: REBOUND {old_local} -> {new_local}");
        }
        frame[..8].copy_from_slice(&i.to_be_bytes());
        if let Err(e) = send.write_all(&frame).await {
            eprintln!("noq-m0 migrate-client: write at {i}: {e}");
            return 6;
        }
    }
    let _ = send.finish();
    let stable_after = conn.stable_id();
    println!(
        "migrate-result stable_before={stable_before} stable_after={stable_after} old={old_local} new={new_local} frames={frames} bytes={}",
        frames * 1024
    );
    let _ = ep.wait_idle().await;
    0
}

/// Test-only client role: identical bridging to `proxy` but the bootstrap
/// record and target port arrive on stdin (no ssh), so binary-level tests can
/// drive the real process stdin/stdout path.
async fn run_proxy_peer() -> i32 {
    let l = Limits::default();
    // Record and port share one buffered stdin in this test-only role.
    let mut reader = BufReader::new(tokio::io::stdin());
    let record = match read_record(&mut reader, &l).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("noq-m0 proxy-peer: {e}");
            return 3;
        }
    };
    let mut port_line = String::new();
    if tokio::time::timeout(
        std::time::Duration::from_secs(10),
        reader.read_line(&mut port_line),
    )
    .await
    .is_err()
        || port_line.trim().is_empty()
    {
        eprintln!("noq-m0 proxy-peer: no port line");
        return 3;
    }
    let target_port: u16 = match port_line.trim().parse() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("noq-m0 proxy-peer: bad port");
            return 3;
        }
    };
    drop(reader);
    let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), record.udp_port);
    let ep = match client_endpoint(record.spki_sha256, &l) {
        Ok(ep) => ep,
        Err(e) => {
            eprintln!("noq-m0 proxy-peer: {e}");
            return 3;
        }
    };
    let (_conn, mut send, mut recv) =
        match client_connect_auth(&ep, server, &record.token, target_port, &l).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("noq-m0 proxy-peer: {e}");
                return 4;
            }
        };
    let state = Arc::new(ShutdownState::new());
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut buf = vec![0u8; l.copy_buf];
    let s2q = {
        let state = state.clone();
        async move {
            loop {
                let n = match stdin.read(&mut buf).await {
                    Ok(0) => {
                        let _ = send.finish();
                        state.request(TerminalCause::LocalEof);
                        break;
                    }
                    Ok(n) => n,
                    Err(_) => {
                        state.request(TerminalCause::Cancelled);
                        break;
                    }
                };
                if std::env::var_os("NOQ_M0_DEBUG").is_some() {
                    eprintln!("noq-m0 proxy-peer s2q read {n}");
                }
                if send.write_all(&buf[..n]).await.is_err() {
                    state.request(TerminalCause::QuicClosed);
                    break;
                }
            }
        }
    };
    let q2s = async {
        let mut rbuf = vec![0u8; l.copy_buf];
        loop {
            match recv.read(&mut rbuf).await {
                Ok(None) => {
                    let _ = stdout.shutdown().await;
                    state.request(TerminalCause::QuicClosed);
                    break;
                }
                Ok(Some(n)) => {
                    if std::env::var_os("NOQ_M0_DEBUG").is_some() {
                        eprintln!("noq-m0 proxy-peer q2s got {n}");
                    }
                    if stdout.write_all(&rbuf[..n]).await.is_err() || stdout.flush().await.is_err()
                    {
                        state.request(TerminalCause::Cancelled);
                        break;
                    }
                }
                Err(_) => {
                    state.request(TerminalCause::QuicClosed);
                    break;
                }
            }
        }
    };
    tokio::join!(s2q, q2s);
    state.drain();
    state.finalize();
    ep.wait_idle().await;
    0
}

/// Client proxy (ProxyCommand role): `noq-m0 proxy DESTINATION PORT`.
///
/// Launches the bootstrap over the system ssh to DESTINATION:PORT (same keys,
/// same authentication as any ordinary ssh), reads the one bootstrap record,
/// connects and authenticates QUIC, then bridges local stdin/stdout to the
/// stream. stdout carries only opaque SSH bytes; all diagnostics on stderr.
/// The token never enters argv or environment of any process.
async fn run_proxy() -> i32 {
    let l = Limits::default();
    let mut args = std::env::args().skip(2);
    let (dest, port) = match (args.next(), args.next()) {
        (Some(d), Some(p)) => (d, p),
        _ => {
            eprintln!("noq-m0 proxy: usage: proxy DESTINATION PORT [extra ssh options...]");
            return 2;
        }
    };
    // Remaining args are passed verbatim to the bootstrap ssh (keys, options).
    let extra: Vec<String> = args.collect();
    let target_port: u16 = match port.parse() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("noq-m0 proxy: bad port");
            return 2;
        }
    };
    let self_exe = std::env::current_exe()
        .expect("self exe path")
        .to_string_lossy()
        .to_string();
    let mut bootstrap = match tokio::process::Command::new("ssh")
        .args({
            let mut v: Vec<String> = vec![
                "-o".into(),
                "ProxyCommand=none".into(),
                "-o".into(),
                "ClearAllForwardings=yes".into(),
                "-o".into(),
                "ForwardX11=no".into(),
                "-o".into(),
                "RequestTTY=no".into(),
                "-o".into(),
                "BatchMode=yes".into(),
                "-p".into(),
                port.clone(),
            ];
            v.extend(extra);
            v.push(dest.clone());
            v.push(format!("{self_exe} bootstrap-parent"));
            v
        })
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("noq-m0 proxy: ssh bootstrap: {e}");
            return 3;
        }
    };
    // Authorized target port travels over the authenticated SSH stdin channel.
    let mut bin = bootstrap.stdin.take().expect("bootstrap stdin");
    let _ = bin.write_all(format!("{target_port}\n").as_bytes()).await;
    let _ = bin.shutdown().await;
    drop(bin);
    let mut bstdout = bootstrap.stdout.take().expect("bootstrap stdout");
    let record = match read_record(&mut BufReader::new(&mut bstdout), &l).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("noq-m0 proxy: {e}");
            let mut errout = String::new();
            if let Some(mut es) = bootstrap.stderr.take() {
                use tokio::io::AsyncReadExt as _;
                let _ = es.read_to_string(&mut errout).await;
            }
            let st = bootstrap.wait().await;
            eprintln!("noq-m0 proxy: bootstrap status={st:?} stderr: {errout}");
            return 3;
        }
    };
    let status = bootstrap.wait().await;
    if !status.map(|s| s.success()).unwrap_or(false) {
        eprintln!("noq-m0 proxy: bootstrap parent failed");
        return 3;
    }
    if std::env::var_os("NOQ_M0_DEBUG").is_some() {
        eprintln!(
            "noq-m0 proxy: record ok udp={} pid={}",
            record.udp_port, record.pid
        );
    }
    let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), record.udp_port);
    let ep = match client_endpoint(record.spki_sha256, &l) {
        Ok(ep) => ep,
        Err(e) => {
            eprintln!("noq-m0 proxy: {e}");
            return 3;
        }
    };
    if std::env::var_os("NOQ_M0_DEBUG").is_some() {
        eprintln!("noq-m0 proxy: endpoint ready");
    }
    let (_conn, mut send, mut recv) =
        match client_connect_auth(&ep, server, &record.token, target_port, &l).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("noq-m0 proxy: {e}");
                return 4;
            }
        };
    let state = Arc::new(ShutdownState::new());
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut buf = vec![0u8; l.copy_buf];
    let s2q = {
        let state = state.clone();
        async move {
            loop {
                let n = match stdin.read(&mut buf).await {
                    Ok(0) => {
                        let _ = send.finish();
                        state.request(TerminalCause::LocalEof);
                        break;
                    }
                    Ok(n) => n,
                    Err(_) => {
                        state.request(TerminalCause::Cancelled);
                        break;
                    }
                };
                if std::env::var_os("NOQ_M0_DEBUG").is_some() {
                    eprintln!("noq-m0 proxy-peer s2q read {n}");
                }
                if send.write_all(&buf[..n]).await.is_err() {
                    state.request(TerminalCause::QuicClosed);
                    break;
                }
            }
        }
    };
    let q2s = async {
        let mut rbuf = vec![0u8; l.copy_buf];
        loop {
            match recv.read(&mut rbuf).await {
                Ok(None) => {
                    let _ = stdout.shutdown().await;
                    state.request(TerminalCause::QuicClosed);
                    break;
                }
                Ok(Some(n)) => {
                    if stdout.write_all(&rbuf[..n]).await.is_err() || stdout.flush().await.is_err()
                    {
                        state.request(TerminalCause::Cancelled);
                        break;
                    }
                }
                Err(_) => {
                    state.request(TerminalCause::QuicClosed);
                    break;
                }
            }
        }
    };
    if std::env::var_os("NOQ_M0_DEBUG").is_some() {
        eprintln!("noq-m0 proxy: auth ok, bridging");
    }
    tokio::join!(s2q, q2s);
    if std::env::var_os("NOQ_M0_DEBUG").is_some() {
        eprintln!("noq-m0 proxy: bridge done cause={:?}", state.cause());
    }
    state.drain();
    state.finalize();
    ep.wait_idle().await;
    0
}
