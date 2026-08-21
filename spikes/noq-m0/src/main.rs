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
            _ => {
                eprintln!("noq-m0: unknown or missing role (private spike binary)");
                2
            }
        }
    });
    std::process::exit(code);
}

/// Read exactly one newline-terminated record (bounded) from a reader.
async fn read_record<R: tokio::io::AsyncRead + Unpin>(
    r: R,
    l: &Limits,
) -> Result<BootstrapRecord, String> {
    let mut line = String::new();
    let mut reader = BufReader::new(r);
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
    let record = match read_record(&mut stdout, &l).await {
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
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
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
    bridge(auth.send, auth.recv, tcp, l, state).await;
    ep.wait_idle().await;
    0
}

/// Test helper: print one bootstrap record for harness scripts (local path).
async fn run_record() -> i32 {
    // Same as bootstrap-parent but the child is not detached from our lifetime
    // management here; used only by scripts to inspect the record format.
    run_bootstrap_parent().await
}

/// Client proxy: one bootstrap record on stdin, then bridge stdin/stdout to
/// the authenticated QUIC stream. Diagnostics on stderr only; stdout carries
/// only opaque SSH bytes.
async fn run_proxy() -> i32 {
    let l = Limits::default();
    let record = match read_record(tokio::io::stdin(), &l).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("noq-m0 proxy: {e}");
            return 3;
        }
    };
    let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), record.udp_port);
    let ep = match client_endpoint(record.spki_sha256, &l) {
        Ok(ep) => ep,
        Err(e) => {
            eprintln!("noq-m0 proxy: {e}");
            return 3;
        }
    };
    // The authorized target port is the sshd port the outer SSH client thinks
    // it is talking to; in the spike harness it is carried by the record's
    // connection context. The harness stamps it on stdin after the record.
    let target_port = match read_port_pipe().await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("noq-m0 proxy: {e}");
            return 3;
        }
    };
    let (_conn, send, recv) =
        match client_connect_auth(&ep, server, &record.token, target_port, &l).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("noq-m0 proxy: {e}");
                return 4;
            }
        };
    let state = Arc::new(ShutdownState::new());
    // Bridge local stdin/stdout to the QUIC stream. stdout carries only SSH
    // bytes (the auth frame was already sent on the stream).
    let (mut send, mut recv) = (send, recv);
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
                    if stdout.write_all(&rbuf[..n]).await.is_err() {
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
