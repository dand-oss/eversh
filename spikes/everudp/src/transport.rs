//! UDP-substrate and noq-datagram echo transports plus the frozen
//! stop-and-wait benchmark loop.

use crate::aead::Substrate;
use crate::frame::{decode, Echo, Frame, Input, MAX_PAYLOAD, MTU_CEILING};
use crate::state::{EchoPolicy, PredictionState, Reconciliation};
use std::net::SocketAddr;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::process::{Child, Command};
use tokio::time::{sleep, sleep_until, Instant};

pub const RETRANSMIT: Duration = Duration::from_millis(20);
pub const TRIAL_TIMEOUT: Duration = Duration::from_secs(2);
pub const INTER_TRIAL: Duration = Duration::from_millis(100);
pub const EPOCH: u32 = 1;

#[derive(Debug, Clone)]
pub struct Trial {
    pub seq: u64,
    pub byte: u8,
    pub predicted: bool,
    pub retransmits: u32,
    pub correct_render_us: u128,
}

#[derive(Debug)]
pub struct BenchError(pub String);

impl std::fmt::Display for BenchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for BenchError {}

pub fn key_from_half(half: [u8; 8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    for chunk in key.chunks_exact_mut(8) {
        chunk.copy_from_slice(&half);
    }
    key
}

/// Shared session nonce prefix. Client and server counters live in
/// disjoint halves of the 64-bit space, so a nonce can never repeat across
/// directions while both sides accept the same prefix.
pub const SESSION_PREFIX: [u8; 4] = [0, 0, 0, 1];
pub const CLIENT_COUNTER_BASE: u64 = 1;
pub const SERVER_COUNTER_BASE: u64 = u64::MAX / 2 + 1;

pub async fn udp_server(bind: SocketAddr, key: [u8; 8]) -> std::io::Result<()> {
    let socket = UdpSocket::bind(bind).await?;
    eprintln!("everudp-spike udp-server {}", socket.local_addr()?);
    let mut server = Substrate::new(key_from_half(key), SESSION_PREFIX, SERVER_COUNTER_BASE);
    let mut packet = [0u8; MTU_CEILING];
    let mut wire = Vec::with_capacity(MTU_CEILING);
    loop {
        let (len, from) = socket.recv_from(&mut packet).await?;
        let plaintext = match server.open(&packet[..len], b"everudp-spike-v1") {
            Ok(plaintext) => plaintext,
            Err(_) => continue,
        };
        let frame = match decode(&plaintext) {
            Ok(frame) => frame,
            Err(_) => continue,
        };
        let Frame::Input(Input { seq, bytes, .. }) = frame else {
            continue;
        };
        Echo { ack: seq, bytes }.encode(&mut wire);
        let sealed = server.seal(&wire, b"everudp-spike-v1");
        socket.send_to(&sealed, from).await?;
    }
}

/// PTY-backed echo server: each authoritative reply comes from the real
/// echo program's stdout (through `script`, so the program owns a PTY),
/// making the everudp latency path end-to-end like zmosh's session path.
pub async fn udp_pty_server(
    bind: SocketAddr,
    key: [u8; 8],
    command: String,
) -> std::io::Result<()> {
    let socket = UdpSocket::bind(bind).await?;
    eprintln!("everudp-spike udp-pty-server {}", socket.local_addr()?);
    let mut server = Substrate::new(key_from_half(key), SESSION_PREFIX, SERVER_COUNTER_BASE);
    let mut child = spawn_echo_child(&command).await?;
    let mut stdin = child.stdin.take().expect("echo child stdin");
    let mut stdout = child.stdout.take().expect("echo child stdout");
    let mut packet = [0u8; MTU_CEILING];
    let mut wire = Vec::with_capacity(MTU_CEILING);
    let mut scratch = [0u8; MAX_PAYLOAD];
    let timing = std::env::var_os("EVERUDP_TIMING").is_some();
    loop {
        let (len, from) = socket.recv_from(&mut packet).await?;
        let t_received = Instant::now();
        let plaintext = match server.open(&packet[..len], b"everudp-spike-v1") {
            Ok(plaintext) => plaintext,
            Err(_) => continue,
        };
        let frame = match decode(&plaintext) {
            Ok(frame) => frame,
            Err(_) => continue,
        };
        let Frame::Input(Input { seq, bytes, .. }) = frame else {
            continue;
        };
        let t_decoded = Instant::now();
        // Try to restart the authoritative program if it exited; a dead
        // child is a benchmark failure, never a silent reflection.
        if let Some(status) = child.try_wait()? {
            return Err(std::io::Error::other(format!(
                "echo child exited before input: {status}"
            )));
        }
        stdin.write_all(&bytes).await?;
        stdin.flush().await?;
        let t_written = Instant::now();
        let mut echoed = Vec::with_capacity(bytes.len());
        while echoed.len() < bytes.len() {
            let want = (bytes.len() - echoed.len()).min(scratch.len());
            // The authoritative echo program owes exactly the bytes it
            // received; the benchmark client's trial timeout bounds a dead
            // child. Avoiding a per-keystroke timer future removes 10s of
            // microseconds of timer churn from the measured path.
            let read = stdout.read(&mut scratch[..want]).await?;
            if read == 0 {
                return Err(std::io::Error::other("echo child EOF"));
            }
            echoed.extend_from_slice(&scratch[..read]);
        }
        let t_echo = Instant::now();
        Echo {
            ack: seq,
            bytes: echoed,
        }
        .encode(&mut wire);
        let sealed = server.seal(&wire, b"everudp-spike-v1");
        socket.send_to(&sealed, from).await?;
        if timing {
            let t_sent = Instant::now();
            eprintln!(
                "TIMING seq={seq} decode_us={} write_us={} echo_us={} seal_send_us={} service_us={}",
                (t_decoded - t_received).as_micros(),
                (t_written - t_decoded).as_micros(),
                (t_echo - t_written).as_micros(),
                (t_sent - t_echo).as_micros(),
                (t_sent - t_received).as_micros(),
            );
        }
    }
}

async fn spawn_echo_child(command: &str) -> std::io::Result<Child> {
    Command::new("/usr/bin/script")
        .arg("-qefc")
        .arg(format!("stty raw -echo; exec {command}"))
        .arg("/dev/null")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
}

pub async fn udp_bench(
    server_addr: SocketAddr,
    key: [u8; 8],
    prediction: bool,
    trials: usize,
) -> Result<Vec<Trial>, BenchError> {
    let bind = if server_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|e| BenchError(e.to_string()))?;
    let mut client = Substrate::new(key_from_half(key), SESSION_PREFIX, CLIENT_COUNTER_BASE);
    let mut state = PredictionState::new(
        EPOCH,
        if prediction {
            EchoPolicy::Predict
        } else {
            EchoPolicy::NoEcho
        },
    );
    let mut result = Vec::with_capacity(trials);
    let mut packet = [0u8; MTU_CEILING];
    let mut wire = Vec::with_capacity(MTU_CEILING);
    for trial in 0..trials {
        let byte = b'a' + (trial % 26) as u8;
        let (seq, predicted) = state.send(&[byte]);
        Input {
            epoch: EPOCH,
            seq,
            bytes: vec![byte],
        }
        .encode(&mut wire);
        let started = Instant::now();
        socket
            .send_to(&client.seal(&wire, b"everudp-spike-v1"), server_addr)
            .await
            .map_err(|e| BenchError(e.to_string()))?;
        let mut retransmits = 0u32;
        let mut next_retransmit = started + RETRANSMIT;
        let correct_render_us = loop {
            tokio::select! {
                received = socket.recv(&mut packet) => {
                    let len = received.map_err(|e| BenchError(e.to_string()))?;
                    let plaintext = client
                        .open(&packet[..len], b"everudp-spike-v1")
                        .map_err(|_| BenchError("server packet failed authentication".into()))?;
                    let frame = decode(&plaintext)
                        .map_err(|_| BenchError("bad server frame".into()))?;
                    let Frame::Echo(echo) = frame else { continue };
                    if echo.ack != seq {
                        state.reconcile(echo.ack, &echo.bytes);
                        continue;
                    }
                    let reconciliation = state.reconcile(echo.ack, &echo.bytes);
                    debug_assert_eq!(reconciliation, Reconciliation::Confirmed { predicted: true });
                    break started.elapsed().as_micros();
                }
                _ = sleep_until(next_retransmit) => {
                    if started.elapsed() >= TRIAL_TIMEOUT {
                        return Err(BenchError(format!("trial {trial} timed out")));
                    }
                    retransmits += 1;
                    next_retransmit = Instant::now() + RETRANSMIT;
                    // Every transmission needs a fresh AEAD nonce: the
                    // server's anti-replay window correctly drops a repeated
                    // nonce, so re-sealing is part of retransmission.
                    socket
                        .send_to(&client.seal(&wire, b"everudp-spike-v1"), server_addr)
                        .await
                        .map_err(|e| BenchError(e.to_string()))?;
                }
            }
        };
        result.push(Trial {
            seq,
            byte,
            predicted,
            retransmits,
            correct_render_us,
        });
        sleep(INTER_TRIAL).await;
    }
    Ok(result)
}

pub async fn quic_server_endpoint_loop(endpoint: noq::Endpoint) -> Result<(), BenchError> {
    loop {
        let incoming = endpoint
            .accept()
            .await
            .ok_or_else(|| BenchError("endpoint closed".into()))?;
        let conn = incoming
            .accept()
            .map_err(|e| BenchError(e.to_string()))?
            .await
            .map_err(|e| BenchError(e.to_string()))?;
        let mut wire = Vec::with_capacity(MTU_CEILING);
        while let Ok(datagram) = conn.read_datagram().await {
            let Some(frame) = decode(&datagram).ok() else {
                continue;
            };
            let Frame::Input(Input { seq, bytes, .. }) = frame else {
                continue;
            };
            Echo { ack: seq, bytes }.encode(&mut wire);
            let _ = conn.send_datagram(wire.clone().into());
        }
    }
}

pub async fn quic_bench(
    endpoint: &noq::Endpoint,
    server_addr: SocketAddr,
    prediction: bool,
    trials: usize,
) -> Result<Vec<Trial>, BenchError> {
    let conn = endpoint
        .connect(server_addr, "localhost")
        .map_err(|e| BenchError(e.to_string()))?
        .await
        .map_err(|e| BenchError(e.to_string()))?;
    let mut state = PredictionState::new(
        EPOCH,
        if prediction {
            EchoPolicy::Predict
        } else {
            EchoPolicy::NoEcho
        },
    );
    let mut result = Vec::with_capacity(trials);
    let mut wire = Vec::with_capacity(MTU_CEILING);
    for trial in 0..trials {
        let byte = b'a' + (trial % 26) as u8;
        let (seq, predicted) = state.send(&[byte]);
        Input {
            epoch: EPOCH,
            seq,
            bytes: vec![byte],
        }
        .encode(&mut wire);
        conn.send_datagram(wire.clone().into())
            .map_err(|e| BenchError(e.to_string()))?;
        let started = Instant::now();
        let mut retransmits = 0u32;
        let mut next_retransmit = started + RETRANSMIT;
        let correct_render_us = loop {
            tokio::select! {
                datagram = conn.read_datagram() => {
                    let datagram = datagram.map_err(|e| BenchError(e.to_string()))?;
                    let Some(Frame::Echo(echo)) = decode(&datagram).ok() else { continue };
                    if echo.ack != seq {
                        state.reconcile(echo.ack, &echo.bytes);
                        continue;
                    }
                    let reconciliation = state.reconcile(echo.ack, &echo.bytes);
                    debug_assert_eq!(reconciliation, Reconciliation::Confirmed { predicted: true });
                    break started.elapsed().as_micros();
                }
                _ = sleep_until(next_retransmit) => {
                    if started.elapsed() >= TRIAL_TIMEOUT {
                        return Err(BenchError(format!("trial {trial} timed out")));
                    }
                    retransmits += 1;
                    next_retransmit = Instant::now() + RETRANSMIT;
                    conn.send_datagram(wire.clone().into())
                        .map_err(|e| BenchError(e.to_string()))?;
                }
            }
        };
        result.push(Trial {
            seq,
            byte,
            predicted,
            retransmits,
            correct_render_us,
        });
        sleep(INTER_TRIAL).await;
    }
    Ok(result)
}

pub fn summarize(trials: &[Trial]) -> (u128, u128, u128, f64) {
    let mut values: Vec<u128> = trials.iter().map(|t| t.correct_render_us).collect();
    values.sort_unstable();
    let pick = |q: f64| -> u128 {
        if values.is_empty() {
            return 0;
        }
        let idx = ((values.len() as f64 - 1.0) * q).round() as usize;
        values[idx.min(values.len() - 1)]
    };
    let median = pick(0.50);
    let p95 = pick(0.95);
    let max = values.last().copied().unwrap_or(0);
    let mean = if trials.is_empty() {
        0.0
    } else {
        trials
            .iter()
            .map(|t| t.correct_render_us as f64)
            .sum::<f64>()
            / trials.len() as f64
    };
    (median, p95, max, mean)
}

pub fn max_payload_check(bytes: &[u8]) -> bool {
    bytes.len() <= MAX_PAYLOAD
}
