//! UDP-substrate and noq-datagram echo transports plus the frozen
//! stop-and-wait benchmark loop.

use crate::aead::{Role, SessionSubstrate, BOOTSTRAP_SECRET_LEN};
use crate::frame::{decode, Echo, Frame, Input, MAX_PAYLOAD, MTU_CEILING};
use crate::handshake::{AmplificationBudget, ClientHandshake, HandshakeError, ServerHandshake};
use crate::state::{EchoPolicy, PredictionState, Reconciliation};
use std::collections::BTreeMap;
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
pub const AMPLIFICATION_CEILING: usize = MTU_CEILING * 4;
const SESSION_AAD: &[u8] = b"everudp-spike-v2";
const SERVER_ECHO_CACHE_LIMIT: usize = 64;

pub type BootstrapSecret = [u8; BOOTSTRAP_SECRET_LEN];

enum ServerInputAction {
    Execute,
    Replay(Vec<u8>),
    Reject,
}

#[derive(Default)]
struct ServerEchoCache {
    epoch: Option<u32>,
    last_executed: Option<u64>,
    echoes: BTreeMap<u64, Vec<u8>>,
}

impl ServerEchoCache {
    fn classify(&self, epoch: u32, seq: u64) -> ServerInputAction {
        if epoch == 0 {
            return ServerInputAction::Reject;
        }
        if let Some(current_epoch) = self.epoch {
            if epoch != current_epoch {
                return ServerInputAction::Reject;
            }
        }
        if let Some(bytes) = self.echoes.get(&seq) {
            return ServerInputAction::Replay(bytes.clone());
        }
        let expected = self.last_executed.map_or(0, |last| last.saturating_add(1));
        if seq != expected {
            return ServerInputAction::Reject;
        }
        ServerInputAction::Execute
    }

    fn record(&mut self, epoch: u32, seq: u64, bytes: &[u8]) {
        self.epoch.get_or_insert(epoch);
        self.last_executed = Some(seq);
        self.echoes.insert(seq, bytes.to_vec());
        while self.echoes.len() > SERVER_ECHO_CACHE_LIMIT {
            let oldest = self.echoes.keys().next().copied().expect("nonempty cache");
            self.echoes.remove(&oldest);
        }
    }
}

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

struct ServerSession {
    handshake: ServerHandshake,
    crypto: SessionSubstrate,
    peer: SocketAddr,
    amplification: AmplificationBudget,
}

impl ServerSession {
    async fn receive(
        &mut self,
        socket: &UdpSocket,
        packet: &[u8],
        from: SocketAddr,
    ) -> std::io::Result<Option<Vec<u8>>> {
        if self.handshake.is_client_retransmit(packet) {
            self.amplification.credit_receive(packet.len());
            let reply = *self.handshake.reply();
            if self.amplification.debit_send(reply.len()) {
                socket.send_to(&reply, from).await?;
            }
            return Ok(None);
        }
        let plaintext = match self.crypto.open(packet, SESSION_AAD) {
            Ok(plaintext) => plaintext,
            Err(_) => return Ok(None),
        };
        // Possession of the directional traffic key authenticates roaming.
        self.peer = from;
        self.amplification.credit_receive(packet.len());
        Ok(Some(plaintext))
    }

    async fn send(&mut self, socket: &UdpSocket, plaintext: &[u8]) -> std::io::Result<()> {
        let sealed = self.crypto.seal(plaintext, SESSION_AAD);
        if !self.amplification.debit_send(sealed.len()) {
            return Err(std::io::Error::other("amplification budget exhausted"));
        }
        socket.send_to(&sealed, self.peer).await?;
        Ok(())
    }
}

async fn accept_server_session(
    socket: &UdpSocket,
    secret: &BootstrapSecret,
    packet: &mut [u8],
) -> std::io::Result<ServerSession> {
    loop {
        let (len, from) = socket.recv_from(packet).await?;
        let handshake = match ServerHandshake::accept(secret, &packet[..len]) {
            Ok(handshake) => handshake,
            Err(HandshakeError::Randomness) => {
                return Err(std::io::Error::other("handshake randomness unavailable"));
            }
            Err(_) => continue,
        };
        let mut amplification = AmplificationBudget::new(AMPLIFICATION_CEILING);
        amplification.credit_receive(len);
        if !amplification.debit_send(handshake.reply().len()) {
            continue;
        }
        socket.send_to(handshake.reply(), from).await?;
        let association = handshake.association_id();
        eprintln!(
            "everudp-spike association={:08x} peer={from}",
            u32::from_be_bytes(association[..4].try_into().expect("association prefix"))
        );
        return Ok(ServerSession {
            crypto: handshake.roots().for_role(Role::Server),
            handshake,
            peer: from,
            amplification,
        });
    }
}

async fn establish_client_session(
    socket: &UdpSocket,
    secret: &BootstrapSecret,
) -> Result<SessionSubstrate, BenchError> {
    let handshake = ClientHandshake::begin(secret)
        .map_err(|error| BenchError(format!("client handshake start failed: {error:?}")))?;
    let started = Instant::now();
    let mut reply = [0u8; MTU_CEILING];
    loop {
        socket
            .send(handshake.wire())
            .await
            .map_err(|error| BenchError(error.to_string()))?;
        let retransmit_at = Instant::now() + RETRANSMIT;
        loop {
            tokio::select! {
                received = socket.recv(&mut reply) => {
                    let len = received.map_err(|error| BenchError(error.to_string()))?;
                    match handshake.finish(secret, &reply[..len]) {
                        Ok(roots) => return Ok(roots.for_role(Role::Client)),
                        Err(HandshakeError::Authentication | HandshakeError::AssociationMismatch) => {
                            return Err(BenchError("server handshake authentication failed".into()));
                        }
                        Err(_) => continue,
                    }
                }
                _ = sleep_until(retransmit_at) => break,
            }
        }
        if started.elapsed() >= TRIAL_TIMEOUT {
            return Err(BenchError("UDP association handshake timed out".into()));
        }
    }
}

pub async fn udp_server(bind: SocketAddr, secret: BootstrapSecret) -> std::io::Result<()> {
    let socket = UdpSocket::bind(bind).await?;
    eprintln!("everudp-spike udp-server {}", socket.local_addr()?);
    udp_server_on_socket(socket, secret).await
}

pub async fn udp_server_on_socket(
    socket: UdpSocket,
    secret: BootstrapSecret,
) -> std::io::Result<()> {
    let mut packet = [0u8; MTU_CEILING];
    let mut server = accept_server_session(&socket, &secret, &mut packet).await?;
    let mut wire = Vec::with_capacity(MTU_CEILING);
    let mut echo_cache = ServerEchoCache::default();
    loop {
        let (len, from) = socket.recv_from(&mut packet).await?;
        let Some(plaintext) = server.receive(&socket, &packet[..len], from).await? else {
            continue;
        };
        let frame = match decode(&plaintext) {
            Ok(frame) => frame,
            Err(_) => continue,
        };
        let Frame::Input(Input { epoch, seq, bytes }) = frame else {
            continue;
        };
        let authoritative = match echo_cache.classify(epoch, seq) {
            ServerInputAction::Execute => {
                echo_cache.record(epoch, seq, &bytes);
                bytes
            }
            ServerInputAction::Replay(bytes) => bytes,
            ServerInputAction::Reject => continue,
        };
        Echo {
            ack: seq,
            bytes: authoritative,
        }
        .encode(&mut wire);
        server.send(&socket, &wire).await?;
    }
}

/// PTY-backed echo server: each authoritative reply comes from the real
/// echo program's stdout (through `script`, so the program owns a PTY),
/// making the everudp latency path end-to-end like zmosh's session path.
pub async fn udp_pty_server(
    bind: SocketAddr,
    secret: BootstrapSecret,
    command: String,
) -> std::io::Result<()> {
    let socket = UdpSocket::bind(bind).await?;
    eprintln!("everudp-spike udp-pty-server {}", socket.local_addr()?);
    udp_pty_server_on_socket(socket, secret, command).await
}

pub async fn udp_pty_server_on_socket(
    socket: UdpSocket,
    secret: BootstrapSecret,
    command: String,
) -> std::io::Result<()> {
    let mut child = spawn_echo_child(&command).await?;
    let mut stdin = child.stdin.take().expect("echo child stdin");
    let mut stdout = child.stdout.take().expect("echo child stdout");
    let mut packet = [0u8; MTU_CEILING];
    let mut wire = Vec::with_capacity(MTU_CEILING);
    let mut scratch = [0u8; MAX_PAYLOAD];
    let timing = std::env::var_os("EVERUDP_TIMING").is_some();
    let mut server = accept_server_session(&socket, &secret, &mut packet).await?;
    let mut echo_cache = ServerEchoCache::default();
    loop {
        let (len, from) = socket.recv_from(&mut packet).await?;
        let t_received = Instant::now();
        let Some(plaintext) = server.receive(&socket, &packet[..len], from).await? else {
            continue;
        };
        let frame = match decode(&plaintext) {
            Ok(frame) => frame,
            Err(_) => continue,
        };
        let Frame::Input(Input { epoch, seq, bytes }) = frame else {
            continue;
        };
        match echo_cache.classify(epoch, seq) {
            ServerInputAction::Replay(bytes) => {
                Echo { ack: seq, bytes }.encode(&mut wire);
                server.send(&socket, &wire).await?;
                continue;
            }
            ServerInputAction::Reject => continue,
            ServerInputAction::Execute => {}
        }
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
        echo_cache.record(epoch, seq, &echoed);
        let t_echo = Instant::now();
        Echo {
            ack: seq,
            bytes: echoed,
        }
        .encode(&mut wire);
        server.send(&socket, &wire).await?;
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
    secret: BootstrapSecret,
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
    socket
        .connect(server_addr)
        .await
        .map_err(|e| BenchError(e.to_string()))?;
    let mut client = establish_client_session(&socket, &secret).await?;
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
            .send(&client.seal(&wire, SESSION_AAD))
            .await
            .map_err(|e| BenchError(e.to_string()))?;
        let mut retransmits = 0u32;
        let mut next_retransmit = started + RETRANSMIT;
        let correct_render_us = loop {
            tokio::select! {
                received = socket.recv(&mut packet) => {
                    let len = received.map_err(|e| BenchError(e.to_string()))?;
                    let plaintext = client
                        .open(&packet[..len], SESSION_AAD)
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
                        .send(&client.seal(&wire, SESSION_AAD))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::KEEPALIVE;
    use tokio::time::timeout;

    const SECRET: BootstrapSecret = [0x41; BOOTSTRAP_SECRET_LEN];
    const OTHER_SECRET: BootstrapSecret = [0x42; BOOTSTRAP_SECRET_LEN];

    async fn client_session(server_addr: SocketAddr) -> (UdpSocket, SessionSubstrate) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(server_addr).await.unwrap();
        let crypto = establish_client_session(&socket, &SECRET).await.unwrap();
        (socket, crypto)
    }

    async fn exchange(
        socket: &UdpSocket,
        crypto: &mut SessionSubstrate,
        epoch: u32,
        seq: u64,
        bytes: &[u8],
    ) -> Echo {
        let mut wire = Vec::new();
        Input {
            epoch,
            seq,
            bytes: bytes.to_vec(),
        }
        .encode(&mut wire);
        socket.send(&crypto.seal(&wire, SESSION_AAD)).await.unwrap();
        let mut packet = [0u8; MTU_CEILING];
        let len = timeout(Duration::from_secs(1), socket.recv(&mut packet))
            .await
            .expect("server echo timed out")
            .unwrap();
        let plaintext = crypto.open(&packet[..len], SESSION_AAD).unwrap();
        match decode(&plaintext).unwrap() {
            Frame::Echo(echo) => echo,
            frame => panic!("expected echo, got {frame:?}"),
        }
    }

    #[test]
    fn echo_cache_executes_only_the_next_input() {
        let cache = ServerEchoCache::default();

        assert!(matches!(cache.classify(7, 0), ServerInputAction::Execute));
        assert!(matches!(cache.classify(0, 0), ServerInputAction::Reject));
        assert!(matches!(cache.classify(7, 1), ServerInputAction::Reject));
    }

    #[test]
    fn echo_cache_replays_duplicates_without_executing_them() {
        let mut cache = ServerEchoCache::default();
        cache.record(7, 0, b"x");

        match cache.classify(7, 0) {
            ServerInputAction::Replay(bytes) => assert_eq!(bytes, b"x"),
            _ => panic!("duplicate input must replay its cached echo"),
        }
        assert!(matches!(cache.classify(7, 1), ServerInputAction::Execute));
        assert!(matches!(cache.classify(8, 1), ServerInputAction::Reject));
    }

    #[test]
    fn echo_cache_is_bounded_and_old_duplicates_are_rejected() {
        let mut cache = ServerEchoCache::default();
        for seq in 0..=(SERVER_ECHO_CACHE_LIMIT as u64) {
            assert!(matches!(cache.classify(7, seq), ServerInputAction::Execute));
            cache.record(7, seq, &[seq as u8]);
        }

        assert_eq!(cache.echoes.len(), SERVER_ECHO_CACHE_LIMIT);
        assert!(matches!(cache.classify(7, 0), ServerInputAction::Reject));
        match cache.classify(7, SERVER_ECHO_CACHE_LIMIT as u64) {
            ServerInputAction::Replay(bytes) => {
                assert_eq!(bytes, vec![SERVER_ECHO_CACHE_LIMIT as u8]);
            }
            _ => panic!("recent duplicate must remain replayable"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn hostile_hello_gets_no_reply_and_does_not_consume_association() {
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let server = tokio::spawn(udp_server_on_socket(server_socket, SECRET));

        let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        attacker.connect(server_addr).await.unwrap();
        let forged = ClientHandshake::begin(&OTHER_SECRET).unwrap();
        attacker.send(forged.wire()).await.unwrap();
        let mut reply = [0u8; MTU_CEILING];
        assert!(
            timeout(Duration::from_millis(50), attacker.recv(&mut reply))
                .await
                .is_err()
        );

        let trials = udp_bench(server_addr, SECRET, false, 1).await.unwrap();
        assert_eq!(trials.len(), 1);
        server.abort();
        let _ = server.await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn authenticated_data_roams_but_forged_data_does_not_move_peer() {
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let first_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let first_addr = first_socket.local_addr().unwrap();
        let handshake = ClientHandshake::begin(&SECRET).unwrap();
        first_socket
            .send_to(handshake.wire(), server_addr)
            .await
            .unwrap();
        let mut packet = [0u8; MTU_CEILING];
        let mut server = accept_server_session(&server_socket, &SECRET, &mut packet)
            .await
            .unwrap();
        assert_eq!(server.peer, first_addr);

        let (reply_len, _) = first_socket.recv_from(&mut packet).await.unwrap();
        let roots = handshake.finish(&SECRET, &packet[..reply_len]).unwrap();
        let mut client_crypto = roots.for_role(Role::Client);

        let roaming_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let roaming_addr = roaming_socket.local_addr().unwrap();
        let sealed = client_crypto.seal(&[KEEPALIVE], SESSION_AAD);
        roaming_socket.send_to(&sealed, server_addr).await.unwrap();
        let (len, from) = server_socket.recv_from(&mut packet).await.unwrap();
        assert_eq!(
            server
                .receive(&server_socket, &packet[..len], from)
                .await
                .unwrap(),
            Some(vec![KEEPALIVE])
        );
        assert_eq!(server.peer, roaming_addr);

        let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        attacker.send_to(&sealed, server_addr).await.unwrap();
        let (len, from) = server_socket.recv_from(&mut packet).await.unwrap();
        assert!(server
            .receive(&server_socket, &packet[..len], from)
            .await
            .unwrap()
            .is_none());
        assert_eq!(server.peer, roaming_addr);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retransmitted_input_is_executed_once_through_the_pty() {
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let command = "/usr/bin/python3 -u -c 'import os\nfor n, _ in enumerate(iter(lambda: os.read(0, 1), b\"\"), 1):\n os.write(1, bytes([n]))'";
        let server = tokio::spawn(udp_pty_server_on_socket(
            server_socket,
            SECRET,
            command.to_string(),
        ));
        let (socket, mut crypto) = client_session(server_addr).await;
        // `script` configures the child PTY asynchronously after spawn.
        sleep(Duration::from_millis(100)).await;

        assert_eq!(exchange(&socket, &mut crypto, 1, 0, b"x").await.bytes, [1]);
        assert_eq!(exchange(&socket, &mut crypto, 1, 0, b"x").await.bytes, [1]);
        assert_eq!(exchange(&socket, &mut crypto, 1, 1, b"y").await.bytes, [2]);

        server.abort();
        let _ = server.await;
    }
}
