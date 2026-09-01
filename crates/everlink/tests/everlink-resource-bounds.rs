//! Named M3 production resource gate.
//!
//! The gate drives the production transport, admission, bridge, and shutdown
//! APIs. Its ceilings are derived from the configured QUIC windows, incoming
//! handshake budget, fixed copy buffers, kernel TCP buffer caps, and absolute
//! lifecycle deadlines. Linux `/proc` observations are process-local and the
//! test owns no helper process.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used)]

use everlink::admission::{AuthenticatedConnection, ConnectedTarget};
use everlink::bootstrap::SecretToken;
use everlink::identity::EphemeralIdentity;
use everlink::transport::{ClientEndpoint, ClientSession, ServerEndpoint, UdpBindPolicy};
use everlink::{
    CopyDirection, CopyOperation, DeadlineKind, DrainStatus, FinalizeStatus, Limits, Phase,
    RequestStatus, Shutdown, TargetBridge, TerminalCause,
};
use std::collections::BTreeSet;
use std::fs;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket as TokioUdpSocket};
use tokio::sync::Barrier;

const CHUNK_BYTES: usize = 16 * 1024;
const SUSTAINED_WINDOW_MULTIPLE: u64 = 32;
const FIXED_RSS_HEADROOM_BYTES: u64 = 16 * 1024 * 1024;
const PLATEAU_HEADROOM_BYTES: u64 = 4 * 1024 * 1024;
const FD_HEADROOM: usize = 16;
const THREAD_HEADROOM: usize = 1;
const RETURN_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessSample {
    rss_kib: u64,
    fds: usize,
    threads: usize,
    cpu_ns: u64,
    children: BTreeSet<u32>,
}

#[derive(Debug)]
struct PeakSample {
    rss_kib: u64,
    fds: usize,
    threads: usize,
}

impl PeakSample {
    fn new(sample: &ProcessSample) -> Self {
        Self {
            rss_kib: sample.rss_kib,
            fds: sample.fds,
            threads: sample.threads,
        }
    }

    fn observe(&mut self, baseline: &ProcessSample) -> ProcessSample {
        let sample = process_sample();
        assert_eq!(
            sample.children, baseline.children,
            "the in-process resource gate must not create helper processes"
        );
        self.rss_kib = self.rss_kib.max(sample.rss_kib);
        self.fds = self.fds.max(sample.fds);
        self.threads = self.threads.max(sample.threads);
        sample
    }
}

#[derive(Debug)]
struct GateCeilings {
    transport_envelope_bytes: u64,
    rss_growth_kib: u64,
    rss_plateau_kib: u64,
    rss_return_kib: u64,
    stalled_accepted_bytes: u64,
    fd_growth: usize,
    thread_growth: usize,
    shutdown: Duration,
}

impl GateCeilings {
    fn from_limits(limits: &Limits) -> Self {
        let copy_bytes = u64::try_from(limits.copy_buf).unwrap();
        let incoming = limits.incoming_buffer_total().unwrap();
        // Both client and server live in this gate process. Four send/receive
        // window pairs, eight fixed copy buffers, and the complete pending
        // handshake budget form the application-controlled envelope.
        let transport_envelope_bytes = (limits.send_window + limits.receive_window)
            .saturating_mul(4)
            .saturating_add(copy_bytes.saturating_mul(8))
            .saturating_add(incoming);
        let kernel_tcp_send_cap = kernel_tcp_send_buffer_cap();
        let rss_plateau_kib =
            PLATEAU_HEADROOM_BYTES.saturating_add(transport_envelope_bytes) / 1024;
        Self {
            transport_envelope_bytes,
            rss_growth_kib: FIXED_RSS_HEADROOM_BYTES
                .saturating_add(transport_envelope_bytes.saturating_mul(4))
                / 1024,
            rss_plateau_kib,
            rss_return_kib: rss_plateau_kib,
            stalled_accepted_bytes: kernel_tcp_send_cap
                .saturating_mul(2)
                .saturating_add(transport_envelope_bytes)
                .saturating_add(CHUNK_BYTES as u64),
            fd_growth: FD_HEADROOM,
            thread_growth: THREAD_HEADROOM,
            shutdown: limits
                .drain_timeout()
                .saturating_add(limits.finalize_timeout())
                .saturating_add(Duration::from_secs(2)),
        }
    }
}

fn gate_limits() -> Limits {
    Limits {
        server_lease_ms: 4_000,
        handshake_timeout_ms: 2_000,
        idle_timeout_ms: 5_000,
        stall_timeout_ms: 5_000,
        drain_timeout_ms: 750,
        finalize_timeout_ms: 1_500,
        ..Limits::default()
    }
}

fn stall_limits() -> Limits {
    Limits {
        stall_timeout_ms: 600,
        ..gate_limits()
    }
}

fn idle_limits() -> Limits {
    Limits {
        idle_timeout_ms: 750,
        stall_timeout_ms: 2_500,
        ..gate_limits()
    }
}

fn process_sample() -> ProcessSample {
    let status = fs::read_to_string("/proc/self/status").unwrap();
    let rss_kib = status
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmRSS:")
                .and_then(|value| value.trim_end_matches(" kB").trim().parse().ok())
        })
        .expect("/proc/self/status must report VmRSS");
    let fds = fs::read_dir("/proc/self/fd").unwrap().count();
    let mut threads = 0usize;
    let mut cpu_ns = 0u64;
    let mut children = BTreeSet::new();
    for entry in fs::read_dir("/proc/self/task").unwrap() {
        let path = entry.unwrap().path();
        if !path.is_dir() {
            continue;
        }
        threads += 1;
        match fs::read_to_string(path.join("schedstat")) {
            Ok(value) => {
                let runtime = value
                    .split_whitespace()
                    .next()
                    .and_then(|field| field.parse::<u64>().ok())
                    .expect("task schedstat must start with CPU nanoseconds");
                cpu_ns = cpu_ns.saturating_add(runtime);
            }
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => panic!("cannot sample task schedstat: {error}"),
        }
        match fs::read_to_string(path.join("children")) {
            Ok(value) => {
                children.extend(
                    value
                        .split_whitespace()
                        .map(|field| field.parse::<u32>().unwrap()),
                );
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => panic!("cannot sample task children: {error}"),
        }
    }
    ProcessSample {
        rss_kib,
        fds,
        threads,
        cpu_ns,
        children,
    }
}

fn kernel_tcp_send_buffer_cap() -> u64 {
    fs::read_to_string("/proc/sys/net/ipv4/tcp_wmem")
        .expect("cannot read the kernel TCP send-buffer policy")
        .split_whitespace()
        .map(|field| field.parse::<u64>().unwrap())
        .max()
        .expect("kernel TCP send-buffer policy must not be empty")
}

fn free_udp() -> SocketAddr {
    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
}

async fn connected_pair(limits: Limits) -> (ConnectedTarget, ClientSession, TcpStream, SocketAddr) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let target_address = listener.local_addr().unwrap();
    let authenticated = AuthenticatedConnection::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 40_001)),
        target_address,
    )
    .unwrap();
    let identity = EphemeralIdentity::generate().unwrap();
    let token = identity.take_bootstrap_token().unwrap();
    let server = ServerEndpoint::bind(
        authenticated,
        UdpBindPolicy::Explicit(free_udp()),
        &identity,
        limits,
    )
    .unwrap();
    let server_address = server.local_addr();
    let client = ClientEndpoint::bind(
        server_address,
        UdpBindPolicy::Explicit(free_udp()),
        identity.spki_sha256(),
        limits,
    )
    .unwrap();
    assert_eq!(server.profile(), client.profile());
    assert_eq!(server.profile().send_window, limits.send_window);
    assert_eq!(server.profile().receive_window, limits.receive_window);
    assert_eq!(server.profile().server_incoming_bidi, limits.max_bi_streams);
    assert_eq!(server.profile().client_incoming_bidi, 0);
    assert_eq!(server.profile().incoming_uni, 0);
    assert_eq!(
        server.profile().incoming_buffer_size_total,
        limits.incoming_buffer_total().unwrap()
    );

    let server_task = tokio::spawn(async move {
        let admitted = server.accept().await?;
        admitted.connect_target().await
    });
    let client = client
        .connect_and_authenticate(&token, target_address.port())
        .await
        .unwrap();
    let connected = server_task.await.unwrap().unwrap();
    let (target, _) = listener.accept().await.unwrap();
    (connected, client, target, server_address)
}

async fn close_client(client: ClientSession, limits: &Limits) {
    tokio::time::timeout(
        limits.finalize_timeout() + Duration::from_secs(1),
        client.close(),
    )
    .await
    .expect("client endpoint cleanup exceeded its finalization bound");
}

async fn assert_udp_released(address: SocketAddr, limits: &Limits) {
    let deadline = tokio::time::Instant::now() + limits.finalize_timeout() + Duration::from_secs(1);
    loop {
        match UdpSocket::bind(address) {
            Ok(socket) => {
                drop(socket);
                return;
            }
            Err(error)
                if error.kind() == ErrorKind::AddrInUse
                    && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => panic!("owned UDP endpoint was not released: {error}"),
        }
    }
}

async fn wait_for_process_baseline(baseline: &ProcessSample, ceilings: &GateCeilings) {
    let deadline = tokio::time::Instant::now() + RETURN_TIMEOUT;
    loop {
        let sample = process_sample();
        if sample.fds <= baseline.fds
            && sample.threads <= baseline.threads
            && sample.children == baseline.children
            && sample.rss_kib <= baseline.rss_kib + ceilings.rss_return_kib
        {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "owned resources did not return to baseline: baseline={baseline:?} current={sample:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn terminal_cause_family(cause: TerminalCause) -> &'static str {
    match cause {
        TerminalCause::SourceEof(_) => "source-eof",
        TerminalCause::OperationFailed { .. } => "operation-failed",
        TerminalCause::OperationStalled { .. } => "operation-stalled",
        TerminalCause::Cancelled => "cancelled",
        TerminalCause::TaskFailed(_) => "task-failed",
        TerminalCause::PathFailed => "path-failed",
        TerminalCause::RouteSupervisorFailed => "route-supervisor-failed",
        TerminalCause::ConstructionFailed => "construction-failed",
        TerminalCause::DeadlineOverflow(_) => "deadline-overflow",
        TerminalCause::FinalizeTimeout => "finalize-timeout",
    }
}

fn all_terminal_causes() -> Vec<TerminalCause> {
    let directions = [CopyDirection::QuicToPeer, CopyDirection::PeerToQuic];
    let operations = [
        CopyOperation::Read,
        CopyOperation::Write,
        CopyOperation::Flush,
        CopyOperation::Shutdown,
        CopyOperation::Delivery,
    ];
    let mut causes = Vec::new();
    for direction in directions {
        causes.push(TerminalCause::SourceEof(direction));
        causes.push(TerminalCause::TaskFailed(direction));
        for operation in operations {
            causes.push(TerminalCause::OperationFailed {
                direction,
                operation,
            });
            causes.push(TerminalCause::OperationStalled {
                direction,
                operation,
            });
        }
    }
    causes.extend([
        TerminalCause::Cancelled,
        TerminalCause::PathFailed,
        TerminalCause::RouteSupervisorFailed,
        TerminalCause::ConstructionFailed,
        TerminalCause::DeadlineOverflow(DeadlineKind::Operation),
        TerminalCause::DeadlineOverflow(DeadlineKind::Drain),
        TerminalCause::DeadlineOverflow(DeadlineKind::Finalize),
        TerminalCause::FinalizeTimeout,
    ]);
    causes
}

async fn complete_terminal_cause(limits: Limits, ceilings: &GateCeilings, cause: TerminalCause) {
    let (connected, mut client, mut target, server_address) = connected_pair(limits).await;
    let shutdown = Shutdown::new();
    let bridge = TargetBridge::try_new(connected, limits, shutdown.clone())
        .await
        .unwrap();
    let bridge_task = tokio::spawn(bridge.run());
    let mut byte = [0u8; 1];
    tokio::time::timeout(
        Duration::from_secs(2),
        client.quic_send_mut().write_all(&[0x5c]),
    )
    .await
    .expect("terminal-cause client write did not reach an active copy task")
    .unwrap();
    tokio::time::timeout(Duration::from_secs(2), target.read_exact(&mut byte))
        .await
        .expect("terminal-cause target read did not reach an active copy task")
        .unwrap();
    assert_eq!(byte, [0x5c]);
    target.write_all(&[0xc5]).await.unwrap();
    tokio::time::timeout(
        Duration::from_secs(2),
        client.quic_recv_mut().read_exact(&mut byte),
    )
    .await
    .expect("terminal-cause client read did not reach an active copy task")
    .unwrap();
    assert_eq!(byte, [0xc5]);
    assert_eq!(shutdown.phase(), Phase::Running);
    assert_eq!(
        shutdown.request(cause, limits.drain_timeout()),
        RequestStatus::Recorded
    );
    assert_eq!(shutdown.cause(), Some(cause));
    let frozen_drain = shutdown.drain_deadline();
    assert_eq!(
        shutdown.request(TerminalCause::Cancelled, Duration::from_secs(60)),
        RequestStatus::Existing
    );
    assert_eq!(shutdown.cause(), Some(cause));
    assert_eq!(shutdown.drain_deadline(), frozen_drain);
    assert_eq!(
        shutdown.cancel(limits.drain_timeout()),
        RequestStatus::Existing
    );
    let completion = tokio::time::timeout(ceilings.shutdown, bridge_task)
        .await
        .expect("terminal-cause bridge cleanup exceeded its bounded deadline")
        .expect("terminal-cause bridge task panicked");
    assert_eq!(completion.cause, cause);
    assert_eq!(completion.finalize, FinalizeStatus::Completed);
    assert_eq!(shutdown.phase(), Phase::Finalized);
    drop(target);
    close_client(client, &limits).await;
    assert_udp_released(server_address, &limits).await;
}

async fn warm_resource_paths(limits: Limits, ceilings: &GateCeilings) {
    for cause in [
        TerminalCause::SourceEof(CopyDirection::QuicToPeer),
        TerminalCause::OperationStalled {
            direction: CopyDirection::PeerToQuic,
            operation: CopyOperation::Write,
        },
        TerminalCause::Cancelled,
        TerminalCause::PathFailed,
    ] {
        complete_terminal_cause(limits, ceilings, cause).await;
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
}

async fn exercise_terminal_catalog_cleanup(
    limits: Limits,
    ceilings: &GateCeilings,
    baseline: &ProcessSample,
    peak: &mut PeakSample,
) -> usize {
    let causes = all_terminal_causes();
    let mut families = BTreeSet::new();
    for cause in causes.iter().copied() {
        families.insert(terminal_cause_family(cause));
        complete_terminal_cause(limits, ceilings, cause).await;
        wait_for_process_baseline(baseline, ceilings).await;
        peak.observe(baseline);
    }
    assert_eq!(
        families.len(),
        10,
        "every terminal-cause family is catalogued"
    );
    causes.len()
}

async fn sustained_transfer(
    limits: Limits,
    ceilings: &GateCeilings,
    baseline: &ProcessSample,
    peak: &mut PeakSample,
) -> (u64, u64) {
    let (connected, mut client, mut target, server_address) = connected_pair(limits).await;
    let shutdown = Shutdown::new();
    let bridge = TargetBridge::try_new(connected, limits, shutdown.clone())
        .await
        .unwrap();
    let bridge_task = tokio::spawn(bridge.run());
    let target_task = tokio::spawn(async move {
        let mut buffer = [0u8; CHUNK_BYTES];
        let mut received = 0u64;
        loop {
            let count = target.read(&mut buffer).await.unwrap();
            if count == 0 {
                break;
            }
            received += count as u64;
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        received
    });
    let transfer_bytes = limits
        .send_window
        .max(limits.receive_window)
        .saturating_mul(SUSTAINED_WINDOW_MULTIPLE);
    let chunk = [0x5a; CHUNK_BYTES];
    let mut sent = 0u64;
    let mut rss_samples = Vec::new();
    while sent < transfer_bytes {
        tokio::time::timeout(
            Duration::from_secs(2),
            client.quic_send_mut().write_all(&chunk),
        )
        .await
        .expect("sustained transfer lost forward progress")
        .unwrap();
        sent += CHUNK_BYTES as u64;
        if (sent / CHUNK_BYTES as u64).is_multiple_of(8) {
            rss_samples.push(peak.observe(baseline).rss_kib);
        }
    }
    client.quic_send_mut().finish().unwrap();
    let received = tokio::time::timeout(ceilings.shutdown, target_task)
        .await
        .expect("target drain exceeded the shutdown ceiling")
        .unwrap();
    assert_eq!(received, sent);
    let completion = tokio::time::timeout(ceilings.shutdown, bridge_task)
        .await
        .expect("sustained bridge shutdown exceeded the ceiling")
        .unwrap();
    assert_eq!(
        completion.cause,
        TerminalCause::SourceEof(CopyDirection::QuicToPeer)
    );
    assert_eq!(completion.drain, DrainStatus::Completed);
    assert_eq!(completion.finalize, FinalizeStatus::Completed);
    assert_eq!(shutdown.phase(), Phase::Finalized);
    assert!(sent >= limits.receive_window * SUSTAINED_WINDOW_MULTIPLE);
    assert!(rss_samples.len() >= 8);
    let warm = &rss_samples[rss_samples.len() / 2..];
    let spread = warm.iter().max().unwrap() - warm.iter().min().unwrap();
    assert!(
        spread <= ceilings.rss_plateau_kib,
        "RSS did not plateau: spread={spread} KiB ceiling={} KiB",
        ceilings.rss_plateau_kib
    );
    close_client(client, &limits).await;
    assert_udp_released(server_address, &limits).await;
    (sent, spread)
}

async fn fill_until_terminal<W>(
    writer: &mut W,
    ceiling: u64,
    timeout: Duration,
    baseline: &ProcessSample,
    peak: &mut PeakSample,
) -> u64
where
    W: AsyncWrite + Unpin,
{
    let deadline = tokio::time::Instant::now() + timeout;
    let chunk = [0xa5; CHUNK_BYTES];
    let mut accepted = 0u64;
    loop {
        match tokio::time::timeout_at(deadline, writer.write_all(&chunk)).await {
            Ok(Ok(())) => {
                accepted += CHUNK_BYTES as u64;
                assert!(
                    accepted <= ceiling,
                    "a stalled path accepted {accepted} bytes beyond its {ceiling}-byte ceiling"
                );
                if (accepted / CHUNK_BYTES as u64).is_multiple_of(8) {
                    peak.observe(baseline);
                }
            }
            Ok(Err(_)) | Err(_) => return accepted,
        }
    }
}

async fn fill_until_terminal_with_heartbeat<W, H>(
    writer: &mut W,
    heartbeat: &mut H,
    ceiling: u64,
    timeout: Duration,
    baseline: &ProcessSample,
    peak: &mut PeakSample,
) -> u64
where
    W: AsyncWrite + Unpin,
    H: AsyncWrite + Unpin,
{
    let deadline = tokio::time::Instant::now() + timeout;
    let chunk = [0x96; CHUNK_BYTES];
    let mut accepted = 0u64;
    loop {
        match tokio::time::timeout(Duration::from_millis(100), writer.write(&chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return accepted,
            Ok(Ok(count)) => {
                accepted += count as u64;
                assert!(
                    accepted <= ceiling,
                    "a stalled path accepted {accepted} bytes beyond its {ceiling}-byte ceiling"
                );
            }
            Err(_) => {}
        }
        if tokio::time::Instant::now() >= deadline {
            return accepted;
        }
        if !matches!(
            tokio::time::timeout(Duration::from_millis(100), heartbeat.write_all(&[0])).await,
            Ok(Ok(()))
        ) {
            return accepted;
        }
        peak.observe(baseline);
    }
}

async fn stalled_tcp_consumer(
    limits: Limits,
    ceilings: &GateCeilings,
    baseline: &ProcessSample,
    peak: &mut PeakSample,
) -> u64 {
    let (connected, mut client, target, server_address) = connected_pair(limits).await;
    let (target_read, mut target_write) = target.into_split();
    let shutdown = Shutdown::new();
    let bridge = TargetBridge::try_new(connected, limits, shutdown.clone())
        .await
        .unwrap();
    let started = Instant::now();
    let bridge_task = tokio::spawn(bridge.run());
    let heartbeat_task = tokio::spawn(async move {
        loop {
            if target_write.write_all(&[0]).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
    let accepted = fill_until_terminal(
        client.quic_send_mut(),
        ceilings.stalled_accepted_bytes,
        limits.stall_timeout() + ceilings.shutdown,
        baseline,
        peak,
    )
    .await;
    let completion = tokio::time::timeout(ceilings.shutdown, bridge_task)
        .await
        .expect("stalled TCP consumer did not shut down")
        .unwrap();
    assert!(accepted >= limits.receive_window);
    assert_eq!(
        completion.cause,
        TerminalCause::OperationStalled {
            direction: CopyDirection::QuicToPeer,
            operation: CopyOperation::Write,
        }
    );
    assert_eq!(completion.finalize, FinalizeStatus::Completed);
    assert_eq!(shutdown.phase(), Phase::Finalized);
    assert!(started.elapsed() <= limits.stall_timeout() + ceilings.shutdown);
    heartbeat_task.abort();
    let _ = heartbeat_task.await;
    drop(target_read);
    close_client(client, &limits).await;
    assert_udp_released(server_address, &limits).await;
    accepted
}

async fn stalled_quic_consumer(
    limits: Limits,
    ceilings: &GateCeilings,
    baseline: &ProcessSample,
    peak: &mut PeakSample,
) -> u64 {
    let (connected, mut client, target, server_address) = connected_pair(limits).await;
    let (target_read, mut target_write) = target.into_split();
    let shutdown = Shutdown::new();
    let bridge = TargetBridge::try_new(connected, limits, shutdown.clone())
        .await
        .unwrap();
    let started = Instant::now();
    let bridge_task = tokio::spawn(bridge.run());
    let accepted = fill_until_terminal_with_heartbeat(
        &mut target_write,
        client.quic_send_mut(),
        ceilings.stalled_accepted_bytes,
        limits.stall_timeout() + ceilings.shutdown,
        baseline,
        peak,
    )
    .await;
    let completion = tokio::time::timeout(ceilings.shutdown, bridge_task)
        .await
        .expect("stalled QUIC consumer did not shut down")
        .unwrap();
    assert!(accepted >= limits.receive_window);
    assert_eq!(
        completion.cause,
        TerminalCause::OperationStalled {
            direction: CopyDirection::PeerToQuic,
            operation: CopyOperation::Write,
        }
    );
    assert_eq!(completion.finalize, FinalizeStatus::Completed);
    assert_eq!(shutdown.phase(), Phase::Finalized);
    assert!(started.elapsed() <= limits.stall_timeout() + ceilings.shutdown);
    drop(target_read);
    drop(target_write);
    close_client(client, &limits).await;
    assert_udp_released(server_address, &limits).await;
    accepted
}

async fn idle_connection(
    limits: Limits,
    ceilings: &GateCeilings,
    baseline: &ProcessSample,
    peak: &mut PeakSample,
) -> (u64, u64) {
    let (connected, client, target, server_address) = connected_pair(limits).await;
    let shutdown = Shutdown::new();
    let bridge = TargetBridge::try_new(connected, limits, shutdown.clone())
        .await
        .unwrap();
    let cpu_before = process_sample().cpu_ns;
    let started = Instant::now();
    let completion = tokio::time::timeout(
        limits.idle_timeout() + ceilings.shutdown,
        tokio::spawn(bridge.run()),
    )
    .await
    .expect("idle connection did not honor its finite deadline")
    .unwrap();
    let elapsed = started.elapsed();
    let after = peak.observe(baseline);
    let cpu_ns = after.cpu_ns.saturating_sub(cpu_before);
    let wall_ns = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
    let cpu_ceiling_ns = wall_ns / 3 + 50_000_000;
    assert!(
        cpu_ns <= cpu_ceiling_ns,
        "idle CPU exceeded the one-third-core plus 50ms ceiling: cpu={cpu_ns}ns wall={wall_ns}ns"
    );
    assert!(matches!(
        completion.cause,
        TerminalCause::OperationFailed {
            operation: CopyOperation::Read,
            ..
        }
    ));
    assert_eq!(completion.finalize, FinalizeStatus::Completed);
    assert_eq!(shutdown.phase(), Phase::Finalized);
    drop(target);
    close_client(client, &limits).await;
    assert_udp_released(server_address, &limits).await;
    (cpu_ns, cpu_ceiling_ns)
}

async fn wrong_token_round(limits: Limits, baseline: &ProcessSample, peak: &mut PeakSample) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let target_address = listener.local_addr().unwrap();
    let authenticated = AuthenticatedConnection::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 40_002)),
        target_address,
    )
    .unwrap();
    let identity = EphemeralIdentity::generate().unwrap();
    let correct = identity.take_bootstrap_token().unwrap();
    let mut wrong_bytes = *correct.as_bytes();
    wrong_bytes[0] ^= 0xff;
    let wrong = SecretToken::from_bytes(wrong_bytes);
    let server = ServerEndpoint::bind(
        authenticated,
        UdpBindPolicy::Explicit(free_udp()),
        &identity,
        limits,
    )
    .unwrap();
    let server_address = server.local_addr();
    let client = ClientEndpoint::bind(
        server_address,
        UdpBindPolicy::Explicit(free_udp()),
        identity.spki_sha256(),
        limits,
    )
    .unwrap();
    let server_task = tokio::spawn(server.accept());
    let client_result = client
        .connect_and_authenticate(&wrong, target_address.port())
        .await;
    let server_result = tokio::time::timeout(
        limits.handshake_timeout() + Duration::from_secs(1),
        server_task,
    )
    .await
    .expect("wrong-token server admission did not terminate")
    .unwrap();
    assert!(matches!(server_result, Err(everlink::Error::AuthRejected)));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err(),
        "wrong-token admission reached target TCP"
    );
    if let Ok(session) = client_result {
        close_client(session, &limits).await;
    }
    assert_udp_released(server_address, &limits).await;
    peak.observe(baseline);
}

async fn concurrent_unauthenticated_attempts(
    limits: Limits,
    baseline: &ProcessSample,
    peak: &mut PeakSample,
) -> (usize, usize) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let target_address = listener.local_addr().unwrap();
    let authenticated = AuthenticatedConnection::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 40_003)),
        target_address,
    )
    .unwrap();
    let identity = EphemeralIdentity::generate().unwrap();
    let correct = identity.take_bootstrap_token().unwrap();
    let mut wrong_bytes = *correct.as_bytes();
    wrong_bytes[0] ^= 0x5a;
    let wrong = SecretToken::from_bytes(wrong_bytes);
    let server = ServerEndpoint::bind(
        authenticated,
        UdpBindPolicy::Explicit(free_udp()),
        &identity,
        limits,
    )
    .unwrap();
    let server_address = server.local_addr();
    assert_eq!(server.profile().max_incoming, limits.max_pending_handshakes);
    assert_eq!(
        server.profile().incoming_buffer_size_total,
        limits.incoming_buffer_total().unwrap()
    );
    let attempts = limits.max_retry_attempts;
    let mut clients = Vec::with_capacity(attempts);
    for _ in 0..attempts {
        clients.push(
            ClientEndpoint::bind(
                server_address,
                UdpBindPolicy::Explicit(free_udp()),
                identity.spki_sha256(),
                limits,
            )
            .unwrap(),
        );
    }
    peak.observe(baseline);
    let start = Arc::new(Barrier::new(attempts + 1));
    let active = Arc::new(AtomicUsize::new(0));
    let peak_active = Arc::new(AtomicUsize::new(0));
    let mut client_tasks = Vec::with_capacity(attempts);
    for client in clients {
        let token = wrong.clone();
        let start = start.clone();
        let active = active.clone();
        let peak_active = peak_active.clone();
        client_tasks.push(tokio::spawn(async move {
            start.wait().await;
            let concurrent = active.fetch_add(1, Ordering::SeqCst) + 1;
            peak_active.fetch_max(concurrent, Ordering::SeqCst);
            let result = client
                .connect_and_authenticate(&token, target_address.port())
                .await;
            active.fetch_sub(1, Ordering::SeqCst);
            result
        }));
    }
    start.wait().await;
    let pressure_deadline = tokio::time::Instant::now() + Duration::from_millis(500);
    while active.load(Ordering::SeqCst) < attempts
        && tokio::time::Instant::now() < pressure_deadline
    {
        tokio::task::yield_now().await;
    }
    let pending_peak = peak_active.load(Ordering::SeqCst);
    assert!(
        pending_peak > limits.max_pending_handshakes,
        "observed client overlap must press beyond the configured pending-handshake budget"
    );
    peak.observe(baseline);
    let server_task = tokio::spawn(server.accept());
    let server_result = tokio::time::timeout(
        limits.handshake_timeout() + Duration::from_secs(2),
        server_task,
    )
    .await
    .expect("pending-handshake budget did not terminate")
    .unwrap();
    assert!(matches!(
        server_result,
        Err(everlink::Error::AuthRejected | everlink::Error::RetryLimitExceeded)
    ));
    for task in client_tasks {
        match tokio::time::timeout(limits.handshake_timeout() + Duration::from_secs(2), task)
            .await
            .expect("unauthenticated client task exceeded its deadline")
        {
            Ok(Ok(session)) => close_client(session, &limits).await,
            Ok(Err(_)) => {}
            Err(error) => panic!("unauthenticated client task failed: {error}"),
        }
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err(),
        "unauthenticated handshake work reached target TCP"
    );
    assert_udp_released(server_address, &limits).await;
    peak.observe(baseline);
    (attempts, pending_peak)
}

async fn malformed_datagram_amplification(
    limits: Limits,
    baseline: &ProcessSample,
    peak: &mut PeakSample,
) -> (u64, u64) {
    let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let authenticated = AuthenticatedConnection::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 40_004)),
        target.local_addr().unwrap(),
    )
    .unwrap();
    let identity = EphemeralIdentity::generate().unwrap();
    let server = ServerEndpoint::bind(
        authenticated,
        UdpBindPolicy::Explicit(free_udp()),
        &identity,
        limits,
    )
    .unwrap();
    let server_address = server.local_addr();
    let packet = [0x3c; 1200];
    let mut senders = Vec::with_capacity(limits.max_pending_handshakes * 2);
    let mut sent = 0u64;
    for _ in 0..limits.max_pending_handshakes * 2 {
        let socket = TokioUdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        sent += socket.send_to(&packet, server_address).await.unwrap() as u64;
        senders.push(socket);
    }
    let mut received = 0u64;
    let mut buffer = [0u8; u16::MAX as usize];
    let observation_deadline =
        tokio::time::Instant::now() + limits.handshake_timeout() + Duration::from_millis(250);
    while tokio::time::Instant::now() < observation_deadline {
        let mut observed = false;
        for socket in &senders {
            loop {
                match socket.try_recv(&mut buffer) {
                    Ok(count) => {
                        received = received.saturating_add(count as u64);
                        observed = true;
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                    Err(error) => panic!("cannot drain malformed-datagram response: {error}"),
                }
            }
        }
        if !observed {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }
    assert!(
        received <= sent.saturating_mul(3),
        "pre-validation UDP amplification exceeded 3x: sent={sent} received={received}"
    );
    drop(senders);
    server.close().await.unwrap();
    assert_udp_released(server_address, &limits).await;
    peak.observe(baseline);
    (sent, received)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn everlink_resource_bounds() {
    let limits = gate_limits();
    limits.validate().unwrap();
    let ceilings = GateCeilings::from_limits(&limits);
    warm_resource_paths(limits, &ceilings).await;
    let baseline = process_sample();
    let mut peak = PeakSample::new(&baseline);
    let cause_count =
        exercise_terminal_catalog_cleanup(limits, &ceilings, &baseline, &mut peak).await;

    let (transferred, rss_plateau) =
        sustained_transfer(limits, &ceilings, &baseline, &mut peak).await;
    wait_for_process_baseline(&baseline, &ceilings).await;
    let stall = stall_limits();
    let stall_ceilings = GateCeilings::from_limits(&stall);
    let stalled_tcp = stalled_tcp_consumer(stall, &stall_ceilings, &baseline, &mut peak).await;
    wait_for_process_baseline(&baseline, &ceilings).await;
    let stalled_quic = stalled_quic_consumer(stall, &stall_ceilings, &baseline, &mut peak).await;
    wait_for_process_baseline(&baseline, &ceilings).await;

    let idle = idle_limits();
    let idle_ceilings = GateCeilings::from_limits(&idle);
    let (idle_cpu_ns, idle_cpu_ceiling_ns) =
        idle_connection(idle, &idle_ceilings, &baseline, &mut peak).await;
    wait_for_process_baseline(&baseline, &ceilings).await;

    for _ in 0..limits.max_pending_handshakes {
        wrong_token_round(limits, &baseline, &mut peak).await;
        wait_for_process_baseline(&baseline, &ceilings).await;
    }
    let (unauthenticated_attempts, pending_handshake_peak) =
        concurrent_unauthenticated_attempts(limits, &baseline, &mut peak).await;
    wait_for_process_baseline(&baseline, &ceilings).await;
    let (amplification_sent, amplification_received) =
        malformed_datagram_amplification(limits, &baseline, &mut peak).await;
    wait_for_process_baseline(&baseline, &ceilings).await;

    let final_sample = process_sample();
    assert_eq!(final_sample.children, baseline.children);
    assert!(final_sample.fds <= baseline.fds);
    assert!(final_sample.threads <= baseline.threads);
    assert!(final_sample.rss_kib <= baseline.rss_kib + ceilings.rss_return_kib);
    assert!(
        peak.fds <= baseline.fds + ceilings.fd_growth,
        "fd ceiling exceeded: baseline={} peak={} growth_ceiling={}",
        baseline.fds,
        peak.fds,
        ceilings.fd_growth
    );
    assert!(
        peak.threads <= baseline.threads + ceilings.thread_growth,
        "thread ceiling exceeded: baseline={} peak={} growth_ceiling={}",
        baseline.threads,
        peak.threads,
        ceilings.thread_growth
    );
    assert!(
        peak.rss_kib <= baseline.rss_kib + ceilings.rss_growth_kib,
        "RSS ceiling exceeded: baseline={} KiB peak={} KiB growth_ceiling={} KiB",
        baseline.rss_kib,
        peak.rss_kib,
        ceilings.rss_growth_kib
    );

    println!(
        "everlink-resource-bounds: PASS transfer_bytes={transferred} rss_baseline_kib={} rss_peak_kib={} rss_final_kib={}/{} rss_plateau_kib={rss_plateau}/{} fd_peak={}/{} thread_peak={}/{} transport_envelope_bytes={} stalled_tcp_bytes={stalled_tcp}/{} stalled_quic_bytes={stalled_quic}/{} idle_cpu_ns={idle_cpu_ns}/{idle_cpu_ceiling_ns} unauthenticated_attempts={unauthenticated_attempts} pending_handshake_peak={pending_handshake_peak}/{} amplification_bytes={amplification_received}/{amplification_sent} terminal_causes_finalized={cause_count}",
        baseline.rss_kib,
        peak.rss_kib,
        final_sample.rss_kib,
        baseline.rss_kib + ceilings.rss_return_kib,
        ceilings.rss_plateau_kib,
        peak.fds,
        baseline.fds + ceilings.fd_growth,
        peak.threads,
        baseline.threads + ceilings.thread_growth,
        ceilings.transport_envelope_bytes,
        ceilings.stalled_accepted_bytes,
        ceilings.stalled_accepted_bytes,
        limits.max_pending_handshakes,
    );
}
