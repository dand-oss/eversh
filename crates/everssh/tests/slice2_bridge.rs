//! M3 Slice 2 integration coverage for the authenticated opaque-byte bridge.
#![allow(clippy::unwrap_used)]

use everssh::admission::{AuthenticatedConnection, ConnectedTarget};
use everssh::error::LimitViolation;
use everssh::identity::EphemeralIdentity;
use everssh::transport::{ClientEndpoint, ClientSession, ServerEndpoint, UdpBindPolicy};
use everssh::{
    CopyDirection, DrainStatus, Error, FinalizeStatus, Limits, Phase, Shutdown, TargetBridge,
    TerminalCause,
};
use std::future::Future;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn free_udp() -> SocketAddr {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    socket.local_addr().unwrap()
}

fn bridge_limits() -> Limits {
    Limits {
        copy_buf: 257,
        server_lease_ms: 5_000,
        handshake_timeout_ms: 3_000,
        idle_timeout_ms: 10_000,
        stall_timeout_ms: 2_000,
        drain_timeout_ms: 1_000,
        finalize_timeout_ms: 5_000,
        ..Limits::default()
    }
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

    let server_address = free_udp();
    let server = ServerEndpoint::bind(
        authenticated,
        UdpBindPolicy::Explicit(server_address),
        &identity,
        limits,
    )
    .unwrap();
    let actual_server_address = server.local_addr();
    let client = ClientEndpoint::bind(
        actual_server_address,
        UdpBindPolicy::Explicit(free_udp()),
        identity.spki_sha256(),
        limits,
    )
    .unwrap();

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
    (connected, client, target, actual_server_address)
}

async fn close_client(client: ClientSession) {
    tokio::time::timeout(Duration::from_secs(6), client.close())
        .await
        .unwrap();
}

async fn assert_udp_released(address: SocketAddr) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(6);
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
            Err(error) => panic!("server UDP endpoint was not released: {error}"),
        }
    }
}

fn opaque_bytes(length: usize, salt: usize) -> Vec<u8> {
    (0..length)
        .map(|index| ((index.wrapping_mul(193).wrapping_add(salt)) & 0xff) as u8)
        .collect()
}

#[test]
fn production_bridge_has_no_process_or_diagnostic_escape_hatch() {
    let bridge = include_str!("../src/bridge.rs");
    let shutdown = include_str!("../src/shutdown.rs");
    for source in [bridge, shutdown] {
        for forbidden in [
            "std::process",
            "Command::",
            "Runtime::new",
            "Builder::new_",
            "eprintln!",
            "println!",
            "std::env",
        ] {
            assert!(
                !source.contains(forbidden),
                "production source contains forbidden escape hatch {forbidden}"
            );
        }
    }
}

#[tokio::test]
async fn authenticated_round_trip_and_quic_fin_preserve_late_tcp_response() {
    let limits = bridge_limits();
    let (connected, mut client, mut target, server_address) = connected_pair(limits).await;
    let shutdown = Shutdown::new();
    let bridge = TargetBridge::try_new(connected, limits, shutdown.clone())
        .await
        .unwrap();

    let payload_marker = "payload-must-not-appear";
    assert!(!format!("{bridge:?}").contains(payload_marker));
    let bridge_task = tokio::spawn(bridge.run());

    let mut uplink = opaque_bytes(limits.copy_buf * 2, 0);
    uplink[0] = 0;
    uplink[1] = 0xff;
    uplink[2] = 0x80;
    uplink[8..8 + payload_marker.len()].copy_from_slice(payload_marker.as_bytes());
    let downlink = opaque_bytes(limits.copy_buf + 1, 17);

    client.quic_send_mut().write_all(&uplink).await.unwrap();
    client.quic_send_mut().finish().unwrap();

    let mut received = Vec::new();
    target.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, uplink);

    target.write_all(&downlink).await.unwrap();
    target.shutdown().await.unwrap();
    let returned = client
        .quic_recv_mut()
        .read_to_end(limits.copy_buf * 4)
        .await
        .unwrap();
    assert_eq!(returned, downlink);

    let completion = tokio::time::timeout(Duration::from_secs(7), bridge_task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        completion.cause,
        TerminalCause::SourceEof(CopyDirection::QuicToPeer)
    );
    assert_eq!(completion.drain, DrainStatus::Completed);
    assert_eq!(completion.finalize, FinalizeStatus::Completed);
    assert_eq!(shutdown.phase(), Phase::Finalized);
    assert!(!format!("{completion:?}").contains(payload_marker));

    close_client(client).await;
    drop(target);
    assert_udp_released(server_address).await;
}

#[tokio::test]
async fn target_tcp_eof_finishes_only_quic_send_and_allows_late_uplink() {
    let limits = bridge_limits();
    let (connected, mut client, mut target, server_address) = connected_pair(limits).await;
    let shutdown = Shutdown::new();
    let bridge = TargetBridge::try_new(connected, limits, shutdown.clone())
        .await
        .unwrap();
    let bridge_task = tokio::spawn(bridge.run());

    let early_response = [0xff, 0x00, 0xfe, 0x80, 0x41];
    target.write_all(&early_response).await.unwrap();
    target.shutdown().await.unwrap();
    let response = client
        .quic_recv_mut()
        .read_to_end(limits.copy_buf)
        .await
        .unwrap();
    assert_eq!(response, early_response);

    let late_uplink = opaque_bytes(limits.copy_buf + 9, 71);
    client
        .quic_send_mut()
        .write_all(&late_uplink)
        .await
        .unwrap();
    client.quic_send_mut().finish().unwrap();
    let mut received = Vec::new();
    target.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, late_uplink);

    let completion = tokio::time::timeout(Duration::from_secs(7), bridge_task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        completion.cause,
        TerminalCause::SourceEof(CopyDirection::PeerToQuic)
    );
    assert_eq!(completion.drain, DrainStatus::Completed);
    assert_eq!(completion.finalize, FinalizeStatus::Completed);
    assert_eq!(shutdown.phase(), Phase::Finalized);

    close_client(client).await;
    drop(target);
    assert_udp_released(server_address).await;
}

#[tokio::test]
async fn request_before_run_admits_no_task_and_releases_owned_sockets() {
    let limits = bridge_limits();
    let (connected, client, mut target, server_address) = connected_pair(limits).await;
    let shutdown = Shutdown::new();
    let bridge = TargetBridge::try_new(connected, limits, shutdown.clone())
        .await
        .unwrap();
    shutdown.cancel(limits.drain_timeout());

    let completion = tokio::time::timeout(Duration::from_secs(7), bridge.run())
        .await
        .unwrap();
    assert_eq!(completion.cause, TerminalCause::Cancelled);
    assert_eq!(completion.drain, DrainStatus::Incomplete);
    assert_eq!(completion.finalize, FinalizeStatus::Completed);
    assert_eq!(shutdown.phase(), Phase::Finalized);
    let mut byte = [0u8; 1];
    assert_eq!(target.read(&mut byte).await.unwrap(), 0);

    close_client(client).await;
    drop(target);
    assert_udp_released(server_address).await;
}

#[tokio::test]
async fn request_before_construction_rejects_without_resurrection() {
    let limits = bridge_limits();
    let (connected, client, mut target, server_address) = connected_pair(limits).await;
    let shutdown = Shutdown::new();
    shutdown.cancel(limits.drain_timeout());
    let frozen_drain = shutdown.drain_deadline();

    let result = TargetBridge::try_new(connected, limits, shutdown.clone()).await;
    assert!(matches!(result, Err(Error::BridgeAdmissionClosed)));
    assert_eq!(shutdown.cause(), Some(TerminalCause::Cancelled));
    assert_eq!(shutdown.drain_deadline(), frozen_drain);
    assert_eq!(shutdown.phase(), Phase::Finalized);
    let mut byte = [0u8; 1];
    assert_eq!(target.read(&mut byte).await.unwrap(), 0);

    close_client(client).await;
    drop(target);
    assert_udp_released(server_address).await;
}

#[tokio::test]
async fn fallible_buffer_construction_rolls_back_connected_target() {
    let normal_limits = bridge_limits();
    let (connected, client, mut target, server_address) = connected_pair(normal_limits).await;
    let shutdown = Shutdown::new();
    let impossible_limits = Limits {
        copy_buf: usize::MAX,
        ..normal_limits
    };

    let result = TargetBridge::try_new(connected, impossible_limits, shutdown.clone()).await;
    assert!(matches!(result, Err(Error::BridgeAllocation)));
    assert_eq!(shutdown.cause(), Some(TerminalCause::ConstructionFailed));
    assert_eq!(shutdown.phase(), Phase::Finalized);
    let mut byte = [0u8; 1];
    assert_eq!(target.read(&mut byte).await.unwrap(), 0);

    close_client(client).await;
    drop(target);
    assert_udp_released(server_address).await;
}

#[tokio::test]
async fn aborting_parent_run_latches_cancellation_and_releases_only_owned_resources() {
    let limits = bridge_limits();
    let (connected, client, mut target, server_address) = connected_pair(limits).await;
    let shutdown = Shutdown::new();
    let bridge = TargetBridge::try_new(connected, limits, shutdown.clone())
        .await
        .unwrap();
    let bridge_task = tokio::spawn(bridge.run());
    tokio::task::yield_now().await;
    assert_eq!(shutdown.phase(), Phase::Running);

    bridge_task.abort();
    let join_error = tokio::time::timeout(Duration::from_secs(1), bridge_task)
        .await
        .unwrap()
        .unwrap_err();
    assert!(join_error.is_cancelled());
    assert_eq!(shutdown.cause(), Some(TerminalCause::Cancelled));
    assert_eq!(shutdown.phase(), Phase::Draining);
    assert!(!shutdown.accepting_work());

    let frozen = shutdown.snapshot();
    shutdown.cancel(Duration::from_secs(30));
    assert_eq!(shutdown.snapshot(), frozen);

    let mut byte = [0u8; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), target.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert_udp_released(server_address).await;
    assert_eq!(shutdown.phase(), Phase::Draining);

    close_client(client).await;
    drop(target);
}

#[tokio::test]
async fn owner_wait_timeout_is_typed_and_does_not_publish_finalized() {
    let limits = Limits {
        finalize_timeout_ms: 1,
        ..bridge_limits()
    };
    let (connected, mut client, mut target, server_address) = connected_pair(limits).await;
    let shutdown = Shutdown::new();
    let bridge = TargetBridge::try_new(connected, limits, shutdown.clone())
        .await
        .unwrap();
    let bridge_task = tokio::spawn(bridge.run());

    client.quic_send_mut().finish().unwrap();
    let mut uplink = Vec::new();
    target.read_to_end(&mut uplink).await.unwrap();
    assert!(uplink.is_empty());
    target.shutdown().await.unwrap();
    let response = client.quic_recv_mut().read_to_end(1).await.unwrap();
    assert!(response.is_empty());

    let completion = tokio::time::timeout(Duration::from_secs(7), bridge_task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        completion.cause,
        TerminalCause::SourceEof(CopyDirection::QuicToPeer)
    );
    assert_eq!(completion.drain, DrainStatus::Completed);
    assert_eq!(completion.finalize, FinalizeStatus::DeadlineExpired);
    assert_eq!(shutdown.phase(), Phase::Draining);
    assert!(shutdown.finalize_deadline().is_some());

    assert_udp_released(server_address).await;
    close_client(client).await;
    drop(target);
}

#[tokio::test]
async fn rejection_cleanup_timeout_is_bounded_and_does_not_publish_finalized() {
    let limits = bridge_limits();
    let (connected, client, mut target, server_address) = connected_pair(limits).await;
    let shutdown = Shutdown::new();
    let invalid_limits = Limits {
        copy_buf: 0,
        finalize_timeout_ms: 1,
        ..limits
    };

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        TargetBridge::try_new(connected, invalid_limits, shutdown.clone()),
    )
    .await
    .unwrap();
    assert!(matches!(
        result,
        Err(Error::InvalidLimits(LimitViolation::ZeroValue))
    ));
    assert_eq!(shutdown.cause(), Some(TerminalCause::ConstructionFailed));
    assert_eq!(shutdown.phase(), Phase::Draining);
    assert!(shutdown.finalize_deadline().is_some());

    let mut byte = [0u8; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), target.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert_udp_released(server_address).await;
    close_client(client).await;
    drop(target);
}

#[tokio::test]
async fn runtime_unavailable_cleanup_remains_non_finalized_and_releases_endpoint() {
    let limits = bridge_limits();
    let (connected, client, mut target, server_address) = connected_pair(limits).await;
    let shutdown = Shutdown::new();
    let thread_shutdown = shutdown.clone();

    let result = std::thread::spawn(move || {
        let mut future = Box::pin(TargetBridge::try_new(connected, limits, thread_shutdown));
        let mut context = Context::from_waker(std::task::Waker::noop());
        match future.as_mut().poll(&mut context) {
            Poll::Ready(result) => result,
            Poll::Pending => panic!("runtime-unavailable construction unexpectedly awaited"),
        }
    })
    .join()
    .unwrap();

    assert!(matches!(result, Err(Error::RuntimeUnavailable)));
    assert_eq!(shutdown.cause(), Some(TerminalCause::ConstructionFailed));
    assert_eq!(shutdown.phase(), Phase::Draining);
    assert!(shutdown.finalize_deadline().is_some());

    let mut byte = [0u8; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), target.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert_udp_released(server_address).await;
    close_client(client).await;
    drop(target);
}
