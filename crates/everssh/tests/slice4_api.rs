//! API-level Slice 4 qualification of the production route supervisor.
#![allow(clippy::unwrap_used)]

use everssh::admission::{AuthenticatedConnection, ConnectedTarget};
use everssh::association::{AssociationId, ClientHello};
use everssh::bootstrap::BootstrapRecord;
use everssh::identity::EphemeralIdentity;
use everssh::transport::{ClientEndpoint, ClientSession, ServerEndpoint, UdpBindPolicy};
use everssh::{EphemeralClientIdentity, Error, Limits, Phase, Shutdown, StdioBridge, TargetBridge};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const FRAME_BYTES: usize = 513;
const FRAME_COUNT: u64 = 96;

fn frame(index: u64) -> Vec<u8> {
    let mut bytes = vec![0u8; FRAME_BYTES];
    bytes[..8].copy_from_slice(&index.to_be_bytes());
    for (offset, byte) in bytes.iter_mut().enumerate().skip(8) {
        *byte = ((index as usize).wrapping_mul(193).wrapping_add(offset) & 0xff) as u8;
    }
    bytes
}

fn limits() -> Limits {
    Limits {
        server_lease_ms: 5_000,
        handshake_timeout_ms: 3_000,
        idle_timeout_ms: 8_000,
        stall_timeout_ms: 3_000,
        drain_timeout_ms: 1_000,
        finalize_timeout_ms: 3_000,
        route_poll_ms: 100,
        route_observation_timeout_ms: 80,
        ..Limits::default()
    }
}

fn netns_limits() -> Limits {
    Limits {
        server_lease_ms: 10_000,
        handshake_timeout_ms: 5_000,
        idle_timeout_ms: 30_000,
        stall_timeout_ms: 20_000,
        drain_timeout_ms: 10_000,
        finalize_timeout_ms: 10_000,
        route_poll_ms: 100,
        route_observation_timeout_ms: 80,
        ..Limits::default()
    }
}

fn selected_non_loopback(probe_peer: SocketAddr) -> std::io::Result<IpAddr> {
    let wildcard = if probe_peer.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    };
    let socket = UdpSocket::bind(wildcard)?;
    socket.connect(probe_peer)?;
    let selected = socket.local_addr()?.ip();
    if selected.is_loopback() || selected.is_unspecified() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "kernel selected no non-loopback source",
        ));
    }
    Ok(selected)
}

fn reserve_udp(ip: IpAddr) -> SocketAddr {
    let socket = UdpSocket::bind(SocketAddr::new(ip, 0)).unwrap();
    socket.local_addr().unwrap()
}

struct Pair {
    client: ClientSession,
    server: tokio::task::JoinHandle<(ConnectedTarget, Vec<u8>, bool)>,
    target: tokio::task::JoinHandle<TcpStream>,
}

async fn establish(ip: IpAddr, expected_frames: u64) -> Pair {
    let target_ip = if ip.is_ipv4() {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        IpAddr::V6(Ipv6Addr::LOCALHOST)
    };
    let listener = TcpListener::bind(SocketAddr::new(target_ip, 0))
        .await
        .unwrap();
    let target_address = listener.local_addr().unwrap();
    let target = tokio::spawn(async move { listener.accept().await.unwrap().0 });

    let identity = EphemeralIdentity::generate().unwrap();
    let token = identity.take_bootstrap_token().unwrap();
    let server_address = reserve_udp(ip);
    let authenticated =
        AuthenticatedConnection::new(SocketAddr::new(ip, 40_001), target_address).unwrap();
    let server = ServerEndpoint::bind(
        authenticated,
        UdpBindPolicy::Explicit(server_address),
        &identity,
        limits(),
    )
    .unwrap();
    let client_identity = EphemeralClientIdentity::generate().unwrap();
    let client = ClientEndpoint::bind(
        server.local_addr(),
        UdpBindPolicy::RouteSelected,
        identity.spki_sha256(),
        &client_identity,
        limits(),
    )
    .unwrap();
    let server = tokio::spawn(async move {
        let admitted = server.accept().await.unwrap();
        let mut connected = admitted.connect_target().await.unwrap();
        let mut received = Vec::with_capacity(FRAME_BYTES * expected_frames as usize);
        let mut complete = true;
        for index in 0..expected_frames {
            let mut bytes = vec![0u8; FRAME_BYTES];
            if connected
                .quic_recv_mut()
                .read_exact(&mut bytes)
                .await
                .is_err()
            {
                complete = false;
                break;
            }
            received.extend_from_slice(&bytes);
            if connected
                .quic_send_mut()
                .write_all(&index.to_be_bytes())
                .await
                .is_err()
            {
                complete = false;
                break;
            }
        }
        let _ = connected.quic_send_mut().finish();
        (connected, received, complete)
    });
    let client = client
        .connect_and_authenticate(&token, target_address.port())
        .await
        .unwrap();
    Pair {
        client,
        server,
        target,
    }
}

async fn assert_udp_released(address: SocketAddr) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        match UdpSocket::bind(address) {
            Ok(socket) => {
                drop(socket);
                return;
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::AddrInUse
                    && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => panic!("UDP socket {address} survived cleanup: {error}"),
        }
    }
}

async fn exercise_port_migration(ip: IpAddr) {
    let mut pair = establish(ip, FRAME_COUNT).await;
    let stable_id = pair.client.stable_id();
    let old_local = pair.client.local_addr().unwrap();
    assert!(pair.client.route_supervisor_snapshot().is_some());
    let fallback_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let snapshot = pair.client.route_supervisor_snapshot().unwrap();
        if snapshot.fallback_observations >= 1 {
            assert_eq!(snapshot.rebinds, 0, "healthy unchanged route rebound");
            break;
        }
        assert!(
            tokio::time::Instant::now() < fallback_deadline,
            "finite fallback polling was not observed: {snapshot:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    for index in 0..FRAME_COUNT / 2 {
        pair.client
            .quic_send_mut()
            .write_all(&frame(index))
            .await
            .unwrap();
    }
    assert!(pair.client.notify_path_failure());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let migrated = loop {
        let snapshot = pair.client.route_supervisor_snapshot().unwrap();
        if snapshot.rebinds == 1 {
            break snapshot;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "same-route replacement did not complete"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    assert_eq!(migrated.same_route_replacements, 1);
    assert_eq!(migrated.stable_id, stable_id);
    assert_eq!(migrated.local_address.ip(), old_local.ip());
    assert_ne!(migrated.local_address.port(), old_local.port());
    assert_eq!(pair.client.stable_id(), stable_id);

    for index in FRAME_COUNT / 2..FRAME_COUNT {
        pair.client
            .quic_send_mut()
            .write_all(&frame(index))
            .await
            .unwrap();
    }
    pair.client.quic_send_mut().finish().unwrap();

    let mut acknowledgements = vec![0u8; FRAME_COUNT as usize * 8];
    pair.client
        .quic_recv_mut()
        .read_exact(&mut acknowledgements)
        .await
        .unwrap();
    for index in 0..FRAME_COUNT {
        assert_eq!(
            &acknowledgements[index as usize * 8..index as usize * 8 + 8],
            &index.to_be_bytes()
        );
    }

    let (connected, received, complete) = pair.server.await.unwrap();
    assert!(complete);
    assert_eq!(received.len(), FRAME_BYTES * FRAME_COUNT as usize);
    for index in 0..FRAME_COUNT {
        let start = index as usize * FRAME_BYTES;
        assert_eq!(&received[start..start + FRAME_BYTES], frame(index));
    }
    assert_eq!(pair.client.stable_id(), stable_id);

    let new_local = migrated.local_address;
    let (server_closed, ()) = tokio::join!(connected.close(), pair.client.close());
    server_closed.unwrap();
    assert_udp_released(old_local).await;
    assert_udp_released(new_local).await;
    let mut target = pair.target.await.unwrap();
    let mut byte = [0u8; 1];
    assert_eq!(target.read(&mut byte).await.unwrap(), 0);
}

fn helper_environment(role: &str) -> Option<(u8, PathBuf)> {
    if std::env::var("EVERSSH_SLICE4_API_ROLE").ok().as_deref() != Some(role) {
        return None;
    }
    let family = std::env::var("EVERSSH_SLICE4_API_FAMILY")
        .expect("missing API helper family")
        .parse::<u8>()
        .expect("invalid API helper family");
    assert!(matches!(family, 4 | 6));
    let directory = PathBuf::from(
        std::env::var_os("EVERSSH_SLICE4_API_DIR").expect("missing API helper directory"),
    );
    Some((family, directory))
}

fn helper_addresses(family: u8) -> (IpAddr, IpAddr, IpAddr, SocketAddr) {
    if family == 4 {
        (
            IpAddr::V4(Ipv4Addr::new(10, 241, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 241, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(10, 241, 1, 2)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 24_004)),
        )
    } else {
        (
            IpAddr::V6("fd42:241::1".parse().unwrap()),
            IpAddr::V6("fd42:241::2".parse().unwrap()),
            IpAddr::V6("fd42:242::2".parse().unwrap()),
            SocketAddr::from((Ipv6Addr::LOCALHOST, 24_006)),
        )
    }
}

fn publish(path: &Path, contents: &str) {
    let temporary = path.with_extension(format!("tmp.{}", std::process::id()));
    fs::write(&temporary, contents).unwrap();
    fs::rename(temporary, path).unwrap();
}

async fn wait_for_file(path: &Path, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    while !path.exists() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

const NETNS_API_FRAME_COUNT: u64 = 400;

/// Root harness helper: a real public-library server in the server namespace.
/// The production-process cases in the same harness remain the qualification
/// path; this companion gives the API assertions access to `stable_id`.
#[tokio::test]
async fn netns_api_server_helper() {
    let Some((family, directory)) = helper_environment("server") else {
        return;
    };
    let (server_ip, old_client_ip, _, target_address) = helper_addresses(family);
    let target_listener = TcpListener::bind(target_address).await.unwrap();
    let target = tokio::spawn(async move {
        let (mut stream, _) = target_listener.accept().await.unwrap();
        let mut received = Vec::new();
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let count = stream.read(&mut buffer).await.unwrap();
            if count == 0 {
                break;
            }
            received.extend_from_slice(&buffer[..count]);
            stream.write_all(&buffer[..count]).await.unwrap();
        }
        received
    });

    let identity = EphemeralIdentity::generate().unwrap();
    let token = identity.take_bootstrap_token().unwrap();
    let server_address = reserve_udp(server_ip);
    let authenticated =
        AuthenticatedConnection::new(SocketAddr::new(old_client_ip, 40_001), target_address)
            .unwrap();
    let server = ServerEndpoint::bind(
        authenticated,
        UdpBindPolicy::Explicit(server_address),
        &identity,
        netns_limits(),
    )
    .unwrap();
    let bootstrap = BootstrapRecord::new(
        server.local_addr().ip(),
        server.local_addr().port(),
        identity.spki_sha256(),
        token,
        AssociationId::from_bytes([0x51; 16]).unwrap(),
        std::process::id(),
    )
    .unwrap();
    publish(&directory.join("bootstrap"), bootstrap.encode().as_str());

    let admitted = server.accept().await.unwrap();
    let connected = admitted.connect_target().await.unwrap();
    let shutdown = Shutdown::new();
    let bridge = TargetBridge::try_new(connected, netns_limits(), shutdown.clone())
        .await
        .unwrap();
    let completion = bridge.run().await;
    assert_eq!(completion.finalize, everssh::FinalizeStatus::Completed);
    assert_eq!(shutdown.phase(), Phase::Finalized);
    let received = target.await.unwrap();
    let mut expected = Vec::new();
    for index in 0..NETNS_API_FRAME_COUNT {
        expected.extend_from_slice(&frame(index));
    }
    assert_eq!(received, expected);
    publish(
        &directory.join("server-report"),
        "frames=400 target_closed=true\n",
    );
}

/// Root harness helper: assert one API connection/stream survives a real
/// IPv4 or IPv6 source-address and output-interface route change.
#[tokio::test]
async fn netns_api_client_helper() {
    let Some((family, directory)) = helper_environment("client") else {
        return;
    };
    let (_, old_client_ip, new_client_ip, target_address) = helper_addresses(family);
    wait_for_file(&directory.join("bootstrap"), Duration::from_secs(5)).await;
    let encoded = fs::read_to_string(directory.join("bootstrap")).unwrap();
    let bootstrap =
        BootstrapRecord::parse(encoded.trim_end_matches('\n'), &netns_limits()).unwrap();
    fs::remove_file(directory.join("bootstrap")).unwrap();
    let endpoint = SocketAddr::new(bootstrap.udp_endpoint, bootstrap.udp_port);
    let client_identity = EphemeralClientIdentity::generate().unwrap();
    let client = ClientEndpoint::bind(
        endpoint,
        UdpBindPolicy::RouteSelected,
        bootstrap.spki_sha256,
        &client_identity,
        netns_limits(),
    )
    .unwrap();
    let mut client = client
        .connect_and_authenticate(bootstrap.token(), target_address.port())
        .await
        .unwrap();
    let stable_id = client.stable_id();
    let old_local = client.local_addr().unwrap();
    assert_eq!(old_local.ip(), old_client_ip);

    for index in 0..16 {
        let expected = frame(index);
        client.quic_send_mut().write_all(&expected).await.unwrap();
        let mut echoed = vec![0u8; expected.len()];
        client
            .quic_recv_mut()
            .read_exact(&mut echoed)
            .await
            .unwrap();
        assert_eq!(echoed, expected);
    }
    publish(&directory.join("old-route-ready"), "ready\n");
    wait_for_file(&directory.join("route-changed"), Duration::from_secs(5)).await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let migrated = loop {
        let snapshot = client.route_supervisor_snapshot().unwrap();
        if snapshot.current_route.source().ip() == new_client_ip
            && snapshot.rebinds == 1
            && snapshot.notification_observations >= 1
            && snapshot.wake_observations >= 1
        {
            break snapshot;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "API source-address migration did not complete: {snapshot:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    assert_eq!(migrated.stable_id, stable_id);
    assert_eq!(migrated.local_address.ip(), new_client_ip);
    assert_ne!(migrated.local_address, old_local);
    assert_eq!(client.stable_id(), stable_id);

    // Keep application bytes opaque while using one round trip per numbered
    // frame. This proves the rebound path is live before adding more stream
    // pressure and avoids treating transport validation as an app protocol.
    for index in 16..NETNS_API_FRAME_COUNT {
        let expected = frame(index);
        client.quic_send_mut().write_all(&expected).await.unwrap();
        let mut echoed = vec![0u8; expected.len()];
        client
            .quic_recv_mut()
            .read_exact(&mut echoed)
            .await
            .unwrap();
        assert_eq!(echoed, expected);
    }
    client.quic_send_mut().finish().unwrap();
    assert_eq!(client.stable_id(), stable_id);
    publish(
        &directory.join("client-report"),
        &format!(
            "stable_id={stable_id} rebinds={} source={} frames=400\n",
            migrated.rebinds, migrated.local_address
        ),
    );
    client.close().await;
}

#[tokio::test]
async fn ipv4_same_connection_and_stream_survive_fresh_source_port() {
    let ip = selected_non_loopback(SocketAddr::from(([192, 0, 2, 1], 9))).unwrap();
    assert!(ip.is_ipv4());
    exercise_port_migration(ip).await;
}

#[tokio::test]
async fn stdio_construction_rollback_cancels_joins_and_releases_supervisor_socket() {
    let ip = selected_non_loopback(SocketAddr::from(([192, 0, 2, 1], 9))).unwrap();
    let pair = establish(ip, 1).await;
    let local_address = pair.client.local_addr().unwrap();
    let shutdown = Shutdown::new();
    let invalid = Limits {
        copy_buf: 0,
        ..limits()
    };
    let result = StdioBridge::try_new(
        pair.client,
        tokio::io::empty(),
        tokio::io::sink(),
        invalid,
        shutdown.clone(),
    )
    .await;
    assert!(matches!(result, Err(Error::InvalidLimits(_))));
    assert_eq!(shutdown.phase(), Phase::Finalized);
    assert_udp_released(local_address).await;

    let (server, received, complete) = pair.server.await.unwrap();
    assert!(!complete);
    assert!(received.is_empty());
    server.close().await.unwrap();
    let mut target = pair.target.await.unwrap();
    let mut byte = [0u8; 1];
    assert_eq!(target.read(&mut byte).await.unwrap(), 0);
}

#[tokio::test]
async fn repeated_same_route_failure_is_bounded_and_fresh_connection_gets_no_replay() {
    let ip = selected_non_loopback(SocketAddr::from(([192, 0, 2, 1], 9))).unwrap();
    let mut lost = establish(ip, 2).await;
    let stable_id = lost.client.stable_id();

    lost.client
        .quic_send_mut()
        .write_all(&frame(0))
        .await
        .unwrap();
    let mut acknowledgement = [0u8; 8];
    lost.client
        .quic_recv_mut()
        .read_exact(&mut acknowledgement)
        .await
        .unwrap();
    assert_eq!(acknowledgement, 0u64.to_be_bytes());

    assert!(lost.client.notify_path_failure());
    let replacement_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        if lost
            .client
            .route_supervisor_snapshot()
            .is_some_and(|snapshot| snapshot.same_route_replacements == 1)
        {
            break;
        }
        assert!(tokio::time::Instant::now() < replacement_deadline);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(lost.client.stable_id(), stable_id);
    assert!(lost.client.notify_path_failure());

    let mut impossible_ack = [0u8; 8];
    let closed = tokio::time::timeout(
        Duration::from_secs(3),
        lost.client.quic_recv_mut().read_exact(&mut impossible_ack),
    )
    .await
    .expect("same-route failure did not terminate boundedly");
    assert!(closed.is_err());
    assert_eq!(lost.client.stable_id(), stable_id);

    let (lost_server, old_bytes, complete) = lost.server.await.unwrap();
    assert!(!complete);
    assert_eq!(old_bytes, frame(0));
    let (server_closed, ()) = tokio::join!(lost_server.close(), lost.client.close());
    server_closed.unwrap();
    let mut old_target = lost.target.await.unwrap();
    let mut byte = [0u8; 1];
    assert_eq!(old_target.read(&mut byte).await.unwrap(), 0);

    // A separate authenticated connection starts with an empty stream. QUIC's
    // old retransmission state is not an application replay source.
    let fresh = establish(ip, 1).await;
    let close_task = tokio::spawn(fresh.client.close());
    let (fresh_server, fresh_bytes, fresh_complete) = fresh.server.await.unwrap();
    assert!(!fresh_complete);
    assert!(
        fresh_bytes.is_empty(),
        "old bytes replayed into a fresh stream"
    );
    let (server_closed, client_closed) = tokio::join!(fresh_server.close(), close_task);
    server_closed.unwrap();
    client_closed.unwrap();
    let mut fresh_target = fresh.target.await.unwrap();
    assert_eq!(fresh_target.read(&mut byte).await.unwrap(), 0);
}

#[tokio::test]
async fn v2_sequential_associations_reuse_one_target_stream() {
    let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let target_address = target_listener.local_addr().unwrap();
    let target_peer = tokio::spawn(async move { target_listener.accept().await.unwrap().0 });
    let server_address = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap();
    let authenticated =
        AuthenticatedConnection::new(SocketAddr::from(([192, 0, 2, 90], 50_001)), target_address)
            .unwrap();
    let identity = EphemeralIdentity::generate().unwrap();
    let token = identity.take_bootstrap_token().unwrap();
    let server = ServerEndpoint::bind(
        authenticated,
        UdpBindPolicy::Explicit(server_address),
        &identity,
        limits(),
    )
    .unwrap();
    let association_id = server.association_id();
    let client_identity = EphemeralClientIdentity::generate().unwrap();
    let first_client = bind_v2_client(
        server.local_addr(),
        identity.spki_sha256(),
        &client_identity,
    )
    .unwrap();

    let initial_hello =
        ClientHello::initial(association_id, 0, token.clone(), target_address.port()).unwrap();
    let initial_server = server.accept_v2_initial();
    let initial_client = first_client.connect_v2_association(initial_hello);
    let (initial, first_client_result) = tokio::join!(initial_server, initial_client);
    let initial = initial.unwrap();
    let (mut first_session, server_hello) = first_client_result.unwrap();
    assert_eq!(server_hello.association_id(), association_id);
    let authorization = initial.connection().authorization();
    let mut target_peer = target_peer.await.unwrap();
    let (mut first_connection, mut persistent_target) = initial.into_parts();
    target_peer.write_all(b"first").await.unwrap();
    let mut first_bytes = [0_u8; 5];
    persistent_target
        .read_exact(&mut first_bytes)
        .await
        .unwrap();
    first_connection
        .quic_send_mut()
        .write_all(&first_bytes)
        .await
        .unwrap();
    first_session
        .quic_recv_mut()
        .read_exact(&mut first_bytes)
        .await
        .unwrap();
    assert_eq!(&first_bytes, b"first");

    let (first_server_closed, ()) = tokio::join!(first_connection.close(), first_session.close());
    first_server_closed.unwrap();

    let foreign_identity = EphemeralClientIdentity::generate().unwrap();
    let foreign_client = bind_v2_client(
        server.local_addr(),
        identity.spki_sha256(),
        &foreign_identity,
    )
    .unwrap();
    let foreign_hello = ClientHello::resume(association_id, 0).unwrap();
    let (foreign_server, foreign_client_result) = tokio::join!(
        server.accept_v2_resume(authorization, 0, 0),
        foreign_client.connect_v2_association(foreign_hello)
    );
    assert!(matches!(foreign_server, Err(Error::AuthRejected)));
    assert!(foreign_client_result.is_err());

    let wrong_id = AssociationId::from_bytes([0x76; 16]).unwrap();
    let wrong_id_client = bind_v2_client(
        server.local_addr(),
        identity.spki_sha256(),
        &client_identity,
    )
    .unwrap();
    let wrong_id_hello = ClientHello::resume(wrong_id, 0).unwrap();
    let (wrong_id_server, wrong_id_client_result) = tokio::join!(
        server.accept_v2_resume(authorization, 0, 0),
        wrong_id_client.connect_v2_association(wrong_id_hello)
    );
    assert!(matches!(wrong_id_server, Err(Error::AuthRejected)));
    assert!(wrong_id_client_result.is_err());

    let reused_token_client = bind_v2_client(
        server.local_addr(),
        identity.spki_sha256(),
        &client_identity,
    )
    .unwrap();
    let reused_token_hello =
        ClientHello::initial(association_id, 0, token, target_address.port()).unwrap();
    let (reused_token_server, reused_token_client_result) = tokio::join!(
        server.accept_v2_initial(),
        reused_token_client.connect_v2_association(reused_token_hello)
    );
    assert!(matches!(reused_token_server, Err(Error::TokenReuse)));
    assert!(reused_token_client_result.is_err());

    let second_client = bind_v2_client(
        server.local_addr(),
        identity.spki_sha256(),
        &client_identity,
    )
    .unwrap();
    let resume_hello = ClientHello::resume(association_id, 0).unwrap();
    let resume_server = server.accept_v2_resume(authorization, 0, 0);
    let resume_client = second_client.connect_v2_association(resume_hello);
    let (second_connection, second_client_result) = tokio::join!(resume_server, resume_client);
    let mut second_connection = second_connection.unwrap();
    let (mut second_session, resume_response) = second_client_result.unwrap();
    assert_eq!(resume_response.association_id(), association_id);

    target_peer.write_all(b"second").await.unwrap();
    let mut second_bytes = [0_u8; 6];
    persistent_target
        .read_exact(&mut second_bytes)
        .await
        .unwrap();
    second_connection
        .quic_send_mut()
        .write_all(&second_bytes)
        .await
        .unwrap();
    second_session
        .quic_recv_mut()
        .read_exact(&mut second_bytes)
        .await
        .unwrap();
    assert_eq!(&second_bytes, b"second");

    let (second_server_closed, ()) =
        tokio::join!(second_connection.close(), second_session.close());
    second_server_closed.unwrap();
    drop(persistent_target);
    let mut end = [0_u8; 1];
    assert_eq!(target_peer.read(&mut end).await.unwrap(), 0);
    server.close().await.unwrap();
}

fn bind_v2_client(
    server: SocketAddr,
    pin: [u8; 32],
    identity: &EphemeralClientIdentity,
) -> Result<ClientEndpoint, Error> {
    for _ in 0..16 {
        let reservation = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        let address = reservation.local_addr()?;
        drop(reservation);
        match ClientEndpoint::bind(
            server,
            UdpBindPolicy::Explicit(address),
            pin,
            identity,
            limits(),
        ) {
            Ok(endpoint) => return Ok(endpoint),
            Err(Error::UdpBind(source)) if source.kind() == std::io::ErrorKind::AddrInUse => {
                continue;
            }
            Err(source) => return Err(source),
        }
    }
    Err(Error::PortRangeExhausted)
}

#[tokio::test]
async fn ipv6_same_connection_and_stream_survive_fresh_source_port_when_supported() {
    let probe = SocketAddr::from((Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888), 9));
    let ip = match selected_non_loopback(probe) {
        Ok(ip) => ip,
        Err(error) => {
            eprintln!("IPv6 route unavailable on this host: {error}");
            return;
        }
    };
    assert!(ip.is_ipv6());
    exercise_port_migration(ip).await;
}
