use everssh::association::AssociationId;
use everssh::bootstrap::SecretToken;
use everudp::wire::ConnectionRole;
use everudp::wire::ALPN;
#[cfg(feature = "stream-floor")]
use everudp::{effective_transport_config_receipt, TransportConfigSide, STREAM_FLOOR_ALPN};
use everudp::{
    ClientAssociation, ClientEndpoint, ClientHello, ClientIdentity, ClientLink, ClientLinkError,
    GatewayAction, GatewayEndpoint, GatewayGeneration, GatewayIdentity, GatewayLifecycle,
    InitialConnectError, InvitationStore, Limits, LockedTransportProfile, QuicAckPolicy,
    ResumePosition, SharedInvitationStore, TransportError,
};
use everudp::{GatewayLink, GatewayReplaySlabs, InputOperation};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[cfg(feature = "datagram-spike")]
use bytes::Bytes;

#[test]
fn reconnect_classification_retries_only_network_reachability_failures() {
    assert!(TransportError::Timeout.is_temporary());
    assert!(TransportError::Connection.is_temporary());
    assert!(TransportError::Stream.is_temporary());
    assert!(
        TransportError::Io(std::io::Error::from(std::io::ErrorKind::NetworkUnreachable))
            .is_temporary()
    );

    assert!(!TransportError::PinMismatch.is_temporary());
    assert!(!TransportError::Rejected.is_temporary());
    assert!(!TransportError::PeerIdentity.is_temporary());
    assert!(!TransportError::Protocol(everudp::WireError::VersionUnsupported(0)).is_temporary());
}

fn association(byte: u8) -> AssociationId {
    AssociationId::from_bytes([byte; 16]).expect("association")
}

fn generation() -> GatewayGeneration {
    GatewayGeneration::from_bytes([3; 16]).expect("generation")
}

fn initial_position() -> ResumePosition {
    ResumePosition {
        input_epoch: 0,
        next_input: 0,
        output_epoch: 0,
        next_output: 0,
        delivered_output_ack: 0,
    }
}

fn shared_store(limits: &Limits) -> SharedInvitationStore {
    Arc::new(Mutex::new(
        InvitationStore::new("work", generation(), limits).expect("store"),
    ))
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

#[cfg(feature = "datagram-spike")]
#[tokio::test(flavor = "current_thread")]
async fn fast_datagram_is_negotiated_flushed_and_received_before_stream_use() {
    let limits = Limits::default();
    let store = shared_store(&limits);
    let gateway_identity = GatewayIdentity::generate().expect("gateway identity");
    let gateway = GatewayEndpoint::bind(loopback(), &gateway_identity, Arc::clone(&store), limits)
        .expect("gateway");
    let client_identity = ClientIdentity::generate().expect("client identity");
    let ticket = store
        .lock()
        .expect("store lock")
        .issue(
            association(19),
            ConnectionRole::Writer,
            client_identity.spki_sha256(),
            everpty::sys::clock_monotonic_ms().expect("clock"),
        )
        .expect("ticket");
    let hello = ClientHello::initial(
        association(19),
        generation(),
        ConnectionRole::Writer,
        initial_position(),
        ticket.token().clone(),
    )
    .expect("hello");
    let client = ClientEndpoint::bind(
        loopback(),
        &client_identity,
        gateway_identity.spki_sha256(),
        limits,
    )
    .expect("client");
    let (admitted, session) = tokio::join!(
        gateway.accept_initial(),
        client.connect_initial(gateway.local_addr(), &hello)
    );
    let (gateway_connection, _, _, _) = admitted.expect("admitted").into_parts();
    let (client_connection, _, _) = session.expect("session").into_parts();
    assert!(client_connection.max_datagram_size().is_some());
    assert!(gateway_connection.max_datagram_size().is_some());

    let before = client_connection.stats().frame_tx.datagram;
    client_connection
        .send_datagram(Bytes::from_static(b"fast"))
        .expect("queue datagram");
    std::future::poll_fn(|context| {
        std::task::Poll::Ready(client_connection.flush_transmit_now(context))
    })
    .await
    .expect("flush datagram");
    let received = tokio::time::timeout(Duration::from_secs(1), gateway_connection.read_datagram())
        .await
        .expect("datagram deadline")
        .expect("read datagram");
    assert_eq!(received.as_ref(), b"fast");
    assert!(client_connection.stats().frame_tx.datagram > before);
    // More than one inline callback budget must drain without another
    // application receive call or a later inbound packet to trigger progress.
    gateway_connection.set_inline_datagram_handler(Some);
    for sequence in 0_u64..32 {
        client_connection
            .send_datagram(Bytes::copy_from_slice(&sequence.to_be_bytes()))
            .expect("queue burst");
    }
    std::future::poll_fn(|context| {
        std::task::Poll::Ready(client_connection.flush_transmit_now(context))
    })
    .await
    .expect("flush burst");
    let mut seen = std::collections::BTreeSet::new();
    tokio::time::timeout(Duration::from_secs(3), async {
        while seen.len() < 32 {
            let echo = client_connection
                .read_datagram()
                .await
                .expect("inline echo");
            let sequence = u64::from_be_bytes(echo.as_ref().try_into().expect("eight bytes"));
            assert!(sequence < 32);
            assert!(seen.insert(sequence), "duplicate echo");
        }
    })
    .await
    .expect("bounded inline handler drains entire burst");
    client_connection.close(0_u32.into(), b"done");
    gateway_connection.close(0_u32.into(), b"done");
}

/// The stream-flush experiment exercises the reliable QUIC path only.  It is
/// deliberately separate from the datagram spike: admission must negotiate no
/// datagrams, while an explicitly flushed uni stream must become observable
/// without waiting for a later runtime yield.
#[cfg(all(feature = "stream-flush-spike", not(feature = "datagram-spike")))]
#[tokio::test(flavor = "current_thread")]
async fn reliable_stream_flush_is_immediate_and_byte_exact() {
    let limits = Limits::default();
    let store = shared_store(&limits);
    let gateway_identity = GatewayIdentity::generate().expect("gateway identity");
    let gateway = GatewayEndpoint::bind(loopback(), &gateway_identity, Arc::clone(&store), limits)
        .expect("gateway");
    let client_identity = ClientIdentity::generate().expect("client identity");
    let ticket = store
        .lock()
        .expect("store lock")
        .issue(
            association(27),
            ConnectionRole::Writer,
            client_identity.spki_sha256(),
            everpty::sys::clock_monotonic_ms().expect("clock"),
        )
        .expect("ticket");
    let hello = ClientHello::initial(
        association(27),
        generation(),
        ConnectionRole::Writer,
        initial_position(),
        ticket.token().clone(),
    )
    .expect("hello");
    let client = ClientEndpoint::bind(
        loopback(),
        &client_identity,
        gateway_identity.spki_sha256(),
        limits,
    )
    .expect("client");
    let (admitted, session) = tokio::join!(
        gateway.accept_initial(),
        client.connect_initial(gateway.local_addr(), &hello)
    );
    let (gateway_connection, _, _, _) = admitted.expect("admitted").into_parts();
    let (client_connection, _, _) = session.expect("session").into_parts();

    // This feature must not silently turn the reliable test into a datagram
    // test or alter the locked transport profile.
    assert!(client_connection.max_datagram_size().is_none());
    assert!(gateway_connection.max_datagram_size().is_none());

    let mut send = client_connection.open_uni().await.expect("open uni");
    let payload = b"reliable stream flush\0exact bytes";
    assert_eq!(
        send.write(payload).await.expect("queue stream bytes"),
        payload.len()
    );
    let before = client_connection.stats().frame_tx.stream;
    std::future::poll_fn(|context| {
        std::task::Poll::Ready(client_connection.flush_transmit_now(context))
    })
    .await
    .expect("flush reliable stream");
    assert!(
        client_connection.stats().frame_tx.stream > before,
        "immediate flush did not emit a stream frame"
    );
    let mut received = gateway_connection
        .accept_uni()
        .await
        .expect("accept uni stream");
    #[cfg(feature = "stream-pump-spike")]
    {
        let mut initial = vec![0; payload.len()];
        received
            .read_exact(&mut initial)
            .await
            .expect("initial payload");
        assert_eq!(initial, payload);
        tokio::time::timeout(Duration::from_secs(20), async {
            // Exercise the ordinary driver's keepalive timer with no application
            // flushes. This is longer than the locked 10-second keepalive period.
            let client_pings = client_connection.stats().frame_tx.ping;
            let gateway_pings = gateway_connection.stats().frame_tx.ping;
            tokio::time::sleep(Duration::from_secs(12)).await;
            assert!(
                client_connection.stats().frame_tx.ping > client_pings
                    || gateway_connection.stats().frame_tx.ping > gateway_pings
            );
            let mut reply = gateway_connection.open_uni().await.expect("reply stream");
            let writer = async {
                for sequence in 0_u64..256 {
                    send.write_all(&sequence.to_be_bytes())
                        .await
                        .expect("request");
                    std::future::poll_fn(|cx| {
                        std::task::Poll::Ready(client_connection.flush_transmit_now(cx))
                    })
                    .await
                    .expect("request flush");
                }
                send.finish().expect("request finish");
            };
            let echo = async {
                for sequence in 0_u64..256 {
                    let mut bytes = [0; 8];
                    received.read_exact(&mut bytes).await.expect("request read");
                    assert_eq!(bytes, sequence.to_be_bytes());
                    reply.write_all(&bytes).await.expect("reply");
                    std::future::poll_fn(|cx| {
                        std::task::Poll::Ready(gateway_connection.flush_transmit_now(cx))
                    })
                    .await
                    .expect("reply flush");
                }
                assert!(received
                    .read(&mut [0])
                    .await
                    .expect("request eof")
                    .is_none());
                reply.finish().expect("reply finish");
            };
            let reader = async {
                let mut response = client_connection
                    .accept_uni()
                    .await
                    .expect("response stream");
                for sequence in 0_u64..256 {
                    let mut bytes = [0; 8];
                    response
                        .read_exact(&mut bytes)
                        .await
                        .expect("response read");
                    assert_eq!(bytes, sequence.to_be_bytes());
                }
                assert!(response
                    .read(&mut [0])
                    .await
                    .expect("response eof")
                    .is_none());
            };
            tokio::join!(writer, echo, reader);
        })
        .await
        .expect("combined stream scheduling deadline");
    }
    #[cfg(not(feature = "stream-pump-spike"))]
    {
        send.finish().expect("finish stream");
        let bytes =
            tokio::time::timeout(Duration::from_secs(1), received.read_to_end(payload.len()))
                .await
                .expect("stream receive deadline")
                .expect("read stream");
        assert_eq!(bytes, payload);
    }
    client_connection.close(0_u32.into(), b"done");
    gateway_connection.close(0_u32.into(), b"done");
}

#[tokio::test(flavor = "current_thread")]
async fn initial_budget_is_one_deadline_and_only_pre_connection_timeout_is_fallback_safe() {
    let limits = Limits::default();
    let client_identity = ClientIdentity::generate().expect("client identity");
    let hello = ClientHello::initial(
        association(9),
        generation(),
        ConnectionRole::Writer,
        initial_position(),
        SecretToken::from_bytes([9; 32]),
    )
    .expect("hello");

    // A live UDP socket that never responds gives a deterministic pre-QUIC
    // black hole. No application record can have reached a gateway, so the
    // dedicated fallback classification is safe.
    let blackhole = UdpSocket::bind(loopback()).expect("blackhole socket");
    let blackhole_address = blackhole.local_addr().expect("blackhole address");
    let blackhole_client =
        ClientEndpoint::bind(loopback(), &client_identity, [0x44; 32], limits).expect("client");
    let error = match blackhole_client
        .connect_initial_until(
            blackhole_address,
            &hello,
            tokio::time::Instant::now() + Duration::from_millis(80),
        )
        .await
    {
        Ok(session) => {
            session.close();
            panic!("black hole unexpectedly completed a QUIC connection");
        }
        Err(error) => error,
    };
    assert!(matches!(
        error,
        InitialConnectError::Unavailable(TransportError::Timeout)
    ));
    assert!(error.fallback_safe());

    // Once TLS completes and CLIENT_HELLO is written, deliberately withhold
    // SERVER_HELLO. The second phase consumes the remainder of the same
    // absolute budget and cannot be classified as safe for SSH fallback.
    let store = shared_store(&limits);
    let gateway_identity = GatewayIdentity::generate().expect("gateway identity");
    let gateway = GatewayEndpoint::bind(loopback(), &gateway_identity, Arc::clone(&store), limits)
        .expect("gateway");
    let ticket = store
        .lock()
        .expect("store lock")
        .issue(
            association(9),
            ConnectionRole::Writer,
            client_identity.spki_sha256(),
            everpty::sys::clock_monotonic_ms().expect("clock"),
        )
        .expect("invitation");
    let hello = ClientHello::initial(
        association(9),
        generation(),
        ConnectionRole::Writer,
        initial_position(),
        ticket.token().clone(),
    )
    .expect("hello");
    let client = ClientEndpoint::bind(
        loopback(),
        &client_identity,
        gateway_identity.spki_sha256(),
        limits,
    )
    .expect("client");
    let started = tokio::time::Instant::now();
    let deadline = started + Duration::from_millis(250);
    let (admitted, session) = tokio::join!(
        gateway.accept_initial(),
        client.connect_initial_until(gateway.local_addr(), &hello, deadline)
    );
    let admitted = admitted.expect("gateway accepted CLIENT_HELLO");
    let session = session.expect("initial transport completed within budget");
    let association =
        ClientAssociation::new(association(9), generation(), ConnectionRole::Writer, limits)
            .expect("association");
    let error = ClientLink::finish_initial_until(session, association, limits, deadline)
        .await
        .expect_err("withheld SERVER_HELLO must consume the remaining budget");
    assert!(matches!(error, ClientLinkError::Timeout));
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(200), "elapsed={elapsed:?}");
    assert!(elapsed < Duration::from_millis(750), "elapsed={elapsed:?}");
    admitted.close();
}

#[test]
fn transport_profile_is_frozen_and_datagrams_match_the_build_contract() {
    let profile = LockedTransportProfile::for_limits(&Limits::default()).expect("profile");
    assert_eq!(profile.alpn, ALPN);
    assert!(profile.tls13_only);
    assert!(profile.client_certificate_required);
    assert!(profile.retry_required);
    assert!(profile.standard_migration);
    assert!(profile.mtu_discovery);
    assert!(!profile.resumption);
    assert!(!profile.early_data);
    assert_eq!(profile.datagrams, cfg!(feature = "datagram-spike"));
    assert!(!profile.multipath);
    assert!(!profile.nat_traversal);
    assert_eq!(profile.server_incoming_bidi, 1);
    assert_eq!(profile.server_incoming_uni, 1);
    assert_eq!(profile.client_incoming_bidi, 0);
    assert_eq!(profile.client_incoming_uni, 1);
    assert_eq!(profile.keepalive_ms, 10_000);
    assert_eq!(profile.idle_timeout_ms, 30_000);
    assert_eq!(profile.initial_mtu, 1_200);
    assert_eq!(profile.initial_rtt_ms, 100);
    assert_eq!(
        profile.ack_policy,
        if cfg!(feature = "datagram-spike") {
            QuicAckPolicy::Disabled
        } else if cfg!(feature = "quic-ack-threshold-spike") {
            QuicAckPolicy::EveryOtherPacket1ms
        } else if cfg!(feature = "quic-ack-coalescing-spike") {
            QuicAckPolicy::EveryOtherPacket5ms
        } else {
            QuicAckPolicy::EveryPacket1ms
        }
    );
    assert_eq!(profile.control_stream_priority, 2);
    assert_eq!(profile.input_stream_priority, 1);
    assert_eq!(profile.output_stream_priority, 0);
    assert!(profile.segmentation_offload);
}

#[cfg(feature = "stream-floor")]
#[test]
fn stream_floor_profile_is_independent_and_effective_receipt_is_stream_only() {
    let limits = Limits::default();
    let profile = LockedTransportProfile::for_stream_floor(&limits).expect("stream profile");
    assert_eq!(profile.alpn, STREAM_FLOOR_ALPN);
    assert!(!profile.datagrams);
    assert_eq!(profile.ack_policy, QuicAckPolicy::EveryPacket1ms);
    assert_eq!(profile.server_incoming_bidi, 1);
    assert_eq!(profile.server_incoming_uni, 1);
    assert_eq!(profile.client_incoming_bidi, 0);
    assert_eq!(profile.client_incoming_uni, 1);

    for side in [TransportConfigSide::Server, TransportConfigSide::Client] {
        let receipt = effective_transport_config_receipt(side, &limits, &profile)
            .expect("effective stream receipt");
        assert_eq!(receipt.alpn, STREAM_FLOOR_ALPN);
        assert!(!receipt.datagrams);
        assert_eq!(receipt.datagram_receive_buffer, None);
        assert_eq!(receipt.datagram_send_buffer, 0);
        assert_eq!(receipt.ack_policy, QuicAckPolicy::EveryPacket1ms);
        assert!(receipt.segmentation_offload);
    }
}

#[cfg(feature = "reliable-datagram-spike")]
#[tokio::test(flavor = "current_thread")]
async fn floor_profile_is_explicit_and_does_not_change_stream_endpoints() {
    let limits = Limits::default();
    let identity = GatewayIdentity::generate().expect("identity");
    let ordinary = GatewayEndpoint::bind(loopback(), &identity, shared_store(&limits), limits)
        .expect("ordinary endpoint");
    let floor =
        GatewayEndpoint::bind_datagram_floor(loopback(), &identity, shared_store(&limits), limits)
            .expect("floor endpoint");
    assert_eq!(ordinary.profile().alpn, everudp::wire::ALPN);
    assert_eq!(ordinary.profile().server_incoming_uni, 1);
    assert_eq!(ordinary.profile().client_incoming_uni, 1);
    assert_eq!(floor.profile().alpn, everudp::reliable_datagram::ALPN);
    assert_eq!(floor.profile().server_incoming_uni, 0);
    assert_eq!(floor.profile().client_incoming_uni, 0);
    assert!(floor.profile().datagrams);
}

#[cfg(feature = "tuning")]
#[test]
fn development_matrix_is_exact_and_records_the_preregistered_default() {
    use everudp::DevelopmentTransportTuning;
    use std::collections::BTreeSet;

    let matrix = DevelopmentTransportTuning::matrix();
    assert_eq!(matrix.len(), 18);
    let unique = matrix
        .iter()
        .map(|profile| {
            (
                profile.initial_rtt_ms(),
                profile.ack_policy() as u8,
                profile.segmentation_offload(),
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(unique.len(), 18);
    assert!(matrix.contains(&DevelopmentTransportTuning::PREREGISTERED_DEFAULT));
    assert!(DevelopmentTransportTuning::new(24, QuicAckPolicy::Disabled, false).is_none());
    assert!(
        DevelopmentTransportTuning::new(100, QuicAckPolicy::EveryOtherPacket1ms, true).is_none()
    );

    let production = LockedTransportProfile::for_limits(&Limits::default()).expect("profile");
    assert_eq!(production.initial_rtt_ms, 100);
    assert_eq!(
        production.ack_policy,
        if cfg!(feature = "datagram-spike") {
            QuicAckPolicy::Disabled
        } else if cfg!(feature = "quic-ack-threshold-spike") {
            QuicAckPolicy::EveryOtherPacket1ms
        } else if cfg!(feature = "quic-ack-coalescing-spike") {
            QuicAckPolicy::EveryOtherPacket5ms
        } else {
            QuicAckPolicy::EveryPacket1ms
        }
    );
    assert!(production.segmentation_offload);
}

#[cfg(feature = "tuning")]
#[tokio::test(flavor = "current_thread")]
async fn development_profile_reaches_both_noq_endpoints() {
    use everudp::DevelopmentTransportTuning;

    let limits = Limits::default();
    let tuning = DevelopmentTransportTuning::new(333, QuicAckPolicy::EveryOtherPacket5ms, true)
        .expect("matrix member");
    let store = shared_store(&limits);
    let gateway_identity = GatewayIdentity::generate().expect("gateway identity");
    let gateway = GatewayEndpoint::bind_for_development_tuning(
        loopback(),
        &gateway_identity,
        store,
        limits,
        tuning,
    )
    .expect("gateway");
    let client_identity = ClientIdentity::generate().expect("client identity");
    let client = ClientEndpoint::bind_for_development_tuning(
        loopback(),
        &client_identity,
        gateway_identity.spki_sha256(),
        limits,
        tuning,
    )
    .expect("client");

    for profile in [gateway.profile(), client.profile()] {
        assert_eq!(profile.initial_rtt_ms, 333);
        assert_eq!(
            profile.ack_policy,
            if cfg!(feature = "datagram-spike") {
                QuicAckPolicy::Disabled
            } else {
                QuicAckPolicy::EveryOtherPacket5ms
            }
        );
        assert!(profile.segmentation_offload);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn pinned_mutual_tls_claims_once_and_gateway_accepts_sequential_connections() {
    let limits = Limits::default();
    let store = shared_store(&limits);
    let gateway_identity = GatewayIdentity::generate().expect("gateway identity");
    let gateway = GatewayEndpoint::bind(loopback(), &gateway_identity, Arc::clone(&store), limits)
        .expect("gateway");
    let mut lifecycle = GatewayLifecycle::new(&limits).expect("lifecycle");

    for byte in 1..=2 {
        let client_identity = ClientIdentity::generate().expect("client identity");
        let ticket = store
            .lock()
            .expect("store lock")
            .issue_with_takeover(
                association(byte),
                ConnectionRole::Writer,
                client_identity.spki_sha256(),
                byte == 2,
                everpty::sys::clock_monotonic_ms().expect("clock"),
            )
            .expect("invitation");
        let hello = ClientHello::initial(
            association(byte),
            generation(),
            ConnectionRole::Writer,
            initial_position(),
            ticket.token().clone(),
        )
        .expect("hello");
        let client = ClientEndpoint::bind(
            loopback(),
            &client_identity,
            gateway_identity.spki_sha256(),
            limits,
        )
        .expect("client");

        let (server_result, client_result) = tokio::join!(
            gateway.accept_initial(),
            client.connect_initial(gateway.local_addr(), &hello)
        );
        let admitted = server_result.expect("admitted");
        let session = client_result.expect("connected");
        assert_eq!(admitted.hello(), &hello);
        assert_eq!(admitted.client_spki_sha256(), client_identity.spki_sha256());
        assert_eq!(admitted.take_over(), byte == 2);
        assert!(admitted.address_was_validated());
        if byte == 1 {
            assert_eq!(
                lifecycle
                    .admit(&admitted, false)
                    .expect("authenticated writer"),
                GatewayAction::CommitEverptyWriter
            );
        } else {
            assert_eq!(
                lifecycle
                    .admit(&admitted, admitted.take_over())
                    .expect("authenticated takeover"),
                GatewayAction::TransferWriter {
                    previous: association(1),
                    replacement: association(2),
                }
            );
        }
        admitted.close();
        session.close();
    }
}

#[tokio::test(flavor = "current_thread")]
async fn wrong_pin_fails_before_application_admission() {
    let limits = Limits::default();
    let store = shared_store(&limits);
    let gateway_identity = GatewayIdentity::generate().expect("gateway identity");
    let gateway = GatewayEndpoint::bind(loopback(), &gateway_identity, Arc::clone(&store), limits)
        .expect("gateway");
    let client_identity = ClientIdentity::generate().expect("client identity");
    let client =
        ClientEndpoint::bind(loopback(), &client_identity, [0x55; 32], limits).expect("client");
    let hello = ClientHello::initial(
        association(1),
        generation(),
        ConnectionRole::Writer,
        initial_position(),
        SecretToken::from_bytes([7; 32]),
    )
    .expect("hello");
    let (server, client) = tokio::join!(
        gateway.accept_initial(),
        client.connect_initial(gateway.local_addr(), &hello)
    );
    assert!(matches!(
        server,
        Err(TransportError::Connection | TransportError::Timeout)
    ));
    assert!(matches!(client, Err(TransportError::PinMismatch)));
}

#[tokio::test(flavor = "current_thread")]
async fn wrong_token_and_client_key_fail_without_consuming_the_invitation() {
    let limits = Limits::default();
    let store = shared_store(&limits);
    let gateway_identity = GatewayIdentity::generate().expect("gateway identity");
    let gateway = GatewayEndpoint::bind(loopback(), &gateway_identity, Arc::clone(&store), limits)
        .expect("gateway");
    let bound_identity = ClientIdentity::generate().expect("bound identity");
    let ticket = store
        .lock()
        .expect("store lock")
        .issue(
            association(1),
            ConnectionRole::Writer,
            bound_identity.spki_sha256(),
            everpty::sys::clock_monotonic_ms().expect("clock"),
        )
        .expect("invitation");

    let wrong_token = ClientHello::initial(
        association(1),
        generation(),
        ConnectionRole::Writer,
        initial_position(),
        SecretToken::from_bytes([0x44; 32]),
    )
    .expect("hello");
    let wrong_key_identity = ClientIdentity::generate().expect("wrong identity");
    let wrong_key_client = ClientEndpoint::bind(
        loopback(),
        &wrong_key_identity,
        gateway_identity.spki_sha256(),
        limits,
    )
    .expect("client");
    let (server, client) = tokio::join!(
        gateway.accept_initial(),
        wrong_key_client.connect_initial(gateway.local_addr(), &wrong_token)
    );
    assert!(matches!(server, Err(TransportError::Admission(_))));
    client.expect("TLS and write complete").close();

    let correct = ClientHello::initial(
        association(1),
        generation(),
        ConnectionRole::Writer,
        initial_position(),
        ticket.token().clone(),
    )
    .expect("hello");
    let correct_client = ClientEndpoint::bind(
        loopback(),
        &bound_identity,
        gateway_identity.spki_sha256(),
        limits,
    )
    .expect("client");
    let (server, client) = tokio::join!(
        gateway.accept_initial(),
        correct_client.connect_initial(gateway.local_addr(), &correct)
    );
    server.expect("invitation remained live").close();
    client.expect("client").close();
}

#[tokio::test(flavor = "current_thread")]
async fn live_noq_connection_survives_a_client_udp_rebind() {
    let limits = Limits::default();
    let store = shared_store(&limits);
    let gateway_identity = GatewayIdentity::generate().expect("gateway identity");
    let gateway = GatewayEndpoint::bind(loopback(), &gateway_identity, Arc::clone(&store), limits)
        .expect("gateway");
    let client_identity = ClientIdentity::generate().expect("client identity");
    let ticket = store
        .lock()
        .expect("store lock")
        .issue(
            association(7),
            ConnectionRole::Writer,
            client_identity.spki_sha256(),
            everpty::sys::clock_monotonic_ms().expect("clock"),
        )
        .expect("ticket");
    let hello = ClientHello::initial(
        association(7),
        generation(),
        ConnectionRole::Writer,
        initial_position(),
        ticket.token().clone(),
    )
    .expect("hello");
    let client = ClientEndpoint::bind(
        loopback(),
        &client_identity,
        gateway_identity.spki_sha256(),
        limits,
    )
    .expect("client");
    let (admitted, session) = tokio::join!(
        gateway.accept_initial(),
        client.connect_initial(gateway.local_addr(), &hello)
    );
    let admitted = admitted.expect("admitted");
    let session = session.expect("session");
    let old_address = client.local_addr().expect("old address");
    let new_address = client
        .rebind(UdpSocket::bind(loopback()).expect("replacement socket"))
        .expect("endpoint rebind");
    assert_ne!(old_address, new_address);

    let mut lifecycle = GatewayLifecycle::new(&limits).expect("lifecycle");
    let mut slabs = GatewayReplaySlabs::new(&limits).expect("slabs");
    let association =
        ClientAssociation::new(association(7), generation(), ConnectionRole::Writer, limits)
            .expect("association");
    let (server, peer) = tokio::join!(
        GatewayLink::accept_initial(admitted, &mut lifecycle, &mut slabs, limits),
        ClientLink::finish_initial(session, association, limits)
    );
    let (mut server, _) = server.expect("gateway link after rebind");
    let mut peer = peer.expect("client link after rebind");
    peer.association_mut()
        .queue_input(b"after-rebind")
        .expect("queue input");
    peer.flush_input().await.expect("send after rebind");
    server
        .receive_input(&mut slabs, |operation| {
            assert_eq!(operation, InputOperation::Bytes(b"after-rebind"));
            Ok(())
        })
        .await
        .expect("receive after rebind");
    server.close();
    peer.close();
}
