//! Local socket integration only; not admission, reliability or latency gates.
#![cfg(feature = "floor-single-owner")]

use bytes::Bytes;
use everpty::sys::{poll, PollFd, PollFlags};
use everudp::floor_admission::{AdmissionPoll, ServerAdmission};
use everudp::floor_client_admission::ClientAdmission;
use everudp::floor_pump::{FloorLimits, FloorPump};
use everudp::floor_reactor::{FloorReactor, StepEdge, StepPhase, StepWork};
use everudp::floor_socket::FloorSocket;
use everudp::transport::{floor_client_config, floor_server_config};
use everudp::{ClientIdentity, GatewayIdentity, Limits};
use noq_proto::{EndpointConfig, Event};
use std::net::UdpSocket;
use std::os::fd::AsFd;
use std::time::Instant;

#[test]
fn real_udp_tls_and_packet_batch_cross_the_single_owner_reactor() {
    let limits = Limits::default();
    let server_identity = GatewayIdentity::generate().expect("server identity");
    let client_identity = ClientIdentity::generate().expect("client identity");
    let make_socket = || {
        FloorSocket::new(
            UdpSocket::bind("127.0.0.1:0").expect("loopback bind"),
            &EndpointConfig::default(),
        )
        .expect("socket state")
    };
    let server_socket = make_socket();
    let server_addr = server_socket.local_addr().expect("server address");
    let server_pump = FloorPump::server_with_mtud(
        EndpointConfig::default(),
        floor_server_config(&server_identity, &limits).expect("server config"),
        FloorLimits::default(),
        !server_socket.may_fragment(),
    );
    let client_socket = make_socket();
    let mut client_pump = FloorPump::client_with_mtud(
        EndpointConfig::default(),
        FloorLimits::default(),
        !client_socket.may_fragment(),
    );
    let (config, mismatch) =
        floor_client_config(&client_identity, server_identity.spki_sha256(), &limits)
            .expect("pinned client config");
    let client_handle = client_pump
        .connect(config, server_addr, "localhost", Instant::now())
        .expect("client connection");
    let mut client = FloorReactor::new(client_pump, client_socket);
    let mut server = FloorReactor::new(server_pump, server_socket);
    let generation = everudp::GatewayGeneration::from_bytes([2; 16]).expect("generation");
    let association =
        everssh::association::AssociationId::from_bytes([1; 16]).expect("association");
    let mut invitations =
        everudp::InvitationStore::new("floor", generation, &limits).expect("store");
    let ticket = invitations
        .issue(
            association,
            everudp::wire::ConnectionRole::Writer,
            client_identity.spki_sha256(),
            0,
        )
        .expect("invitation");
    let hello = everudp::ClientHello::initial(
        association,
        generation,
        everudp::wire::ConnectionRole::Writer,
        everudp::ResumePosition {
            input_epoch: 0,
            next_input: 0,
            output_epoch: 0,
            next_output: 0,
            delivered_output_ack: 0,
        },
        ticket.token().clone(),
    )
    .expect("hello");
    let deadline = Instant::now() + std::time::Duration::from_secs(3);
    let mut client_admission =
        ClientAdmission::new(&hello, &limits, deadline).expect("client admission");
    let mut server_admission = ServerAdmission::new(limits, deadline).expect("server admission");
    let mut client_ready = false;
    let mut server_ready = false;
    let mut client_connected = false;
    let mut server_handle = None;
    let mut sent = false;
    let mut received = Vec::new();
    let mut client_work = StepWork::default();
    let mut server_work = StepWork::default();
    let mut client_saw_send = false;
    let mut server_saw_receive = false;
    for _ in 0..1000 {
        let mut edges = Vec::new();
        client
            .step_observed_with_hook(Instant::now(), &mut client_work, |phase, edge| {
                edges.push((phase, edge));
            })
            .expect("client turn");
        assert_eq!(edges.len() % 2, 0);
        for pair in edges.chunks_exact(2) {
            assert_eq!(pair[0].1, StepEdge::Begin);
            assert_eq!(pair[1], (pair[0].0, StepEdge::End));
        }
        for (phase, expected) in [
            (StepPhase::PumpDrive, client_work.pump_drive_calls),
            (StepPhase::Send, client_work.send_attempts),
            (StepPhase::Receive, client_work.receive_calls),
        ] {
            assert_eq!(
                edges
                    .iter()
                    .filter(|item| **item == (phase, StepEdge::Begin))
                    .count() as u64,
                expected
            );
        }
        server
            .step_observed(Instant::now(), &mut server_work)
            .expect("server turn");
        client_saw_send |= client_work.send_accepted > 0;
        server_saw_receive |= server_work.receive_datagrams > 0;
        while let Some((_, event)) = client.pump_mut().poll_event() {
            match event {
                Event::Connected => client_connected = true,
                Event::ConnectionLost { reason } => panic!("client lost: {reason}"),
                _ => {}
            }
        }
        while let Some((handle, event)) = server.pump_mut().poll_event() {
            match event {
                Event::Connected => server_handle = Some(handle),
                Event::ConnectionLost { reason } => panic!("server lost: {reason}"),
                _ => {}
            }
        }
        if client_connected && !client_ready {
            client_ready = matches!(
                client_admission
                    .poll(
                        client
                            .pump_mut()
                            .connection_mut(client_handle)
                            .expect("client live"),
                        Instant::now()
                    )
                    .expect("client negotiation"),
                AdmissionPoll::Ready { .. }
            );
        }
        if let Some(handle) = server_handle {
            if !server_ready {
                server_ready = matches!(
                    server_admission
                        .poll(
                            server
                                .pump_mut()
                                .connection_mut(handle)
                                .expect("server live"),
                            &mut invitations,
                            Instant::now(),
                            1
                        )
                        .expect("server negotiation"),
                    AdmissionPoll::Ready { .. }
                );
            }
        }
        if client_ready && server_ready && !sent {
            let connection = client
                .pump_mut()
                .connection_mut(client_handle)
                .expect("client live");
            for byte in 0_u8..32 {
                connection
                    .datagrams()
                    .send(Bytes::copy_from_slice(&[byte]), false)
                    .expect("queue packet");
            }
            sent = true;
        }
        if let Some(handle) = server_handle {
            let connection = server
                .pump_mut()
                .connection_mut(handle)
                .expect("server live");
            while let Some(packet) = connection.datagrams().recv() {
                assert!(client_ready && server_ready, "data before admission");
                assert_eq!(packet.len(), 1);
                received.push(packet[0]);
            }
        }
        if received.len() >= 32 {
            break;
        }
        let mut fds = [
            PollFd::new(client.socket().as_fd(), PollFlags::POLLIN),
            PollFd::new(server.socket().as_fd(), PollFlags::POLLIN),
        ];
        poll(&mut fds, Some(1)).expect("bounded poll");
    }
    assert!(client_connected && server_handle.is_some());
    assert!(!mismatch.observed());
    received.sort_unstable();
    assert_eq!(received, (0_u8..32).collect::<Vec<_>>());
    assert!(client_saw_send, "observed client counters missed traffic");
    assert!(
        server_saw_receive,
        "observed server counters missed traffic"
    );
}

#[test]
fn saturated_receive_yields_and_retained_batch_is_drained_before_idle() {
    let socket = FloorSocket::new(
        UdpSocket::bind("127.0.0.1:0").expect("bind"),
        &EndpointConfig::default(),
    )
    .expect("socket state");
    let address = socket.local_addr().expect("address");
    let pump = FloorPump::client(EndpointConfig::default(), FloorLimits::default());
    let mut reactor = FloorReactor::new(pump, socket);
    let sender = UdpSocket::bind("127.0.0.1:0").expect("sender");
    for _ in 0..80 {
        sender
            .send_to(&[0], address)
            .expect("invalid protocol fixture packet");
    }
    let first = reactor.step(Instant::now()).expect("first bounded turn");
    assert!(first.work <= 64);
    assert!(
        first.exhausted,
        "saturated receive must return before becoming idle"
    );
    let mut became_idle = false;
    for _ in 0..10 {
        let next = reactor.step(Instant::now()).expect("drain retained batch");
        assert!(next.work <= 64);
        assert!(!next.write_blocked);
        if !next.exhausted {
            became_idle = true;
            break;
        }
    }
    assert!(became_idle, "idle must be distinct from budget exhaustion");
}

#[test]
fn observed_idle_turn_counts_would_block_and_matches_normal_outcome() {
    let socket = FloorSocket::new(
        UdpSocket::bind("127.0.0.1:0").expect("bind"),
        &EndpointConfig::default(),
    )
    .expect("socket state");
    let pump = FloorPump::client(EndpointConfig::default(), FloorLimits::default());
    let mut observed = FloorReactor::new(pump, socket);
    let mut counters = StepWork::default();
    let observed_result = observed
        .step_observed(Instant::now(), &mut counters)
        .expect("observed idle turn");
    assert!(!counters.overflow);
    assert_eq!(counters.pump_drive_calls, 1);
    assert_eq!(counters.receive_calls, 1);
    assert_eq!(counters.receive_would_block, 1);
    assert_eq!(counters.receive_batches, 0);
    assert_eq!(counters.receive_datagrams, 0);
    assert_eq!(counters.send_attempts, 0);
    assert_eq!(counters.retained_gro_segments_delivered, 0);

    let normal_socket = FloorSocket::new(
        UdpSocket::bind("127.0.0.1:0").expect("bind"),
        &EndpointConfig::default(),
    )
    .expect("socket state");
    let normal_pump = FloorPump::client(EndpointConfig::default(), FloorLimits::default());
    let mut normal = FloorReactor::new(normal_pump, normal_socket);
    let normal_result = normal.step(Instant::now()).expect("normal idle turn");
    assert_eq!(observed_result.exhausted, normal_result.exhausted);
    assert_eq!(observed_result.write_blocked, normal_result.write_blocked);
}

#[test]
fn observed_hook_has_balanced_ordered_edges_and_matches_idle_counters() {
    let socket = FloorSocket::new(
        UdpSocket::bind("127.0.0.1:0").expect("bind"),
        &EndpointConfig::default(),
    )
    .expect("socket state");
    let pump = FloorPump::client(EndpointConfig::default(), FloorLimits::default());
    let mut reactor = FloorReactor::new(pump, socket);
    let mut work = StepWork::default();
    let mut edges = Vec::new();
    let result = reactor
        .step_observed_with_hook(Instant::now(), &mut work, |phase, edge| {
            edges.push((phase, edge));
        })
        .expect("idle reactor turn");
    assert!(!result.write_blocked);
    assert!(!work.overflow);
    assert_eq!(edges.len() % 2, 0);
    for pair in edges.chunks_exact(2) {
        assert_eq!(pair[0].1, StepEdge::Begin);
        assert_eq!(pair[1].1, StepEdge::End);
        assert_eq!(pair[0].0, pair[1].0);
    }
    let count = |phase| {
        edges
            .iter()
            .filter(|(item, edge)| *item == phase && *edge == StepEdge::Begin)
            .count() as u64
    };
    assert_eq!(count(StepPhase::PumpDrive), work.pump_drive_calls);
    assert_eq!(count(StepPhase::Receive), work.receive_calls);
    assert_eq!(count(StepPhase::Send), work.send_attempts);
    assert_eq!(count(StepPhase::Segment), 1);
}
