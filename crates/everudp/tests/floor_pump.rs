//! Deterministic protocol-owner checks, not performance or product qualification.
#![cfg(feature = "floor-single-owner")]

use bytes::BytesMut;
use everudp::floor_pump::{FloorLimits, FloorPump, PumpWork};
use everudp::transport::{floor_client_config, floor_server_config};
use everudp::{ClientIdentity, GatewayIdentity, Limits};
use noq_proto::{ConnectionHandle, EndpointConfig, Event, FourTuple};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

type Events = Vec<(ConnectionHandle, Event)>;

#[test]
fn client_admission_rejects_wrong_reply_truncation_and_timeout() {
    use everudp::floor_admission::{AdmissionPoll, SERVER_CAPABILITY};
    use everudp::floor_client_admission::ClientAdmission;
    let hello = everudp::ClientHello::initial(
        everssh::association::AssociationId::from_bytes([1; 16]).expect("association"),
        everudp::GatewayGeneration::from_bytes([2; 16]).expect("generation"),
        everudp::wire::ConnectionRole::Writer,
        everudp::ResumePosition {
            input_epoch: 0,
            next_input: 0,
            output_epoch: 0,
            next_output: 0,
            delivered_output_ack: 0,
        },
        everssh::bootstrap::SecretToken::from_bytes([3; 32]),
    )
    .expect("hello");
    for mode in ["wrong", "truncated", "timeout"] {
        let mut pair = Pair::new(false);
        let mut client_admission = ClientAdmission::new(
            &hello,
            &Limits::default(),
            pair.now + Duration::from_secs(1),
        )
        .expect("client admission");
        if mode == "timeout" {
            let conn = pair.client.connection_mut(pair.client_id).expect("client");
            assert!(client_admission
                .poll(conn, pair.now + Duration::from_secs(1))
                .is_err());
            assert!(client_admission.poll(conn, pair.now).is_err());
            continue;
        }
        let mut server_handle = None;
        let mut replied = false;
        let mut rejected = false;
        for _ in 0..100 {
            for (handle, event) in pair.tick().1 {
                if matches!(event, Event::Connected) {
                    server_handle = Some(handle);
                }
            }
            let result = client_admission.poll(
                pair.client.connection_mut(pair.client_id).expect("client"),
                pair.now,
            );
            assert!(!matches!(result, Ok(AdmissionPoll::Ready { .. })));
            if result.is_err() {
                rejected = true;
                break;
            }
            if let Some(handle) = server_handle {
                let server = pair.server.connection_mut(handle).expect("server");
                if !replied {
                    if let Some(stream) = server.streams().accept(noq_proto::Dir::Bi) {
                        let mut bytes = SERVER_CAPABILITY.to_vec();
                        if mode == "wrong" {
                            bytes[0] ^= 1;
                        } else {
                            bytes.pop();
                        }
                        assert_eq!(
                            server.send_stream(stream).write(&bytes).expect("reply"),
                            bytes.len()
                        );
                        if mode == "truncated" {
                            server.send_stream(stream).finish().expect("FIN");
                        }
                        replied = true;
                    }
                }
            }
        }
        assert!(replied && rejected, "{mode}");
        assert!(client_admission
            .poll(
                pair.client.connection_mut(pair.client_id).expect("client"),
                pair.now
            )
            .is_err());
    }
}

#[test]
fn server_admission_requires_capability_and_enforces_deadline() {
    use everudp::floor_admission::{
        AdmissionPoll, ServerAdmission, CLIENT_CAPABILITY, SERVER_CAPABILITY,
    };
    use everudp::floor_control_writer::ControlWriter;
    use everudp::wire::ConnectionRole;
    use everudp::{ClientHello, GatewayGeneration, InvitationStore, ResumePosition};
    for mode in ["valid", "bad-capability", "deadline"] {
        let mut pair = Pair::new(false);
        let mut server_handle = None;
        for _ in 0..100 {
            for (handle, event) in pair.tick().1 {
                if matches!(event, Event::Connected) {
                    server_handle = Some(handle);
                }
            }
            if server_handle.is_some() {
                break;
            }
        }
        let server_handle = server_handle.expect("TLS connected");
        let limits = Limits::default();
        let generation = GatewayGeneration::from_bytes([2; 16]).expect("generation");
        let association =
            everssh::association::AssociationId::from_bytes([1; 16]).expect("association");
        let mut store = InvitationStore::new("floor", generation, &limits).expect("invitations");
        let ticket = store
            .issue(
                association,
                ConnectionRole::Writer,
                pair.client_identity.spki_sha256(),
                0,
            )
            .expect("ticket");
        let hello = ClientHello::initial(
            association,
            generation,
            ConnectionRole::Writer,
            ResumePosition {
                input_epoch: 0,
                next_input: 0,
                output_epoch: 0,
                next_output: 0,
                delivered_output_ack: 0,
            },
            ticket.token().clone(),
        )
        .expect("hello");
        let mut admission =
            ServerAdmission::new(limits, pair.now + Duration::from_millis(100)).expect("admission");
        if mode == "deadline" {
            let server = pair.server.connection_mut(server_handle).expect("server");
            assert!(admission
                .poll(server, &mut store, pair.now + Duration::from_millis(100), 1)
                .is_err());
            assert!(
                admission.poll(server, &mut store, pair.now, 1).is_err(),
                "failure latches"
            );
            assert!(admission.admitted_hello().is_none());
            continue;
        }
        let client = pair.client.connection_mut(pair.client_id).expect("client");
        let stream = client.streams().open(noq_proto::Dir::Bi).expect("control");
        assert!(
            ControlWriter::hello(&hello, &Limits::default())
                .expect("writer")
                .write_stream(client, stream)
                .expect("hello write")
                .complete
        );
        let mut capability = CLIENT_CAPABILITY;
        if mode == "bad-capability" {
            capability[7] ^= 1;
        }
        assert!(
            ControlWriter::from_bytes(&capability)
                .expect("capability writer")
                .write_stream(client, stream)
                .expect("capability write")
                .complete
        );
        let mut finished = false;
        for _ in 0..50 {
            assert!(admission.admitted_hello().is_none());
            pair.tick();
            let server = pair.server.connection_mut(server_handle).expect("server");
            match admission.poll(server, &mut store, pair.now, 1) {
                Ok(AdmissionPoll::Ready { stream: admitted }) => {
                    assert_eq!(mode, "valid");
                    assert_eq!(admitted, stream);
                    assert_eq!(admission.admitted_hello(), Some(&hello));
                    finished = true;
                    break;
                }
                Err(_) => {
                    assert_eq!(mode, "bad-capability");
                    assert!(admission.admitted_hello().is_none());
                    finished = true;
                    break;
                }
                Ok(AdmissionPoll::Pending { .. }) => {}
            }
        }
        assert!(finished, "admission must reach a terminal decision");
        if mode == "valid" {
            for _ in 0..10 {
                pair.tick();
            }
            let mut recv = pair
                .client
                .connection_mut(pair.client_id)
                .expect("client")
                .recv_stream(stream);
            let mut chunks = recv.read(true).expect("reply stream");
            let reply = chunks.next(8).expect("reply read").expect("reply bytes");
            assert_eq!(reply.bytes.as_ref(), SERVER_CAPABILITY);
            let _ = chunks.finalize();
            let server = pair.server.connection_mut(server_handle).expect("server");
            server.close(
                pair.now,
                noq_proto::VarInt::from_u32(1),
                bytes::Bytes::new(),
            );
            assert!(
                admission.poll(server, &mut store, pair.now, 1).is_err(),
                "closed connection must revoke admission readiness"
            );
            assert!(admission.admitted_hello().is_none());
            assert!(admission.poll(server, &mut store, pair.now, 1).is_err());
        }
    }
}

#[test]
fn stream_hello_reader_preserves_capability_and_rejects_truncated_fin() {
    use everudp::floor_control::HelloReader;
    use everudp::wire::{encode_record, ConnectionRole, Kind, StreamRole, HEADER_LEN};
    use everudp::{ClientHello, GatewayGeneration, ResumePosition};
    let hello = ClientHello::initial(
        everssh::association::AssociationId::from_bytes([1; 16]).expect("association"),
        GatewayGeneration::from_bytes([2; 16]).expect("generation"),
        ConnectionRole::Writer,
        ResumePosition {
            input_epoch: 0,
            next_input: 0,
            output_epoch: 0,
            next_output: 0,
            delivered_output_ack: 0,
        },
        everssh::bootstrap::SecretToken::from_bytes([3; 32]),
    )
    .expect("hello");
    let mut payload = [0; ClientHello::MAX_ENCODED_LEN];
    let used = hello.encode_into(&mut payload).expect("encode hello");
    let mut wire = vec![0; HEADER_LEN + used];
    encode_record(
        StreamRole::Control,
        Kind::ClientHello,
        0,
        &payload[..used],
        &Limits::default(),
        &mut wire,
    )
    .expect("encode record");
    for truncated in [false, true] {
        let mut pair = Pair::new(false);
        let mut server_handle = None;
        for _ in 0..100 {
            for (handle, event) in pair.tick().1 {
                if matches!(event, Event::Connected) {
                    server_handle = Some(handle);
                }
            }
            if server_handle.is_some() {
                break;
            }
        }
        let server_handle = server_handle.expect("server connected");
        let client = pair.client.connection_mut(pair.client_id).expect("client");
        let stream = client
            .streams()
            .open(noq_proto::Dir::Bi)
            .expect("control stream");
        if truncated {
            let mut bytes = wire.clone();
            bytes.pop();
            assert_eq!(
                client.send_stream(stream).write(&bytes).expect("write"),
                bytes.len()
            );
            client.send_stream(stream).finish().expect("FIN");
        } else {
            use everudp::floor_control_writer::ControlWriter;
            let mut writer =
                ControlWriter::hello(&hello, &Limits::default()).expect("hello writer");
            assert!(
                writer
                    .write_stream(client, stream)
                    .expect("hello write")
                    .complete
            );
            let mut capability =
                ControlWriter::from_bytes(b"capability").expect("capability writer");
            assert!(
                capability
                    .write_stream(client, stream)
                    .expect("capability write")
                    .complete
            );
        }
        let mut accepted = None;
        for _ in 0..100 {
            pair.tick();
            accepted = pair
                .server
                .connection_mut(server_handle)
                .expect("server")
                .streams()
                .accept(noq_proto::Dir::Bi);
            if accepted.is_some() {
                break;
            }
        }
        let stream = accepted.expect("incoming control");
        let server = pair.server.connection_mut(server_handle).expect("server");
        let mut reader = HelloReader::new(Limits::default()).expect("reader");
        let first = reader.read_stream(server, stream).expect("header chunk");
        assert!(first.progressed && first.hello.is_none());
        let second = reader.read_stream(server, stream).expect("payload chunk");
        if truncated {
            assert!(second.hello.is_none());
            assert!(reader.read_stream(server, stream).is_err(), "truncated FIN");
        } else {
            assert_eq!(second.hello, Some(hello.clone()));
            let mut recv = server.recv_stream(stream);
            let mut chunks = recv.read(true).expect("read remaining");
            let capability = chunks
                .next(10)
                .expect("capability read")
                .expect("capability chunk");
            assert_eq!(capability.bytes.as_ref(), b"capability");
            let _ = chunks.finalize(); // Fixture ends before another transmit turn.
        }
    }
}

#[test]
fn floor_admission_binds_tls_identity_and_one_use_invitation() {
    use everssh::association::AssociationId;
    use everudp::admission::AdmissionError;
    use everudp::transport::floor_authorize_initial;
    use everudp::wire::ConnectionRole;
    use everudp::{
        ClientHello, GatewayGeneration, InvitationStore, ResumePosition, TransportError,
    };

    for mismatch in ["none", "key", "generation", "role", "association", "expiry"] {
        let mut pair = Pair::new(false);
        let mut server_handle = None;
        for _ in 0..100 {
            for (handle, event) in pair.tick().1 {
                if matches!(event, Event::Connected) {
                    server_handle = Some(handle);
                }
            }
            if server_handle.is_some() {
                break;
            }
        }
        let limits = Limits::default();
        let association = AssociationId::from_bytes([1; 16]).expect("association");
        let generation = GatewayGeneration::from_bytes([2; 16]).expect("generation");
        let mut store = InvitationStore::new("floor", generation, &limits).expect("store");
        let key = if mismatch == "key" {
            [0; 32]
        } else {
            pair.client_identity.spki_sha256()
        };
        let ticket = store
            .issue(association, ConnectionRole::Writer, key, 0)
            .expect("invitation");
        let hello = ClientHello::initial(
            if mismatch == "association" {
                AssociationId::from_bytes([3; 16]).expect("other association")
            } else {
                association
            },
            if mismatch == "generation" {
                GatewayGeneration::from_bytes([3; 16]).expect("other generation")
            } else {
                generation
            },
            if mismatch == "role" {
                ConnectionRole::Observer
            } else {
                ConnectionRole::Writer
            },
            ResumePosition {
                input_epoch: 0,
                next_input: 0,
                output_epoch: 0,
                next_output: 0,
                delivered_output_ack: 0,
            },
            ticket.token().clone(),
        )
        .expect("initial hello");
        let connection = pair
            .server
            .connection_mut(server_handle.expect("TLS connected"))
            .expect("server connection");
        let now = if mismatch == "expiry" {
            limits.invitation_lifetime_ms
        } else {
            1
        };
        let result = floor_authorize_initial(connection, &hello, &mut store, now);
        if mismatch == "none" {
            assert!(!result.expect("valid admission"));
            assert!(matches!(
                floor_authorize_initial(connection, &hello, &mut store, now),
                Err(TransportError::Admission(AdmissionError::TokenReuse))
            ));
        } else if mismatch == "expiry" {
            assert!(matches!(
                result,
                Err(TransportError::Admission(AdmissionError::InvitationExpired))
            ));
        } else {
            assert!(
                matches!(
                    result,
                    Err(TransportError::Admission(AdmissionError::BindingMismatch))
                ),
                "{mismatch}"
            );
        }
    }
}

fn transfer(from: &mut FloorPump, to: &mut FloorPump, address: SocketAddr, now: Instant) {
    let Some(pending) = from.pending_transmit() else {
        return;
    };
    let meta = pending.transmit();
    let destination = meta.destination;
    let ecn = meta.ecn;
    let bytes = pending.bytes().to_vec();
    // This fixture uses one-segment drive(), not a GSO benchmark.
    assert!(meta.segment_size.is_none() || meta.segment_size == Some(bytes.len()));
    from.confirm_transmit(bytes.len())
        .expect("floor test fixture succeeds");
    to.receive(
        FourTuple::new(address, Some(destination.ip())),
        ecn,
        BytesMut::from(bytes.as_slice()),
        now,
    )
    .expect("floor test fixture succeeds");
}

struct Pair {
    client: FloorPump,
    server: FloorPump,
    client_id: ConnectionHandle,
    client_identity: ClientIdentity,
    mismatch: everssh::pinning::PinMismatchState,
    now: Instant,
}

impl Pair {
    fn new(wrong_pin: bool) -> Self {
        let server_identity = GatewayIdentity::generate().expect("floor test fixture succeeds");
        let client_identity = ClientIdentity::generate().expect("floor test fixture succeeds");
        let limits = Limits::default();
        let server = FloorPump::server(
            EndpointConfig::default(),
            floor_server_config(&server_identity, &limits).expect("floor test fixture succeeds"),
            FloorLimits::default(),
        );
        let mut client = FloorPump::client(EndpointConfig::default(), FloorLimits::default());
        let pin = if wrong_pin {
            [0; 32]
        } else {
            server_identity.spki_sha256()
        };
        let (config, mismatch) = floor_client_config(&client_identity, pin, &limits)
            .expect("floor test fixture succeeds");
        let now = Instant::now();
        let client_id = client
            .connect(
                config,
                "127.0.0.1:4444"
                    .parse()
                    .expect("floor test fixture succeeds"),
                "localhost",
                now,
            )
            .expect("floor test fixture succeeds");
        Self {
            client,
            server,
            client_id,
            client_identity,
            mismatch,
            now,
        }
    }

    fn tick(&mut self) -> (Events, Events) {
        self.now += Duration::from_millis(1);
        self.client
            .drive(self.now)
            .expect("floor test fixture succeeds");
        self.server
            .drive(self.now)
            .expect("floor test fixture succeeds");
        // Drain each direction independently before servicing new transmit work.
        transfer(
            &mut self.client,
            &mut self.server,
            "127.0.0.1:5555"
                .parse()
                .expect("floor test fixture succeeds"),
            self.now,
        );
        transfer(
            &mut self.server,
            &mut self.client,
            "127.0.0.1:4444"
                .parse()
                .expect("floor test fixture succeeds"),
            self.now,
        );
        let mut client = Vec::new();
        let mut server = Vec::new();
        while let Some(event) = self.client.poll_event() {
            client.push(event);
        }
        while let Some(event) = self.server.poll_event() {
            server.push(event);
        }
        (client, server)
    }
}

#[test]
fn retry_and_mutual_tls_complete_without_runtime_drivers() {
    let mut pair = Pair::new(false);
    // The first Initial only earns a Retry, not a server association.
    pair.client
        .drive(pair.now)
        .expect("floor test fixture succeeds");
    transfer(
        &mut pair.client,
        &mut pair.server,
        "127.0.0.1:5555"
            .parse()
            .expect("floor test fixture succeeds"),
        pair.now,
    );
    assert_eq!(pair.server.connection_count(), 0);
    assert!(pair.server.pending_transmit().is_some());
    let mut client_connected = false;
    let mut server_connected = None;
    for _ in 0..1000 {
        let (client, server) = pair.tick();
        client_connected |= client.iter().any(|(_, e)| matches!(e, Event::Connected));
        for (handle, event) in server {
            if matches!(event, Event::Connected) {
                server_connected = Some(handle);
            }
        }
        if client_connected && server_connected.is_some() {
            break;
        }
    }
    assert!(client_connected);
    let connection = pair
        .server
        .connection_mut(server_connected.expect("server TLS connected"))
        .expect("floor test fixture succeeds");
    let peer = connection
        .crypto_session()
        .peer_identity()
        .expect("floor test fixture succeeds")
        .downcast::<Vec<noq::rustls::pki_types::CertificateDer<'static>>>()
        .expect("floor test fixture succeeds");
    assert_eq!(peer[0], *pair.client_identity.certificate_der());
    assert!(connection.crypto_session().early_crypto().is_none());
    assert!(!pair.mismatch.observed());
    assert!(pair.client.connection_mut(pair.client_id).is_some());
    // TLS alone is not an invitation/association admission receipt.
}

#[test]
fn wrong_server_pin_never_reports_client_connected() {
    let mut pair = Pair::new(true);
    let mut rejected = false;
    for _ in 0..1000 {
        let (client, _) = pair.tick();
        for (_, event) in client {
            assert!(!matches!(event, Event::Connected));
            rejected |= matches!(event, Event::ConnectionLost { .. });
        }
        if rejected {
            break;
        }
    }
    assert!(rejected, "pin rejection must reach the application");
    assert!(pair.mismatch.observed());
}

#[test]
fn drained_connections_release_the_single_slot() {
    let mut pair = Pair::new(false);
    for _ in 0..100 {
        pair.tick();
    }
    pair.client
        .connection_mut(pair.client_id)
        .expect("client connection")
        .close(
            pair.now,
            noq_proto::VarInt::from_u32(0),
            bytes::Bytes::new(),
        );
    for _ in 0..2000 {
        pair.tick();
        if pair.client.connection_count() == 0 && pair.server.connection_count() == 0 {
            break;
        }
    }
    assert_eq!(
        pair.client.connection_count(),
        0,
        "drained client slot leaked"
    );
    assert_eq!(
        pair.server.connection_count(),
        0,
        "drained server slot leaked"
    );
}

#[test]
fn blocked_send_does_not_hide_terminal_timeout() {
    let mut pair = Pair::new(false);
    pair.client.drive(pair.now).expect("generate initial");
    let original = pair
        .client
        .pending_transmit()
        .expect("pending initial")
        .bytes()
        .to_vec();
    pair.now += Duration::from_secs(31);
    pair.client
        .drive(pair.now)
        .expect("service deadline with blocked socket");
    let mut timed_out = false;
    while let Some((_, event)) = pair.client.poll_event() {
        timed_out |= matches!(
            event,
            Event::ConnectionLost {
                reason: noq_proto::ConnectionError::TimedOut
            }
        );
    }
    assert!(timed_out, "blocked send hid the terminal timeout");
    assert_eq!(
        pair.client
            .pending_transmit()
            .expect("retained initial")
            .bytes(),
        original
    );
}

#[test]
fn old_generation_work_prevents_connection_handle_reuse() {
    let mut pair = Pair::new(false);
    pair.client.drive(pair.now).expect("initial packet");
    pair.now += Duration::from_secs(31);
    pair.client.drive(pair.now).expect("terminal timeout");
    assert_eq!(pair.client.connection_count(), 0);
    let configure = || {
        floor_client_config(&pair.client_identity, [0; 32], &Limits::default())
            .expect("client configuration")
            .0
    };
    let address = "127.0.0.1:4444".parse().expect("literal address");
    assert!(
        pair.client
            .connect(configure(), address, "localhost", pair.now)
            .is_err(),
        "old pending bytes/events must block handle reuse"
    );
    let size = pair
        .client
        .pending_transmit()
        .expect("old packet")
        .bytes()
        .len();
    pair.client
        .confirm_transmit(size)
        .expect("discarded by test sink");
    assert!(
        pair.client
            .connect(configure(), address, "localhost", pair.now)
            .is_err(),
        "old application events must block handle reuse"
    );
    while pair.client.poll_event().is_some() {}
    assert!(
        pair.client
            .connect(configure(), address, "localhost", pair.now)
            .is_ok(),
        "fully retired generation permits a new connection"
    );
}

#[test]
fn observed_initial_drive_preserves_normal_pending_transmit_result() {
    let mut observed = Pair::new(false);
    let mut counters = PumpWork::default();
    observed
        .client
        .drive_observed(observed.now, &mut counters)
        .expect("observed drive");
    assert!(!counters.overflow);
    assert_eq!(counters.deferred_receives, 0);
    assert_eq!(counters.deferred_receives_queued, 0);
    assert_eq!(counters.connections_retired, 0);

    let mut normal = Pair::new(false);
    normal.client.drive(normal.now).expect("normal drive");
    assert_eq!(
        observed.client.pending_transmit().is_some(),
        normal.client.pending_transmit().is_some()
    );
    assert_eq!(
        observed.client.connection_count(),
        normal.client.connection_count()
    );
}
