use everssh::association::AssociationId;
use everudp::wire::{ConnectionRole, Kind};
use everudp::{
    AdmissionError, ClientAssociation, ClientControlReceipt, ClientEndpoint, ClientHello,
    ClientIdentity, ClientInputFlush, ClientLink, ClientOutputReceipt, ControlDisposition,
    ControlReceipt, GatewayAction, GatewayAssociation, GatewayEndpoint, GatewayGeneration,
    GatewayIdentity, GatewayLifecycle, GatewayLink, GatewayReplaySlabs, InputOperation,
    InputReceipt, InvitationStore, Limits, OutputFlush, OutputOperation, OutputPush,
    ReconnectEvent, ReconnectState, RecoveryAction, ResumePosition, TransportError,
};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn association() -> AssociationId {
    AssociationId::from_bytes([51; 16]).expect("association")
}

fn generation() -> GatewayGeneration {
    GatewayGeneration::from_bytes([52; 16]).expect("generation")
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
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

fn deterministic_bytes(length: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    let mut bytes = Vec::with_capacity(length);
    for _ in 0..length {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        bytes.push(state as u8);
    }
    bytes
}

#[tokio::test(flavor = "current_thread")]
async fn sequential_connection_replays_only_unacknowledged_terminal_operations() {
    tokio::time::timeout(Duration::from_secs(8), async {
        let limits = Limits::default();
        let store = Arc::new(Mutex::new(
            InvitationStore::new("work", generation(), &limits).expect("store"),
        ));
        let gateway_identity = GatewayIdentity::generate().expect("gateway identity");
        let gateway =
            GatewayEndpoint::bind(loopback(), &gateway_identity, Arc::clone(&store), limits)
                .expect("gateway");
        let client_identity = ClientIdentity::generate().expect("client identity");
        let ticket = store
            .lock()
            .expect("store lock")
            .issue(
                association(),
                ConnectionRole::Writer,
                client_identity.spki_sha256(),
                everpty::sys::clock_monotonic_ms().expect("clock"),
            )
            .expect("ticket");
        let initial = ClientHello::initial(
            association(),
            generation(),
            ConnectionRole::Writer,
            initial_position(),
            ticket.token().clone(),
        )
        .expect("initial hello");
        let client = ClientEndpoint::bind(
            loopback(),
            &client_identity,
            gateway_identity.spki_sha256(),
            limits,
        )
        .expect("client endpoint");
        let (admitted, session) = tokio::join!(
            gateway.accept_initial(),
            client.connect_initial(gateway.local_addr(), &initial)
        );
        let admitted = admitted.expect("initial admission");
        let session = session.expect("initial session");
        let mut lifecycle = GatewayLifecycle::new(&limits).expect("lifecycle");
        let mut slabs = GatewayReplaySlabs::new(&limits).expect("slabs");
        let client_association =
            ClientAssociation::new(association(), generation(), ConnectionRole::Writer, limits)
                .expect("client association");
        let (server_link, client_link) = tokio::join!(
            GatewayLink::accept_initial(admitted, &mut lifecycle, &mut slabs, limits),
            ClientLink::finish_initial(session, client_association, limits)
        );
        let (mut server_link, action) = server_link.expect("initial gateway link");
        assert_eq!(action, GatewayAction::CommitEverptyWriter);
        let mut client_link = client_link.expect("initial client link");

        client_link
            .association_mut()
            .queue_input(b"acknowledged-input")
            .expect("queue first input");
        assert_eq!(
            client_link.flush_input().await.expect("send first input"),
            ClientInputFlush::Sent { records: 1 }
        );
        assert!(matches!(
            server_link
                .receive_input(&mut slabs, |operation| {
                    assert_eq!(operation, InputOperation::Bytes(b"acknowledged-input"));
                    Ok(())
                })
                .await
                .expect("receive first input"),
            InputReceipt::Delivered {
                acknowledgement: 1,
                ..
            }
        ));
        server_link
            .flush_control(&mut slabs)
            .await
            .expect("send input ACK");
        assert!(matches!(
            client_link
                .receive_control()
                .await
                .expect("receive input ACK"),
            ClientControlReceipt::InputAck(everudp::wire::Ack {
                next_expected: 1,
                ..
            })
        ));

        slabs
            .push_output(Kind::Output, b"acknowledged-output")
            .expect("queue first output");
        server_link
            .flush_output(&slabs)
            .await
            .expect("send first output");
        assert!(matches!(
            client_link
                .receive_output(|operation| {
                    assert_eq!(operation, OutputOperation::Bytes(b"acknowledged-output"));
                    Ok(())
                })
                .await
                .expect("receive first output"),
            ClientOutputReceipt::Delivered {
                acknowledgement: 1,
                ..
            }
        ));
        // Leave this output ACK queued locally. The resume hello must retire
        // it at the gateway even though connection one never carried it.

        client_link
            .association_mut()
            .queue_input(b"replayed-input")
            .expect("queue replay input");
        client_link
            .flush_input()
            .await
            .expect("send stranded input");
        slabs
            .push_output(Kind::Output, b"replayed-output")
            .expect("queue replay output");
        server_link
            .flush_output(&slabs)
            .await
            .expect("send stranded output");

        let authorization = server_link.association().authorization();
        let server_association = server_link.into_resumable_association();
        let client_association = client_link.into_resumable_association();
        let remote = gateway.local_addr();
        let server_resume = async {
            let admitted = gateway
                .accept_resume(authorization)
                .await
                .expect("resume admission");
            GatewayLink::accept_resume(
                admitted,
                server_association,
                &mut lifecycle,
                &mut slabs,
                limits,
            )
            .await
        };
        let (_cancel_tx, mut cancel) = tokio::sync::watch::channel(false);
        let mut events = Vec::new();
        let client_resume = everudp::reconnect_until(
            ReconnectState::new(client, remote, client_association, 0x1234),
            limits,
            &mut cancel,
            |_| async { Ok(RecoveryAction::Unchanged) },
            |event| events.push(event),
        );
        let (server_link, client_link) = tokio::join!(server_resume, client_resume);
        let (mut server_link, action) = server_link.expect("resumed gateway link");
        assert_eq!(action, GatewayAction::WriterResumed);
        let mut client_link = client_link.expect("resumed client link").link;
        assert_eq!(
            events,
            [
                ReconnectEvent::Waiting {
                    attempt: 0,
                    delay: Duration::ZERO,
                },
                ReconnectEvent::Attempt { attempt: 0 },
                ReconnectEvent::Connected,
            ]
        );
        assert_eq!(
            slabs.writer_output().unacknowledged_operations(),
            1,
            "the resume position retires only output already accepted by stdout"
        );

        assert_eq!(
            client_link.flush_input().await.expect("replay input"),
            ClientInputFlush::Sent { records: 1 }
        );
        let mut replayed_input = 0usize;
        assert!(matches!(
            server_link
                .receive_input(&mut slabs, |operation| {
                    assert_eq!(operation, InputOperation::Bytes(b"replayed-input"));
                    replayed_input += 1;
                    Ok(())
                })
                .await
                .expect("receive replayed input"),
            InputReceipt::Delivered {
                acknowledgement: 2,
                ..
            }
        ));
        assert_eq!(replayed_input, 1);
        server_link
            .flush_control(&mut slabs)
            .await
            .expect("send replay input ACK");
        assert!(matches!(
            client_link
                .receive_control()
                .await
                .expect("receive replay input ACK"),
            ClientControlReceipt::InputAck(everudp::wire::Ack {
                next_expected: 2,
                ..
            })
        ));

        assert_eq!(
            server_link
                .flush_output(&slabs)
                .await
                .expect("replay output"),
            OutputFlush::Sent { records: 1 }
        );
        let mut replayed_output = 0usize;
        assert!(matches!(
            client_link
                .receive_output(|operation| {
                    assert_eq!(operation, OutputOperation::Bytes(b"replayed-output"));
                    replayed_output += 1;
                    Ok(())
                })
                .await
                .expect("receive replayed output"),
            ClientOutputReceipt::Delivered {
                acknowledgement: 2,
                ..
            }
        ));
        assert_eq!(replayed_output, 1);
        client_link
            .flush_control()
            .await
            .expect("send replay output ACK");
        assert!(matches!(
            server_link
                .receive_control(&mut slabs)
                .await
                .expect("receive cumulative replay output ACK"),
            ControlReceipt::OutputAck {
                acknowledgement: everudp::wire::Ack {
                    next_expected: 2,
                    ..
                },
                disposition: ControlDisposition::Applied,
            }
        ));
        assert_eq!(slabs.writer_output().unacknowledged_operations(), 0);
        server_link.close();
        client_link.close();
    })
    .await
    .expect("resume test deadline");
}

#[tokio::test(flavor = "current_thread")]
async fn ten_mib_is_byte_identical_across_five_forced_reconnects() {
    tokio::time::timeout(Duration::from_secs(60), async {
        const BYTE_COUNT: usize = 10 * 1024 * 1024;
        const CHUNK_BYTES: usize = 16 * 1024;
        const FORCED_RECONNECTS: usize = 5;

        let limits = Limits::default();
        let store = Arc::new(Mutex::new(
            InvitationStore::new("byte-identity", generation(), &limits).expect("store"),
        ));
        let gateway_identity = GatewayIdentity::generate().expect("gateway identity");
        let gateway =
            GatewayEndpoint::bind(loopback(), &gateway_identity, Arc::clone(&store), limits)
                .expect("gateway");
        let client_identity = ClientIdentity::generate().expect("client identity");
        let ticket = store
            .lock()
            .expect("store lock")
            .issue(
                association(),
                ConnectionRole::Writer,
                client_identity.spki_sha256(),
                everpty::sys::clock_monotonic_ms().expect("clock"),
            )
            .expect("ticket");
        let initial = ClientHello::initial(
            association(),
            generation(),
            ConnectionRole::Writer,
            initial_position(),
            ticket.token().clone(),
        )
        .expect("initial hello");
        let client = ClientEndpoint::bind(
            loopback(),
            &client_identity,
            gateway_identity.spki_sha256(),
            limits,
        )
        .expect("client endpoint");
        let remote = gateway.local_addr();
        let (admitted, session) = tokio::join!(
            gateway.accept_initial(),
            client.connect_initial(remote, &initial)
        );
        let mut lifecycle = GatewayLifecycle::new(&limits).expect("lifecycle");
        let mut slabs = GatewayReplaySlabs::new(&limits).expect("slabs");
        let client_association =
            ClientAssociation::new(association(), generation(), ConnectionRole::Writer, limits)
                .expect("client association");
        let (server_link, client_link) = tokio::join!(
            GatewayLink::accept_initial(
                admitted.expect("initial admission"),
                &mut lifecycle,
                &mut slabs,
                limits,
            ),
            ClientLink::finish_initial(
                session.expect("initial session"),
                client_association,
                limits,
            )
        );
        let (mut server_link, action) = server_link.expect("initial gateway link");
        assert_eq!(action, GatewayAction::CommitEverptyWriter);
        let mut client_link = client_link.expect("initial client link");
        let authorization = server_link.association().authorization();

        let client_input = deterministic_bytes(BYTE_COUNT, 0x5f37_59df_a711_44cd);
        let gateway_output = deterministic_bytes(BYTE_COUNT, 0x94d0_49bb_1331_11eb);
        let mut gateway_received = Vec::with_capacity(BYTE_COUNT);
        let mut client_received = Vec::with_capacity(BYTE_COUNT);
        let total_chunks = BYTE_COUNT.div_ceil(CHUNK_BYTES);
        let chunks_per_connection = total_chunks / (FORCED_RECONNECTS + 1);
        let mut reconnects = 0usize;

        for (index, (input, output)) in client_input
            .chunks(CHUNK_BYTES)
            .zip(gateway_output.chunks(CHUNK_BYTES))
            .enumerate()
        {
            client_link
                .association_mut()
                .queue_input(input)
                .expect("queue input chunk");
            assert_eq!(
                client_link.flush_input().await.expect("flush input chunk"),
                ClientInputFlush::Sent { records: 1 }
            );
            assert!(matches!(
                server_link
                    .receive_input(&mut slabs, |operation| {
                        let InputOperation::Bytes(bytes) = operation else {
                            panic!("byte-identity stream carried a non-byte input operation");
                        };
                        gateway_received.extend_from_slice(bytes);
                        Ok(())
                    })
                    .await
                    .expect("receive input chunk"),
                InputReceipt::Delivered { .. }
            ));
            server_link
                .flush_control(&mut slabs)
                .await
                .expect("flush input acknowledgement");
            assert!(matches!(
                client_link
                    .receive_control()
                    .await
                    .expect("receive input acknowledgement"),
                ClientControlReceipt::InputAck(_)
            ));

            slabs
                .push_output(Kind::Output, output)
                .expect("queue output chunk");
            assert_eq!(
                server_link
                    .flush_output(&slabs)
                    .await
                    .expect("flush output chunk"),
                OutputFlush::Sent { records: 1 }
            );
            assert!(matches!(
                client_link
                    .receive_output(|operation| {
                        let OutputOperation::Bytes(bytes) = operation else {
                            panic!("byte-identity stream carried a non-byte output operation");
                        };
                        client_received.extend_from_slice(bytes);
                        Ok(())
                    })
                    .await
                    .expect("receive output chunk"),
                ClientOutputReceipt::Delivered { .. }
            ));
            client_link
                .flush_control()
                .await
                .expect("flush output acknowledgement");
            assert!(matches!(
                server_link
                    .receive_control(&mut slabs)
                    .await
                    .expect("receive output acknowledgement"),
                ControlReceipt::OutputAck { .. }
            ));

            let crossed_boundary = (index + 1) % chunks_per_connection == 0;
            if crossed_boundary && reconnects < FORCED_RECONNECTS {
                let server_association = server_link.into_resumable_association();
                let client_association = client_link.into_resumable_association();
                let hello = client_association.resume_hello().expect("resume hello");
                let (admitted, session) = tokio::join!(
                    gateway.accept_resume(authorization),
                    client.connect_resume(remote, &hello)
                );
                let (resumed_server, resumed_client) = tokio::join!(
                    GatewayLink::accept_resume(
                        admitted.expect("resume admission"),
                        server_association,
                        &mut lifecycle,
                        &mut slabs,
                        limits,
                    ),
                    ClientLink::finish_resume(
                        session.expect("resume transport"),
                        client_association,
                        limits,
                    )
                );
                let (next_server_link, action) = resumed_server.expect("resumed gateway link");
                assert_eq!(action, GatewayAction::WriterResumed);
                server_link = next_server_link;
                client_link = resumed_client.expect("resumed client link");
                reconnects += 1;
            }
        }

        assert_eq!(reconnects, FORCED_RECONNECTS);
        assert_eq!(gateway_received, client_input);
        assert_eq!(client_received, gateway_output);
        assert_eq!(slabs.input().unacknowledged_operations(), 0);
        assert_eq!(slabs.writer_output().unacknowledged_operations(), 0);
        server_link.close();
        client_link.close();
        eprintln!("everudp 10 MiB byte identity across five forced reconnects: PASS");
    })
    .await
    .expect("10 MiB byte-identity reconnect deadline");
}

#[tokio::test(flavor = "current_thread")]
async fn gap_and_control_sequences_survive_a_resume_that_the_client_never_finishes() {
    tokio::time::timeout(Duration::from_secs(8), async {
        let limits = Limits::default();
        let store = Arc::new(Mutex::new(
            InvitationStore::new("work", generation(), &limits).expect("store"),
        ));
        let gateway_identity = GatewayIdentity::generate().expect("gateway identity");
        let gateway =
            GatewayEndpoint::bind(loopback(), &gateway_identity, Arc::clone(&store), limits)
                .expect("gateway");
        let client_identity = ClientIdentity::generate().expect("client identity");
        let ticket = store
            .lock()
            .expect("store lock")
            .issue(
                association(),
                ConnectionRole::Writer,
                client_identity.spki_sha256(),
                everpty::sys::clock_monotonic_ms().expect("clock"),
            )
            .expect("ticket");
        let initial = ClientHello::initial(
            association(),
            generation(),
            ConnectionRole::Writer,
            initial_position(),
            ticket.token().clone(),
        )
        .expect("initial hello");
        let client = ClientEndpoint::bind(
            loopback(),
            &client_identity,
            gateway_identity.spki_sha256(),
            limits,
        )
        .expect("client endpoint");
        let (admitted, session) = tokio::join!(
            gateway.accept_initial(),
            client.connect_initial(gateway.local_addr(), &initial)
        );
        let mut lifecycle = GatewayLifecycle::new(&limits).expect("lifecycle");
        let mut slabs = GatewayReplaySlabs::new(&limits).expect("slabs");
        let client_association =
            ClientAssociation::new(association(), generation(), ConnectionRole::Writer, limits)
                .expect("client association");
        let (server_link, client_link) = tokio::join!(
            GatewayLink::accept_initial(
                admitted.expect("initial admission"),
                &mut lifecycle,
                &mut slabs,
                limits,
            ),
            ClientLink::finish_initial(
                session.expect("initial session"),
                client_association,
                limits,
            )
        );
        let server_link = server_link.expect("initial server link").0;
        let client_link = client_link.expect("initial client link");

        for _ in 0..limits.queue_operations_per_direction {
            slabs
                .push_output(Kind::Output, b"stale")
                .expect("fill output");
        }
        assert!(matches!(
            slabs
                .push_output(Kind::Output, b"discarded tail")
                .expect("overrun")
                .writer,
            OutputPush::Overrun {
                abandoned_epoch: 0,
                replacement_epoch: 1,
            }
        ));

        let authorization = server_link.association().authorization();
        let mut server_association = server_link.into_resumable_association();
        let client_association = client_link.into_resumable_association();
        let remote = gateway.local_addr();

        // A connection that passes TLS/association admission but presents an
        // impossible replay position must not consume the durable server
        // association. The same actor can immediately retry correctly.
        let mut impossible_position = client_association.position();
        impossible_position.next_output = impossible_position
            .delivered_output_ack
            .checked_add(1)
            .expect("position");
        let impossible = ClientHello::resume(
            association(),
            generation(),
            ConnectionRole::Writer,
            impossible_position,
        )
        .expect("impossible resume hello");
        let (admitted, rejected_session) = tokio::join!(
            gateway.accept_resume(authorization),
            client.connect_resume(remote, &impossible)
        );
        let failure = GatewayLink::try_accept_resume(
            admitted.expect("position admission"),
            server_association,
            &mut lifecycle,
            &mut slabs,
            limits,
        )
        .await
        .expect_err("impossible position must fail");
        let (error, returned) = failure.into_parts();
        assert!(matches!(
            error,
            everudp::LinkError::Association(everudp::AssociationError::ResumePosition)
        ));
        server_association = returned;
        rejected_session.expect("position peer").close();

        // The gateway completes resume one and sends SERVER_HELLO plus GAP,
        // but this client generation never consumes either record.
        let resume_hello = client_association.resume_hello().expect("hello one");
        let (admitted, abandoned_session) = tokio::join!(
            gateway.accept_resume(authorization),
            client.connect_resume(remote, &resume_hello)
        );
        let (failed_client_server_link, action) = GatewayLink::accept_resume(
            admitted.expect("resume one admission"),
            server_association,
            &mut lifecycle,
            &mut slabs,
            limits,
        )
        .await
        .expect("gateway completes resume one");
        assert_eq!(action, GatewayAction::WriterResumed);
        abandoned_session
            .expect("resume one client transport")
            .close();
        let server_association = failed_client_server_link.into_resumable_association();
        assert_eq!(slabs.writer_output().pending_gap(), Some((0, 1)));

        // The same durable client state retries. Both reconstructed control
        // streams start at their link-local sequence, while the output epoch
        // transition remains pending and is applied exactly once.
        let resume_hello = client_association.resume_hello().expect("hello two");
        let (admitted, session) = tokio::join!(
            gateway.accept_resume(authorization),
            client.connect_resume(remote, &resume_hello)
        );
        let (server_link, client_link) = tokio::join!(
            GatewayLink::accept_resume(
                admitted.expect("resume two admission"),
                server_association,
                &mut lifecycle,
                &mut slabs,
                limits,
            ),
            ClientLink::finish_resume(
                session.expect("resume two client transport"),
                client_association,
                limits,
            )
        );
        let mut server_link = server_link.expect("resume two server link").0;
        let mut client_link = client_link.expect("resume two client link");
        assert_eq!(client_link.association().position().output_epoch, 1);
        assert_eq!(
            client_link.association_mut().take_gap_notice(),
            Some(everudp::wire::EpochGap::new(0, 1).expect("gap"))
        );
        assert_eq!(client_link.association_mut().take_gap_notice(), None);

        client_link
            .association_mut()
            .queue_input(b"future-input-after-gap")
            .expect("queue future input after gap");
        assert_eq!(
            client_link
                .flush_input()
                .await
                .expect("send future input after gap"),
            ClientInputFlush::Sent { records: 1 }
        );
        assert!(matches!(
            server_link
                .receive_input(&mut slabs, |operation| {
                    assert_eq!(operation, InputOperation::Bytes(b"future-input-after-gap"));
                    Ok(())
                })
                .await
                .expect("receive future input after gap"),
            InputReceipt::Delivered {
                acknowledgement: 1,
                ..
            }
        ));
        server_link
            .flush_control(&mut slabs)
            .await
            .expect("acknowledge future input after gap");
        assert!(matches!(
            client_link
                .receive_control()
                .await
                .expect("receive future input acknowledgement"),
            ClientControlReceipt::InputAck(everudp::wire::Ack {
                next_expected: 1,
                ..
            })
        ));

        slabs
            .push_output(Kind::Output, b"future-only")
            .expect("future output");
        assert_eq!(
            server_link
                .flush_output(&slabs)
                .await
                .expect("send future output"),
            OutputFlush::Sent { records: 1 }
        );
        assert!(matches!(
            client_link
                .receive_output(|operation| {
                    assert_eq!(operation, OutputOperation::Bytes(b"future-only"));
                    Ok(())
                })
                .await
                .expect("receive future output"),
            ClientOutputReceipt::Delivered {
                acknowledgement: 1,
                ..
            }
        ));
        server_link.close();
        client_link.close();
    })
    .await
    .expect("failed resume regression deadline");
}

#[tokio::test(flavor = "current_thread")]
async fn hostile_resume_bindings_are_terminal_but_do_not_kill_the_gateway_endpoint() {
    tokio::time::timeout(Duration::from_secs(8), async {
        let limits = Limits::default();
        let store = Arc::new(Mutex::new(
            InvitationStore::new("work", generation(), &limits).expect("store"),
        ));
        let gateway_identity = GatewayIdentity::generate().expect("gateway identity");
        let gateway =
            GatewayEndpoint::bind(loopback(), &gateway_identity, Arc::clone(&store), limits)
                .expect("gateway");
        let client_identity = ClientIdentity::generate().expect("client identity");
        let ticket = store
            .lock()
            .expect("store lock")
            .issue(
                association(),
                ConnectionRole::Writer,
                client_identity.spki_sha256(),
                everpty::sys::clock_monotonic_ms().expect("clock"),
            )
            .expect("ticket");
        let hello = ClientHello::initial(
            association(),
            generation(),
            ConnectionRole::Writer,
            initial_position(),
            ticket.token().clone(),
        )
        .expect("initial hello");
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
        let admitted = admitted.expect("initial admission");
        session.expect("initial session").close();
        let mut lifecycle = GatewayLifecycle::new(&limits).expect("lifecycle");
        let mut slabs = GatewayReplaySlabs::new(&limits).expect("slabs");
        let (association_state, _) =
            GatewayAssociation::establish(&admitted, &mut lifecycle, &mut slabs)
                .expect("association");
        let authorization = association_state.authorization();
        admitted.close();

        let position = initial_position();
        let wrong_generation = GatewayGeneration::from_bytes([99; 16]).expect("generation");
        for hostile in [
            ClientHello::resume(
                AssociationId::from_bytes([88; 16]).expect("wrong association"),
                generation(),
                ConnectionRole::Writer,
                position,
            )
            .expect("hostile hello"),
            ClientHello::resume(
                association(),
                wrong_generation,
                ConnectionRole::Writer,
                position,
            )
            .expect("hostile hello"),
            ClientHello::resume(
                association(),
                generation(),
                ConnectionRole::Observer,
                position,
            )
            .expect("hostile hello"),
        ] {
            let (server, peer) = tokio::join!(
                gateway.accept_resume(authorization),
                client.connect_resume(gateway.local_addr(), &hostile)
            );
            assert!(matches!(
                server,
                Err(TransportError::Admission(AdmissionError::BindingMismatch))
            ));
            peer.expect("hostile client wrote hello").close();
        }

        let wrong_identity = ClientIdentity::generate().expect("wrong client identity");
        let wrong_client = ClientEndpoint::bind(
            loopback(),
            &wrong_identity,
            gateway_identity.spki_sha256(),
            limits,
        )
        .expect("wrong client endpoint");
        let correct = ClientHello::resume(
            association(),
            generation(),
            ConnectionRole::Writer,
            position,
        )
        .expect("correct-shaped resume");
        let (server, peer) = tokio::join!(
            gateway.accept_resume(authorization),
            wrong_client.connect_resume(gateway.local_addr(), &correct)
        );
        assert!(matches!(
            server,
            Err(TransportError::Admission(AdmissionError::BindingMismatch))
        ));
        peer.expect("wrong key wrote hello").close();

        let (server, peer) = tokio::join!(
            gateway.accept_resume(authorization),
            client.connect_resume(gateway.local_addr(), &correct)
        );
        server.expect("gateway remains available").close();
        peer.expect("correct resume remains available").close();
    })
    .await
    .expect("hostile resume deadline");
}
