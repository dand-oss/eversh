use everssh::association::AssociationId;
use everudp::wire::{
    decode_record, encode_record, Ack, ConnectionRole, Kind, StreamRole, HEADER_LEN,
};
use everudp::{
    ClientEndpoint, ClientHello, ClientIdentity, ControlReceipt, GatewayAction, GatewayEndpoint,
    GatewayGeneration, GatewayIdentity, GatewayLifecycle, GatewayLink, GatewayReplaySlabs,
    InputOperation, InputReceipt, InvitationStore, Limits, LinkError, OutputFlush, ResumePosition,
    ServerHello,
};
use noq::{RecvStream, SendStream};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

async fn send_record(
    send: &mut SendStream,
    stream: StreamRole,
    kind: Kind,
    sequence: u64,
    payload: &[u8],
    limits: &Limits,
) {
    let mut wire = vec![0_u8; HEADER_LEN + payload.len()];
    let used = encode_record(stream, kind, sequence, payload, limits, &mut wire).expect("encode");
    send.write_all(&wire[..used]).await.expect("send record");
}

async fn receive_record(
    recv: &mut RecvStream,
    stream: StreamRole,
    limits: &Limits,
) -> (Kind, u64, Vec<u8>) {
    let mut header = [0_u8; HEADER_LEN];
    recv.read_exact(&mut header).await.expect("record header");
    let payload_len = u32::from_be_bytes(header[10..14].try_into().expect("length")) as usize;
    let mut wire = vec![0_u8; HEADER_LEN + payload_len];
    wire[..HEADER_LEN].copy_from_slice(&header);
    recv.read_exact(&mut wire[HEADER_LEN..])
        .await
        .expect("record payload");
    let (record, consumed) = decode_record(stream, &wire, limits).expect("decode record");
    assert_eq!(consumed, wire.len());
    (
        record.header.kind,
        record.header.sequence,
        record.payload.to_vec(),
    )
}

fn endpoints(role: ConnectionRole) -> (Limits, GatewayEndpoint, ClientEndpoint, ClientHello) {
    let limits = Limits::default();
    let store = Arc::new(Mutex::new(
        InvitationStore::new("work", generation(), &limits).expect("store"),
    ));
    let gateway_identity = GatewayIdentity::generate().expect("gateway identity");
    let gateway = GatewayEndpoint::bind(loopback(), &gateway_identity, Arc::clone(&store), limits)
        .expect("gateway");
    let client_identity = ClientIdentity::generate().expect("client identity");
    let ticket = store
        .lock()
        .expect("store lock")
        .issue(
            association(1),
            role,
            client_identity.spki_sha256(),
            everpty::sys::clock_monotonic_ms().expect("clock"),
        )
        .expect("invitation");
    let hello = ClientHello::initial(
        association(1),
        generation(),
        role,
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
    (limits, gateway, client, hello)
}

#[tokio::test(flavor = "current_thread")]
async fn live_writer_is_exactly_once_and_acks_only_after_both_sinks_accept() {
    let (limits, gateway, client, hello) = endpoints(ConnectionRole::Writer);
    let (admitted, client_session) = tokio::join!(
        gateway.accept_initial(),
        client.connect_initial(gateway.local_addr(), &hello)
    );
    let admitted = admitted.expect("admitted");
    let client_session = client_session.expect("client session");
    let mut lifecycle = GatewayLifecycle::new(&limits).expect("lifecycle");
    let mut slabs = GatewayReplaySlabs::new(&limits).expect("slabs");

    let server = async {
        let (mut link, action) =
            GatewayLink::accept_initial(admitted, &mut lifecycle, &mut slabs, limits)
                .await
                .expect("link");
        assert_eq!(action, GatewayAction::CommitEverptyWriter);
        let mut accepted = Vec::new();
        assert!(matches!(
            link.receive_input(&mut slabs, |_| {
                Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
            })
            .await,
            Err(LinkError::Sink(error)) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
        assert_eq!(
            link.association()
                .control(&slabs)
                .expect("control")
                .unacknowledged_operations(),
            0,
            "a rejected sink operation must not queue an ACK"
        );
        let first = link
            .receive_input(&mut slabs, |operation| {
                let InputOperation::Bytes(bytes) = operation else {
                    panic!("unexpected input operation")
                };
                accepted.push(bytes.to_vec());
                Ok(())
            })
            .await
            .expect("input");
        assert_eq!(
            first,
            InputReceipt::Delivered {
                kind: Kind::Input,
                sequence: 0,
                acknowledgement: 1,
            }
        );
        assert_eq!(link.flush_control(&mut slabs).await.expect("input ACK"), 1);

        let duplicate = link
            .receive_input(&mut slabs, |_| panic!("duplicate reached sink"))
            .await
            .expect("duplicate");
        assert_eq!(
            duplicate,
            InputReceipt::Duplicate {
                sequence: 0,
                acknowledgement: 1,
            }
        );
        assert_eq!(link.flush_control(&mut slabs).await.expect("repeat ACK"), 1);
        assert_eq!(accepted, [b"hello".to_vec()]);

        let closed = link
            .receive_input(&mut slabs, |operation| {
                assert_eq!(operation, InputOperation::Close);
                Ok(())
            })
            .await
            .expect("input close");
        assert_eq!(
            closed,
            InputReceipt::Delivered {
                kind: Kind::InputClose,
                sequence: 1,
                acknowledgement: 2,
            }
        );
        assert_eq!(link.flush_control(&mut slabs).await.expect("close ACK"), 1);
        assert_eq!(
            link.receive_input(&mut slabs, |_| panic!("operation after close"))
                .await
                .expect("finished input"),
            InputReceipt::Finished
        );

        slabs
            .push_output(Kind::Output, b"world")
            .expect("queue output");
        assert_eq!(
            link.flush_output(&slabs).await.expect("flush output"),
            OutputFlush::Sent { records: 1 }
        );
        let receipt = link.receive_control(&mut slabs).await.expect("output ACK");
        assert_eq!(
            receipt,
            ControlReceipt::OutputAck {
                acknowledgement: Ack {
                    epoch: 0,
                    next_expected: 1,
                },
                disposition: everudp::ControlDisposition::Applied,
            }
        );
        assert_eq!(slabs.writer_output().unacknowledged_operations(), 0);
        link.close();
    };

    let peer = async {
        let (connection, mut control_send, mut control_recv) = client_session.into_parts();
        let (kind, sequence, payload) =
            receive_record(&mut control_recv, StreamRole::Control, &limits).await;
        assert_eq!((kind, sequence), (Kind::ServerHello, 0));
        let server_hello = ServerHello::decode_exact(&payload).expect("server hello");
        assert_eq!(server_hello.association_id(), association(1));

        let mut input = connection.open_uni().await.expect("input stream");
        send_record(
            &mut input,
            StreamRole::Input,
            Kind::Input,
            0,
            b"hello",
            &limits,
        )
        .await;
        send_record(
            &mut input,
            StreamRole::Input,
            Kind::Input,
            0,
            b"hello",
            &limits,
        )
        .await;
        send_record(
            &mut input,
            StreamRole::Input,
            Kind::InputClose,
            1,
            &[],
            &limits,
        )
        .await;
        input.finish().expect("finish input");

        for (expected_sequence, expected_ack) in [(1, 1), (2, 1), (3, 2)] {
            let (kind, sequence, payload) =
                receive_record(&mut control_recv, StreamRole::Control, &limits).await;
            assert_eq!((kind, sequence), (Kind::AckInput, expected_sequence));
            assert_eq!(
                Ack::decode_exact(&payload, kind).expect("input ACK"),
                Ack {
                    epoch: 0,
                    next_expected: expected_ack,
                }
            );
        }

        let mut output = connection.accept_uni().await.expect("output stream");
        let (kind, sequence, payload) =
            receive_record(&mut output, StreamRole::Output, &limits).await;
        assert_eq!(
            (kind, sequence, payload.as_slice()),
            (Kind::Output, 0, &b"world"[..])
        );
        let ack = Ack {
            epoch: 0,
            next_expected: 1,
        };
        send_record(
            &mut control_send,
            StreamRole::Control,
            Kind::AckOutput,
            1,
            &ack.encode(),
            &limits,
        )
        .await;
        let _ = connection.closed().await;
    };

    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(server, peer);
    })
    .await
    .expect("live link deadline");
}

#[tokio::test(flavor = "current_thread")]
async fn observer_input_stream_is_rejected_without_committing_a_writer() {
    let (limits, gateway, client, hello) = endpoints(ConnectionRole::Observer);
    let (admitted, client_session) = tokio::join!(
        gateway.accept_initial(),
        client.connect_initial(gateway.local_addr(), &hello)
    );
    let admitted = admitted.expect("admitted");
    let client_session = client_session.expect("client session");
    let mut lifecycle = GatewayLifecycle::new(&limits).expect("lifecycle");
    let mut slabs = GatewayReplaySlabs::new(&limits).expect("slabs");

    let server = async {
        let (mut link, action) =
            GatewayLink::accept_initial(admitted, &mut lifecycle, &mut slabs, limits)
                .await
                .expect("observer link");
        assert_eq!(action, GatewayAction::ObserverAdded);
        assert!(matches!(
            link.reject_observer_input().await,
            Err(LinkError::ObserverInputStream)
        ));
        link.close();
    };
    let peer = async {
        let (connection, _, mut control_recv) = client_session.into_parts();
        let (kind, sequence, _) =
            receive_record(&mut control_recv, StreamRole::Control, &limits).await;
        assert_eq!((kind, sequence), (Kind::ServerHello, 0));
        let mut forbidden = connection.open_uni().await.expect("forbidden input");
        send_record(
            &mut forbidden,
            StreamRole::Input,
            Kind::Input,
            0,
            b"x",
            &limits,
        )
        .await;
        let _ = connection.closed().await;
    };

    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(server, peer);
    })
    .await
    .expect("observer rejection deadline");
    assert!(!lifecycle.everpty_writer_committed());
}

#[tokio::test(flavor = "current_thread")]
async fn output_acknowledged_before_flush_does_not_create_a_sequence_gap() {
    let (received, receive_ack) = tokio::sync::oneshot::channel();
    let (limits, gateway, client, hello) = endpoints(ConnectionRole::Writer);
    let (admitted, client_session) = tokio::join!(
        gateway.accept_initial(),
        client.connect_initial(gateway.local_addr(), &hello)
    );
    let admitted = admitted.expect("admitted");
    let client_session = client_session.expect("client session");
    let mut lifecycle = GatewayLifecycle::new(&limits).expect("lifecycle");
    let mut slabs = GatewayReplaySlabs::new(&limits).expect("slabs");

    let server = async {
        let (mut link, action) =
            GatewayLink::accept_initial(admitted, &mut lifecycle, &mut slabs, limits)
                .await
                .expect("link");
        assert_eq!(action, GatewayAction::CommitEverptyWriter);

        // Model a fast path delivering the first output before the reliable
        // stream gets a chance to flush it. The reliable queue is empty, but
        // its next sequence is now one.
        slabs
            .push_output(Kind::Output, b"fast-path")
            .expect("queue fast-path output");
        slabs
            .acknowledge_writer_epoch(0, 1)
            .expect("acknowledge fast-path output");
        assert_eq!(slabs.writer_output().unacknowledged_operations(), 0);
        assert_eq!(
            link.flush_output(&slabs)
                .await
                .expect("empty reliable flush"),
            OutputFlush::Idle
        );

        // A later record must retain the next sequence and remain deliverable
        // after the fast-path record was retired.
        slabs
            .push_output(Kind::Exit, &7_i32.to_be_bytes())
            .expect("queue future exit");
        assert_eq!(
            link.flush_output(&slabs)
                .await
                .expect("future reliable flush"),
            OutputFlush::Sent { records: 1 }
        );
        receive_ack.await.expect("peer accepted future exit");
        link.close();
    };

    let peer = async {
        let (connection, _, mut control_recv) = client_session.into_parts();
        let (kind, sequence, payload) =
            receive_record(&mut control_recv, StreamRole::Control, &limits).await;
        assert_eq!((kind, sequence), (Kind::ServerHello, 0));
        ServerHello::decode_exact(&payload).expect("server hello");

        let mut output = connection.accept_uni().await.expect("output stream");
        let (kind, sequence, payload) =
            receive_record(&mut output, StreamRole::Output, &limits).await;
        assert_eq!(
            (kind, sequence, payload.as_slice()),
            (Kind::Exit, 1, &7_i32.to_be_bytes()[..])
        );
        received.send(()).expect("report received exit");
        let _ = connection.closed().await;
    };

    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(server, peer);
    })
    .await
    .expect("fast-path acknowledgement deadline");
}
