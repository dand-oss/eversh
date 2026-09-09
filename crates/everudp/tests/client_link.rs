use everssh::association::AssociationId;
use everudp::wire::{ConnectionRole, Kind};
use everudp::{
    ClientAssociation, ClientControlReceipt, ClientEndpoint, ClientHello, ClientIdentity,
    ClientInputFlush, ClientLink, ClientLinkError, ClientOutputReceipt, GatewayAction,
    GatewayEndpoint, GatewayGeneration, GatewayIdentity, GatewayLifecycle, GatewayLink,
    GatewayReplaySlabs, InputOperation, InputReceipt, InvitationStore, Limits, OutputFlush,
    OutputOperation, ResumePosition,
};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn association() -> AssociationId {
    AssociationId::from_bytes([7; 16]).expect("association")
}

fn generation() -> GatewayGeneration {
    GatewayGeneration::from_bytes([8; 16]).expect("generation")
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

#[tokio::test(flavor = "current_thread")]
async fn client_and_gateway_links_deliver_both_directions_exactly_once() {
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
    let endpoint = ClientEndpoint::bind(
        loopback(),
        &client_identity,
        gateway_identity.spki_sha256(),
        limits,
    )
    .expect("client endpoint");
    let (admitted, session) = tokio::join!(
        gateway.accept_initial(),
        endpoint.connect_initial(gateway.local_addr(), &hello)
    );
    let admitted = admitted.expect("admitted");
    let session = session.expect("session");
    let mut lifecycle = GatewayLifecycle::new(&limits).expect("lifecycle");
    let mut slabs = GatewayReplaySlabs::new(&limits).expect("slabs");

    let server = async {
        let (mut link, action) =
            GatewayLink::accept_initial(admitted, &mut lifecycle, &mut slabs, limits)
                .await
                .expect("gateway link");
        assert_eq!(action, GatewayAction::CommitEverptyWriter);
        let mut input = Vec::new();
        assert_eq!(
            link.receive_input(&mut slabs, |operation| {
                let InputOperation::Bytes(bytes) = operation else {
                    panic!("expected bytes")
                };
                input.extend_from_slice(bytes);
                Ok(())
            })
            .await
            .expect("input"),
            InputReceipt::Delivered {
                kind: Kind::Input,
                sequence: 0,
                acknowledgement: 1,
            }
        );
        link.flush_control(&mut slabs).await.expect("input ACK");
        assert!(matches!(
            link.receive_input(&mut slabs, |operation| {
                assert_eq!(operation, InputOperation::Close);
                Ok(())
            })
            .await
            .expect("close"),
            InputReceipt::Delivered {
                kind: Kind::InputClose,
                sequence: 1,
                acknowledgement: 2,
            }
        ));
        link.flush_control(&mut slabs).await.expect("close ACK");
        assert_eq!(input, b"from-client");

        slabs
            .push_output(Kind::Output, b"from-server")
            .expect("output");
        assert_eq!(
            link.flush_output(&slabs).await.expect("flush output"),
            OutputFlush::Sent { records: 1 }
        );
        link.receive_control(&mut slabs).await.expect("output ACK");
        assert_eq!(slabs.writer_output().unacknowledged_operations(), 0);
        link.close();
    };

    let peer = async {
        let association =
            ClientAssociation::new(association(), generation(), ConnectionRole::Writer, limits)
                .expect("association");
        let mut link = ClientLink::finish_initial(session, association, limits)
            .await
            .expect("client link");
        link.association_mut()
            .queue_input(b"from-client")
            .expect("queue input");
        link.association_mut()
            .queue_input_close()
            .expect("queue close");
        assert_eq!(
            link.flush_input().await.expect("flush input"),
            ClientInputFlush::Sent { records: 2 }
        );
        assert!(matches!(
            link.receive_control().await.expect("first input ACK"),
            ClientControlReceipt::InputAck(everudp::wire::Ack {
                next_expected: 1,
                ..
            })
        ));
        assert!(matches!(
            link.receive_control().await.expect("close ACK"),
            ClientControlReceipt::InputAck(everudp::wire::Ack {
                next_expected: 2,
                ..
            })
        ));
        assert!(matches!(
            link.receive_output(|_| {
                Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
            })
            .await,
            Err(ClientLinkError::Sink(error)) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
        let mut output = Vec::new();
        assert_eq!(
            link.receive_output(|operation| {
                let OutputOperation::Bytes(bytes) = operation else {
                    panic!("expected output bytes")
                };
                output.extend_from_slice(bytes);
                Ok(())
            })
            .await
            .expect("output"),
            ClientOutputReceipt::Delivered {
                kind: Kind::Output,
                sequence: 0,
                acknowledgement: 1,
            }
        );
        assert_eq!(output, b"from-server");
        assert_eq!(link.flush_control().await.expect("output ACK"), 1);
        link.wait_closed().await;
    };

    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(server, peer);
    })
    .await
    .expect("link pair deadline");
}
