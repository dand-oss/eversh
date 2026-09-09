use super::*;
use crate::{
    ClientAssociation, ClientEndpoint, ClientIdentity, ClientLink, GatewayGeneration,
    GatewayIdentity, InvitationStore, OutputFlush, ResumePosition,
};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

#[test]
fn committed_bytes_request_only_the_experimental_pty_probe() {
    assert_eq!(
        prefer_pty_after_commit(crate::InputOperation::Bytes(b"echo")),
        cfg!(feature = "pty-ready-spike")
    );
    assert!(!prefer_pty_after_commit(crate::InputOperation::Signal(2)));
    assert!(!prefer_pty_after_commit(crate::InputOperation::Close));
    assert!(!prefer_pty_after_commit(crate::InputOperation::Resize(
        crate::wire::Resize {
            rows: 24,
            columns: 80,
            pixel_width: 0,
            pixel_height: 0,
        }
    )));
}

#[tokio::test(flavor = "current_thread")]
async fn immediate_pty_probe_polls_ready_and_pending_only_once() {
    use std::cell::Cell;
    for ready in [false, true] {
        let polls = Cell::new(0);
        let result = poll_once_now(poll_fn(|_| {
            polls.set(polls.get() + 1);
            if ready {
                Poll::Ready(7)
            } else {
                Poll::Pending
            }
        }))
        .await;
        assert_eq!(result, ready.then_some(7));
        assert_eq!(polls.get(), 1, "a pending PTY must never delay ACK work");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn terminal_selector_does_not_starve_resume_admission() {
    let mut next = 0;
    for expected in [0, 1, 0, 1] {
        let value =
            match select_terminal_ready(&mut next, std::future::ready(0), std::future::ready(1))
                .await
            {
                TerminalReady::Inbound(value) | TerminalReady::Admission(value) => value,
            };
        assert_eq!(
            value, expected,
            "terminal link work must yield to resume admission"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn outer_selector_pending_poll_registers_every_source_without_rotating() {
    use std::cell::Cell;
    let polls = [Cell::new(0), Cell::new(0), Cell::new(0)];
    let polls = &polls;
    let tracked = |index: usize| {
        poll_fn(move |_cx| {
            polls[index].set(polls[index].get() + 1);
            Poll::<()>::Pending
        })
    };
    let mut next = 1;
    {
        let future = select_ready(&mut next, tracked(0), tracked(1), tracked(2));
        let mut future = std::pin::pin!(future);
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(future.as_mut().poll(&mut context).is_pending());
    }
    assert_eq!(next, 1);
    assert!(polls.iter().all(|count| count.get() == 1));
}

#[tokio::test(flavor = "current_thread")]
async fn outer_selector_services_every_continuously_ready_class() {
    let mut next = 0;
    for expected in [0, 1, 2, 0, 1, 2] {
        let selected = select_ready(
            &mut next,
            std::future::ready(0),
            std::future::ready(1),
            std::future::ready(2),
        )
        .await;
        let value = match selected {
            Ready::Inbound(value) | Ready::Admission(value) | Ready::Pty(value) => value,
        };
        assert_eq!(
            value, expected,
            "ready link must not starve admission or PTY"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn outer_selector_skips_blocked_link_without_starving_pty() {
    let mut next = 0;
    for expected in [1, 2, 1, 2] {
        let selected = select_ready(
            &mut next,
            std::future::pending::<u8>(),
            std::future::ready(1),
            std::future::ready(2),
        )
        .await;
        let value = match selected {
            Ready::Inbound(value) | Ready::Admission(value) | Ready::Pty(value) => value,
        };
        assert_eq!(value, expected);
    }
}

struct Fixture {
    gateway: GatewayLink,
    client: ClientLink,
    slabs: GatewayReplaySlabs,
    _server: GatewayEndpoint,
    _endpoint: ClientEndpoint,
}

async fn fixture(id_byte: u8) -> Fixture {
    let limits = Limits::default();
    let id = AssociationId::from_bytes([id_byte; 16]).expect("id");
    let generation = GatewayGeneration::from_bytes([72; 16]).expect("generation");
    let role = ConnectionRole::Writer;
    let store = Arc::new(Mutex::new(
        InvitationStore::new("fairness", generation, &limits).expect("store"),
    ));
    let identity = ClientIdentity::generate().expect("client identity");
    let server_identity = GatewayIdentity::generate().expect("server identity");
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let server = GatewayEndpoint::bind(address, &server_identity, Arc::clone(&store), limits)
        .expect("server");
    let ticket = store
        .lock()
        .expect("store")
        .issue(
            id,
            role,
            identity.spki_sha256(),
            everpty::sys::clock_monotonic_ms().expect("clock"),
        )
        .expect("invitation");
    let hello = ClientHello::initial(
        id,
        generation,
        role,
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
    let endpoint = ClientEndpoint::bind(address, &identity, server_identity.spki_sha256(), limits)
        .expect("endpoint");
    let (admitted, session) = tokio::join!(
        server.accept_initial(),
        endpoint.connect_initial(server.local_addr(), &hello)
    );
    let mut lifecycle = GatewayLifecycle::new(&limits).expect("lifecycle");
    let mut slabs = GatewayReplaySlabs::new(&limits).expect("slabs");
    let association = ClientAssociation::new(id, generation, role, limits).expect("association");
    let (gateway, client) = tokio::join!(
        GatewayLink::accept_initial(
            admitted.expect("admission"),
            &mut lifecycle,
            &mut slabs,
            limits
        ),
        ClientLink::finish_initial(session.expect("session"), association, limits)
    );
    Fixture {
        gateway: gateway.expect("gateway").0,
        client: client.expect("client"),
        slabs,
        _server: server,
        _endpoint: endpoint,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn ready_control_does_not_skip_output_poll() {
    let mut f = fixture(81).await;
    f.client
        .association_mut()
        .queue_input(b"input")
        .expect("input");
    f.client.flush_input().await.expect("input write");
    f.gateway
        .receive_input(&mut f.slabs, |_| Ok(()))
        .await
        .expect("accepted input");
    assert_eq!(
        f.gateway
            .association()
            .control(&f.slabs)
            .expect("control")
            .unacknowledged_operations(),
        1
    );
    f.slabs
        .push_output(Kind::Output, b"output")
        .expect("output");
    assert!(poll_fn(|cx| f.gateway.poll_outbound(&mut f.slabs, cx))
        .await
        .expect("poll"));
    assert_eq!(
        f.gateway
            .flush_output(&f.slabs)
            .await
            .expect("remaining output"),
        OutputFlush::Idle,
        "one ready control record must not defer ready output"
    );
}

#[cfg(feature = "input-ack-hold-spike")]
#[tokio::test(flavor = "current_thread")]
async fn input_ack_hold_preserves_commit_and_releases_on_output_or_timer() {
    for output_ready in [false, true] {
        let mut f = fixture(if output_ready { 91 } else { 92 }).await;
        f.client
            .association_mut()
            .queue_input(b"input")
            .expect("input");
        f.client.flush_input().await.expect("input write");
        let mut delivered = 0;
        f.gateway
            .receive_input(&mut f.slabs, |_| {
                delivered += 1;
                Ok(())
            })
            .await
            .expect("committed input");
        assert_eq!(delivered, 1, "wire hold cannot delay the sink commit");
        assert!(
            poll_once_now(poll_fn(|cx| f.gateway.poll_outbound(&mut f.slabs, cx)))
                .await
                .is_none(),
            "the sole unsent ACK should initially wait"
        );
        assert_eq!(
            f.gateway
                .association()
                .control(&f.slabs)
                .expect("control")
                .unacknowledged_operations(),
            1,
            "held ACK remains queued"
        );
        if output_ready {
            f.slabs
                .push_output(Kind::Output, b"output")
                .expect("output");
            assert!(
                poll_once_now(poll_fn(|cx| f.gateway.poll_outbound(&mut f.slabs, cx)))
                    .await
                    .expect("ready output releases ACK without another wake")
                    .expect("outbound")
            );
            assert_eq!(
                f.gateway.flush_output(&f.slabs).await.expect("output"),
                OutputFlush::Idle
            );
        } else {
            assert!(tokio::time::timeout(
                std::time::Duration::from_secs(1),
                poll_fn(|cx| f.gateway.poll_outbound(&mut f.slabs, cx))
            )
            .await
            .expect("registered hold timer must wake the outbound future")
            .expect("outbound"));
        }
        assert_eq!(
            f.gateway
                .association()
                .control(&f.slabs)
                .expect("control")
                .unacknowledged_operations(),
            0,
            "released ACK was written exactly once"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn already_pending_associations_receive_round_robin_service() {
    let first = fixture(82).await;
    let second = fixture(83).await;
    let mut associations = Associations::new().expect("associations");
    let mut slabs = first.slabs;
    let a = associations
        .insert(AssociationState::Connected(Box::new(first.gateway)))
        .expect("first");
    let b = associations
        .insert(AssociationState::Connected(Box::new(second.gateway)))
        .expect("second");
    // Both slots already have an event. The dispatcher must not monopolize
    // slot zero if its caller has ready work again on the following turn.
    for index in [a, b] {
        associations.slots[index].as_mut().expect("slot").pending =
            Some(Err(LinkError::StreamRead));
    }
    assert!(
        matches!(next_link_ready(&mut associations, &mut slabs).await, LinkReady::Event(i) if i == a)
    );
    assert!(
        matches!(next_link_ready(&mut associations, &mut slabs).await, LinkReady::Event(i) if i == b)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn committed_inbound_yields_one_outbound_turn_before_more_input() {
    let mut f = fixture(84).await;
    for input in [b"first".as_slice(), b"second".as_slice()] {
        f.client
            .association_mut()
            .queue_input(input)
            .expect("input");
    }
    f.client.flush_input().await.expect("input writes");
    let mut associations = Associations::new().expect("associations");
    let index = associations
        .insert(AssociationState::Connected(Box::new(f.gateway)))
        .expect("association");
    loop {
        assert!(
            matches!(next_link_ready(&mut associations, &mut f.slabs).await,
        LinkReady::Event(i) if i == index)
        );
        let event = associations.slots[index]
            .as_mut()
            .expect("slot")
            .pending
            .take()
            .expect("pending")
            .expect("inbound");
        // Mirror the production take/apply/put lifecycle, including sink commit.
        let AssociationState::Connected(mut link) = associations.take(index).expect("state") else {
            panic!("connected");
        };
        let token = match link.prepare_inbound(event, &mut f.slabs).expect("prepare") {
            InboundApply::Deliver(input) => input.token(),
            InboundApply::None => {
                associations.put(index, AssociationState::Connected(link));
                continue;
            }
            _ => panic!("expected input"),
        };
        link.commit_prepared_input(token, &mut f.slabs)
            .expect("commit");
        associations.put(index, AssociationState::Connected(link));
        break;
    }
    f.slabs
        .push_output(Kind::Output, b"first response")
        .expect("output");
    assert!(
        matches!(
            next_link_ready(&mut associations, &mut f.slabs).await,
            LinkReady::OutboundProgress
        ),
        "ready input must yield after a committed input turn"
    );
}
