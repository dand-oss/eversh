use super::*;
use crate::{
    ClientAssociation, ClientEndpoint, ClientHello, ClientIdentity, GatewayEndpoint,
    GatewayGeneration, GatewayIdentity, GatewayLifecycle, GatewayLink, GatewayReplaySlabs,
    InvitationStore, ResumePosition,
};
use everpty::sys;
use everssh::association::AssociationId;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::AsFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncReadExt;

#[tokio::test(flavor = "current_thread")]
async fn blocked_input_keeps_output_and_local_cancel_live() {
    let limits = Limits::default();
    let id = AssociationId::from_bytes([71; 16]).expect("association");
    let generation = GatewayGeneration::from_bytes([72; 16]).expect("generation");
    let role = ConnectionRole::Writer;
    let store = Arc::new(Mutex::new(
        InvitationStore::new("backpressure", generation, &limits).expect("store"),
    ));
    let server_identity = GatewayIdentity::generate().expect("server identity");
    let identity = ClientIdentity::generate().expect("identity");
    let loopback = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let server = GatewayEndpoint::bind(loopback, &server_identity, Arc::clone(&store), limits)
        .expect("server");
    let ticket = store
        .lock()
        .expect("store lock")
        .issue(
            id,
            role,
            identity.spki_sha256(),
            sys::clock_monotonic_ms().expect("clock"),
        )
        .expect("ticket");
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
    let endpoint = ClientEndpoint::bind(loopback, &identity, server_identity.spki_sha256(), limits)
        .expect("endpoint");
    let (admitted, session) = tokio::join!(
        server.accept_initial(),
        endpoint.connect_initial(server.local_addr(), &hello)
    );
    let mut lifecycle = GatewayLifecycle::new(&limits).expect("lifecycle");
    let mut slabs = GatewayReplaySlabs::new(&limits).expect("slabs");
    let association = ClientAssociation::new(id, generation, role, limits).expect("client");
    let (gateway, client) = tokio::join!(
        GatewayLink::accept_initial(
            admitted.expect("admission"),
            &mut lifecycle,
            &mut slabs,
            limits
        ),
        ClientLink::finish_initial(session.expect("session"), association, limits),
    );
    let (mut gateway, _) = gateway.expect("gateway link");
    let mut client = client.expect("client link");
    client.set_test_send_window(0);
    client
        .association_mut()
        .queue_input(b"retained input")
        .expect("input");

    let (stdin, _stdin_writer) = sys::pipe_cloexec().expect("stdin");
    let (mut output, stdout) = tokio::net::UnixStream::pair().expect("stdout");
    let (_stderr, stderr) = sys::pipe_cloexec().expect("stderr");
    let terminal =
        TerminalEdge::stage(stdin.as_fd(), stdout.as_fd(), stderr.as_fd()).expect("stage");
    let mut driver = ClientDriver::activate(terminal, &client, limits, None).expect("driver");
    driver.delivery_timeout = Duration::from_millis(20);
    let mut cancel_queued = false;
    let result = tokio::time::timeout(Duration::from_secs(2), async {
        let remote = async {
            slabs
                .push_output(crate::wire::Kind::Output, b"still live")
                .expect("output");
            gateway.flush_output(&slabs).await.expect("flush output");
            let mut received = [0; 10];
            output.read_exact(&mut received).await.expect("stdout");
            assert_eq!(&received, b"still live");
            let signal = sys::AttachSignal::Terminate.number();
            sys::signal_thread(sys::current_thread_id(), signal).expect("queue cancel");
            cancel_queued = true;
        };
        let (outcome, ()) = tokio::join!(driver.run_link(&mut client), remote);
        outcome
    })
    .await;
    // A failing signal regression must never leak SIGTERM when the guard
    // restores this test thread's signal mask.
    if result.is_err() && cancel_queued {
        let _ = tokio::time::timeout(
            Duration::from_secs(1),
            driver.next_disconnected_terminal_event(),
        )
        .await;
    }
    assert!(
        result.is_ok(),
        "blocked input stalled; output delivered and cancel queued: {cancel_queued}"
    );
    let outcome = result.expect("checked deadline").expect("run");
    assert_eq!(
        outcome,
        ClientRunOutcome::LocalCancelled {
            signal: sys::AttachSignal::Terminate.number()
        }
    );
    assert_eq!(
        client.association().ambiguous_input_operations(),
        1,
        "blocked input remains owned, never silently acknowledged"
    );
}
