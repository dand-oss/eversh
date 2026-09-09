#![cfg(all(
    feature = "diagnostic-events",
    feature = "stream-delivery-handoff",
    feature = "rustls",
    feature = "ring",
    feature = "runtime-tokio"
))]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;

use noq::diagnostic::{self, Event};
use noq::{ClientConfig, Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

static DRIVER_POLLS: AtomicUsize = AtomicUsize::new(0);

fn record_diagnostic(event: Event) {
    if matches!(event, Event::DriverPoll) {
        DRIVER_POLLS.fetch_add(1, Ordering::Relaxed);
    }
}

/// A blocked stream reader must be woken promptly, while the driver's next poll still makes
/// ordinary transmit progress. Repeated wakeups exercise the one-shot deferral guard.
#[tokio::test(flavor = "current_thread")]
async fn blocked_reader_wakeup_has_one_bounded_handoff() {
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        exercise_delivery_handoff(),
    )
    .await
    .expect("delivery handoff test timed out");
}

async fn exercise_delivery_handoff() {
    diagnostic::install(record_diagnostic).expect("install diagnostic callback");
    DRIVER_POLLS.store(0, Ordering::Relaxed);

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert);
    let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let server_config = ServerConfig::with_single_cert(vec![cert_der.clone()], key.into()).unwrap();
    let server = Endpoint::server(server_config, SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let client = Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    client
        .set_default_client_config(ClientConfig::with_root_certificates(Arc::new(roots)).unwrap());

    let server_addr = server.local_addr().unwrap();
    let (permit_tx, mut permit_rx) = tokio::sync::mpsc::unbounded_channel();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let server_acceptor = server.clone();
    let server_task = tokio::spawn(async move {
        let incoming = server_acceptor.accept().await.unwrap();
        let connection = incoming.await.unwrap();
        let (mut send, mut recv) = connection.accept_bi().await.unwrap();
        send.write_all(&[0x11]).await.unwrap();

        let mut ping = [0u8; 4];
        recv.read_exact(&mut ping).await.unwrap();
        assert_eq!(&ping, b"ping");

        // Every iteration starts with a genuinely blocked reader on the client.
        // The reverse-direction acknowledgement proves that the peer continues
        // making transmit progress rather than merely waking the reader.
        for index in 0..64u8 {
            permit_rx.recv().await.expect("client read permit");
            let value = 0x20u8.wrapping_add(index);
            send.write_all(&[value]).await.unwrap();
            let mut ack = [0u8; 1];
            recv.read_exact(&mut ack).await.unwrap();
            assert_eq!(
                ack,
                [value ^ 0x80],
                "reverse stream byte changed at {index}"
            );
        }
        send.finish().unwrap();
        done_rx.await.unwrap();
        connection.close(0u32.into(), b"handoff complete");
    });

    let connection = client
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    // Opening a QUIC stream is lazy: write before the peer can accept it.
    send.write_all(b"ping").await.unwrap();
    let mut first = [0u8; 1];
    recv.read_exact(&mut first).await.unwrap();
    assert_eq!(first, [0x11]);

    for index in 0..64u8 {
        let expected = 0x20u8.wrapping_add(index);
        let mut next = [0u8; 1];
        let mut pending_read = Box::pin(recv.read_exact(&mut next));
        let was_pending =
            std::future::poll_fn(|cx| Poll::Ready(pending_read.as_mut().poll(cx).is_pending()))
                .await;
        assert!(
            was_pending,
            "read was not blocked before server wake {index}"
        );
        permit_tx.send(()).unwrap();
        pending_read.await.unwrap();
        assert_eq!(next, [expected]);
        send.write_all(&[expected ^ 0x80]).await.unwrap();
    }

    let mut eof = [0u8; 1];
    assert_eq!(recv.read(&mut eof).await.unwrap(), None);

    // With no application reads left, the driver must settle rather than spin.
    // This is deliberately a generous bound: it catches a busy
    // loop without asserting a scheduler-specific poll count.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let before_idle = DRIVER_POLLS.load(Ordering::Relaxed);
    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    let idle_polls = DRIVER_POLLS.load(Ordering::Relaxed) - before_idle;
    assert!(
        idle_polls <= 1_000,
        "driver appears busy while idle: {idle_polls} polls"
    );

    // Explicit close and endpoint drain provide a real lifecycle-progress
    // assertion without relying on a paused or simulated clock.
    done_tx.send(()).unwrap();
    server_task.await.unwrap();
    connection.closed().await;
    client.close(0u32.into(), b"test complete");
    client.wait_all_draining().await;
    server.close(0u32.into(), b"test complete");
    server.wait_all_draining().await;
    client.wait_idle().await;
    server.wait_idle().await;
}
