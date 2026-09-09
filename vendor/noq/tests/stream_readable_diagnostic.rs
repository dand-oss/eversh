#![cfg(all(
    feature = "diagnostic-events",
    feature = "rustls",
    feature = "ring",
    feature = "runtime-tokio"
))]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::Poll;

use noq::diagnostic::{self, Event};
use noq::{ClientConfig, Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

static STREAM_READABLES: AtomicUsize = AtomicUsize::new(0);
static LAST_STREAM: AtomicU64 = AtomicU64::new(u64::MAX);

fn record(event: Event) {
    if let Event::StreamReadable { stream, .. } = event {
        LAST_STREAM.store(stream, Ordering::Relaxed);
        STREAM_READABLES.fetch_add(1, Ordering::Relaxed);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn buffered_stream_read_emits_matching_stream_readable() {
    tokio::time::timeout(std::time::Duration::from_secs(10), exercise_stream())
        .await
        .expect("stream diagnostic test timed out");
}

async fn exercise_stream() {
    diagnostic::install(record).expect("install callback");

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
    let (permit_tx, permit_rx) = tokio::sync::oneshot::channel();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        let connection = incoming.await.unwrap();
        let mut send = connection.open_uni().await.unwrap();
        send.write_all(&[0x11]).await.unwrap();
        permit_rx.await.unwrap();
        send.write_all(&[0x22]).await.unwrap();
        send.finish().unwrap();
        done_rx.await.unwrap();
    });
    let connection = client
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let mut recv = connection.accept_uni().await.unwrap();
    let stream_id = u64::from(recv.id());
    let mut first = [0_u8; 1];
    recv.read_exact(&mut first).await.unwrap();
    assert_eq!(first, [0x11]);
    STREAM_READABLES.store(0, Ordering::Relaxed);
    LAST_STREAM.store(u64::MAX, Ordering::Relaxed);
    let mut second = [0_u8; 1];
    let mut pending_read = Box::pin(recv.read_exact(&mut second));
    let was_pending =
        std::future::poll_fn(|cx| Poll::Ready(pending_read.as_mut().poll(cx).is_pending())).await;
    assert!(was_pending, "second read unexpectedly had buffered data");
    permit_tx.send(()).unwrap();
    pending_read.await.unwrap();
    assert_eq!(second, [0x22]);
    done_tx.send(()).unwrap();
    server_task.await.unwrap();
    assert!(STREAM_READABLES.load(Ordering::Relaxed) > 0);
    assert_eq!(LAST_STREAM.load(Ordering::Relaxed), stream_id);
}
