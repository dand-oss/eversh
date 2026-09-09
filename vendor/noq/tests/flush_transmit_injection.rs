#![cfg(all(
    feature = "immediate-datagram-flush",
    feature = "inline-received-events",
    feature = "rustls",
    feature = "ring",
    feature = "runtime-tokio"
))]

#[cfg(feature = "packet-diagnostics")]
use std::collections::HashSet;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use noq::{
    AsyncUdpSocket, ClientConfig, Endpoint, EndpointConfig, Runtime, ServerConfig, TokioRuntime,
    UdpSender,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

#[cfg(feature = "packet-diagnostics")]
static PACKET_EVENTS: Mutex<Vec<noq::diagnostic::Event>> = Mutex::new(Vec::new());

#[cfg(feature = "packet-diagnostics")]
static PROTOCOL_EVENTS: Mutex<Vec<noq::packet_diagnostic::Event>> = Mutex::new(Vec::new());

#[cfg(feature = "packet-diagnostics")]
fn record_packet(event: noq::diagnostic::Event) {
    if matches!(
        event,
        noq::diagnostic::Event::PacketTransmit { .. }
            | noq::diagnostic::Event::DatagramReceived { .. }
    ) {
        let mut events = PACKET_EVENTS.lock().unwrap();
        assert!(
            events.len() < events.capacity(),
            "diagnostic test buffer exhausted"
        );
        events.push(event);
    }
}

#[cfg(feature = "packet-diagnostics")]
fn record_protocol(event: noq::packet_diagnostic::Event) {
    assert!(
        !matches!(event, noq::packet_diagnostic::Event::UnsupportedPath { .. }),
        "single-path test emitted unsupported-path marker"
    );
    if matches!(
        event,
        noq::packet_diagnostic::Event::PacketBuilt { .. }
            | noq::packet_diagnostic::Event::StreamSent { .. }
            | noq::packet_diagnostic::Event::PacketAuthenticated { .. }
            | noq::packet_diagnostic::Event::StreamReceived { .. }
    ) {
        let mut events = PROTOCOL_EVENTS.lock().unwrap();
        assert!(
            events.len() < events.capacity(),
            "protocol diagnostic test buffer exhausted"
        );
        events.push(event);
    }
}

#[derive(Debug)]
struct ArmState {
    mode: std::sync::atomic::AtomicU8,
    pending_hits: std::sync::atomic::AtomicUsize,
    error_hits: std::sync::atomic::AtomicUsize,
    wakers: Mutex<Vec<std::task::Waker>>,
}

impl ArmState {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            mode: std::sync::atomic::AtomicU8::new(0),
            pending_hits: std::sync::atomic::AtomicUsize::new(0),
            error_hits: std::sync::atomic::AtomicUsize::new(0),
            wakers: Mutex::new(Vec::new()),
        })
    }

    fn pending(&self) {
        self.mode.store(1, std::sync::atomic::Ordering::SeqCst);
    }

    fn error(&self) {
        self.mode.store(2, std::sync::atomic::Ordering::SeqCst);
    }

    fn release(&self) {
        self.mode.store(0, std::sync::atomic::Ordering::SeqCst);
        let wakers = std::mem::take(&mut *self.wakers.lock().unwrap());
        for waker in wakers {
            waker.wake();
        }
    }
}

#[derive(Debug)]
struct InjectedSocket {
    inner: Box<dyn AsyncUdpSocket>,
    state: Arc<ArmState>,
}

impl AsyncUdpSocket for InjectedSocket {
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
        Box::pin(InjectedSender {
            inner: self.inner.create_sender(),
            state: self.state.clone(),
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [noq::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_receive_segments(&self) -> NonZeroUsize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[derive(Debug)]
struct InjectedSender {
    inner: Pin<Box<dyn UdpSender>>,
    state: Arc<ArmState>,
}

impl UdpSender for InjectedSender {
    fn poll_send(
        mut self: Pin<&mut Self>,
        transmit: &noq::udp::Transmit<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        match self.state.mode.load(std::sync::atomic::Ordering::SeqCst) {
            1 => {
                self.state
                    .pending_hits
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut wakers = self.state.wakers.lock().unwrap();
                if !wakers.iter().any(|waker| waker.will_wake(cx.waker())) {
                    wakers.push(cx.waker().clone());
                }
                Poll::Pending
            }
            2 => {
                self.state
                    .error_hits
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "injected transmit failure",
                )))
            }
            _ => self.inner.as_mut().poll_send(transmit, cx),
        }
    }

    fn max_transmit_segments(&self) -> NonZeroUsize {
        self.inner.max_transmit_segments()
    }
}

#[tokio::test(flavor = "current_thread")]
async fn flush_transmit_preserves_pending_and_propagates_error() {
    tokio::time::timeout(Duration::from_secs(10), exercise())
        .await
        .unwrap();
}

async fn exercise() {
    #[cfg(feature = "packet-diagnostics")]
    {
        *PACKET_EVENTS.lock().unwrap() = Vec::with_capacity(4096);
        *PROTOCOL_EVENTS.lock().unwrap() = Vec::with_capacity(4096);
        noq::diagnostic::install(record_packet).unwrap();
        noq::packet_diagnostic::install(record_protocol).unwrap();
    }
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert);
    let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let server_config = ServerConfig::with_single_cert(vec![cert_der.clone()], key.into()).unwrap();
    let server = Endpoint::server(server_config, SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    let runtime = Arc::new(TokioRuntime);
    let socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    socket.set_nonblocking(true).unwrap();
    let state = ArmState::new();
    let wrapped = runtime.wrap_udp_socket(socket).unwrap();
    let client = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        None,
        Box::new(InjectedSocket {
            inner: wrapped,
            state: state.clone(),
        }),
        runtime,
    )
    .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    client
        .set_default_client_config(ClientConfig::with_root_certificates(Arc::new(roots)).unwrap());
    let server_addr = server.local_addr().unwrap();
    let (hold_tx, hold_rx) = tokio::sync::oneshot::channel();
    let (delivered_tx, delivered_rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        let connection = incoming.await.unwrap();
        let mut send = connection.open_uni().await.unwrap();
        send.write_all(b"flush-test").await.unwrap();
        send.finish().unwrap();
        let mut incoming = connection.accept_uni().await.unwrap();
        let received = incoming.read_to_end(64).await.unwrap();
        assert_eq!(received, b"retry-test");
        delivered_tx.send(()).unwrap();
        hold_rx.await.unwrap();
    });
    let connection = client
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let mut recv = connection.accept_uni().await.unwrap();
    let got = recv.read_to_end(64).await.unwrap();
    assert_eq!(got, b"flush-test");

    state.pending();
    let mut send = connection.open_uni().await.unwrap();
    send.write_all(b"retry-test").await.unwrap();
    let before = state.pending_hits.load(std::sync::atomic::Ordering::SeqCst);
    std::future::poll_fn(|cx| Poll::Ready(connection.flush_transmit_now(cx)))
        .await
        .unwrap();
    assert!(
        state.pending_hits.load(std::sync::atomic::Ordering::SeqCst) > before,
        "explicit flush must hit the injected Pending"
    );
    let after_flush = state.pending_hits.load(std::sync::atomic::Ordering::SeqCst);
    send.finish().unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if state.pending_hits.load(std::sync::atomic::Ordering::SeqCst) > after_flush {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    state.release();
    // No second explicit flush: the normal driver must deliver the retained
    // transmit after socket wake, including the exact stream ending.
    delivered_rx.await.unwrap();
    state.error();
    connection.close(0u32.into(), b"error");
    let error = std::future::poll_fn(|cx| Poll::Ready(connection.flush_transmit_now(cx))).await;
    assert_eq!(error.unwrap_err().kind(), io::ErrorKind::ConnectionReset);
    assert_eq!(
        state.error_hits.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    hold_tx.send(()).unwrap();
    server_task.await.unwrap();
    #[cfg(feature = "packet-diagnostics")]
    {
        use noq::diagnostic::{Event::PacketTransmit, TransmitOutcome};
        use noq::packet_diagnostic::Event::{PacketBuilt, StreamSent};
        let events = PACKET_EVENTS.lock().unwrap();
        let mut received_cookies = HashSet::new();
        for event in events.iter() {
            if let noq::diagnostic::Event::DatagramReceived { cookie, bytes } = event {
                assert_ne!(*cookie, 0);
                assert!(*bytes > 0);
                assert!(received_cookies.insert(*cookie), "receive cookie reused");
            }
        }
        assert!(
            !received_cookies.is_empty(),
            "no received UDP segments recorded"
        );
        for event in events.iter() {
            if let PacketTransmit { cookie, .. } = event {
                assert!(
                    !received_cookies.contains(cookie),
                    "send and receive cookies collide"
                );
            }
        }
        let blocked: Vec<_> = events
            .iter()
            .enumerate()
            .filter_map(|(index, event)| {
                if let PacketTransmit {
                    connection,
                    cookie,
                    bytes,
                    segment_size,
                    outcome: TransmitOutcome::Blocked,
                } = event
                {
                    Some((index, *connection, *cookie, *bytes, *segment_size))
                } else {
                    None
                }
            })
            .collect();
        assert!(!blocked.is_empty());
        for (index, connection, cookie, bytes, segment_size) in &blocked {
            assert_ne!(*cookie, 0);
            assert!(
                events[*index + 1..].iter().any(|event| *event
                    == PacketTransmit {
                        connection: *connection,
                        cookie: *cookie,
                        bytes: *bytes,
                        segment_size: *segment_size,
                        outcome: TransmitOutcome::Accepted,
                    }),
                "blocked transmit must keep its identity through eventual acceptance"
            );
        }
        assert!(events.iter().any(|event| matches!(
            event,
            PacketTransmit {
                outcome: TransmitOutcome::Error,
                ..
            }
        )));

        let protocol_events = PROTOCOL_EVENTS.lock().unwrap();
        use noq::packet_diagnostic::{
            Direction, Event::PacketAuthenticated, Event::StreamReceived,
        };
        let authenticated: Vec<_> = protocol_events.iter().filter_map(|event| {
            if let PacketAuthenticated { context, packet_number, number_space, packet_offset, packet_len } = event {
                assert_eq!(context.direction, Direction::Receive);
                assert!(events.iter().any(|event| matches!(event,
                    noq::diagnostic::Event::DatagramReceived { cookie, bytes }
                        if *cookie == context.cookie && packet_offset.checked_add(*packet_len).is_some_and(|end| end <= *bytes)
                )), "authenticated packet must fit its original received segment");
                Some((*context, *packet_number, *number_space))
            } else { None }
        }).collect();
        assert!(!authenticated.is_empty());
        for expected_stream in [2, 3] {
            assert!(protocol_events.iter().any(|event| matches!(event,
                StreamReceived { context, packet_number, number_space, stream, offset: 0, length: 10, .. }
                    if *stream == expected_stream && authenticated.contains(&(*context, *packet_number, *number_space))
            )), "received exact stream range must join its authenticated packet");
        }
        let builds: Vec<_> = protocol_events
            .iter()
            .filter_map(|event| match event {
                PacketBuilt {
                    context,
                    packet_number,
                    number_space,
                    packet_offset,
                    packet_len,
                } => Some((
                    *context,
                    *packet_number,
                    *number_space,
                    *packet_offset,
                    *packet_len,
                )),
                _ => None,
            })
            .collect();
        let stream_ranges: Vec<_> = protocol_events
            .iter()
            .filter_map(|event| match event {
                StreamSent {
                    context,
                    packet_number,
                    number_space,
                    ..
                } => Some((*context, *packet_number, *number_space)),
                _ => None,
            })
            .collect();
        assert!(!stream_ranges.is_empty(), "no stream frames observed");
        // Each endpoint writes exactly ten bytes on its first unidirectional
        // stream. Check real byte ranges, not only packet-event proximity.
        for expected_stream in [2, 3] {
            assert!(
                protocol_events.iter().any(|event| matches!(event,
                    StreamSent { stream, offset: 0, length: 10, .. }
                        if *stream == expected_stream
                )),
                "missing exact initial stream range"
            );
        }

        let mut unique_builds = HashSet::new();
        for (context, packet_number, number_space, packet_offset, packet_len) in &builds {
            assert!(*packet_len > 0, "built packet length must be nonzero");
            assert!(
                unique_builds.insert((context.cookie, *packet_number, *number_space)),
                "duplicate PacketBuilt for one cookie/packet number space"
            );
            let transmit = events.iter().any(|event| {
                matches!(
                    event,
                    PacketTransmit {
                        connection,
                        cookie,
                        bytes,
                        segment_size: transmit_segment_size,
                        ..
                    } if *connection == context.connection
                        && *cookie == context.cookie
                        && (*packet_offset)
                            .checked_add(*packet_len)
                            .is_some_and(|end| end <= *bytes)
                        && match (transmit_segment_size, *packet_len) {
                            (Some(segment_size), packet_len) => {
                                packet_len <= *segment_size
                                    && *packet_offset / *segment_size
                                        == (*packet_offset + packet_len - 1) / *segment_size
                            }
                            (None, _) => true,
                        }
                )
            });
            assert!(
                transmit,
                "built packet range must fit its transmit buffer and one GSO segment"
            );
        }

        for (context, packet_number, number_space) in &stream_ranges {
            assert!(
                builds.iter().any(
                    |(built_context, built_packet_number, built_number_space, ..)| {
                        built_context == context
                            && built_packet_number == packet_number
                            && built_number_space == number_space
                    }
                ),
                "every StreamSent event must join a PacketBuilt event"
            );
        }

        let blocked_with_stream = blocked.iter().any(|(_, connection, cookie, _, _)| {
            builds
                .iter()
                .any(|(context, ..)| context.connection == *connection && context.cookie == *cookie)
                && stream_ranges.iter().any(|(context, ..)| {
                    context.connection == *connection && context.cookie == *cookie
                })
        });
        assert!(
            blocked_with_stream,
            "no blocked cookie has both PacketBuilt and StreamSent events"
        );
    }
}
