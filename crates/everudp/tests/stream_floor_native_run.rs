//! Real UDP/descriptor integration of the native owner; not a timing fixture.
#![cfg(feature = "stream-floor")]

use everpty::sys::{poll, PollFd, PollFlags};
use everssh::association::AssociationId;
use everudp::floor_pump::{FloorLimits, FloorPump};
use everudp::floor_reactor::FloorReactor;
use everudp::floor_socket::FloorSocket;
use everudp::stream_floor_fd::Descriptor;
use everudp::stream_floor_native::{NativeClientHandshake, NativeHandshakePoll};
use everudp::stream_floor_native_client::NativeClient;
use everudp::stream_floor_native_run::{run_until, RunOutcome};
use everudp::stream_floor_ordinary::{serve_echo, server_handshake_until};
use everudp::transport::{stream_floor_client_config, stream_floor_server_config};
use everudp::wire::ConnectionRole;
use everudp::{
    ClientHello, ClientIdentity, GatewayGeneration, GatewayIdentity, InvitationStore, Limits,
    ResumePosition,
};
use noq_proto::{EndpointConfig, Event};
use std::net::UdpSocket;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test(flavor = "current_thread")]
async fn native_owner_delivers_six_mib_over_authenticated_udp_and_real_descriptors() {
    tokio::time::timeout(Duration::from_secs(25), async {
        let limits = Limits::default();
        let server_identity = GatewayIdentity::generate().expect("server identity");
        let client_identity = ClientIdentity::generate().expect("client identity");
        let server = noq::Endpoint::server(
            stream_floor_server_config(&server_identity, &limits).expect("server config"),
            "127.0.0.1:0".parse().expect("address"),
        )
        .expect("server endpoint");
        let address = server.local_addr().expect("server address");
        let (config, mismatch) =
            stream_floor_client_config(&client_identity, server_identity.spki_sha256(), &limits)
                .expect("client config");
        let association = AssociationId::from_bytes([7; 16]).expect("association");
        let generation = GatewayGeneration::from_bytes([8; 16]).expect("generation");
        let mut invitations =
            InvitationStore::new("native-run", generation, &limits).expect("store");
        let ticket = invitations
            .issue(
                association,
                ConnectionRole::Writer,
                client_identity.spki_sha256(),
                everpty::sys::clock_monotonic_ms().expect("clock"),
            )
            .expect("invitation");
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
        let (input_fd, feed_fd) = UnixStream::pair().expect("input pair");
        let (output_fd, drain_fd) = UnixStream::pair().expect("output pair");
        feed_fd.set_nonblocking(true).expect("feed flags");
        drain_fd.set_nonblocking(true).expect("drain flags");
        let mut feeder = tokio::net::UnixStream::from_std(feed_fd).expect("feeder");
        let mut drain = tokio::net::UnixStream::from_std(drain_fd).expect("drain");
        let (finished, finish_rx) = std::sync::mpsc::sync_channel(1);

        // The fixture peer uses Tokio, but the native owner thread does not
        // construct a runtime or use asynchronous descriptor wrappers.
        let native = tokio::task::spawn_blocking(move || {
            let endpoint = EndpointConfig::default();
            let socket = FloorSocket::new_stream_floor(
                UdpSocket::bind("127.0.0.1:0").expect("bind"),
                &endpoint,
            )
            .expect("socket");
            let mut pump = FloorPump::client_with_mtud(
                endpoint,
                FloorLimits::default(),
                !socket.may_fragment(),
            );
            let handle = pump
                .connect(config, address, "localhost", Instant::now())
                .expect("connect");
            let mut reactor = FloorReactor::new(pump, socket);
            let admission_deadline = Instant::now() + Duration::from_secs(3);
            let mut handshake =
                NativeClientHandshake::new(hello, limits, admission_deadline).expect("handshake");
            let mut retained = Vec::new();
            let control = loop {
                assert!(Instant::now() < admission_deadline, "admission deadline");
                reactor.step(Instant::now()).expect("admission drive");
                while let Some((owner, event)) = reactor.pump_mut().poll_event() {
                    assert_eq!(owner, handle);
                    assert!(
                        !matches!(event, Event::ConnectionLost { .. }),
                        "TLS connection lost"
                    );
                    assert!(retained.len() < 128, "bounded pre-admission events");
                    retained.push(event);
                }
                let state = handshake
                    .poll(
                        reactor
                            .pump_mut()
                            .connection_mut(handle)
                            .expect("connection"),
                        Instant::now(),
                    )
                    .expect("admission poll");
                reactor
                    .step(Instant::now())
                    .expect("admission transmission");
                if let NativeHandshakePoll::Ready { stream } = state {
                    break stream;
                }
                let mut fds = [PollFd::new(reactor.socket().as_fd(), PollFlags::POLLIN)];
                poll(&mut fds, Some(1)).expect("admission wait");
            };
            assert!(!mismatch.observed(), "SPKI pin");
            let mut client = NativeClient::new(control, limits).expect("client");
            for event in retained {
                client
                    .event(
                        reactor
                            .pump_mut()
                            .connection_mut(handle)
                            .expect("connection"),
                        &event,
                        Instant::now(),
                    )
                    .expect("retained event");
            }
            let mut input = Descriptor::new(input_fd.as_fd()).expect("input");
            let mut output = Descriptor::new(output_fd.as_fd()).expect("output");
            let deadline = Instant::now() + Duration::from_secs(20);
            let outcome = run_until(
                &mut reactor,
                handle,
                &mut client,
                &mut input,
                &mut output,
                None,
                deadline,
            )
            .expect("native owner");
            // Output delivery can precede the server observing its final ACK.
            // Keep driving the retained owner until the peer confirms completion.
            loop {
                assert!(
                    Instant::now() < deadline,
                    "peer FIN acknowledgment deadline"
                );
                reactor.step(Instant::now()).expect("completion drive");
                while let Some((_, event)) = reactor.pump_mut().poll_event() {
                    client
                        .event(
                            reactor
                                .pump_mut()
                                .connection_mut(handle)
                                .expect("connection"),
                            &event,
                            Instant::now(),
                        )
                        .expect("completion event");
                }
                match finish_rx.try_recv() {
                    Ok(()) => break,
                    Err(std::sync::mpsc::TryRecvError::Empty) => {}
                    Err(error) => panic!("peer completion lost: {error}"),
                }
                let mut fds = [PollFd::new(reactor.socket().as_fd(), PollFlags::POLLIN)];
                poll(&mut fds, Some(1)).expect("completion wait");
            }
            reactor
                .pump_mut()
                .connection_mut(handle)
                .expect("connection")
                .close(
                    Instant::now(),
                    noq_proto::VarInt::from_u32(0),
                    bytes::Bytes::from_static(b"verified delivery"),
                );
            reactor.step(Instant::now()).expect("close transmission");
            outcome
        });
        let serve = async {
            let connection = loop {
                let incoming = server.accept().await.expect("incoming");
                if !incoming.remote_address_validated() {
                    incoming.retry().expect("retry");
                    continue;
                }
                break incoming.await.expect("server TLS");
            };
            let control = server_handshake_until(
                connection,
                &mut invitations,
                limits,
                Duration::from_secs(3),
            )
            .await
            .expect("server admission");
            let owner = serve_echo(control, limits).await.expect("server echo");
            finished.send(()).expect("completion notification");
            owner
        };
        let expected: Vec<u8> = (0..6 * 1024 * 1024)
            .map(|index| (index % 251) as u8)
            .collect();
        let feed = async {
            feeder.write_all(&expected).await.expect("feed");
            feeder.shutdown().await.expect("input EOF");
        };
        let receive = async {
            let mut actual = vec![0; expected.len()];
            drain.read_exact(&mut actual).await.expect("output");
            actual
        };
        let (owner, outcome, (), actual) = tokio::join!(serve, native, feed, receive);
        assert_eq!(
            outcome.expect("native thread"),
            RunOutcome::Complete {
                bytes: expected.len() as u64
            }
        );
        assert_eq!(actual, expected);
        drop(owner);
        server.wait_idle().await;
    })
    .await
    .expect("bounded live owner test");
}
