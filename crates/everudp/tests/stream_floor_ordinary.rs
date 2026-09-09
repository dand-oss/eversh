#![cfg(feature = "stream-floor")]

use everssh::association::AssociationId;
use everudp::stream_floor_app::{InputSource, OutputSink};
use everudp::stream_floor_io::{ReadProgress, RecordReader, RecordWriter};
use everudp::stream_floor_ordinary::{client_handshake, server_handshake_until};
use everudp::transport::{stream_floor_client_config, stream_floor_server_config};
use everudp::wire::{ConnectionRole, Kind, StreamRole};
use everudp::{
    ClientHello, ClientIdentity, GatewayGeneration, GatewayIdentity, InvitationStore, Limits,
    ResumePosition, TransportError,
};
use std::time::Duration;

async fn connected_pair(
    server_identity: &GatewayIdentity,
    client_identity: &ClientIdentity,
) -> (
    noq::Connection,
    noq::Connection,
    noq::Endpoint,
    noq::Endpoint,
) {
    let limits = Limits::default();
    let server = noq::Endpoint::server(
        stream_floor_server_config(server_identity, &limits).expect("server config"),
        "127.0.0.1:0".parse().expect("server address"),
    )
    .expect("server endpoint");
    let client = noq::Endpoint::client("127.0.0.1:0".parse().expect("client address"))
        .expect("client endpoint");
    let (config, mismatch) =
        stream_floor_client_config(client_identity, server_identity.spki_sha256(), &limits)
            .expect("client config");
    client.set_default_client_config(config);
    let connecting = client
        .connect(server.local_addr().expect("server address"), "localhost")
        .expect("connect");
    let accepting = async {
        loop {
            let incoming = server.accept().await.expect("incoming");
            if !incoming.remote_address_validated() {
                incoming.retry().expect("retry");
                continue;
            }
            break incoming.await.expect("server TLS");
        }
    };
    let (client_connection, server_connection) = tokio::join!(connecting, accepting);
    assert!(!mismatch.observed());
    (
        client_connection.expect("client TLS"),
        server_connection,
        client,
        server,
    )
}

#[tokio::test(flavor = "current_thread")]
async fn negotiated_profile_uses_live_tls_and_rejects_missing_or_mismatched_properties() {
    use everudp::stream_floor_protocol::validate_negotiated_profile;
    tokio::time::timeout(Duration::from_secs(10), async {
        let server_identity = GatewayIdentity::generate().expect("server identity");
        let client_identity = ClientIdentity::generate().expect("client identity");
        let (client_connection, server_connection, client, server) =
            connected_pair(&server_identity, &client_identity).await;
        for connection in [&client_connection, &server_connection] {
            validate_negotiated_profile(
                connection.handshake_data(),
                connection.max_datagram_size(),
            )
            .expect("live stream-only profile");
            assert!(validate_negotiated_profile(None, None).is_err());
            assert!(validate_negotiated_profile(Some(Box::new(())), None).is_err());
            assert!(validate_negotiated_profile(connection.handshake_data(), Some(1200)).is_err());
            for protocol in [None, Some(b"wrong-product/1".to_vec())] {
                let mut data = connection
                    .handshake_data()
                    .expect("live handshake")
                    .downcast::<noq_proto::crypto::rustls::HandshakeData>()
                    .expect("rustls handshake");
                data.protocol = protocol;
                assert!(validate_negotiated_profile(Some(data), None).is_err());
            }
        }
        client.close(0_u32.into(), b"profile test complete");
        server.close(0_u32.into(), b"profile test complete");
    })
    .await
    .expect("bounded profile test");
}

fn hello(token: everssh::bootstrap::SecretToken) -> ClientHello {
    ClientHello::initial(
        AssociationId::from_bytes([7; 16]).expect("association"),
        GatewayGeneration::from_bytes([8; 16]).expect("generation"),
        ConnectionRole::Writer,
        ResumePosition {
            input_epoch: 0,
            next_input: 0,
            output_epoch: 0,
            next_output: 0,
            delivered_output_ack: 0,
        },
        token,
    )
    .expect("hello")
}

fn invitation(
    client: &ClientIdentity,
    limits: &Limits,
) -> (InvitationStore, everssh::bootstrap::SecretToken) {
    let generation = GatewayGeneration::from_bytes([8; 16]).expect("generation");
    let mut store = InvitationStore::new("ordinary", generation, limits).expect("store");
    let now = everpty::sys::clock_monotonic_ms().expect("clock");
    let ticket = store
        .issue(
            AssociationId::from_bytes([7; 16]).expect("association"),
            ConnectionRole::Writer,
            client.spki_sha256(),
            now,
        )
        .expect("ticket");
    (store, ticket.token().clone())
}

#[tokio::test(flavor = "current_thread")]
async fn valid_client_and_server_handshake_retain_control_streams() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let limits = Limits::default();
        let server_identity = GatewayIdentity::generate().expect("server identity");
        let client_identity = ClientIdentity::generate().expect("client identity");
        let (client_connection, server_connection, client, server) =
            connected_pair(&server_identity, &client_identity).await;
        let (mut invitations, token) = invitation(&client_identity, &limits);
        let expected = hello(token);
        let (server_result, client_result) = tokio::join!(
            server_handshake_until(
                server_connection,
                &mut invitations,
                limits,
                Duration::from_secs(3)
            ),
            client_handshake(client_connection, expected, limits),
        );
        let mut server_control = server_result.expect("server handshake");
        let mut client_control = client_result.expect("client handshake");
        assert_eq!(server_control.send.id(), server_control.recv.id());
        assert_eq!(client_control.send.id(), client_control.recv.id());
        assert_eq!(server_control.send.id(), client_control.send.id());
        let mut writer = RecordWriter::new(StreamRole::Control, limits).expect("writer");
        writer
            .load(Kind::LinkStatus, 0, b"post-handshake")
            .expect("follow-on record");
        while !writer.is_complete() {
            std::future::poll_fn(|cx| writer.poll_write_ordinary(&mut client_control.send, cx))
                .await
                .expect("follow-on write");
        }
        let mut reader = RecordReader::new(StreamRole::Control, limits).expect("reader");
        loop {
            match std::future::poll_fn(|cx| reader.poll_read_ordinary(&mut server_control.recv, cx))
                .await
                .expect("follow-on read")
            {
                ReadProgress::Consumed(_) => continue,
                ReadProgress::Record(_) => {
                    let record = reader.record().expect("follow-on record");
                    assert_eq!(record.header.kind, Kind::LinkStatus);
                    assert_eq!(record.header.sequence, 0);
                    assert_eq!(record.payload, b"post-handshake");
                    assert!(reader.consume_record());
                    break;
                }
                ReadProgress::CleanEof => panic!("control closed before follow-on record"),
            }
        }
        server_control.close();
        client_control.close();
        server.wait_idle().await;
        client.wait_idle().await;
    })
    .await
    .expect("bounded ordinary handshake");
}

#[tokio::test(flavor = "current_thread")]
async fn wrong_token_is_rejected_and_connection_is_closed() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let limits = Limits::default();
        let server_identity = GatewayIdentity::generate().expect("server identity");
        let client_identity = ClientIdentity::generate().expect("client identity");
        let (client_connection, server_connection, client, server) =
            connected_pair(&server_identity, &client_identity).await;
        let server_closed = server_connection.clone();
        let client_closed = client_connection.clone();
        let (mut invitations, _) = invitation(&client_identity, &limits);
        let expected = hello(everssh::bootstrap::SecretToken::from_bytes([0xA5; 32]));
        let (server_result, client_result) = tokio::join!(
            server_handshake_until(
                server_connection,
                &mut invitations,
                limits,
                Duration::from_secs(3)
            ),
            client_handshake(client_connection, expected, limits),
        );
        assert!(matches!(server_result, Err(TransportError::Admission(_))));
        assert!(client_result.is_err());
        tokio::time::timeout(Duration::from_secs(1), server_closed.closed())
            .await
            .expect("server peer close");
        tokio::time::timeout(Duration::from_secs(1), client_closed.closed())
            .await
            .expect("client peer close");
        server.wait_idle().await;
        client.wait_idle().await;
    })
    .await
    .expect("bounded wrong-token handshake");
}

#[tokio::test(flavor = "current_thread")]
async fn silent_peer_times_out_and_is_closed() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let limits = Limits::default();
        let server_identity = GatewayIdentity::generate().expect("server identity");
        let client_identity = ClientIdentity::generate().expect("client identity");
        let (client_connection, server_connection, client, server) =
            connected_pair(&server_identity, &client_identity).await;
        let server_closed = server_connection.clone();
        let (mut invitations, _) = invitation(&client_identity, &limits);
        let result = server_handshake_until(
            server_connection,
            &mut invitations,
            limits,
            Duration::from_millis(25),
        )
        .await;
        assert!(matches!(result, Err(TransportError::Timeout)));
        tokio::time::timeout(Duration::from_secs(1), server_closed.closed())
            .await
            .expect("silent peer close");
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), client_connection.closed())
                .await
                .expect("remote observes timeout close"),
            noq::ConnectionError::ApplicationClosed(_)
        ));
        server.wait_idle().await;
        client.wait_idle().await;
    })
    .await
    .expect("bounded silent handshake");
}

#[tokio::test(flavor = "current_thread")]
async fn nonzero_control_sequence_is_rejected_before_admission() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let limits = Limits::default();
        let server_identity = GatewayIdentity::generate().expect("server identity");
        let client_identity = ClientIdentity::generate().expect("client identity");
        let (client_connection, server_connection, client, server) =
            connected_pair(&server_identity, &client_identity).await;
        let (mut invitations, token) = invitation(&client_identity, &limits);
        let hello = hello(token);
        let (mut send, _recv) = client_connection.open_bi().await.expect("control");
        send.set_priority(2).expect("priority");
        let mut payload = [0; ClientHello::MAX_ENCODED_LEN];
        let used = hello.encode_into(&mut payload).expect("hello encoding");
        let mut writer = RecordWriter::new(StreamRole::Control, limits).expect("writer");
        writer
            .load(Kind::ClientHello, 1, &payload[..used])
            .expect("wrong sequence");
        while !writer.is_complete() {
            std::future::poll_fn(|cx| writer.poll_write_ordinary(&mut send, cx))
                .await
                .expect("wrong record write");
        }
        let result = server_handshake_until(
            server_connection,
            &mut invitations,
            limits,
            Duration::from_secs(3),
        )
        .await;
        assert!(matches!(result, Err(TransportError::Rejected)));
        client_connection.close(noq::VarInt::from_u32(0), b"malformed handshake");
        server.wait_idle().await;
        client.wait_idle().await;
    })
    .await
    .expect("bounded malformed handshake");
}

#[tokio::test(flavor = "current_thread")]
async fn authenticated_three_stream_echo_preserves_large_data_and_control() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let limits = Limits::default();
        let server_identity = GatewayIdentity::generate().expect("server identity");
        let client_identity = ClientIdentity::generate().expect("client identity");
        let (client_connection, server_connection, client, server) =
            connected_pair(&server_identity, &client_identity).await;
        let (mut invitations, token) = invitation(&client_identity, &limits);
        let (server_control, client_control) = tokio::join!(
            server_handshake_until(
                server_connection,
                &mut invitations,
                limits,
                Duration::from_secs(3)
            ),
            client_handshake(client_connection, hello(token), limits)
        );
        let server_control = server_control.expect("server admission");
        let mut client_control = client_control.expect("client admission");
        let connection = client_control.connection.clone();
        let send_connection = connection.clone();
        let receive_connection = connection.clone();
        let payload: Vec<u8> = (0..65536).map(|n| (n % 251) as u8).collect();
        let send_data = async {
            let mut stream = send_connection.open_uni().await.expect("input stream");
            stream.set_priority(1).expect("input priority");
            let mut source = InputSource::new(limits).expect("input source");
            let total = 96 * payload.len();
            while (source.bytes_read() as usize) < total {
                let offset = source.bytes_read() as usize;
                let buffer = source.buffer().expect("previous input fully sent");
                let count = buffer.len().min(total - offset);
                for (index, byte) in buffer[..count].iter_mut().enumerate() {
                    *byte = payload[(offset + index) % payload.len()];
                }
                source.commit_read(count).expect("local input acceptance");
                assert!(
                    source.buffer().is_none(),
                    "pending input backpressures local reads"
                );
                let writer = source.writer().expect("framed input");
                while !writer.is_complete() {
                    std::future::poll_fn(|cx| writer.poll_write_ordinary(&mut stream, cx))
                        .await
                        .expect("input write");
                }
            }
            source.commit_read(0).expect("local EOF");
            assert!(source.finish_ready());
            assert_eq!(source.bytes_read(), total as u64);
            stream.finish().expect("input FIN");
            assert_eq!(stream.stopped().await.expect("input acknowledged"), None);
        };
        let receive_data = async {
            let mut stream = receive_connection
                .accept_uni()
                .await
                .expect("output stream");
            let mut sink = OutputSink::new(limits).expect("sink");
            let mut received = 0_usize;
            loop {
                let reader = sink.reader().expect("unblocked sink");
                match std::future::poll_fn(|cx| reader.poll_read_ordinary(&mut stream, cx))
                    .await
                    .expect("output read")
                {
                    ReadProgress::Consumed(_) => continue,
                    ReadProgress::CleanEof => break,
                    ReadProgress::Record(_) => {
                        assert!(sink.stage().expect("output validation"));
                        assert!(!sink.commit(0).expect("temporary sink stall"));
                        while let Some(bytes) = sink.pending() {
                            let count = bytes.len().min(257);
                            let offset = received % payload.len();
                            assert_eq!(&bytes[..count], &payload[offset..offset + count]);
                            received += count;
                            sink.commit(count).expect("partial sink acceptance");
                        }
                    }
                }
            }
            assert_eq!(received, 96 * payload.len());
        };
        let ping = async {
            let mut writer =
                RecordWriter::new(StreamRole::Control, limits).expect("control writer");
            writer
                .load(Kind::LinkStatus, 0, b"control-progress")
                .expect("ping");
            while !writer.is_complete() {
                std::future::poll_fn(|cx| writer.poll_write_ordinary(&mut client_control.send, cx))
                    .await
                    .expect("ping write");
            }
            let mut reader =
                RecordReader::new(StreamRole::Control, limits).expect("control reader");
            loop {
                match std::future::poll_fn(|cx| {
                    reader.poll_read_ordinary(&mut client_control.recv, cx)
                })
                .await
                .expect("pong read")
                {
                    ReadProgress::Consumed(_) => continue,
                    ReadProgress::Record(_) => {
                        let record = reader.record().expect("pong");
                        assert_eq!(record.header.kind, Kind::LinkStatus);
                        assert_eq!(record.header.sequence, 0);
                        assert_eq!(record.payload, b"control-progress");
                        break;
                    }
                    ReadProgress::CleanEof => panic!("control ended without pong"),
                }
            }
        };
        let server_echo = everudp::stream_floor_ordinary::serve_echo(server_control, limits);
        let (served, (), (), ()) = tokio::join!(server_echo, send_data, receive_data, ping);
        served.expect("server echo completion");
        connection.close(noq::VarInt::from_u32(0), b"echo verified");
        client.wait_idle().await;
        server.wait_idle().await;
    })
    .await
    .expect("bounded three-stream echo");
}

#[tokio::test(flavor = "current_thread")]
async fn ordinary_echo_stop_reset_and_control_eof_close_the_connection() {
    tokio::time::timeout(Duration::from_secs(20), async {
        for case in 0..3 {
            let limits = Limits::default();
            let server_identity = GatewayIdentity::generate().expect("server identity");
            let client_identity = ClientIdentity::generate().expect("client identity");
            let (client_connection, server_connection, client, server) =
                connected_pair(&server_identity, &client_identity).await;
            let (mut invitations, token) = invitation(&client_identity, &limits);
            let (server_control, client_control) = tokio::join!(
                server_handshake_until(
                    server_connection,
                    &mut invitations,
                    limits,
                    Duration::from_secs(3)
                ),
                client_handshake(client_connection, hello(token), limits)
            );
            let server_control = server_control.expect("server admission");
            let mut client_control = client_control.expect("client admission");
            let connection = client_control.connection.clone();
            let server_echo = everudp::stream_floor_ordinary::serve_echo(server_control, limits);
            let peer_operation = async {
                let mut input = connection.open_uni().await.expect("input stream");
                let mut writer = RecordWriter::new(StreamRole::Input, limits).expect("writer");
                writer
                    .load(Kind::Input, 0, b"pending echo")
                    .expect("record");
                while !writer.is_complete() {
                    std::future::poll_fn(|cx| writer.poll_write_ordinary(&mut input, cx))
                        .await
                        .expect("input write");
                }
                // A real output stream proves the server reached its data loop.
                let mut output = connection.accept_uni().await.expect("output stream");
                match case {
                    0 => output
                        .stop(noq::VarInt::from_u32(17))
                        .expect("STOP_SENDING"),
                    1 => input
                        .reset(noq::VarInt::from_u32(19))
                        .expect("RESET_STREAM"),
                    _ => client_control.send.finish().expect("premature control FIN"),
                }
                assert!(
                    matches!(
                        connection.closed().await,
                        noq::ConnectionError::ApplicationClosed(_)
                    ),
                    "peer must observe explicit failure close, case {case}"
                );
            };
            let (result, ()) = tokio::join!(server_echo, peer_operation);
            assert!(
                result.is_err(),
                "case {case} must not become successful completion"
            );
            client.wait_idle().await;
            server.wait_idle().await;
        }
    })
    .await
    .expect("bounded ordinary failure matrix");
}

#[tokio::test(flavor = "current_thread")]
async fn ordinary_server_completion_retains_control_while_local_sink_is_pending() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let limits = Limits::default();
        let server_identity = GatewayIdentity::generate().expect("server identity");
        let client_identity = ClientIdentity::generate().expect("client identity");
        let (client_connection, server_connection, client, server) =
            connected_pair(&server_identity, &client_identity).await;
        let (mut invitations, token) = invitation(&client_identity, &limits);
        let (server_control, client_control) = tokio::join!(
            server_handshake_until(
                server_connection,
                &mut invitations,
                limits,
                Duration::from_secs(3)
            ),
            client_handshake(client_connection, hello(token), limits)
        );
        let server_control = server_control.expect("server admission");
        let client_control = client_control.expect("client admission");
        let connection = client_control.connection.clone();
        let receive_pending = async {
            let mut input = connection.open_uni().await.expect("input stream");
            let mut writer = RecordWriter::new(StreamRole::Input, limits).expect("writer");
            writer
                .load(Kind::Input, 0, b"pending sink")
                .expect("record");
            while !writer.is_complete() {
                std::future::poll_fn(|cx| writer.poll_write_ordinary(&mut input, cx))
                    .await
                    .expect("input write");
            }
            input.finish().expect("input FIN");
            let mut output = connection.accept_uni().await.expect("output stream");
            let mut sink = OutputSink::new(limits).expect("sink");
            loop {
                let reader = sink.reader().expect("reader");
                match std::future::poll_fn(|cx| reader.poll_read_ordinary(&mut output, cx))
                    .await
                    .expect("read")
                {
                    ReadProgress::Record(_) => {
                        sink.stage().expect("stage");
                        break;
                    }
                    ReadProgress::Consumed(_) => {}
                    ReadProgress::CleanEof => panic!("missing echo"),
                }
            }
            (sink, output, input)
        };
        let (served, (mut sink, _output, _input)) = tokio::join!(
            everudp::stream_floor_ordinary::serve_echo(server_control, limits),
            receive_pending
        );
        let _server_owner = served.expect("server FIN acknowledged");
        assert_eq!(sink.bytes_delivered(), 0);
        assert_eq!(
            sink.pending().expect("local sink still pending"),
            b"pending sink"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), client_control.send.stopped())
                .await
                .is_err(),
            "server completion must not abandon control receive ownership"
        );
        sink.commit(b"pending sink".len())
            .expect("local acceptance");
        assert_eq!(sink.bytes_delivered(), 12);
        connection.close(noq::VarInt::from_u32(0), b"local delivery complete");
        client.wait_idle().await;
        server.wait_idle().await;
    })
    .await
    .expect("bounded pending-sink completion");
}

#[tokio::test(flavor = "current_thread")]
async fn ordinary_client_loop_delivers_exact_data_through_bounded_local_io() {
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
    struct ObservedSink {
        inner: tokio::io::DuplexStream,
        blocked: usize,
    }
    impl AsyncWrite for ObservedSink {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let result = Pin::new(&mut self.inner).poll_write(cx, bytes);
            if result.is_pending() {
                self.blocked += 1;
            }
            result
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }
        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }
    tokio::time::timeout(Duration::from_secs(20), async {
        let limits = Limits::default();
        let server_identity = GatewayIdentity::generate().expect("server identity");
        let client_identity = ClientIdentity::generate().expect("client identity");
        let (client_connection, server_connection, client, server) =
            connected_pair(&server_identity, &client_identity).await;
        let (mut invitations, token) = invitation(&client_identity, &limits);
        let (server_control, client_control) = tokio::join!(
            server_handshake_until(
                server_connection,
                &mut invitations,
                limits,
                Duration::from_secs(3)
            ),
            client_handshake(client_connection, hello(token), limits)
        );
        let server_control = server_control.expect("server admission");
        let client_control = client_control.expect("client admission");
        let connection = client_control.connection.clone();
        let (mut feeder, mut local_input) = tokio::io::duplex(4096);
        let (sink_writer, mut drain) = tokio::io::duplex(127);
        let mut sink = ObservedSink {
            inner: sink_writer,
            blocked: 0,
        };
        let expected: Vec<u8> = (0..262144).map(|index| (index % 251) as u8).collect();
        let feed = async {
            feeder.write_all(&expected).await.expect("feed");
            feeder.shutdown().await.expect("local EOF");
        };
        let receive = async {
            let mut actual = vec![0; expected.len()];
            drain.read_exact(&mut actual).await.expect("local output");
            actual
        };
        let (served, delivered, (), actual) = tokio::join!(
            everudp::stream_floor_ordinary::serve_echo(server_control, limits),
            everudp::stream_floor_ordinary_client::run(
                client_control,
                &mut local_input,
                &mut sink,
                limits
            ),
            feed,
            receive
        );
        let _server_owner = served.expect("server completion");
        let (_client_owner, count) = delivered.expect("client completion");
        assert_eq!(actual, expected);
        assert_eq!(count, expected.len() as u64);
        assert!(sink.blocked > 0, "local output Pending must be exercised");
        connection.close(noq::VarInt::from_u32(0), b"verified client delivery");
        client.wait_idle().await;
        server.wait_idle().await;
    })
    .await
    .expect("bounded real client loop");
}

#[tokio::test(flavor = "current_thread")]
async fn ordinary_client_loop_uses_real_unbuffered_descriptors() {
    use everudp::stream_floor_fd::AsyncDescriptor;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    tokio::time::timeout(Duration::from_secs(20), async {
        let limits = Limits::default();
        let server_identity = GatewayIdentity::generate().expect("server identity");
        let client_identity = ClientIdentity::generate().expect("client identity");
        let (client_connection, server_connection, client, server) =
            connected_pair(&server_identity, &client_identity).await;
        let (mut invitations, token) = invitation(&client_identity, &limits);
        let (server_control, client_control) = tokio::join!(
            server_handshake_until(
                server_connection,
                &mut invitations,
                limits,
                Duration::from_secs(3)
            ),
            client_handshake(client_connection, hello(token), limits)
        );
        let server_control = server_control.expect("server admission");
        let client_control = client_control.expect("client admission");
        let connection = client_control.connection.clone();

        // Register the actual local descriptor edges only after admission.
        let (input_fd, feed_fd) = UnixStream::pair().expect("input pair");
        let (output_fd, drain_fd) = UnixStream::pair().expect("output pair");
        feed_fd.set_nonblocking(true).expect("nonblocking feeder");
        drain_fd.set_nonblocking(true).expect("nonblocking drain");
        let mut feeder = tokio::net::UnixStream::from_std(feed_fd).expect("feeder");
        let mut drain = tokio::net::UnixStream::from_std(drain_fd).expect("drain");
        let mut input = AsyncDescriptor::new(input_fd.as_fd()).expect("input descriptor");
        let mut output = AsyncDescriptor::new(output_fd.as_fd()).expect("output descriptor");
        let expected: Vec<u8> = (0..6 * 1024 * 1024)
            .map(|index| (index % 251) as u8)
            .collect();
        let feed = async {
            feeder.write_all(&expected).await.expect("feed");
            feeder.shutdown().await.expect("real input EOF");
        };
        let receive = async {
            let mut actual = vec![0; expected.len()];
            drain.read_exact(&mut actual).await.expect("local delivery");
            actual
        };
        let (served, delivered, (), actual) = tokio::join!(
            everudp::stream_floor_ordinary::serve_echo(server_control, limits),
            everudp::stream_floor_ordinary_client::run(
                client_control,
                &mut input,
                &mut output,
                limits
            ),
            feed,
            receive
        );
        let _server_owner = served.expect("server completion");
        let (_client_owner, count) = delivered.expect("client completion");
        assert_eq!(actual, expected);
        assert_eq!(count, expected.len() as u64);
        drop(input);
        drop(output);
        // Adapter shutdown/drop must not close the caller-owned output edge.
        let mut byte = [0];
        assert!(
            tokio::time::timeout(Duration::from_millis(10), drain.read(&mut byte))
                .await
                .is_err()
        );
        drop(output_fd);
        assert_eq!(drain.read(&mut byte).await.expect("owner closes output"), 0);
        connection.close(noq::VarInt::from_u32(0), b"verified descriptor delivery");
        client.wait_idle().await;
        server.wait_idle().await;
    })
    .await
    .expect("bounded descriptor client loop");
}
