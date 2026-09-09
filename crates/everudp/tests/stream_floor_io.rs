//! Deterministic native stream I/O checks, not application admission or timing.
#![cfg(feature = "stream-floor")]

use bytes::BytesMut;
use everudp::floor_pump::{FloorLimits, FloorPump};
use everudp::stream_floor_io::StreamIoError;
use everudp::stream_floor_io::{ReadProgress, RecordReader, RecordWriter};
use everudp::transport::{stream_floor_client_config, stream_floor_server_config};
use everudp::wire::{Kind, StreamRole};
use everudp::{ClientIdentity, GatewayIdentity, Limits};
use noq_proto::{ConnectionHandle, Dir, EndpointConfig, Event, FourTuple};
use std::time::{Duration, Instant};

struct Pair {
    client: FloorPump,
    server: FloorPump,
    client_id: ConnectionHandle,
    server_id: Option<ConnectionHandle>,
    now: Instant,
}

impl Pair {
    fn new() -> Self {
        let limits = Limits::default();
        let server_identity = GatewayIdentity::generate().expect("server identity");
        let client_identity = ClientIdentity::generate().expect("client identity");
        let server = FloorPump::server(
            EndpointConfig::default(),
            stream_floor_server_config(&server_identity, &limits).expect("server config"),
            FloorLimits::default(),
        );
        let mut client = FloorPump::client(EndpointConfig::default(), FloorLimits::default());
        let (config, mismatch) =
            stream_floor_client_config(&client_identity, server_identity.spki_sha256(), &limits)
                .expect("client config");
        let now = Instant::now();
        let client_id = client
            .connect(
                config,
                "127.0.0.1:4444".parse().expect("address"),
                "localhost",
                now,
            )
            .expect("connect");
        let mut pair = Self {
            client,
            server,
            client_id,
            server_id: None,
            now,
        };
        let mut connected = false;
        for _ in 0..1000 {
            let (client_events, _) = pair.tick();
            connected |= client_events
                .iter()
                .any(|event| matches!(event, Event::Connected));
            if connected && pair.server_id.is_some() {
                break;
            }
        }
        assert!(connected && pair.server_id.is_some());
        assert!(!mismatch.observed());
        assert_eq!(
            pair.client
                .connection_mut(client_id)
                .expect("client")
                .datagrams()
                .max_size(),
            None
        );
        assert_eq!(
            pair.server
                .connection_mut(pair.server_id.expect("server id"))
                .expect("server")
                .datagrams()
                .max_size(),
            None
        );
        pair
    }

    fn tick(&mut self) -> (Vec<Event>, Vec<Event>) {
        self.now += Duration::from_millis(1);
        self.client.drive(self.now).expect("client drive");
        self.server.drive(self.now).expect("server drive");
        transfer(
            &mut self.client,
            &mut self.server,
            "127.0.0.1:5555",
            self.now,
        );
        transfer(
            &mut self.server,
            &mut self.client,
            "127.0.0.1:4444",
            self.now,
        );
        let mut client = Vec::new();
        let mut server = Vec::new();
        while let Some((_, event)) = self.client.poll_event() {
            client.push(event);
        }
        while let Some((handle, event)) = self.server.poll_event() {
            if matches!(event, Event::Connected) {
                self.server_id = Some(handle);
            }
            server.push(event);
        }
        (client, server)
    }
}

fn transfer(from: &mut FloorPump, to: &mut FloorPump, source: &str, now: Instant) {
    let Some(pending) = from.pending_transmit() else {
        return;
    };
    let destination = pending.transmit().destination;
    let ecn = pending.transmit().ecn;
    let bytes = pending.bytes().to_vec();
    assert!(
        pending.transmit().segment_size.is_none()
            || pending.transmit().segment_size == Some(bytes.len())
    );
    from.confirm_transmit(bytes.len()).expect("send accepted");
    to.receive(
        FourTuple::new(source.parse().expect("source"), Some(destination.ip())),
        ecn,
        BytesMut::from(bytes.as_slice()),
        now,
    )
    .expect("receive packet");
}

#[test]
fn native_records_cross_receive_window_and_finish_without_datagrams() {
    let mut pair = Pair::new();
    let limits = Limits::default();
    let stream = pair
        .client
        .connection_mut(pair.client_id)
        .expect("client")
        .streams()
        .open(Dir::Uni)
        .expect("input stream credit");
    let mut reader = RecordReader::new(StreamRole::Input, limits).expect("reader");
    let mut writer = RecordWriter::new(StreamRole::Input, limits).expect("writer");
    // Six MiB exceeds the four-MiB stream window and requires receive credit.
    let payload: Vec<u8> = (0..65536).map(|n| (n % 251) as u8).collect();
    let records = 96;
    writer.load(Kind::Input, 0, &payload).expect("first record");
    let mut queued = 1;
    let mut received = 0;
    let mut incoming = None;
    let mut finished = false;
    let mut clean_eof = false;
    let mut credit = false;
    for _ in 0..100_000 {
        pair.tick();
        let client = pair.client.connection_mut(pair.client_id).expect("client");
        if !writer.is_complete() {
            writer.write_native(client, stream).expect("write record");
        } else if queued < records {
            writer.load(Kind::Input, queued, &payload).expect("reload");
            queued += 1;
        } else if !finished {
            client.send_stream(stream).finish().expect("FIN");
            finished = true;
        }
        let server = pair
            .server
            .connection_mut(pair.server_id.expect("server id"))
            .expect("server");
        if incoming.is_none() {
            incoming = server.streams().accept(Dir::Uni);
        }
        if let Some(stream) = incoming {
            let read = reader.read_native(server, stream);
            credit |= read.should_transmit;
            match read.result.expect("read record") {
                ReadProgress::Record(_) => {
                    let record = reader.record().expect("complete record");
                    assert_eq!(record.header.sequence, received);
                    assert_eq!(record.payload, payload);
                    received += 1;
                    assert!(reader.consume_record());
                }
                ReadProgress::CleanEof => {
                    clean_eof = true;
                    break;
                }
                ReadProgress::Consumed(_) => {}
            }
        }
    }
    assert_eq!(received, records);
    assert!(clean_eof && finished && credit);
}

#[test]
fn native_truncated_fin_and_reset_remain_errors() {
    for reset in [false, true] {
        let mut pair = Pair::new();
        let limits = Limits::default();
        let client = pair.client.connection_mut(pair.client_id).expect("client");
        let stream = client.streams().open(Dir::Uni).expect("input stream");
        let mut wire = [0; 64];
        let used = everudp::wire::encode_record(
            StreamRole::Input,
            Kind::Input,
            0,
            b"incomplete",
            &limits,
            &mut wire,
        )
        .expect("record");
        let prefix = used - 1;
        assert_eq!(
            client
                .send_stream(stream)
                .write(&wire[..prefix])
                .expect("prefix"),
            prefix
        );
        let mut incoming = None;
        let mut reader = RecordReader::new(StreamRole::Input, limits).expect("reader");
        let mut consumed = 0;
        for _ in 0..1000 {
            pair.tick();
            let server = pair
                .server
                .connection_mut(pair.server_id.expect("server id"))
                .expect("server");
            if incoming.is_none() {
                incoming = server.streams().accept(Dir::Uni);
            }
            if let Some(stream) = incoming {
                match reader
                    .read_native(server, stream)
                    .result
                    .expect("prefix read")
                {
                    ReadProgress::Consumed(count) => consumed += count,
                    other => panic!("incomplete record became {other:?}"),
                }
            }
            if consumed == prefix {
                break;
            }
        }
        assert_eq!(consumed, prefix);
        let client = pair.client.connection_mut(pair.client_id).expect("client");
        if reset {
            client
                .send_stream(stream)
                .reset(noq_proto::VarInt::from_u32(9))
                .expect("reset");
        } else {
            client.send_stream(stream).finish().expect("truncated FIN");
        }
        let stream = incoming.expect("accepted input");
        let mut failed = false;
        for _ in 0..1000 {
            pair.tick();
            let server = pair
                .server
                .connection_mut(pair.server_id.expect("server id"))
                .expect("server");
            match reader.read_native(server, stream).result {
                Err(error) => {
                    assert_eq!(
                        error,
                        if reset {
                            StreamIoError::Stream
                        } else {
                            StreamIoError::TruncatedRecord
                        }
                    );
                    assert!(reader.read_native(server, stream).result.is_err());
                    assert!(reader.clean_eof().is_err());
                    failed = true;
                    break;
                }
                Ok(ReadProgress::Consumed(0)) => {}
                other => panic!("terminal stream unexpectedly returned {other:?}"),
            }
        }
        assert!(
            failed,
            "terminal stream error was not delivered: reset={reset}"
        );
    }
}

#[test]
fn native_stop_sending_latches_writer_failure() {
    let mut pair = Pair::new();
    let client = pair.client.connection_mut(pair.client_id).expect("client");
    let stream = client.streams().open(Dir::Uni).expect("input stream");
    let mut writer = RecordWriter::new(StreamRole::Input, Limits::default()).expect("writer");
    writer.load(Kind::Input, 0, &[7; 65536]).expect("record");
    let first = writer.write_native(client, stream).expect("initial write");
    assert!(first.accepted > 0 && !first.complete);
    let mut stopped = false;
    for _ in 0..1000 {
        pair.tick();
        let server = pair
            .server
            .connection_mut(pair.server_id.expect("server id"))
            .expect("server");
        if let Some(incoming) = server.streams().accept(Dir::Uni) {
            server
                .recv_stream(incoming)
                .stop(noq_proto::VarInt::from_u32(17))
                .expect("stop receiving");
            stopped = true;
            break;
        }
    }
    assert!(stopped);
    let mut event_seen = false;
    for _ in 0..1000 {
        let (events, _) = pair.tick();
        event_seen |= events.iter().any(|event| {
            matches!(event,
            Event::Stream(noq_proto::StreamEvent::Stopped { id, error_code })
                if *id == stream && *error_code == noq_proto::VarInt::from_u32(17))
        });
        if event_seen {
            break;
        }
    }
    assert!(event_seen, "STOP_SENDING event was not delivered");
    let client = pair.client.connection_mut(pair.client_id).expect("client");
    assert_eq!(
        writer.write_native(client, stream),
        Err(StreamIoError::Stream)
    );
    assert_eq!(
        writer.write_native(client, stream),
        Err(StreamIoError::Stream)
    );
    assert!(writer.load(Kind::Input, 1, b"must not resume").is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn ordinary_records_cross_receive_window_and_finish_without_datagrams() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let limits = Limits::default();
        let server_identity = GatewayIdentity::generate().expect("server identity");
        let client_identity = ClientIdentity::generate().expect("client identity");
        let server = noq::Endpoint::server(
            stream_floor_server_config(&server_identity, &limits).expect("server config"),
            "127.0.0.1:0".parse().expect("server address"),
        )
        .expect("server endpoint");
        let client = noq::Endpoint::client("127.0.0.1:0".parse().expect("client address"))
            .expect("client endpoint");
        let (config, mismatch) =
            stream_floor_client_config(&client_identity, server_identity.spki_sha256(), &limits)
                .expect("client config");
        client.set_default_client_config(config);
        let connecting = client
            .connect(server.local_addr().expect("address"), "localhost")
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
        let (connected, accepted) = tokio::join!(connecting, accepting);
        let connected = connected.expect("client TLS");
        assert!(!mismatch.observed());
        assert_eq!(connected.max_datagram_size(), None);
        assert_eq!(accepted.max_datagram_size(), None);
        let payload: Vec<u8> = (0..65536).map(|n| (n % 251) as u8).collect();
        let send = async {
            let mut stream = connected.open_uni().await.expect("input stream");
            let mut writer = RecordWriter::new(StreamRole::Input, limits).expect("writer");
            for sequence in 0..96 {
                writer.load(Kind::Input, sequence, &payload).expect("load");
                while !writer.is_complete() {
                    std::future::poll_fn(|cx| writer.poll_write_ordinary(&mut stream, cx))
                        .await
                        .expect("write record");
                }
            }
            stream.finish().expect("FIN");
            assert_eq!(stream.stopped().await.expect("sender completion"), None);
        };
        let receive = async {
            let mut stream = accepted.accept_uni().await.expect("accepted input");
            let mut reader = RecordReader::new(StreamRole::Input, limits).expect("reader");
            let mut sequence = 0;
            loop {
                match std::future::poll_fn(|cx| reader.poll_read_ordinary(&mut stream, cx))
                    .await
                    .expect("read record")
                {
                    ReadProgress::Consumed(_) => {}
                    ReadProgress::Record(_) => {
                        let record = reader.record().expect("record");
                        assert_eq!(record.header.sequence, sequence);
                        assert_eq!(record.payload, payload);
                        sequence += 1;
                        assert!(reader.consume_record());
                    }
                    ReadProgress::CleanEof => break,
                }
            }
            assert_eq!(sequence, 96);
        };
        tokio::join!(send, receive);
        connected.close(noq::VarInt::from_u32(0), b"test complete");
        accepted.close(noq::VarInt::from_u32(0), b"test complete");
    })
    .await
    .expect("bounded ordinary stream test");
}
