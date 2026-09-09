//! Native stream-floor handshake checks over the deterministic pinned fixture.
#![cfg(feature = "stream-floor")]

use bytes::BytesMut;
use everssh::{association::AssociationId, bootstrap::SecretToken};
use everudp::floor_pump::{FloorLimits, FloorPump};
use everudp::stream_floor_io::{ReadProgress, RecordReader, RecordWriter};
use everudp::stream_floor_native::{
    NativeClientHandshake, NativeHandshakePoll, NativeServerHandshake,
};
use everudp::transport::{stream_floor_client_config, stream_floor_server_config};
use everudp::wire::{ConnectionRole, Kind, StreamRole};
use everudp::{
    ClientHello, ClientIdentity, GatewayGeneration, GatewayIdentity, InvitationStore, Limits,
    ResumePosition, TransportError,
};
use noq_proto::{ConnectionHandle, EndpointConfig, Event, FourTuple};
use std::time::{Duration, Instant};

struct Pair {
    client: FloorPump,
    server: FloorPump,
    client_id: ConnectionHandle,
    server_id: ConnectionHandle,
    now: Instant,
    client_identity: ClientIdentity,
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
        assert!(!mismatch.observed());
        let now = Instant::now();
        let client_id = client
            .connect(
                config,
                "127.0.0.1:4444".parse().expect("remote"),
                "localhost",
                now,
            )
            .expect("connect");
        let mut pair = Self {
            client,
            server,
            client_id,
            server_id: ConnectionHandle(usize::MAX),
            now,
            client_identity,
        };
        let mut connected = false;
        for _ in 0..1000 {
            let (client_events, server_events) = pair.tick();
            connected |= client_events
                .iter()
                .any(|event| matches!(event, Event::Connected));
            if let Some((handle, _)) = server_events
                .iter()
                .find(|(_, event)| matches!(event, Event::Connected))
            {
                pair.server_id = *handle;
            }
            if connected && pair.server_id.0 != usize::MAX {
                break;
            }
        }
        assert!(connected && pair.server_id.0 != usize::MAX);
        pair
    }

    fn tick(&mut self) -> (Vec<Event>, Vec<(ConnectionHandle, Event)>) {
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
            server.push((handle, event));
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
    from.confirm_transmit(bytes.len()).expect("confirm");
    to.receive(
        FourTuple::new(source.parse().expect("source"), Some(destination.ip())),
        ecn,
        BytesMut::from(bytes.as_slice()),
        now,
    )
    .expect("receive");
}

fn hello(token: SecretToken) -> ClientHello {
    ClientHello::initial(
        AssociationId::from_bytes([1; 16]).expect("association"),
        GatewayGeneration::from_bytes([2; 16]).expect("generation"),
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

#[test]
fn native_handshake_rejects_expired_deadline_before_connection_work() {
    let mut pair = Pair::new();
    let limits = Limits::default();
    let hello = hello(SecretToken::from_bytes([7; 32]));
    let mut handshake = NativeClientHandshake::new(hello, limits, pair.now).expect("handshake");
    let connection = pair.client.connection_mut(pair.client_id).expect("client");
    assert!(matches!(
        handshake.poll(connection, pair.now),
        Err(TransportError::Timeout)
    ));
    assert!(connection.is_closed());
    assert!(handshake.poll(connection, pair.now).is_err());
    assert!(!handshake.ready());
    assert!(handshake.control().is_none());
}

#[test]
fn native_silent_server_waits_then_closes_at_deadline() {
    let mut pair = Pair::new();
    let deadline = pair.now + Duration::from_millis(25);
    let mut handshake = NativeServerHandshake::new(Limits::default(), deadline).expect("handshake");
    let mut store = InvitationStore::new(
        "stream-floor",
        GatewayGeneration::from_bytes([2; 16]).expect("native fixture invariant"),
        &Limits::default(),
    )
    .expect("native fixture invariant");
    let connection = pair.server.connection_mut(pair.server_id).expect("server");
    assert!(matches!(
        handshake.poll(connection, &mut store, pair.now, 0),
        Ok(NativeHandshakePoll::Pending {
            progressed: false,
            ..
        })
    ));
    assert!(matches!(
        handshake.poll(connection, &mut store, deadline, 25),
        Err(TransportError::Timeout)
    ));
    assert!(connection.is_closed());
    assert!(handshake
        .poll(connection, &mut store, deadline, 25)
        .is_err());
    assert!(!handshake.ready());
    assert!(handshake.control().is_none());
}

#[test]
fn native_handshake_admits_pinned_writer_and_returns_control_stream() {
    let mut pair = Pair::new();
    let limits = Limits::default();
    let generation = GatewayGeneration::from_bytes([2; 16]).expect("generation");
    let association = AssociationId::from_bytes([1; 16]).expect("association");
    let mut invitations = InvitationStore::new("stream-floor", generation, &limits).expect("store");
    let ticket = invitations
        .issue(
            association,
            ConnectionRole::Writer,
            pair.client_identity.spki_sha256(),
            0,
        )
        .expect("ticket");
    let mut client = NativeClientHandshake::new(
        hello(ticket.token().clone()),
        limits,
        pair.now + Duration::from_secs(3),
    )
    .expect("client handshake");
    let mut server = NativeServerHandshake::new(limits, pair.now + Duration::from_secs(3))
        .expect("server handshake");
    let mut client_ready = false;
    let mut server_ready = false;
    for _ in 0..2000 {
        pair.tick();
        if !client_ready {
            let connection = pair
                .client
                .connection_mut(pair.client_id)
                .expect("client connection");
            client_ready = matches!(
                client.poll(connection, pair.now).expect("client poll"),
                NativeHandshakePoll::Ready { .. }
            );
        }
        if !server_ready {
            let connection = pair
                .server
                .connection_mut(pair.server_id)
                .expect("server connection");
            server_ready = matches!(
                server
                    .poll(connection, &mut invitations, pair.now, 1)
                    .expect("server poll"),
                NativeHandshakePoll::Ready { .. }
            );
        }
        if client_ready && server_ready {
            break;
        }
    }
    assert!(client_ready && server_ready);
    assert!(client.control().is_some() && server.control().is_some());
    let stream = client.control().expect("native fixture invariant").stream;
    assert_eq!(
        stream,
        server.control().expect("native fixture invariant").stream
    );
    let mut writer =
        RecordWriter::new(StreamRole::Control, limits).expect("native fixture invariant");
    writer
        .load(Kind::LinkStatus, 0, b"retained-control")
        .expect("native fixture invariant");
    let mut reader =
        RecordReader::new(StreamRole::Control, limits).expect("native fixture invariant");
    let mut received = false;
    for _ in 0..1000 {
        writer
            .write_native(
                pair.client
                    .connection_mut(pair.client_id)
                    .expect("native fixture invariant"),
                stream,
            )
            .expect("native fixture invariant");
        pair.tick();
        let read = reader.read_native(
            pair.server
                .connection_mut(pair.server_id)
                .expect("native fixture invariant"),
            stream,
        );
        if matches!(
            read.result.expect("follow-on read"),
            ReadProgress::Record(_)
        ) {
            let record = reader.record().expect("native fixture invariant");
            assert_eq!(record.header.kind, Kind::LinkStatus);
            assert_eq!(record.payload, b"retained-control");
            received = true;
            break;
        }
    }
    assert!(received);
}

#[test]
fn native_bad_token_sequence_and_early_fin_close_and_latch() {
    // Each case reaches the adapter through real protocol stream delivery.
    for case in 0..3 {
        let mut pair = Pair::new();
        let limits = Limits::default();
        let mut store = InvitationStore::new(
            "stream-floor",
            GatewayGeneration::from_bytes([2; 16]).expect("native fixture invariant"),
            &limits,
        )
        .expect("native fixture invariant");
        let ticket = store
            .issue(
                AssociationId::from_bytes([1; 16]).expect("native fixture invariant"),
                ConnectionRole::Writer,
                pair.client_identity.spki_sha256(),
                0,
            )
            .expect("native fixture invariant");
        let request = hello(if case == 0 {
            SecretToken::from_bytes([99; 32])
        } else {
            ticket.token().clone()
        });
        let mut payload = zeroize::Zeroizing::new([0; ClientHello::MAX_ENCODED_LEN]);
        let used = request
            .encode_into(&mut payload[..])
            .expect("native fixture invariant");
        let mut writer =
            RecordWriter::new(StreamRole::Control, limits).expect("native fixture invariant");
        writer
            .load(Kind::ClientHello, u64::from(case == 1), &payload[..used])
            .expect("native fixture invariant");
        let connection = pair
            .client
            .connection_mut(pair.client_id)
            .expect("native fixture invariant");
        let stream = connection
            .streams()
            .open(noq_proto::Dir::Bi)
            .expect("native fixture invariant");
        if case == 2 {
            connection
                .send_stream(stream)
                .finish()
                .expect("native fixture invariant");
        }
        let mut server = NativeServerHandshake::new(limits, pair.now + Duration::from_secs(3))
            .expect("native fixture invariant");
        let mut rejected = false;
        for _ in 0..1000 {
            if case != 2 {
                writer
                    .write_native(
                        pair.client
                            .connection_mut(pair.client_id)
                            .expect("native fixture invariant"),
                        stream,
                    )
                    .expect("native fixture invariant");
            }
            pair.tick();
            let connection = pair
                .server
                .connection_mut(pair.server_id)
                .expect("native fixture invariant");
            match server.poll(connection, &mut store, pair.now, 1) {
                Err(error) => {
                    match case {
                        0 => assert!(matches!(error, TransportError::Admission(_))),
                        1 => assert!(matches!(error, TransportError::Rejected)),
                        _ => assert!(matches!(error, TransportError::Stream)),
                    }
                    assert!(connection.is_closed());
                    assert!(!server.ready());
                    assert!(server.control().is_none());
                    assert!(server.poll(connection, &mut store, pair.now, 1).is_err());
                    rejected = true;
                    break;
                }
                Ok(NativeHandshakePoll::Ready { .. }) => panic!("invalid handshake admitted"),
                Ok(NativeHandshakePoll::Pending { .. }) => {}
            }
        }
        assert!(rejected, "case {case}");
        let mut remote_closed = false;
        for _ in 0..1000 {
            let (events, _) = pair.tick();
            remote_closed |= events
                .iter()
                .any(|event| matches!(event, Event::ConnectionLost { .. }));
            if remote_closed {
                break;
            }
        }
        assert!(remote_closed, "peer must observe close for case {case}");
    }
}
