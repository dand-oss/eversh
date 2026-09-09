//! Live authenticated native three-stream echo coverage.
#![cfg(feature = "stream-floor")]

use bytes::BytesMut;
use everssh::{association::AssociationId, bootstrap::SecretToken};
use everudp::floor_pump::{FloorLimits, FloorPump};
use everudp::stream_floor_app::{InputSource, OutputSink};
use everudp::stream_floor_io::{ReadProgress, RecordReader, RecordWriter};
use everudp::stream_floor_native::{
    NativeClientHandshake, NativeHandshakePoll, NativeServerHandshake,
};
use everudp::stream_floor_native_echo::NativeServerEcho;
use everudp::transport::{stream_floor_client_config, stream_floor_server_config};
use everudp::wire::{ConnectionRole, Kind, StreamRole};
use everudp::{
    ClientHello, ClientIdentity, GatewayGeneration, GatewayIdentity, InvitationStore, Limits,
    ResumePosition,
};
use noq_proto::{ConnectionHandle, Dir, EndpointConfig, Event, FourTuple};
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
            let (ce, se) = pair.tick();
            connected |= ce.iter().any(|e| matches!(e, Event::Connected));
            if let Some((h, _)) = se.iter().find(|(_, e)| matches!(e, Event::Connected)) {
                pair.server_id = *h;
            }
            if connected && pair.server_id.0 != usize::MAX {
                break;
            }
        }
        assert_ne!(pair.server_id.0, usize::MAX);
        assert!(connected && !mismatch.observed());
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
        let mut c = Vec::new();
        while let Some((_, e)) = self.client.poll_event() {
            c.push(e);
        }
        let mut s = Vec::new();
        while let Some((h, e)) = self.server.poll_event() {
            s.push((h, e));
        }
        (c, s)
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

fn admitted_pair() -> (Pair, noq_proto::StreamId) {
    let mut pair = Pair::new();
    let limits = Limits::default();
    let generation = GatewayGeneration::from_bytes([2; 16]).expect("generation");
    let mut invitations = InvitationStore::new("stream-floor", generation, &limits).expect("store");
    let ticket = invitations
        .issue(
            AssociationId::from_bytes([1; 16]).expect("association"),
            ConnectionRole::Writer,
            pair.client_identity.spki_sha256(),
            0,
        )
        .expect("ticket");
    let mut client_h = NativeClientHandshake::new(
        hello(ticket.token().clone()),
        limits,
        pair.now + Duration::from_secs(3),
    )
    .expect("client handshake");
    let mut server_h = NativeServerHandshake::new(limits, pair.now + Duration::from_secs(3))
        .expect("server handshake");
    let (mut cr, mut sr) = (false, false);
    for _ in 0..2000 {
        pair.tick();
        if !cr {
            let c = pair.client.connection_mut(pair.client_id).expect("client");
            cr = matches!(
                client_h.poll(c, pair.now).expect("client poll"),
                NativeHandshakePoll::Ready { .. }
            );
        }
        if !sr {
            let s = pair.server.connection_mut(pair.server_id).expect("server");
            sr = matches!(
                server_h
                    .poll(s, &mut invitations, pair.now, 1)
                    .expect("server poll"),
                NativeHandshakePoll::Ready { .. }
            );
        }
        if cr && sr {
            break;
        }
    }
    assert!(cr && sr);
    let control = server_h.control().expect("control").stream;
    (pair, control)
}

#[test]
fn native_echo_control_progresses_while_output_blocked_then_exact_data_resumes() {
    let (mut pair, control) = admitted_pair();
    let limits = Limits::default();
    let mut echo = NativeServerEcho::new(control, limits).expect("echo");
    let input = pair
        .client
        .connection_mut(pair.client_id)
        .expect("client")
        .streams()
        .open(Dir::Uni)
        .expect("input stream");
    let mut source = InputSource::new(limits).expect("input source");
    let mut output = None;
    let mut sink = OutputSink::new(limits).expect("sink");
    let mut ping = RecordWriter::new(StreamRole::Control, limits).expect("ping writer");
    ping.load(Kind::LinkStatus, 0, b"control-progress")
        .expect("ping");
    let mut pong = RecordReader::new(StreamRole::Control, limits).expect("pong reader");
    let mut pong_seen = false;
    let mut output_blocked_seen = false;
    let total = 6 * 1024 * 1024;
    let chunk = 64 * 1024;
    let mut received = 0;
    let mut input_fin_sent = false;
    let mut output_fin_seen = false;
    for _ in 0..200_000 {
        let (_, events) = pair.tick();
        let server = pair.server.connection_mut(pair.server_id).expect("server");
        for (_, event) in events {
            if let Err(error) = echo.event(server, &event, pair.now) {
                panic!("server event {event:?}: {error:?}");
            }
        }
        let _ = echo.poll(server, pair.now).expect("server echo poll");
        output_blocked_seen |= echo.output_blocked();
        if output.is_none() {
            output = pair
                .client
                .connection_mut(pair.client_id)
                .expect("client")
                .streams()
                .accept(Dir::Uni);
        }
        let sent = source.bytes_read() as usize;
        if sent < total {
            if let Some(buffer) = source.buffer() {
                let count = buffer.len().min(total - sent);
                buffer[..count].fill((sent / chunk % 251) as u8);
                source.commit_read(count).expect("local input acceptance");
                assert!(source.buffer().is_none());
            }
        }
        let writer = source.writer().expect("framed input");
        if !writer.is_complete() {
            writer
                .write_native(
                    pair.client.connection_mut(pair.client_id).expect("client"),
                    input,
                )
                .expect("input write");
        }
        if source.bytes_read() as usize == total && source.buffer().is_some() && !input_fin_sent {
            source.commit_read(0).expect("local EOF");
            assert!(source.finish_ready());
            pair.client
                .connection_mut(pair.client_id)
                .expect("client")
                .send_stream(input)
                .finish()
                .expect("input FIN");
            input_fin_sent = true;
        }
        if output_blocked_seen && !pong_seen {
            let connection = pair.client.connection_mut(pair.client_id).expect("client");
            ping.write_native(connection, control).expect("ping write");
            match pong
                .read_native(connection, control)
                .result
                .expect("pong read")
            {
                ReadProgress::Record(_) => {
                    let record = pong.record().expect("pong record");
                    assert_eq!(record.header.kind, Kind::LinkStatus);
                    assert_eq!(record.header.sequence, 0);
                    assert_eq!(record.payload, b"control-progress");
                    assert!(
                        echo.output_blocked(),
                        "control must progress before data credit is released"
                    );
                    pong_seen = true;
                }
                ReadProgress::Consumed(_) => {}
                ReadProgress::CleanEof => panic!("control closed before pong"),
            }
        }
        if let Some(id) = output.filter(|_| pong_seen && !output_fin_seen) {
            if let Some(reader) = sink.reader() {
                let read = reader.read_native(
                    pair.client.connection_mut(pair.client_id).expect("client"),
                    id,
                );
                match read.result.expect("output read") {
                    ReadProgress::Record(_) => {
                        assert!(sink.stage().expect("ordered output"));
                        assert!(!sink.commit(0).expect("temporary sink stall"));
                    }
                    ReadProgress::CleanEof => output_fin_seen = true,
                    ReadProgress::Consumed(_) => {}
                }
            }
            if let Some(bytes) = sink.pending() {
                let count = bytes.len().min(257);
                let expected = (received / chunk % 251) as u8;
                assert!(
                    bytes[..count].iter().all(|byte| *byte == expected),
                    "payload mismatch at {received}"
                );
                received += count;
                sink.commit(count).expect("partial local sink acceptance");
            }
        }
        if received == total && output_fin_seen && echo.complete() && pong_seen {
            break;
        }
    }
    assert_eq!(received, total, "native echo must preserve every byte");
    assert!(input_fin_sent && output_fin_seen && pong_seen && output_blocked_seen);
    assert!(
        echo.complete(),
        "server must observe actual FIN acknowledgment"
    );
    assert!(echo.layout_complete());
}

#[test]
fn native_echo_stop_reset_and_control_eof_are_terminal() {
    for case in 0..3 {
        let (mut pair, control) = admitted_pair();
        let limits = Limits::default();
        let mut echo = NativeServerEcho::new(control, limits).expect("echo");
        let client = pair.client.connection_mut(pair.client_id).expect("client");
        let input = client.streams().open(Dir::Uni).expect("input");
        let mut writer = RecordWriter::new(StreamRole::Input, limits).expect("writer");
        writer
            .load(Kind::Input, 0, b"pending echo")
            .expect("record");
        let mut output = None;
        // Wait for actual server output before injecting each peer operation.
        for _ in 0..1000 {
            writer
                .write_native(
                    pair.client.connection_mut(pair.client_id).expect("client"),
                    input,
                )
                .expect("input write");
            let (_, events) = pair.tick();
            let server = pair.server.connection_mut(pair.server_id).expect("server");
            for (_, event) in events {
                echo.event(server, &event, pair.now).expect("setup event");
            }
            echo.poll(server, pair.now).expect("setup poll");
            output = pair
                .client
                .connection_mut(pair.client_id)
                .expect("client")
                .streams()
                .accept(Dir::Uni);
            if output.is_some() {
                break;
            }
        }
        let output = output.expect("actual output stream");
        assert!(!echo.complete());
        let client = pair.client.connection_mut(pair.client_id).expect("client");
        match case {
            0 => {
                client
                    .recv_stream(output)
                    .stop(noq_proto::VarInt::from_u32(17))
                    .expect("STOP_SENDING");
            }
            1 => {
                client
                    .send_stream(input)
                    .reset(noq_proto::VarInt::from_u32(19))
                    .expect("RESET_STREAM");
            }
            _ => {
                client
                    .send_stream(control)
                    .finish()
                    .expect("premature control FIN");
            }
        }
        let mut failed = false;
        for _ in 0..1000 {
            let (_, events) = pair.tick();
            let server = pair.server.connection_mut(pair.server_id).expect("server");
            for (_, event) in events {
                if echo.event(server, &event, pair.now).is_err() {
                    failed = true;
                }
            }
            failed |= echo.poll(server, pair.now).is_err();
            if failed {
                assert!(server.is_closed());
                assert!(!echo.complete());
                assert!(echo.poll(server, pair.now).is_err());
                break;
            }
        }
        assert!(failed, "case {case} must be terminal");
        let mut peer_closed = false;
        for _ in 0..1000 {
            let (events, _) = pair.tick();
            peer_closed |= events
                .iter()
                .any(|event| matches!(event, Event::ConnectionLost { .. }));
            if peer_closed {
                break;
            }
        }
        assert!(peer_closed, "peer must observe case {case} closure");
    }
}

#[test]
fn native_echo_rejects_replacement_input_after_stream_credit_returns() {
    let (mut pair, control) = admitted_pair();
    let mut echo = NativeServerEcho::new(control, Limits::default()).expect("echo");
    let client = pair.client.connection_mut(pair.client_id).expect("client");
    let first = client.streams().open(Dir::Uni).expect("first input");
    client.send_stream(first).finish().expect("empty input FIN");
    let mut replacement = None;
    let mut rejected = false;
    for _ in 0..2000 {
        let (_, events) = pair.tick();
        let server = pair.server.connection_mut(pair.server_id).expect("server");
        for (_, event) in events {
            // Process the whole event batch before considering completion.
            rejected |= echo.event(server, &event, pair.now).is_err();
        }
        rejected |= echo.poll(server, pair.now).is_err();
        if rejected {
            assert!(server.is_closed());
            assert!(!echo.complete());
            assert!(echo.poll(server, pair.now).is_err());
            break;
        }
        if replacement.is_none() {
            let client = pair.client.connection_mut(pair.client_id).expect("client");
            if let Some(id) = client.streams().open(Dir::Uni) {
                assert_eq!(id.index(), 1);
                // No transport limit is relaxed: the first stream's credit
                // must really return before the replacement can be opened.
                assert!(!echo.complete(), "replacement must race before completion");
                assert_eq!(
                    client
                        .send_stream(id)
                        .write(b"replacement")
                        .expect("replacement write"),
                    11
                );
                replacement = Some(id);
            }
        }
    }
    assert!(replacement.is_some(), "first stream must release credit");
    assert!(rejected, "replacement input must not be accepted");
}

#[test]
fn native_client_rearms_local_readiness_and_delivers_exact_bytes() {
    use everudp::stream_floor_native_client::{ClientPoll, NativeClient};
    use std::io::{Cursor, Read, Write};
    struct Source {
        data: Cursor<Vec<u8>>,
        calls: usize,
        ready: bool,
    }
    impl Read for Source {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            self.calls += 1;
            if !self.ready {
                return Err(std::io::ErrorKind::WouldBlock.into());
            }
            self.data.read(bytes)
        }
    }
    struct Sink {
        data: Vec<u8>,
        calls: usize,
        ready: bool,
    }
    impl Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.calls += 1;
            if !self.ready {
                return Err(std::io::ErrorKind::WouldBlock.into());
            }
            let count = bytes.len().min(257);
            self.data.extend_from_slice(&bytes[..count]);
            Ok(count)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let (mut pair, control) = admitted_pair();
    let limits = Limits::default();
    let mut client = NativeClient::new(control, limits).expect("client");
    let mut server = NativeServerEcho::new(control, limits).expect("server");
    let expected: Vec<u8> = (0..262144).map(|index| (index % 251) as u8).collect();
    let mut source = Source {
        data: Cursor::new(expected.clone()),
        calls: 0,
        ready: false,
    };
    let mut sink = Sink {
        data: Vec::new(),
        calls: 0,
        ready: false,
    };
    let mut sink_wakeup = None;
    let mut complete = None;
    for turn in 0..30000 {
        let (client_events, server_events) = pair.tick();
        let connection = pair
            .client
            .connection_mut(pair.client_id)
            .expect("client connection");
        for event in client_events {
            client
                .event(connection, &event, pair.now)
                .expect("client event");
        }
        if turn == 10 {
            assert_eq!(source.calls, 1, "blocked input must not be busy-polled");
            source.ready = true;
            client.local_input_ready();
        }
        if sink_wakeup == Some(turn) {
            assert_eq!(
                sink.calls, 1,
                "blocked output must retain its pending record"
            );
            assert!(sink.data.is_empty());
            sink.ready = true;
            client.local_output_ready();
        }
        if complete.is_none() {
            if let ClientPoll::Complete { bytes } = client
                .poll(connection, pair.now, &mut source, &mut sink)
                .expect("client poll")
            {
                complete = Some(bytes);
            }
        }
        if sink.calls == 1 && sink_wakeup.is_none() {
            sink_wakeup = Some(turn + 20);
        }
        let connection = pair
            .server
            .connection_mut(pair.server_id)
            .expect("server connection");
        for (_, event) in server_events {
            server
                .event(connection, &event, pair.now)
                .expect("server event");
        }
        server.poll(connection, pair.now).expect("server poll");
        if complete.is_some() && server.complete() {
            break;
        }
    }
    assert!(source.ready && sink.ready);
    assert_eq!(complete, Some(expected.len() as u64));
    assert!(server.complete());
    assert_eq!(sink.data, expected);
}
