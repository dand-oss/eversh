use everudp::wire::{
    decode_fast_datagram, decode_record, encode_fast_datagram, encode_record, Ack, ConnectionRole,
    EpochGap, FastDirection, FrameHeader, Kind, Resize, StreamLayout, StreamRole, ALPN,
    BOOTSTRAP_PREFIX, FAST_DATAGRAM_HEADER_LEN, FAST_DATAGRAM_PAYLOAD_MAX, HEADER_LEN,
    STATUS_PREFIX, WIRE_VERSION,
};
use everudp::{Limits, WireError};

#[test]
fn protocol_identifiers_and_header_bytes_are_frozen() {
    assert_eq!(ALPN, b"everudp-link/1");
    assert_eq!(BOOTSTRAP_PREFIX, "everudp v1 ");
    assert_eq!(STATUS_PREFIX, "everudp-status-v1 ");
    assert_eq!(WIRE_VERSION, 1);
    assert_eq!(HEADER_LEN, 14);

    let header = FrameHeader::new(Kind::Input, 0x0102_0304_0506_0708, 3);
    assert_eq!(
        header.encode(),
        [1, 0x20, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 3,]
    );
}

#[test]
fn fast_datagram_round_trip_is_exact_and_bounded() {
    let mut encoded = [0_u8; FAST_DATAGRAM_HEADER_LEN + FAST_DATAGRAM_PAYLOAD_MAX];
    let used = encode_fast_datagram(
        FastDirection::GatewayToClient,
        Kind::Output,
        0x0102_0304_0506_0708,
        0x1112_1314_1516_1718,
        b"opaque\0output",
        &mut encoded,
    )
    .expect("encode fast datagram");
    let record = decode_fast_datagram(FastDirection::GatewayToClient, &encoded[..used])
        .expect("decode fast datagram");
    assert_eq!(record.direction, FastDirection::GatewayToClient);
    assert_eq!(record.kind, Kind::Output);
    assert_eq!(record.epoch, 0x0102_0304_0506_0708);
    assert_eq!(record.sequence, 0x1112_1314_1516_1718);
    assert_eq!(record.payload, b"opaque\0output");
    assert_eq!(
        record.payload.as_ptr(),
        encoded[FAST_DATAGRAM_HEADER_LEN..].as_ptr()
    );
}

#[test]
fn fast_datagram_rejects_every_truncation_and_noncanonical_shape() {
    let mut encoded = [0_u8; FAST_DATAGRAM_HEADER_LEN + 3];
    let used = encode_fast_datagram(
        FastDirection::ClientToGateway,
        Kind::Input,
        7,
        11,
        b"abc",
        &mut encoded,
    )
    .expect("encode fast datagram");
    for length in 0..used {
        assert!(matches!(
            decode_fast_datagram(FastDirection::ClientToGateway, &encoded[..length]),
            Err(WireError::Incomplete { .. })
        ));
    }

    let mut wrong = encoded;
    wrong[0] = 2;
    assert_eq!(
        decode_fast_datagram(FastDirection::ClientToGateway, &wrong),
        Err(WireError::VersionUnsupported(2))
    );
    wrong = encoded;
    wrong[1] = FastDirection::GatewayToClient as u8;
    assert_eq!(
        decode_fast_datagram(FastDirection::ClientToGateway, &wrong),
        Err(WireError::DatagramDirection(
            FastDirection::GatewayToClient as u8
        ))
    );
    wrong = encoded;
    wrong[2] = Kind::Resize as u8;
    assert_eq!(
        decode_fast_datagram(FastDirection::ClientToGateway, &wrong),
        Err(WireError::KindNotAllowed {
            kind: Kind::Resize,
            stream: StreamRole::Input,
        })
    );
    let mut extra = encoded.to_vec();
    extra.push(0);
    assert!(matches!(
        decode_fast_datagram(FastDirection::ClientToGateway, &extra),
        Err(WireError::LengthInvalid { .. })
    ));

    let oversized = vec![0_u8; FAST_DATAGRAM_PAYLOAD_MAX + 1];
    assert_eq!(
        encode_fast_datagram(
            FastDirection::ClientToGateway,
            Kind::Input,
            0,
            0,
            &oversized,
            &mut encoded,
        ),
        Err(WireError::PayloadTooLarge {
            kind: Kind::Input,
            length: FAST_DATAGRAM_PAYLOAD_MAX + 1,
            maximum: FAST_DATAGRAM_PAYLOAD_MAX,
        })
    );
}

#[test]
fn every_stream_round_trips_without_allocating_a_payload() {
    let limits = Limits::default();
    let cases: &[(StreamRole, Kind, &[u8])] = &[
        (StreamRole::Control, Kind::ClientHello, &[7]),
        (StreamRole::Control, Kind::AckInput, &[0; 16]),
        (StreamRole::Control, Kind::Gap, &[0; 16]),
        (StreamRole::Input, Kind::Input, b"abc"),
        (StreamRole::Input, Kind::Resize, &[0; 8]),
        (StreamRole::Input, Kind::Signal, &[15]),
        (StreamRole::Input, Kind::InputClose, &[]),
        (StreamRole::Output, Kind::Output, b"opaque\0bytes"),
        (StreamRole::Output, Kind::Ownership, &[1]),
        (StreamRole::Output, Kind::Exit, &[0; 4]),
    ];

    for (stream, kind, payload) in cases {
        let mut encoded = [0_u8; 128];
        let used = encode_record(*stream, *kind, 41, payload, &limits, &mut encoded)
            .expect("encode record");
        let (record, consumed) =
            decode_record(*stream, &encoded[..used], &limits).expect("decode record");
        assert_eq!(consumed, used);
        assert_eq!(record.header.kind, *kind);
        assert_eq!(record.header.sequence, 41);
        assert_eq!(record.payload, *payload);
        assert_eq!(record.payload.as_ptr(), encoded[HEADER_LEN..].as_ptr());
    }
}

#[test]
fn malformed_version_kind_length_and_stream_fail_closed() {
    let limits = Limits::default();
    let mut header = FrameHeader::new(Kind::Input, 0, 1).encode();

    header[0] = 2;
    assert_eq!(
        decode_record(StreamRole::Input, &header, &limits),
        Err(WireError::VersionUnsupported(2))
    );

    header[0] = WIRE_VERSION;
    header[1] = 0xff;
    assert_eq!(
        decode_record(StreamRole::Input, &header, &limits),
        Err(WireError::UnknownKind(0xff))
    );

    let wrong_stream = FrameHeader::new(Kind::Output, 0, 1).encode();
    assert_eq!(
        decode_record(StreamRole::Input, &wrong_stream, &limits),
        Err(WireError::KindNotAllowed {
            kind: Kind::Output,
            stream: StreamRole::Input,
        })
    );

    let wrong_resize = FrameHeader::new(Kind::Resize, 0, 7).encode();
    assert_eq!(
        decode_record(StreamRole::Input, &wrong_resize, &limits),
        Err(WireError::LengthInvalid {
            kind: Kind::Resize,
            length: 7,
        })
    );
}

#[test]
fn caps_are_checked_from_the_header_before_payload_is_buffered() {
    let limits = Limits::default();
    let oversized = FrameHeader::new(
        Kind::Output,
        0,
        u32::try_from(limits.terminal_frame_max + 1).expect("cap"),
    )
    .encode();
    assert_eq!(
        decode_record(StreamRole::Output, &oversized, &limits),
        Err(WireError::PayloadTooLarge {
            kind: Kind::Output,
            length: limits.terminal_frame_max + 1,
            maximum: limits.terminal_frame_max,
        })
    );

    let incomplete = FrameHeader::new(Kind::Input, 0, 3).encode();
    assert_eq!(
        decode_record(StreamRole::Input, &incomplete, &limits),
        Err(WireError::Incomplete {
            needed: HEADER_LEN + 3,
            available: HEADER_LEN,
        })
    );
}

#[test]
fn stream_layout_rejects_observer_input_and_every_extra_stream() {
    let mut writer = StreamLayout::new(ConnectionRole::Writer);
    writer.admit(StreamRole::Control).expect("control");
    writer.admit(StreamRole::Input).expect("input");
    writer.admit(StreamRole::Output).expect("output");
    assert!(writer.is_complete());
    assert_eq!(
        writer.admit(StreamRole::Output),
        Err(WireError::DuplicateStream(StreamRole::Output))
    );

    let mut observer = StreamLayout::new(ConnectionRole::Observer);
    observer.admit(StreamRole::Control).expect("control");
    assert_eq!(
        observer.admit(StreamRole::Input),
        Err(WireError::ObserverInputStream)
    );
    observer.admit(StreamRole::Output).expect("output");
    assert!(observer.is_complete());
}

#[test]
fn resize_has_one_canonical_network_order_encoding() {
    let resize = Resize {
        rows: 24,
        columns: 80,
        pixel_width: 1_920,
        pixel_height: 1_080,
    };
    let encoded = resize.encode();
    assert_eq!(encoded, [0, 24, 0, 80, 7, 128, 4, 56]);
    assert_eq!(Resize::decode_exact(&encoded), Ok(resize));
    assert_eq!(
        Resize::decode_exact(&encoded[..7]),
        Err(WireError::LengthInvalid {
            kind: Kind::Resize,
            length: 7,
        })
    );
}

#[test]
fn cumulative_ack_and_gap_epochs_are_explicit_and_canonical() {
    let ack = Ack {
        epoch: 0x0102_0304_0506_0708,
        next_expected: 0x1112_1314_1516_1718,
    };
    assert_eq!(Ack::decode_exact(&ack.encode(), Kind::AckInput), Ok(ack));
    assert!(Ack::decode_exact(&ack.encode()[..15], Kind::AckOutput).is_err());

    let gap = EpochGap::new(8, 9).expect("gap");
    assert_eq!(EpochGap::decode_exact(&gap.encode()), Ok(gap));
    assert!(EpochGap::new(9, 9).is_err());
    assert!(EpochGap::new(9, 8).is_err());
}
