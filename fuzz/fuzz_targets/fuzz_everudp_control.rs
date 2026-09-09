#![no_main]

use everudp::wire::{decode_record, encode_record, Ack, EpochGap, Kind, StreamRole, HEADER_LEN};
use everudp::{ClientHello, Limits, ServerHello};
use libfuzzer_sys::fuzz_target;

const MAX_CONTROL_WIRE: usize = 4 * 1024 + HEADER_LEN;

fuzz_target!(|data: &[u8]| {
    let limits = Limits::default();
    let Ok((record, consumed)) = decode_record(StreamRole::Control, data, &limits) else {
        return;
    };

    assert!(consumed <= data.len(), "decoder consumed past input");
    assert!(consumed <= MAX_CONTROL_WIRE, "control cap was bypassed");
    let opaque_tail = &data[consumed..];

    let mut encoded = [0_u8; MAX_CONTROL_WIRE];
    let used = encode_record(
        StreamRole::Control,
        record.header.kind,
        record.header.sequence,
        record.payload,
        &limits,
        &mut encoded,
    )
    .expect("an accepted record must encode");
    assert_eq!(used, consumed, "canonical record length changed");
    assert_eq!(
        &encoded[..used],
        &data[..consumed],
        "canonical control bytes changed"
    );
    assert_eq!(
        opaque_tail,
        &data[consumed..],
        "bytes after the accepted record changed"
    );

    match record.header.kind {
        Kind::ClientHello => {
            if let Ok(hello) = ClientHello::decode_exact(record.payload) {
                let mut payload = [0_u8; ClientHello::MAX_ENCODED_LEN];
                let length = hello
                    .encode_into(&mut payload)
                    .expect("accepted client hello must encode");
                assert_eq!(&payload[..length], record.payload);
                assert_eq!(
                    ClientHello::decode_exact(&payload[..length]).unwrap(),
                    hello
                );
            }
        }
        Kind::ServerHello => {
            if let Ok(hello) = ServerHello::decode_exact(record.payload) {
                let mut payload = [0_u8; ServerHello::ENCODED_LEN];
                let length = hello
                    .encode_into(&mut payload)
                    .expect("accepted server hello must encode");
                assert_eq!(&payload[..length], record.payload);
                assert_eq!(
                    ServerHello::decode_exact(&payload[..length]).unwrap(),
                    hello
                );
            }
        }
        Kind::AckInput | Kind::AckOutput => {
            if let Ok(ack) = Ack::decode_exact(record.payload, record.header.kind) {
                assert_eq!(ack.encode().as_slice(), record.payload);
            }
        }
        Kind::Gap => {
            if let Ok(gap) = EpochGap::decode_exact(record.payload) {
                assert_eq!(gap.encode().as_slice(), record.payload);
            }
        }
        Kind::LinkStatus
        | Kind::Detach
        | Kind::Kill
        | Kind::ProtocolClose
        | Kind::Input
        | Kind::Resize
        | Kind::Signal
        | Kind::InputClose
        | Kind::Output
        | Kind::Ownership
        | Kind::Exit => {}
    }
});
