#![no_main]

use everudp::wire::{decode_record, Kind, StreamRole, HEADER_LEN};
use everudp::{ClientHello, Limits, ServerHello};
use libfuzzer_sys::fuzz_target;

const MAX_CHUNK_STEPS: usize = 64;

fuzz_target!(|data: &[u8]| {
    let (plan, wire) = if let Some((&declared, remainder)) = data.split_first() {
        let plan_len = usize::from(declared)
            .min(MAX_CHUNK_STEPS)
            .min(remainder.len());
        remainder.split_at(plan_len)
    } else {
        (&[][..], data)
    };

    let limits = Limits::default();
    let maximum = limits.control_frame_max + HEADER_LEN;
    let mut buffered = Vec::with_capacity(maximum);
    let mut offset = 0_usize;

    for &requested in plan {
        if offset == wire.len() || buffered.len() == maximum {
            break;
        }
        let end = offset
            .saturating_add(usize::from(requested))
            .min(wire.len())
            .min(offset + maximum - buffered.len());
        buffered.extend_from_slice(&wire[offset..end]);
        offset = end;
        check_prefix(&buffered, &limits);
    }

    if offset < wire.len() && buffered.len() < maximum {
        let take = (wire.len() - offset).min(maximum - buffered.len());
        buffered.extend_from_slice(&wire[offset..offset + take]);
    }
    check_prefix(&buffered, &limits);

    let direct = decode_record(StreamRole::Control, &buffered, &limits);
    if let Ok((record, consumed)) = direct {
        assert!(
            consumed <= buffered.len(),
            "resume record crossed its boundary"
        );
        let tail_before = buffered[consumed..].to_vec();
        match record.header.kind {
            Kind::ClientHello => {
                if let Ok(hello) = ClientHello::decode_exact(record.payload) {
                    let mut encoded = [0_u8; ClientHello::MAX_ENCODED_LEN];
                    let used = hello.encode_into(&mut encoded).unwrap();
                    assert_eq!(&encoded[..used], record.payload);
                }
            }
            Kind::ServerHello => {
                if let Ok(hello) = ServerHello::decode_exact(record.payload) {
                    let mut encoded = [0_u8; ServerHello::ENCODED_LEN];
                    let used = hello.encode_into(&mut encoded).unwrap();
                    assert_eq!(&encoded[..used], record.payload);
                }
            }
            _ => {}
        }
        assert_eq!(
            &buffered[consumed..],
            tail_before.as_slice(),
            "opaque bytes entered the resume handshake"
        );
    }
});

fn check_prefix(prefix: &[u8], limits: &Limits) {
    match decode_record(StreamRole::Control, prefix, limits) {
        Ok((record, consumed)) => {
            assert!(consumed <= prefix.len());
            assert_eq!(record.payload.len() + HEADER_LEN, consumed);
        }
        Err(error) => {
            let _ = error;
        }
    }
}
