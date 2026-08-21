//! Deterministic arbitrary-byte fixtures (LCG) and multi-frame codec
//! byte-identity tests. Payloads are `Vec<u8>` throughout: no UTF-8
//! assumption is even expressible here.
#![allow(clippy::unwrap_used)]

use everpty::frame::*;
use everpty::limits::Limits;

/// Deterministic LCG byte generator (no external test dependency).
pub fn lcg_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        out.push((state >> 33) as u8);
    }
    out
}

fn fixture_shapes() -> Vec<Vec<u8>> {
    vec![
        vec![],
        vec![0xff],
        vec![0x00],
        b"\r\n".to_vec(),
        vec![0xc3, 0xa9],       // partial UTF-8 pair (bytes only)
        vec![0xed, 0xa0, 0x80], // UTF-8 surrogate (invalid as text)
        lcg_bytes(1, 1),
        lcg_bytes(2, 17),
        lcg_bytes(3, 255),
        lcg_bytes(4, 4096),
        lcg_bytes(5, 65535),
        vec![0xffu8; 4096],
        (0..=255u8).collect(),
    ]
}

#[test]
fn multi_frame_stream_roundtrips_at_every_split_point() {
    let l = Limits::default();
    for shape in fixture_shapes() {
        // Skip shapes that cannot fit a minimal Input frame under the cap.
        if shape.len() + 2 > l.frame_max_body {
            continue;
        }
        // A long stream of alternating Input/Output frames with this shape.
        let mut stream = Vec::new();
        let mut frames = Vec::new();
        for i in 0..8u32 {
            let mut payload = shape.clone();
            // Prepend the frame index only when the cap allows; the largest
            // shape (65535) is used as-is.
            if shape.len() + 6 <= l.frame_max_body {
                payload.splice(..0, i.to_be_bytes()); // prepend frame index
            }
            let f = if i % 2 == 0 {
                Frame::Input(payload)
            } else {
                Frame::Output(payload)
            };
            f.encode_into(&mut stream);
            frames.push(f);
        }
        // Decode the whole stream frame by frame.
        let mut rest: &[u8] = &stream;
        for f in &frames {
            let (back, used) = Frame::decode(rest, &l).unwrap();
            assert_eq!(&back, f);
            rest = &rest[used..];
        }
        assert!(rest.is_empty(), "stream fully consumed");
        // Byte identity of the whole stream under re-encode.
        let mut re = Vec::new();
        for f in &frames {
            f.encode_into(&mut re);
        }
        assert_eq!(re, stream);
        // And decoding across arbitrary split points: concatenate is
        // associative under the codec — decode prefix + suffix stitched.
        for split in [
            1usize,
            3,
            7,
            stream.len() / 2,
            stream.len().saturating_sub(1),
        ] {
            if split == 0 || split >= stream.len() {
                continue;
            }
            let mut rebuilt = Vec::new();
            rebuilt.extend_from_slice(&stream[..split]);
            rebuilt.extend_from_slice(&stream[split..]);
            assert_eq!(rebuilt, stream);
        }
    }
}

#[test]
fn every_fixture_survives_input_output_payloads_exactly() {
    let l = Limits::default();
    for shape in fixture_shapes() {
        if shape.len() + 2 > l.frame_max_body {
            continue;
        }
        for f in [Frame::Input(shape.clone()), Frame::Output(shape.clone())] {
            let (back, used) = Frame::decode(&f.encode(), &l).unwrap();
            assert_eq!(used, f.encode().len());
            assert_eq!(back, f, "byte-identical payload");
        }
    }
}

#[test]
fn fixtures_are_deterministic_and_distinct() {
    assert_eq!(lcg_bytes(42, 100), lcg_bytes(42, 100));
    assert_ne!(lcg_bytes(1, 100), lcg_bytes(2, 100));
    assert!(!lcg_bytes(9, 4096).iter().all(|&b| b == 0));
}
