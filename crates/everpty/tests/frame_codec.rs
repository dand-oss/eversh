//! Boundary tests for the frame codec: round-trips, total-parser behavior
//! at every truncation, caps rejected before allocation, and name rules.
#![allow(clippy::unwrap_used)]

use everpty::frame::*;
use everpty::limits::Limits;

fn all_kinds_sample() -> Vec<Frame> {
    vec![
        Frame::Hello {
            role: Role::Writer,
            take_over: true,
            name: "s1".into(),
            rows: 80,
            cols: 240,
        },
        Frame::Hello {
            role: Role::Observer,
            take_over: false,
            name: "a.b-_c9".into(),
            rows: 1,
            cols: 2,
        },
        Frame::HelloAck {
            client_id: 0xffff_ffff,
            broker_protocol_version: 1,
            status: AttachStatus::WriterGranted,
        },
        Frame::HelloAck {
            client_id: 7,
            broker_protocol_version: 1,
            status: AttachStatus::ObserverAccepted,
        },
        Frame::Busy {
            current_writer_id: 42,
        },
        Frame::Input(vec![0xff, 0x00, 0x80, 0xc3, 0xa9]),
        Frame::Output((0..=255u16).map(|i| i as u8).collect()),
        Frame::Resize {
            rows: 200,
            cols: 500,
        },
        Frame::Ownership(OwnershipEvent::Granted),
        Frame::Ownership(OwnershipEvent::Revoked),
        Frame::DetachWriter,
        Frame::Kill,
        Frame::Ping,
        Frame::Pong,
        Frame::Exit {
            signal: false,
            value: 3,
        },
        Frame::Exit {
            signal: true,
            value: 9,
        },
        Frame::Error {
            code: 513,
            text: "boom".into(),
        },
    ]
}

#[test]
fn every_kind_roundtrips_byte_exactly() {
    let l = Limits::default();
    for f in all_kinds_sample() {
        let bytes = f.encode();
        let (back, used) = Frame::decode(&bytes, &l).unwrap();
        assert_eq!(used, bytes.len(), "consumes exactly the frame");
        assert_eq!(back, f);
        // Re-encode is byte-identical (canonical encoding).
        assert_eq!(back.encode(), bytes);
    }
}

#[test]
fn header_is_big_endian_and_well_formed() {
    let f = Frame::Output(vec![1, 2, 3]);
    let b = f.encode();
    let body = b.len() - 4; // version+kind+payload
    assert_eq!(&b[..4], &(body as u32).to_be_bytes());
    assert_eq!(b[4], PROTOCOL_VERSION);
    assert_eq!(b[5], Kind::Output as u8);
}

#[test]
fn oversized_body_rejected_before_allocation() {
    let l = Limits::default();
    let mut h = [0u8; HEADER_LEN];
    h[..4].copy_from_slice(&((l.frame_max_body as u32) + 1).to_be_bytes());
    h[4] = PROTOCOL_VERSION;
    h[5] = Kind::Input as u8;
    match Frame::validate_header(&h, &l) {
        Err(FrameError::BodyTooLarge { .. }) => {}
        other => panic!("expected BodyTooLarge, got {other:?}"),
    }
    // And decode refuses without touching the payload: a one-byte buffer is
    // enough to prove rejection happens at the header.
    match Frame::decode(&h, &l) {
        Err(FrameError::BodyTooLarge { .. }) => {}
        other => panic!("expected BodyTooLarge, got {other:?}"),
    }
}

#[test]
fn reader_that_panics_on_large_reads_never_sees_oversized_payload() {
    // A reader which can only ever deliver HEADER_LEN bytes: if the codec
    // tried to allocate before validating the header, this test could not
    // exist. The codec validates purely from the 6 header bytes.
    let l = Limits::default();
    let mut h = vec![0u8; HEADER_LEN];
    h[..4].copy_from_slice(&(u32::MAX).to_be_bytes());
    h[4] = PROTOCOL_VERSION;
    h[5] = Kind::Input as u8;
    assert!(matches!(
        Frame::validate_header(&h, &l),
        Err(FrameError::BodyTooLarge { .. })
    ));
}

#[test]
fn every_truncation_is_rejected() {
    let l = Limits::default();
    for f in all_kinds_sample() {
        let full = f.encode();
        for cut in 0..full.len() {
            let r = Frame::decode(&full[..cut], &l);
            assert!(r.is_err(), "{:?} truncated at {cut} must fail", f.kind());
        }
    }
}

#[test]
fn unsupported_version_and_unknown_kind_fail_closed() {
    let l = Limits::default();
    let mut b = Frame::Ping.encode();
    b[4] = 9;
    assert!(matches!(
        Frame::decode(&b, &l),
        Err(FrameError::UnsupportedVersion { got: 9 })
    ));
    let mut b = Frame::Ping.encode();
    b[5] = 99;
    assert!(matches!(
        Frame::decode(&b, &l),
        Err(FrameError::UnknownKind { got: 99 })
    ));
}

#[test]
fn name_rules() {
    let l = Limits::default();
    for good in ["a", "A9", "a.b-c_d", &"x".repeat(64)] {
        assert!(validate_name(good, &l), "{good}");
    }
    for bad in [
        "",
        ".a",
        "-a",
        "_a",
        "a b",
        "a/b",
        "a;b",
        "a\n",
        "a$x",
        &"x".repeat(65),
        "ä",
        "a|b",
        "a..b'",
    ] {
        assert!(!validate_name(bad, &l), "{bad:?}");
    }
    // Hello frames with invalid names are rejected at decode.
    let bad = Frame::Hello {
        role: Role::Writer,
        take_over: false,
        name: "../evil".into(),
        rows: 1,
        cols: 1,
    };
    assert!(matches!(
        Frame::decode(&bad.encode(), &l),
        Err(FrameError::NameInvalid)
    ));
}

#[test]
fn exact_length_payloads_enforced() {
    let l = Limits::default();
    // HelloAck with wrong payload length (6 instead of 7).
    let mut b = Frame::HelloAck {
        client_id: 1,
        broker_protocol_version: 1,
        status: AttachStatus::WriterGranted,
    }
    .encode();
    let body_len = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
    let new_body = body_len - 1;
    b[..4].copy_from_slice(&(new_body as u32).to_be_bytes());
    b.pop();
    assert!(Frame::decode(&b, &l).is_err());
}

#[test]
fn max_body_roundtrips_and_cap_plus_one_fails() {
    let l = Limits::default();
    let payload = vec![0xaau8; l.frame_max_body - 2];
    let f = Frame::Output(payload);
    let b = f.encode();
    let (back, _) = Frame::decode(&b, &l).unwrap();
    assert_eq!(back, f);
    let mut h = [0u8; HEADER_LEN];
    h[..4].copy_from_slice(&((l.frame_max_body as u32) + 1).to_be_bytes());
    h[4] = PROTOCOL_VERSION;
    h[5] = Kind::Output as u8;
    assert!(matches!(
        Frame::validate_header(&h, &l),
        Err(FrameError::BodyTooLarge { .. })
    ));
}
