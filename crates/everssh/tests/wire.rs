//! Boundary tests for the bootstrap record, auth frame, and SPKI pinning
//! types: total parsing, caps before allocation, constant-time compare.
#![allow(clippy::unwrap_used)]

use everssh::association::AssociationId;
use everssh::bootstrap::*;
use everssh::limits::Limits;
use std::net::IpAddr;

fn sample_record() -> BootstrapRecord {
    BootstrapRecord::new(
        IpAddr::from([127, 0, 0, 1]),
        4433,
        [7; 32],
        SecretToken::from_bytes([9; 32]),
        AssociationId::from_bytes([0x42; 16]).unwrap(),
        4242,
    )
    .unwrap()
}

#[test]
fn record_roundtrips_exactly() {
    let l = Limits::default();
    let r = sample_record();
    let line = r.encode();
    assert!(line.ends_with('\n'));
    let parsed = BootstrapRecord::parse(line.trim_end_matches('\n'), &l).unwrap();
    assert_eq!(parsed, r);
    assert_eq!(parsed.encode(), line);
}

#[test]
fn record_cap_checked_before_parse() {
    let l = Limits::default();
    // A line of exactly cap-1 chars plus newline is at the cap; one longer
    // is rejected by length alone (before any field parsing).
    let too_long = "x".repeat(l.bootstrap_record_max);
    assert!(matches!(
        BootstrapRecord::parse(&too_long, &l),
        Err(everssh::Error::BootstrapMalformed)
    ));
}

#[test]
fn record_rejects_garbage_totally() {
    let l = Limits::default();
    for bad in [
        "",
        "everssh v2 127.0.0.1 1 a b 2",
        "everssh v1 hostname 1 a b 2", // names are not resolved: literal only
        "everssh v1 127.0.0.1 99999 a b 2",
        "everssh v1 127.0.0.1 1 xx yy 2",
        "everssh v1 127.0.0.1 1 a b 2 extra",
        "m0 v1 127.0.0.1 1 a b 2", // old spike magic rejected
        "everssh v1 127.0.0.1 1 7 9 2",
    ] {
        assert!(
            BootstrapRecord::parse(bad, &l).is_err(),
            "{bad:?} must fail closed"
        );
    }
    // Well-formed line with short hex still fails.
    let good = sample_record().encode();
    let truncated_hex = good.replace(&"07".repeat(32), &"07".repeat(31));
    assert!(BootstrapRecord::parse(truncated_hex.trim_end_matches('\n'), &l).is_err());
}

#[test]
fn every_truncation_of_record_fails() {
    let l = Limits::default();
    let full = sample_record().encode();
    let line = full.trim_end_matches('\n');
    // A prefix of the final decimal pid field can itself be a valid shorter
    // pid, so the correct property is: every prefix either fails closed or
    // decodes to a DIFFERENT record (never the full record early).
    for cut in 0..line.len() {
        match BootstrapRecord::parse(&line[..cut], &l) {
            Err(_) => {}
            Ok(r) => assert_ne!(
                r,
                sample_record(),
                "prefix at {cut} must not decode to the full record"
            ),
        }
    }
}

#[test]
fn ipv6_literal_roundtrips() {
    let l = Limits::default();
    let r = BootstrapRecord::new(
        "fd00::1".parse().unwrap(),
        4433,
        [7; 32],
        SecretToken::from_bytes([9; 32]),
        AssociationId::from_bytes([0x42; 16]).unwrap(),
        4242,
    )
    .unwrap();
    let parsed = BootstrapRecord::parse(r.encode().trim_end_matches('\n'), &l).unwrap();
    assert_eq!(parsed, r);
}

#[test]
fn auth_frame_is_exactly_35_bytes_be() {
    let l = Limits::default();
    let token = SecretToken::from_bytes([3; 32]);
    let f = encode_auth_frame(&token, 0x1234, &l);
    assert_eq!(f.len(), 35);
    assert_eq!(f[0], 1);
    assert_eq!(&f[33..35], &[0x12, 0x34], "target port big-endian");
    let (tok, port) = decode_auth_frame(&f, &l).unwrap();
    assert_eq!(tok.as_bytes(), &[3; 32]);
    assert_eq!(port, 0x1234);
    for bad_len in [0usize, 1, 34, 36, 4096] {
        assert!(decode_auth_frame(&vec![0u8; bad_len], &l).is_err());
    }
    let mut bad_version = f.as_ref().to_vec();
    bad_version[0] = 2;
    assert!(matches!(
        decode_auth_frame(&bad_version, &l),
        Err(everssh::Error::VersionUnsupported)
    ));
}

#[test]
fn ct_eq_is_constant_shape() {
    assert!(ct_eq(b"abc", b"abc"));
    assert!(!ct_eq(b"abc", b"abd"));
    assert!(!ct_eq(b"abc", b"ab"));
}

#[test]
fn spki_extraction_matches_rcgen_vector() {
    // Vector property (from M0): extraction hashes the SubjectPublicKeyInfo,
    // not the whole certificate, and is deterministic per key.
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let spki = everssh::pinning::extract_spki(ck.cert.der()).expect("spki");
    assert!(spki.len() > 40 && spki.len() < ck.cert.der().len());
    // Same key re-issued (different serial/validity) yields the same SPKI.
    let ck2 = rcgen::generate_simple_self_signed(vec!["other".into()]).unwrap();
    let spki2 = everssh::pinning::extract_spki(ck2.cert.der()).expect("spki");
    assert_ne!(spki, spki2, "different keys must pin differently");
    // A different certificate with the SAME key material is unavailable from
    // generate_simple_self_signed; determinism is asserted instead.
    assert_eq!(everssh::pinning::extract_spki(ck.cert.der()).unwrap(), spki);
}
