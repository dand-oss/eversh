//! Boundary tests for the remote-control request codec, session names, and
//! socket path checks.
#![allow(clippy::unwrap_used)]

use eversh::limits::Limits;
use eversh::remote::*;
use eversh::Error;

fn sample() -> RemoteRequest {
    RemoteRequest {
        version: 1,
        args: vec![b"connect".to_vec(), b"--session".to_vec(), b"work".to_vec()],
    }
}

#[test]
fn roundtrips_exactly_be() {
    let l = Limits::default();
    let e = sample().encode(&l).unwrap();
    assert_eq!(&e[..3], &[1u8, 0, 3], "version + BE arg_count");
    assert_eq!(&e[3..7], &7u32.to_be_bytes(), "BE arg_len");
    let d = RemoteRequest::decode(&e, &l).unwrap();
    assert_eq!(d, sample());
    assert_eq!(d.encode(&l).unwrap(), e, "canonical encoding");
}

#[test]
fn arbitrary_binary_args_roundtrip() {
    let l = Limits::default();
    let r = RemoteRequest {
        version: 1,
        args: vec![
            vec![0xff, 0x80, 0x01],
            (0u16..600).map(|i| (i % 255 + 1) as u8).collect(), // never NUL (rejected by contract)
            b"-".repeat(1000),
        ],
    };
    let d = RemoteRequest::decode(&r.encode(&l).unwrap(), &l).unwrap();
    assert_eq!(d, r);
}

#[test]
fn cap_checked_before_allocation() {
    let l = Limits::default();
    // Encode a request whose DECLARED length exceeds the cap: decode must
    // reject on total length without walking argument lengths.
    let mut big = vec![1u8, 0, 1];
    big.extend_from_slice(&u32::MAX.to_be_bytes());
    big.extend_from_slice(&[0u8; 8]);
    assert!(matches!(
        RemoteRequest::decode(&big, &l),
        Err(Error::RequestTooLarge)
    ));
    // And a genuinely oversized buffer is rejected immediately.
    let oversized = vec![0u8; l.remote_control_max + 1];
    assert!(matches!(
        RemoteRequest::decode(&oversized, &l),
        Err(Error::RequestTooLarge)
    ));
}

#[test]
fn nul_rejected_in_any_arg() {
    let l = Limits::default();
    let bad = RemoteRequest {
        version: 1,
        args: vec![b"a".to_vec(), b"x\0y".to_vec()],
    };
    assert!(matches!(bad.encode(&l), Err(Error::NullInArg)));
    let mut wire = vec![1u8, 0, 1, 0, 0, 0, 3, b'a', 0, b'c'];
    assert!(matches!(
        RemoteRequest::decode(&wire, &l),
        Err(Error::NullInArg)
    ));
    wire.clear();
}

#[test]
fn arg_count_and_trailing_bytes_enforced() {
    let l = Limits::default();
    let mut e = sample().encode(&l).unwrap();
    e[2] = 200; // arg_count beyond cap
    assert!(matches!(
        RemoteRequest::decode(&e, &l),
        Err(Error::ArgCountExceeded)
    ));
    let mut e2 = sample().encode(&l).unwrap();
    e2.push(0); // trailing byte
    assert!(matches!(
        RemoteRequest::decode(&e2, &l),
        Err(Error::RequestTooLarge)
    ));
    let mut e3 = sample().encode(&l).unwrap();
    e3[0] = 2;
    assert!(matches!(
        RemoteRequest::decode(&e3, &l),
        Err(Error::VersionUnsupported)
    ));
}

#[test]
fn every_truncation_fails() {
    let l = Limits::default();
    let e = sample().encode(&l).unwrap();
    for cut in 0..e.len() {
        assert!(RemoteRequest::decode(&e[..cut], &l).is_err(), "cut {cut}");
    }
}

#[test]
fn names_and_paths() {
    let l = Limits::default();
    assert!(validate_name("a.b-_c9", &l));
    for bad in ["", "-a", "a b", &"x".repeat(65), "a;b"] {
        assert!(!validate_name(bad, &l), "{bad:?}");
    }
    let ok_path = "/run/user/1000/eversh/sessions/a-name-_/socket";
    assert!(check_socket_path(ok_path, &l).is_ok());
    let long = format!("/{}", "x".repeat(l.unix_path_max));
    assert!(matches!(
        check_socket_path(&long, &l),
        Err(Error::PathTooLong)
    ));
    // Exactly at the limit is allowed; one byte over is not.
    let exact = "x".repeat(l.unix_path_max);
    assert!(check_socket_path(&exact, &l).is_ok());
    let over = format!("{}x", exact);
    assert!(check_socket_path(&over, &l).is_err());
}
