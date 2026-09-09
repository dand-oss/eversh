//! Direct contract tests for the M3 Slice 1 identity and authorization core.
#![allow(clippy::unwrap_used)]

use everssh::admission::AuthenticatedConnection;
use everssh::association::AssociationId;
use everssh::bootstrap::{
    decode_auth_frame, encode_auth_frame, try_encode_auth_frame, BootstrapRecord, SecretToken,
    AUTH_FRAME_LEN,
};
use everssh::identity::EphemeralIdentity;
use everssh::limits::Limits;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn identity_is_ephemeral_spki_pinned_and_redacted() {
    let first = EphemeralIdentity::generate().unwrap();
    let second = EphemeralIdentity::generate().unwrap();
    let first_token = first.take_bootstrap_token().unwrap();
    let second_token = second.take_bootstrap_token().unwrap();
    assert!(matches!(
        first.take_bootstrap_token(),
        Err(everssh::Error::IdentityUnavailable)
    ));

    let extracted = everssh::pinning::extract_spki(first.certificate_der()).unwrap();
    assert_eq!(first.spki_sha256(), everssh::bootstrap::sha256(extracted));
    assert_ne!(
        first.spki_sha256(),
        everssh::bootstrap::sha256(first.certificate_der().as_ref())
    );
    assert_ne!(first.spki_sha256(), second.spki_sha256());
    assert_ne!(first_token.as_bytes(), second_token.as_bytes());

    let diagnostics = format!("{first:?} {first_token:?}");
    assert!(!diagnostics.contains(&hex(first_token.as_bytes())));
    assert!(diagnostics.contains("REDACTED"));
}

#[test]
fn bootstrap_debug_redacts_token_without_changing_wire() {
    let token = SecretToken::from_bytes([0x5a; 32]);
    let record = BootstrapRecord::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        4433,
        [0x33; 32],
        token,
        AssociationId::from_bytes([0x44; 16]).unwrap(),
        4242,
    )
    .unwrap();
    let wire = record.encode();

    assert!(wire.as_str().contains(&"5a".repeat(32)));
    assert!(!format!("{record:?}").contains(&"5a".repeat(32)));
    assert!(!format!("{wire:?}").contains(&"5a".repeat(32)));
    assert_eq!(
        BootstrapRecord::parse(wire.as_str().trim_end_matches('\n'), &Limits::default()).unwrap(),
        record
    );
}

#[test]
fn auth_prefix_is_frozen_and_secret_owned() {
    let limits = Limits::default();
    let token = SecretToken::from_bytes([3; 32]);
    let frame = encode_auth_frame(&token, 0x1234, &limits);

    assert_eq!(frame.len(), AUTH_FRAME_LEN);
    assert_eq!(frame[0], 1);
    assert_eq!(&frame[1..33], token.as_bytes());
    assert_eq!(&frame[33..], &[0x12, 0x34]);
    let (decoded, port) = decode_auth_frame(frame.as_ref(), &limits).unwrap();
    assert_eq!(decoded.as_bytes(), token.as_bytes());
    assert_eq!(port, 0x1234);
    assert!(!format!("{frame:?}").contains(&hex(token.as_bytes())));
    assert!(matches!(
        try_encode_auth_frame(&token, 0, &limits),
        Err(everssh::Error::TargetUnauthorized)
    ));
}

#[test]
fn authenticated_endpoints_derive_only_matching_loopback_target() {
    let v4 = AuthenticatedConnection::new(
        SocketAddr::from(([192, 0, 2, 10], 55_000)),
        SocketAddr::from(([192, 0, 2, 20], 2222)),
    )
    .unwrap();
    assert_eq!(
        v4.authorized_target_addr(),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 2222))
    );

    let v6 = AuthenticatedConnection::new(
        SocketAddr::from(("2001:db8::10".parse::<Ipv6Addr>().unwrap(), 55_000)),
        SocketAddr::from(("2001:db8::20".parse::<Ipv6Addr>().unwrap(), 2223)),
    )
    .unwrap();
    assert_eq!(
        v6.authorized_target_addr(),
        SocketAddr::from((Ipv6Addr::LOCALHOST, 2223))
    );

    assert!(AuthenticatedConnection::new(
        SocketAddr::from(([192, 0, 2, 10], 0)),
        SocketAddr::from(([192, 0, 2, 20], 22)),
    )
    .is_err());
    assert!(AuthenticatedConnection::new(
        SocketAddr::from(([192, 0, 2, 10], 50_000)),
        SocketAddr::from((Ipv6Addr::LOCALHOST, 22)),
    )
    .is_err());
    assert!(AuthenticatedConnection::new(
        SocketAddr::from(([192, 0, 2, 10], 50_000)),
        SocketAddr::from(([192, 0, 2, 20], 0)),
    )
    .is_err());
    assert!(AuthenticatedConnection::new(
        SocketAddr::from(("fe80::1".parse::<Ipv6Addr>().unwrap(), 50_000)),
        SocketAddr::from(("fe80::2".parse::<Ipv6Addr>().unwrap(), 22)),
    )
    .is_err());
}
