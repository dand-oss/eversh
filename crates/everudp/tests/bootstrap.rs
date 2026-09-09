use everssh::association::AssociationId;
use everssh::bootstrap::SecretToken;
use everudp::{BootstrapError, BootstrapRecord, GatewayGeneration, Limits};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

fn record(endpoint: SocketAddr) -> BootstrapRecord {
    BootstrapRecord::new(
        endpoint,
        [2; 32],
        SecretToken::from_bytes([3; 32]),
        AssociationId::from_bytes([4; 16]).expect("association"),
        GatewayGeneration::from_bytes([5; 16]).expect("generation"),
        1234,
    )
    .expect("record")
}

#[test]
fn bootstrap_round_trips_ipv4_and_ipv6_canonically() {
    let limits = Limits::default();
    for endpoint in [
        SocketAddr::from((Ipv4Addr::new(192, 0, 2, 10), 4444)),
        SocketAddr::from((Ipv6Addr::LOCALHOST, 4444)),
    ] {
        let expected = record(endpoint);
        let line = expected.encode();
        assert!(line.as_str().starts_with("everudp v1 "));
        assert!(line.as_str().ends_with('\n'));
        let decoded = BootstrapRecord::parse_line(line.as_str(), &limits).expect("parse");
        assert_eq!(decoded, expected);
        assert_eq!(decoded.encode().as_str(), line.as_str());
    }
}

#[test]
fn bootstrap_rejects_trailing_noncanonical_and_unusable_fields() {
    let limits = Limits::default();
    let line = record(SocketAddr::from((Ipv4Addr::LOCALHOST, 4444))).encode();
    for malformed in [
        line.as_str().trim_end().to_owned(),
        format!("{}x", line.as_str()),
        line.as_str().replacen(" 4444 ", " 04444 ", 1),
        line.as_str().replacen("everudp v1", "everudp v2", 1),
    ] {
        assert_eq!(
            BootstrapRecord::parse_line(&malformed, &limits),
            Err(BootstrapError::Malformed)
        );
    }
    assert_eq!(
        BootstrapRecord::new(
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 4444)),
            [2; 32],
            SecretToken::from_bytes([3; 32]),
            AssociationId::from_bytes([4; 16]).expect("association"),
            GatewayGeneration::from_bytes([5; 16]).expect("generation"),
            1234,
        ),
        Err(BootstrapError::Endpoint)
    );
}

#[test]
fn bootstrap_secret_paths_are_redacted() {
    let record = record(SocketAddr::from((Ipv4Addr::LOCALHOST, 4444)));
    let line = record.encode();
    assert!(format!("{record:?} {line:?}").contains("REDACTED"));
    assert!(!format!("{record:?}").contains(&"03".repeat(32)));
}
