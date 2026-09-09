use everssh::association::AssociationId;
use everudp::wire::ConnectionRole;
use everudp::{BootstrapOperation, BootstrapRequest, RequestError};

fn association() -> AssociationId {
    AssociationId::from_bytes([7; 16]).expect("association")
}

fn request(operation: BootstrapOperation) -> Result<BootstrapRequest, RequestError> {
    let observe = operation == BootstrapOperation::Observe;
    BootstrapRequest::new(
        operation,
        "claude-work".to_owned(),
        if observe {
            ConnectionRole::Observer
        } else {
            ConnectionRole::Writer
        },
        false,
        if observe { 0 } else { 40 },
        if observe { 0 } else { 120 },
        association(),
        [9; 32],
        if operation == BootstrapOperation::Connect {
            "eversh:badger".to_owned()
        } else {
            String::new()
        },
        if operation == BootstrapOperation::Connect {
            vec![b"claude".to_vec(), b"--resume".to_vec()]
        } else {
            Vec::new()
        },
    )
}

#[test]
fn every_operation_round_trips_as_one_canonical_shell_safe_token() {
    for operation in [
        BootstrapOperation::Connect,
        BootstrapOperation::Attach,
        BootstrapOperation::Observe,
    ] {
        let original = request(operation).expect("request");
        let token = original.encode_token().expect("token");
        assert!(token.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(token, token.to_ascii_lowercase());
        let decoded = BootstrapRequest::decode_token(&token).expect("decode");
        assert_eq!(decoded.operation(), operation);
        assert_eq!(decoded.session(), "claude-work");
        assert_eq!(decoded.association_id(), association());
        assert_eq!(decoded.client_spki_sha256(), [9; 32]);
        assert_eq!(decoded.command(), original.command());
        assert_eq!(decoded.encode_token().expect("canonical"), token);
        assert!(!format!("{decoded:?}").contains("--resume"));
    }
}

#[test]
fn malformed_role_dimension_takeover_command_and_token_edges_fail_closed() {
    assert!(BootstrapRequest::new(
        BootstrapOperation::Observe,
        "work".into(),
        ConnectionRole::Writer,
        false,
        0,
        0,
        association(),
        [1; 32],
        String::new(),
        vec![],
    )
    .is_err());
    assert!(BootstrapRequest::new(
        BootstrapOperation::Attach,
        "work".into(),
        ConnectionRole::Writer,
        false,
        0,
        80,
        association(),
        [1; 32],
        String::new(),
        vec![],
    )
    .is_err());
    assert!(BootstrapRequest::new(
        BootstrapOperation::Observe,
        "work".into(),
        ConnectionRole::Observer,
        true,
        0,
        0,
        association(),
        [1; 32],
        String::new(),
        vec![],
    )
    .is_err());
    assert!(BootstrapRequest::new(
        BootstrapOperation::Attach,
        "work".into(),
        ConnectionRole::Writer,
        false,
        24,
        80,
        association(),
        [1; 32],
        String::new(),
        vec![b"forbidden".to_vec()],
    )
    .is_err());

    let token = request(BootstrapOperation::Connect)
        .expect("request")
        .encode_token()
        .expect("token");
    for malformed in [
        String::new(),
        token[..token.len() - 1].to_owned(),
        format!("{}G0", &token[..token.len() - 2]),
        format!("{}00", token),
    ] {
        assert!(BootstrapRequest::decode_token(&malformed).is_err());
    }
}
