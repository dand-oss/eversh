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
        if operation == BootstrapOperation::Connect {
            "xterm-kitty".to_owned()
        } else {
            String::new()
        },
    )
}

fn connect_with_term(term: &str) -> Result<BootstrapRequest, RequestError> {
    BootstrapRequest::new(
        BootstrapOperation::Connect,
        "claude-work".to_owned(),
        ConnectionRole::Writer,
        false,
        40,
        120,
        association(),
        [9; 32],
        "eversh:badger".to_owned(),
        vec![b"bash".to_vec()],
        term.to_owned(),
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
        assert_eq!(decoded.term(), original.term());
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
        String::new(),
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
        String::new(),
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
        String::new(),
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
        String::new(),
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

#[test]
fn term_is_optional_bounded_connect_only_and_absent_from_legacy_tokens() {
    // A token from a client that predates the field (no trailing TERM
    // bytes) decodes with an empty TERM: the wire stays compatible.
    let with_term = connect_with_term("screen-256color").expect("request");
    let legacy = connect_with_term("").expect("request");
    let with_term_token = with_term.encode_token().expect("token");
    let legacy_token = legacy.encode_token().expect("token");
    assert!(with_term_token.starts_with(&legacy_token));
    assert_eq!(
        BootstrapRequest::decode_token(&legacy_token)
            .expect("legacy decodes")
            .term(),
        ""
    );
    assert_eq!(
        BootstrapRequest::decode_token(&with_term_token)
            .expect("decodes")
            .term(),
        "screen-256color"
    );
    assert!(format!("{with_term:?}").contains("screen-256color"));

    // Acceptable names are terminfo-shaped and bounded.
    assert!(BootstrapRequest::acceptable_term("xterm-kitty"));
    assert!(BootstrapRequest::acceptable_term("tmux-256color"));
    assert!(!BootstrapRequest::acceptable_term(""));
    assert!(!BootstrapRequest::acceptable_term("xterm kitty"));
    assert!(!BootstrapRequest::acceptable_term("xterm;rm"));
    assert!(!BootstrapRequest::acceptable_term(&"x".repeat(65)));
    assert!(matches!(
        connect_with_term("bad term"),
        Err(RequestError::InvalidTerm)
    ));
    assert!(matches!(
        connect_with_term(&"x".repeat(65)),
        Err(RequestError::InvalidTerm)
    ));

    // Only Connect creates a session, so only Connect may carry TERM.
    assert!(matches!(
        BootstrapRequest::new(
            BootstrapOperation::Attach,
            "work".into(),
            ConnectionRole::Writer,
            false,
            24,
            80,
            association(),
            [1; 32],
            String::new(),
            vec![],
            "xterm-kitty".to_owned(),
        ),
        Err(RequestError::InvalidTerm)
    ));

    // A trailing zero-length TERM field is not canonical and is refused.
    assert!(BootstrapRequest::decode_token(&format!("{legacy_token}00")).is_err());
}
