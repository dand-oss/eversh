use everssh::association::AssociationId;
use everssh::bootstrap::SecretToken;
use everudp::wire::ConnectionRole;
use everudp::{ClientHello, GatewayGeneration, HandshakeError, ResumePosition, ServerHello};

fn association() -> AssociationId {
    AssociationId::from_bytes([1; 16]).expect("association")
}

fn generation() -> GatewayGeneration {
    GatewayGeneration::from_bytes([2; 16]).expect("generation")
}

fn position() -> ResumePosition {
    ResumePosition {
        input_epoch: 3,
        next_input: 4,
        output_epoch: 5,
        next_output: 6,
        delivered_output_ack: 6,
    }
}

fn initial_position() -> ResumePosition {
    ResumePosition {
        input_epoch: 0,
        next_input: 0,
        output_epoch: 0,
        next_output: 0,
        delivered_output_ack: 0,
    }
}

#[test]
fn initial_and_resume_hellos_have_canonical_exact_shapes() {
    let initial = ClientHello::initial(
        association(),
        generation(),
        ConnectionRole::Writer,
        initial_position(),
        SecretToken::from_bytes([7; 32]),
    )
    .expect("initial");
    let mut bytes = [0_u8; ClientHello::MAX_ENCODED_LEN];
    let used = initial.encode_into(&mut bytes).expect("encode");
    assert_eq!(used, ClientHello::INITIAL_ENCODED_LEN);
    assert_eq!(
        ClientHello::decode_exact(&bytes[..used]),
        Ok(initial.clone())
    );

    let resume = ClientHello::resume(
        association(),
        generation(),
        ConnectionRole::Observer,
        position(),
    )
    .expect("resume");
    let used = resume.encode_into(&mut bytes).expect("encode");
    assert_eq!(used, ClientHello::RESUME_ENCODED_LEN);
    assert_eq!(ClientHello::decode_exact(&bytes[..used]), Ok(resume));

    for cut in 0..used {
        assert!(ClientHello::decode_exact(&bytes[..cut]).is_err());
    }
    assert!(format!("{initial:?}").contains("REDACTED"));
    assert!(!format!("{initial:?}").contains(&"7".repeat(32)));
}

#[test]
fn hello_rejects_invalid_modes_roles_acks_and_trailing_bytes() {
    let hello = ClientHello::resume(
        association(),
        generation(),
        ConnectionRole::Writer,
        position(),
    )
    .expect("resume");
    let mut bytes = [0_u8; ClientHello::MAX_ENCODED_LEN + 1];
    let used = hello.encode_into(&mut bytes).expect("encode");

    bytes[0] = 9;
    assert_eq!(
        ClientHello::decode_exact(&bytes[..used]),
        Err(HandshakeError::UnknownHelloMode(9))
    );
    bytes[0] = 2;
    bytes[33] = 9;
    assert_eq!(
        ClientHello::decode_exact(&bytes[..used]),
        Err(HandshakeError::UnknownRole(9))
    );
    bytes[33] = 1;
    assert_eq!(
        ClientHello::decode_exact(&bytes[..=used]),
        Err(HandshakeError::InvalidLength)
    );

    let invalid_position = ResumePosition {
        delivered_output_ack: 7,
        ..position()
    };
    assert_eq!(
        ClientHello::resume(
            association(),
            generation(),
            ConnectionRole::Writer,
            invalid_position,
        ),
        Err(HandshakeError::AckAheadOfSequence)
    );
    assert_eq!(
        ClientHello::initial(
            association(),
            generation(),
            ConnectionRole::Writer,
            position(),
            SecretToken::from_bytes([7; 32]),
        ),
        Err(HandshakeError::InitialPositionNotZero)
    );
}

#[test]
fn server_hello_round_trips_pending_gap_without_ambiguity() {
    let hello = ServerHello::new(
        association(),
        generation(),
        ConnectionRole::Writer,
        3,
        4,
        5,
        6,
        Some((4, 5)),
    )
    .expect("server hello");
    let mut bytes = [0_u8; ServerHello::ENCODED_LEN];
    hello.encode_into(&mut bytes).expect("encode");
    assert_eq!(ServerHello::decode_exact(&bytes), Ok(hello));

    bytes[65] = 2;
    assert_eq!(
        ServerHello::decode_exact(&bytes),
        Err(HandshakeError::InvalidGapFlag(2))
    );
}
