use everssh::association::AssociationId;
use everudp::wire::ConnectionRole;
use everudp::{AdmissionError, GatewayGeneration, InvitationStore, Limits};

fn association(byte: u8) -> AssociationId {
    AssociationId::from_bytes([byte; 16]).expect("nonzero association")
}

fn generation(byte: u8) -> GatewayGeneration {
    GatewayGeneration::from_bytes([byte; 16]).expect("nonzero generation")
}

#[test]
fn invitation_binds_every_authenticated_dimension_and_consumes_once() {
    let limits = Limits::default();
    let mut store = InvitationStore::new("work", generation(7), &limits).expect("store");
    let ticket = store
        .issue_with_takeover(association(1), ConnectionRole::Writer, [2; 32], true, 1_000)
        .expect("issue");
    assert!(ticket.take_over());

    let claims = [
        store.claim(
            ticket.token().as_bytes(),
            association(3),
            "work",
            generation(7),
            ConnectionRole::Writer,
            [2; 32],
            1_001,
        ),
        store.claim(
            ticket.token().as_bytes(),
            association(1),
            "other",
            generation(7),
            ConnectionRole::Writer,
            [2; 32],
            1_001,
        ),
        store.claim(
            ticket.token().as_bytes(),
            association(1),
            "work",
            generation(8),
            ConnectionRole::Writer,
            [2; 32],
            1_001,
        ),
        store.claim(
            ticket.token().as_bytes(),
            association(1),
            "work",
            generation(7),
            ConnectionRole::Observer,
            [2; 32],
            1_001,
        ),
        store.claim(
            ticket.token().as_bytes(),
            association(1),
            "work",
            generation(7),
            ConnectionRole::Writer,
            [4; 32],
            1_001,
        ),
    ];
    assert!(claims
        .iter()
        .all(|claim| *claim == Err(AdmissionError::BindingMismatch)));

    assert!(store
        .claim(
            ticket.token().as_bytes(),
            association(1),
            "work",
            generation(7),
            ConnectionRole::Writer,
            [2; 32],
            1_001,
        )
        .expect("matching claim"));
    assert_eq!(
        store.claim(
            ticket.token().as_bytes(),
            association(1),
            "work",
            generation(7),
            ConnectionRole::Writer,
            [2; 32],
            1_002,
        ),
        Err(AdmissionError::TokenReuse)
    );
}

#[test]
fn takeover_is_writer_only_and_is_cryptographically_carried_by_the_invitation() {
    let limits = Limits::default();
    let mut store = InvitationStore::new("work", generation(7), &limits).expect("store");
    assert_eq!(
        store.issue_with_takeover(
            association(1),
            ConnectionRole::Observer,
            [2; 32],
            true,
            1_000,
        ),
        Err(AdmissionError::BindingMismatch)
    );
    let ordinary = store
        .issue(association(2), ConnectionRole::Writer, [3; 32], 1_000)
        .expect("ordinary ticket");
    assert!(!store
        .claim(
            ordinary.token().as_bytes(),
            association(2),
            "work",
            generation(7),
            ConnectionRole::Writer,
            [3; 32],
            1_001,
        )
        .expect("ordinary claim"));
}

#[test]
fn wrong_token_does_not_consume_and_expiration_is_strict() {
    let limits = Limits::default();
    let mut store = InvitationStore::new("work", generation(7), &limits).expect("store");
    let ticket = store
        .issue(association(1), ConnectionRole::Writer, [2; 32], 5_000)
        .expect("issue");
    assert_eq!(
        store.claim(
            &[9; 32],
            association(1),
            "work",
            generation(7),
            ConnectionRole::Writer,
            [2; 32],
            5_001,
        ),
        Err(AdmissionError::TokenRejected)
    );
    store
        .claim(
            ticket.token().as_bytes(),
            association(1),
            "work",
            generation(7),
            ConnectionRole::Writer,
            [2; 32],
            5_001,
        )
        .expect("wrong token left invitation live");

    let expired = store
        .issue(association(2), ConnectionRole::Observer, [3; 32], 8_000)
        .expect("issue expiring");
    assert_eq!(
        store.claim(
            expired.token().as_bytes(),
            association(2),
            "work",
            generation(7),
            ConnectionRole::Observer,
            [3; 32],
            8_000 + limits.invitation_lifetime_ms,
        ),
        Err(AdmissionError::InvitationExpired)
    );
}

#[test]
fn capacity_is_eight_and_expired_slots_are_reused() {
    let limits = Limits::default();
    let mut store = InvitationStore::new("work", generation(7), &limits).expect("store");
    let mut fingerprints = Vec::new();
    for byte in 1..=8_u8 {
        let ticket = store
            .issue(association(byte), ConnectionRole::Observer, [byte; 32], 10)
            .expect("bounded issue");
        assert_ne!(ticket.token().as_bytes(), &[0; 32]);
        fingerprints.push(*ticket.token().as_bytes());
    }
    fingerprints.sort();
    fingerprints.dedup();
    assert_eq!(fingerprints.len(), 8, "tokens must be independently random");
    assert_eq!(
        store.issue(association(9), ConnectionRole::Observer, [9; 32], 11),
        Err(AdmissionError::InvitationCapacity)
    );
    store
        .issue(
            association(9),
            ConnectionRole::Observer,
            [9; 32],
            10 + limits.invitation_lifetime_ms,
        )
        .expect("expiration releases capacity");
}

#[test]
fn secret_debug_paths_are_redacted() {
    let limits = Limits::default();
    let mut store = InvitationStore::new("work", generation(7), &limits).expect("store");
    let ticket = store
        .issue(association(1), ConnectionRole::Writer, [2; 32], 0)
        .expect("issue");
    let rendered = format!("{ticket:?} {store:?}");
    assert!(rendered.contains("REDACTED"));
    assert!(!rendered.contains(&format!("{:?}", ticket.token().as_bytes())));
}
