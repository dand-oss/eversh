use everudp::{LimitViolation, Limits};

#[test]
fn locked_limits_validate() {
    let limits = Limits::default();
    limits.validate().expect("frozen defaults");
    assert_eq!(limits.bootstrap_record_max, 4 * 1024);
    assert_eq!(limits.control_frame_max, 4 * 1024);
    assert_eq!(limits.terminal_frame_max, 64 * 1024);
    assert_eq!(limits.queue_bytes_per_direction, 4 * 1024 * 1024);
    assert_eq!(limits.queue_operations_per_direction, 1_024);
    assert_eq!(limits.global_queue_bytes, 48 * 1024 * 1024);
    assert_eq!(limits.copy_buffer_bytes, 16 * 1024);
    assert_eq!(limits.initial_udp_budget_ms, 3_000);
    assert_eq!(limits.invitation_bytes, 32);
    assert_eq!(limits.invitation_lifetime_ms, 20_000);
    assert_eq!(limits.max_pending_invitations, 8);
    assert_eq!(limits.max_observers, 8);
    assert_eq!(limits.keepalive_ms, 10_000);
    assert_eq!(limits.idle_timeout_ms, 30_000);
    assert_eq!(limits.first_ssh_recovery_ms, 30_000);
    assert_eq!(limits.ssh_recovery_interval_ms, 60_000);
    assert_eq!(limits.safe_initial_mtu, 1_200);
}

#[test]
fn contract_limits_cannot_drift_silently() {
    let limits = Limits {
        terminal_frame_max: 64 * 1024 + 1,
        ..Limits::default()
    };
    assert_eq!(limits.validate(), Err(LimitViolation::TerminalFrameMax));

    let limits = Limits {
        max_observers: 9,
        ..Limits::default()
    };
    assert_eq!(limits.validate(), Err(LimitViolation::MaxObservers));

    let limits = Limits {
        idle_timeout_ms: Limits::default().keepalive_ms,
        ..Limits::default()
    };
    assert_eq!(limits.validate(), Err(LimitViolation::IdleTimeout));
}
