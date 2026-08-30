//! Compile-time trait assertions and provisional-limits inventory.
#![allow(clippy::unwrap_used)]

#[test]
fn error_is_static_send_sync() {
    fn assert_traits<T: std::error::Error + Send + Sync + 'static>() {}
    assert_traits::<everlink::Error>();
}

#[test]
fn runtime_limits_are_provisional() {
    let l = everlink::Limits::default();
    let named: [(&str, u64); 14] = [
        ("copy_buf", l.copy_buf as u64),
        ("send_window", l.send_window),
        ("receive_window", l.receive_window),
        ("server_lease_ms", l.server_lease_ms),
        ("handshake_timeout_ms", l.handshake_timeout_ms),
        ("idle_timeout_ms", l.idle_timeout_ms),
        ("stall_timeout_ms", l.stall_timeout_ms),
        ("drain_timeout_ms", l.drain_timeout_ms),
        ("finalize_timeout_ms", l.finalize_timeout_ms),
        ("bootstrap_timeout_ms", l.bootstrap_timeout_ms),
        ("max_pending_handshakes", l.max_pending_handshakes as u64),
        ("incoming_buffer_size", l.incoming_buffer_size),
        ("max_retry_attempts", l.max_retry_attempts as u64),
        ("max_udp_port_span", l.max_udp_port_span as u64),
    ];
    for (name, v) in named {
        assert!(v > 0, "{name} must be finite and named");
    }
    assert!(l.validate().is_ok());
    assert_eq!(
        l.incoming_buffer_total().unwrap(),
        l.incoming_buffer_size * l.max_pending_handshakes as u64
    );
}

#[test]
fn contract_limits_are_fixed() {
    let l = everlink::Limits::default();
    assert_eq!(l.token_len, 32, "256-bit token is a contract value");
    assert_eq!(
        l.max_bi_streams, 1,
        "exactly one bidirectional stream is a contract value"
    );
    assert_eq!(l.auth_frame_len, 35);
    assert_eq!(l.bootstrap_record_max, 4096);
}
