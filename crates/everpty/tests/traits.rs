//! Compile-time trait assertions and provisional-limits inventory.
#![allow(clippy::unwrap_used)]

#[test]
fn error_is_static_send_sync() {
    fn assert_traits<T: std::error::Error + Send + Sync + 'static>() {}
    assert_traits::<everpty::Error>();
}

#[test]
fn runtime_limits_are_provisional() {
    // Every PROVISIONAL limit must be listed here by name so a retune forces
    // a conscious update of this inventory (design section 4).
    let l = everpty::Limits::default();
    let named: [(&str, u64); 6] = [
        ("startup_deadline_ms", l.startup_deadline_ms),
        ("kill_grace_ms", l.kill_grace_ms),
        ("writer_queue_bytes", l.writer_queue_bytes as u64),
        ("observer_queue_bytes", l.observer_queue_bytes as u64),
        ("observer_count", l.observer_count as u64),
        ("aggregate_queue_bytes", l.aggregate_queue_bytes as u64),
    ];
    for (name, v) in named {
        assert!(v > 0, "{name} must be finite and named");
    }
}
