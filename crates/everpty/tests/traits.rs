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
    // a conscious update of this inventory (design section 4, m2-plan §11).
    let l = everpty::Limits::default();
    let named: [(&str, u64); 19] = [
        ("startup_deadline_ms", l.startup_deadline_ms),
        ("kill_grace_ms", l.kill_grace_ms),
        ("writer_queue_bytes", l.writer_queue_bytes as u64),
        ("observer_queue_bytes", l.observer_queue_bytes as u64),
        ("observer_count", l.observer_count as u64),
        ("aggregate_queue_bytes", l.aggregate_queue_bytes as u64),
        ("max_connections", l.max_connections as u64),
        (
            "writer_input_queue_bytes",
            l.writer_input_queue_bytes as u64,
        ),
        (
            "incomplete_frame_deadline_ms",
            l.incomplete_frame_deadline_ms,
        ),
        ("accepts_per_iteration", l.accepts_per_iteration as u64),
        ("read_chunk_bytes", l.read_chunk_bytes as u64),
        ("stall_deadline_ms", l.stall_deadline_ms),
        ("pty_exit_drain_ms", l.pty_exit_drain_ms),
        ("control_reply_deadline_ms", l.control_reply_deadline_ms),
        ("list_probe_deadline_ms", l.list_probe_deadline_ms),
        ("metadata_max_bytes", l.metadata_max_bytes as u64),
        ("exec_label_max_bytes", l.exec_label_max_bytes as u64),
        ("origin_label_max_bytes", l.origin_label_max_bytes as u64),
        ("origin_count_max", l.origin_count_max as u64),
    ];
    for (name, v) in named {
        assert!(v > 0, "{name} must be finite and named");
    }
    // The §11 provisional defaults are pinned by name.
    assert_eq!(l.max_connections, 16);
    assert_eq!(l.writer_input_queue_bytes, 64 * 1024);
    assert_eq!(l.incomplete_frame_deadline_ms, 5_000);
    assert_eq!(l.accepts_per_iteration, 8);
    assert_eq!(l.read_chunk_bytes, 16 * 1024);
    assert_eq!(l.stall_deadline_ms, 20_000);
    assert_eq!(l.pty_exit_drain_ms, 5_000);
    assert_eq!(l.control_reply_deadline_ms, 5_000);
    assert_eq!(l.list_probe_deadline_ms, 500);
    assert_eq!(l.metadata_max_bytes, 4096);
    assert_eq!(l.exec_label_max_bytes, 256);
    assert_eq!(l.origin_label_max_bytes, 64);
    assert_eq!(l.origin_count_max, 4);
}
