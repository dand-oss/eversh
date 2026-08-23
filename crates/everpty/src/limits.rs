//! Named finite limits. Wire caps are contract values; runtime values are
//! PROVISIONAL M0 candidates remeasured in M2/M3 (design section 4).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    // --- contract (wire) values ---
    /// Maximum frame body in bytes (u32 length + kind + payload).
    pub frame_max_body: usize,
    /// Maximum session name length in bytes.
    pub name_max: usize,
    /// Maximum UTF-8 error text length in bytes.
    pub error_text_max: usize,
    /// Maximum Unix socket pathname bytes (107) plus NUL.
    pub unix_path_max: usize,

    // --- PROVISIONAL runtime values (M0 candidates; remeasure M2/M3) ---
    /// Deadline for the initial writer to arrive after broker readiness.
    pub startup_deadline_ms: u64,
    /// Grace period between SIGTERM and SIGKILL.
    pub kill_grace_ms: u64,
    /// Per-writer live output queue bytes.
    pub writer_queue_bytes: usize,
    /// Per-observer live output queue bytes.
    pub observer_queue_bytes: usize,
    /// Maximum observer count.
    pub observer_count: usize,
    /// Aggregate live queue bytes across clients.
    pub aggregate_queue_bytes: usize,
    /// Maximum simultaneously connected clients (writers, observers, and
    /// control connections all count; §5).
    pub max_connections: usize,
    /// Bound on retained writer input awaiting a POLLOUT-draining PTY
    /// master (§5).
    pub writer_input_queue_bytes: usize,
    /// Any incomplete frame — first or later — must complete within this
    /// window of its FIRST byte; drip-fed bytes never extend it (§5).
    pub incomplete_frame_deadline_ms: u64,
    /// Accepts serviced per poll iteration (§3).
    pub accepts_per_iteration: usize,
    /// One read chunk from the PTY master or a client socket (§3, §6).
    pub read_chunk_bytes: usize,
    /// Writer-queue high-water stall deadline before revoke/evict (§6).
    pub stall_deadline_ms: u64,
    /// Post-reap PTY drain-to-EOF deadline (§7).
    pub pty_exit_drain_ms: u64,
    /// A control reply frame must fully drain within this window of being
    /// queued or the control connection closes (§5).
    pub control_reply_deadline_ms: u64,
    /// `list`/`current` live-probe deadline (§8).
    pub list_probe_deadline_ms: u64,
    /// Complete metadata record cap in bytes (§8).
    pub metadata_max_bytes: usize,
    /// Executable display-label cap in bytes (§8).
    pub exec_label_max_bytes: usize,
    /// Per-origin label cap in bytes (§8).
    pub origin_label_max_bytes: usize,
    /// Maximum origin entries per metadata record (§8).
    pub origin_count_max: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            frame_max_body: 64 * 1024,
            name_max: 64,
            error_text_max: 256,
            unix_path_max: 107, // + NUL = sun_path[108]
            startup_deadline_ms: 10_000,
            kill_grace_ms: 5_000,
            writer_queue_bytes: 256 * 1024,
            observer_queue_bytes: 64 * 1024,
            observer_count: 8,
            aggregate_queue_bytes: 1024 * 1024,
            max_connections: 16,
            writer_input_queue_bytes: 64 * 1024,
            incomplete_frame_deadline_ms: 5_000,
            accepts_per_iteration: 8,
            read_chunk_bytes: 16 * 1024,
            stall_deadline_ms: 20_000,
            pty_exit_drain_ms: 5_000,
            control_reply_deadline_ms: 5_000,
            list_probe_deadline_ms: 500,
            metadata_max_bytes: 4096,
            exec_label_max_bytes: 256,
            origin_label_max_bytes: 64,
            origin_count_max: 4,
        }
    }
}
