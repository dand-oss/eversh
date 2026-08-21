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
        }
    }
}
