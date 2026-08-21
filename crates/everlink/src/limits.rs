//! Named finite limits. Wire caps, token length, and the single-stream rule
//! are contract values; runtime values are PROVISIONAL M0 candidates
//! remeasured in M3 (design section 4).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    // --- contract (wire) values ---
    /// Maximum bootstrap record bytes including the newline.
    pub bootstrap_record_max: usize,
    /// Exact authentication-frame length in bytes.
    pub auth_frame_len: usize,
    /// Token length in bytes (256-bit; contract).
    pub token_len: usize,
    /// Maximum concurrent application bidirectional streams (contract: 1).
    pub max_bi_streams: u32,

    // --- PROVISIONAL runtime values (M0 candidates; remeasure M3) ---
    /// Per-copy-direction buffer bytes.
    pub copy_buf: usize,
    /// Connection/stream send window bytes.
    pub send_window: u64,
    /// Connection/stream receive window bytes.
    pub receive_window: u64,
    /// One-shot server lease before an authenticated client must arrive.
    pub server_lease_ms: u64,
    /// QUIC handshake deadline including Retry.
    pub handshake_timeout_ms: u64,
    /// Idle deadline after which the connection is torn down.
    pub idle_timeout_ms: u64,
    /// Copy-direction stall deadline.
    pub stall_timeout_ms: u64,
    /// Drain-phase deadline.
    pub drain_timeout_ms: u64,
    /// Finalize deadline.
    pub finalize_timeout_ms: u64,
    /// Client wait for the bootstrap record.
    pub bootstrap_timeout_ms: u64,
    /// Maximum pending handshakes before authentication.
    pub max_pending_handshakes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            bootstrap_record_max: 4096,
            auth_frame_len: 35,
            token_len: 32,
            max_bi_streams: 1,
            copy_buf: 16 * 1024,
            send_window: 384 * 1024,
            receive_window: 384 * 1024,
            server_lease_ms: 30_000,
            handshake_timeout_ms: 10_000,
            idle_timeout_ms: 30_000,
            stall_timeout_ms: 20_000,
            drain_timeout_ms: 5_000,
            finalize_timeout_ms: 5_000,
            bootstrap_timeout_ms: 20_000,
            max_pending_handshakes: 4,
        }
    }
}
