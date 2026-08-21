//! Named finite limits for the spike. Every value is a hard bound; boundary
//! tests saturate them and the resource gate records measured maxima against
//! them.

use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Maximum bootstrap record size carried over the SSH stdout channel.
    pub bootstrap_record_max: usize,
    /// Exact authenticated-frame size on the first bidirectional stream.
    pub auth_frame_len: usize,
    /// Token bytes (256-bit).
    pub token_len: usize,
    /// Per-copy-direction buffer size. Two buffers total for the bridge.
    pub copy_buf: usize,
    /// QUIC connection-level send window (bytes).
    pub send_window: u64,
    /// QUIC connection-level receive window (bytes).
    pub receive_window: u64,
    /// Maximum concurrent bidirectional streams advertised (one is used).
    pub max_bi_streams: u32,
    /// One-shot server lease: exit if no authenticated client arrives.
    pub server_lease: Duration,
    /// Max time for the QUIC handshake including Retry.
    pub handshake_timeout: Duration,
    /// Idle/path deadline after which the connection is torn down.
    pub idle_timeout: Duration,
    /// Max time a copy direction may stall before the bridge requests teardown.
    pub stall_timeout: Duration,
    /// Drain-phase deadline per direction.
    pub drain_timeout: Duration,
    /// Finalize deadline for joining/aborting owned tasks.
    pub finalize_timeout: Duration,
    /// How long the client waits for the bootstrap record.
    pub bootstrap_timeout: Duration,
    /// Maximum concurrent pending handshakes the server endpoint holds.
    pub max_pending_handshakes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            bootstrap_record_max: 4096,
            auth_frame_len: 35, // version(1) + token(32) + target_port(2)
            token_len: 32,
            copy_buf: 16 * 1024,
            send_window: 384 * 1024,
            receive_window: 384 * 1024,
            max_bi_streams: 1,
            server_lease: Duration::from_secs(30),
            handshake_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(30),
            stall_timeout: Duration::from_secs(20),
            drain_timeout: Duration::from_secs(5),
            finalize_timeout: Duration::from_secs(5),
            bootstrap_timeout: Duration::from_secs(20),
            max_pending_handshakes: 4,
        }
    }
}
