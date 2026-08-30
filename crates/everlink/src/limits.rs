//! Named finite limits. Wire caps, token length, and the single-stream rule
//! are contract values; runtime values are PROVISIONAL M0 candidates
//! remeasured in M3 (design section 4).

use crate::error::{Error, LimitViolation};
use std::time::Duration;

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
    /// Maximum bytes noq may buffer for one uncommitted `Incoming`.
    pub incoming_buffer_size: u64,
    /// Maximum Initial/Retry attempts before this one-shot server fails closed.
    pub max_retry_attempts: usize,
    /// Largest inclusive UDP port-range width accepted by policy.
    pub max_udp_port_span: u32,
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
            incoming_buffer_size: 64 * 1024,
            max_retry_attempts: 8,
            max_udp_port_span: 1024,
        }
    }
}

impl Limits {
    /// Validate every contract and runtime value before constructing resources.
    pub fn validate(&self) -> Result<(), Error> {
        if self.bootstrap_record_max != 4096
            || self.auth_frame_len != 35
            || self.token_len != 32
            || self.max_bi_streams != 1
        {
            return Err(Error::InvalidLimits(LimitViolation::ContractValue));
        }

        let nonzero_values = [
            self.copy_buf as u64,
            self.send_window,
            self.receive_window,
            self.server_lease_ms,
            self.handshake_timeout_ms,
            self.idle_timeout_ms,
            self.stall_timeout_ms,
            self.drain_timeout_ms,
            self.finalize_timeout_ms,
            self.bootstrap_timeout_ms,
            self.max_pending_handshakes as u64,
            self.incoming_buffer_size,
            self.max_retry_attempts as u64,
            self.max_udp_port_span as u64,
        ];
        if nonzero_values.contains(&0) {
            return Err(Error::InvalidLimits(LimitViolation::ZeroValue));
        }
        if self.send_window > noq::VarInt::MAX.into_inner()
            || self.receive_window > noq::VarInt::MAX.into_inner()
        {
            return Err(Error::InvalidLimits(LimitViolation::WindowTooLarge));
        }
        if noq::IdleTimeout::try_from(self.idle_timeout()).is_err() {
            return Err(Error::InvalidLimits(LimitViolation::DeadlineOverflow));
        }
        if self.max_retry_attempts < 2 {
            return Err(Error::InvalidLimits(LimitViolation::RetryBudgetTooSmall));
        }
        if self.max_udp_port_span > u32::from(u16::MAX) {
            return Err(Error::InvalidLimits(LimitViolation::PortSpanTooLarge));
        }
        self.incoming_buffer_total()?;
        Ok(())
    }

    pub fn incoming_buffer_total(&self) -> Result<u64, Error> {
        let pending = u64::try_from(self.max_pending_handshakes)
            .map_err(|_| Error::InvalidLimits(LimitViolation::IncomingTotalOverflow))?;
        self.incoming_buffer_size
            .checked_mul(pending)
            .ok_or(Error::InvalidLimits(LimitViolation::IncomingTotalOverflow))
    }

    pub fn server_lease(&self) -> Duration {
        Duration::from_millis(self.server_lease_ms)
    }

    pub fn handshake_timeout(&self) -> Duration {
        Duration::from_millis(self.handshake_timeout_ms)
    }

    pub fn idle_timeout(&self) -> Duration {
        Duration::from_millis(self.idle_timeout_ms)
    }

    pub fn finalize_timeout(&self) -> Duration {
        Duration::from_millis(self.finalize_timeout_ms)
    }
}
