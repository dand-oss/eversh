use crate::error::LimitViolation;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub bootstrap_record_max: usize,
    pub control_frame_max: usize,
    pub terminal_frame_max: usize,
    pub queue_bytes_per_direction: usize,
    pub queue_operations_per_direction: usize,
    pub global_queue_bytes: usize,
    pub copy_buffer_bytes: usize,
    pub initial_udp_budget_ms: u64,
    pub invitation_bytes: usize,
    pub invitation_lifetime_ms: u64,
    pub max_pending_invitations: usize,
    pub max_observers: usize,
    pub keepalive_ms: u64,
    pub idle_timeout_ms: u64,
    pub first_ssh_recovery_ms: u64,
    pub ssh_recovery_interval_ms: u64,
    pub safe_initial_mtu: u16,
    pub max_bidi_streams: u32,
    pub max_client_uni_streams: u32,
    pub max_server_uni_streams: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            bootstrap_record_max: 4 * 1024,
            control_frame_max: 4 * 1024,
            terminal_frame_max: 64 * 1024,
            queue_bytes_per_direction: 4 * 1024 * 1024,
            queue_operations_per_direction: 1_024,
            global_queue_bytes: 48 * 1024 * 1024,
            copy_buffer_bytes: 16 * 1024,
            initial_udp_budget_ms: 3_000,
            invitation_bytes: 32,
            invitation_lifetime_ms: 20_000,
            max_pending_invitations: 8,
            max_observers: 8,
            keepalive_ms: 10_000,
            idle_timeout_ms: 30_000,
            first_ssh_recovery_ms: 30_000,
            ssh_recovery_interval_ms: 60_000,
            safe_initial_mtu: 1_200,
            max_bidi_streams: 1,
            max_client_uni_streams: 1,
            max_server_uni_streams: 1,
        }
    }
}

impl Limits {
    pub fn validate(&self) -> Result<(), LimitViolation> {
        if self.bootstrap_record_max != 4 * 1024 {
            return Err(LimitViolation::BootstrapRecordMax);
        }
        if self.control_frame_max != 4 * 1024 {
            return Err(LimitViolation::ControlFrameMax);
        }
        if self.terminal_frame_max != 64 * 1024 {
            return Err(LimitViolation::TerminalFrameMax);
        }
        if self.queue_bytes_per_direction != 4 * 1024 * 1024 {
            return Err(LimitViolation::QueueBytesPerDirection);
        }
        if self.queue_operations_per_direction != 1_024 {
            return Err(LimitViolation::QueueOperationsPerDirection);
        }
        if self.global_queue_bytes != 48 * 1024 * 1024 {
            return Err(LimitViolation::GlobalQueueBytes);
        }
        if self.copy_buffer_bytes != 16 * 1024 {
            return Err(LimitViolation::CopyBufferBytes);
        }
        if self.initial_udp_budget_ms != 3_000 {
            return Err(LimitViolation::InitialUdpBudget);
        }
        if self.invitation_bytes != 32 {
            return Err(LimitViolation::InvitationBytes);
        }
        if self.invitation_lifetime_ms != 20_000 {
            return Err(LimitViolation::InvitationLifetime);
        }
        if self.max_pending_invitations != 8 {
            return Err(LimitViolation::MaxPendingInvitations);
        }
        if self.max_observers != 8 {
            return Err(LimitViolation::MaxObservers);
        }
        if self.keepalive_ms != 10_000 {
            return Err(LimitViolation::Keepalive);
        }
        if self.idle_timeout_ms != 30_000 || self.idle_timeout_ms <= self.keepalive_ms {
            return Err(LimitViolation::IdleTimeout);
        }
        if self.first_ssh_recovery_ms != 30_000 {
            return Err(LimitViolation::FirstSshRecovery);
        }
        if self.ssh_recovery_interval_ms != 60_000
            || self.ssh_recovery_interval_ms < self.first_ssh_recovery_ms
        {
            return Err(LimitViolation::SshRecoveryInterval);
        }
        if self.safe_initial_mtu != 1_200 {
            return Err(LimitViolation::SafeInitialMtu);
        }
        if self.max_bidi_streams != 1
            || self.max_client_uni_streams != 1
            || self.max_server_uni_streams != 1
        {
            return Err(LimitViolation::StreamCounts);
        }
        Ok(())
    }

    pub fn initial_udp_budget(&self) -> Duration {
        Duration::from_millis(self.initial_udp_budget_ms)
    }

    pub fn invitation_lifetime(&self) -> Duration {
        Duration::from_millis(self.invitation_lifetime_ms)
    }

    pub fn keepalive(&self) -> Duration {
        Duration::from_millis(self.keepalive_ms)
    }

    pub fn idle_timeout(&self) -> Duration {
        Duration::from_millis(self.idle_timeout_ms)
    }

    pub fn first_ssh_recovery(&self) -> Duration {
        Duration::from_millis(self.first_ssh_recovery_ms)
    }

    pub fn ssh_recovery_interval(&self) -> Duration {
        Duration::from_millis(self.ssh_recovery_interval_ms)
    }
}
