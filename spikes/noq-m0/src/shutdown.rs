//! Request -> Drain -> Finalize with first-cause-wins semantics.
//!
//! `TerminalCause` is recorded exactly once (the first cause wins); later
//! causes are dropped. The bridge consults the state to stop admitting new
//! work, drain with deadlines, and finalize idempotently. Library-level state
//! transitions are unit-tested here; the process-level deadlines are exercised
//! by the integration tests.

use std::sync::Mutex;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Running,
    Requested,
    Draining,
    Finalized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalCause {
    /// QUIC stream or connection ended (EOF, reset, or connection lost).
    QuicClosed,
    /// Target TCP connection ended.
    TargetClosed,
    /// Local stdin closed by the OpenSSH client.
    LocalEof,
    /// Copy direction exceeded the stall deadline.
    Stalled,
    /// Authentication or protocol violation.
    AuthFailure,
    /// Server one-shot lease expired.
    LeaseExpired,
    /// External cancellation (supervisor/test).
    Cancelled,
    /// Child process died.
    ChildExit,
}

#[derive(Debug)]
pub struct ShutdownState {
    inner: Mutex<Inner>,
}

#[derive(Debug)]
struct Inner {
    phase: Phase,
    cause: Option<TerminalCause>,
    recorded_at: Option<Instant>,
}

impl ShutdownState {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                phase: Phase::Running,
                cause: None,
                recorded_at: None,
            }),
        }
    }

    /// Request: records the first terminal cause once and stops new work.
    /// Returns true if this call recorded the cause.
    pub fn request(&self, cause: TerminalCause) -> bool {
        let mut g = self.inner.lock().unwrap();
        if g.cause.is_some() {
            return false;
        }
        g.phase = Phase::Requested;
        g.cause = Some(cause);
        g.recorded_at = Some(Instant::now());
        true
    }

    /// Drain: advance from Requested. No-op (and false) unless already
    /// requested; idempotent once draining.
    pub fn drain(&self) -> bool {
        let mut g = self.inner.lock().unwrap();
        match g.phase {
            Phase::Running => false,
            Phase::Requested => {
                g.phase = Phase::Draining;
                true
            }
            _ => false,
        }
    }

    /// Finalize: terminal, idempotent.
    pub fn finalize(&self) -> Phase {
        let mut g = self.inner.lock().unwrap();
        if g.phase != Phase::Finalized {
            g.phase = Phase::Finalized;
        }
        g.phase
    }

    pub fn phase(&self) -> Phase {
        self.inner.lock().unwrap().phase
    }

    pub fn cause(&self) -> Option<TerminalCause> {
        self.inner.lock().unwrap().cause
    }
}

impl Default for ShutdownState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_cause_wins() {
        let s = ShutdownState::new();
        assert!(s.request(TerminalCause::QuicClosed));
        assert!(!s.request(TerminalCause::TargetClosed));
        assert_eq!(s.cause(), Some(TerminalCause::QuicClosed));
        assert_eq!(s.phase(), Phase::Requested);
    }

    #[test]
    fn phases_advance_monotonically() {
        let s = ShutdownState::new();
        assert!(!s.drain(), "drain before request is rejected");
        s.request(TerminalCause::Cancelled);
        assert!(s.drain());
        assert!(!s.drain());
        assert_eq!(s.finalize(), Phase::Finalized);
        assert_eq!(s.finalize(), Phase::Finalized);
    }

    #[test]
    fn concurrent_requests_record_exactly_one() {
        let s = std::sync::Arc::new(ShutdownState::new());
        let winners = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..16 {
            let s = s.clone();
            let w = winners.clone();
            handles.push(std::thread::spawn(move || {
                if s.request(TerminalCause::Cancelled) {
                    w.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(winners.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(s.cause().is_some());
    }
}
