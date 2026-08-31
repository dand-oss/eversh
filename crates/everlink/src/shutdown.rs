//! Typed Request -> Drain -> Finalize coordination for one bridge.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::Instant;

/// One of the bridge's two independently half-closeable copy directions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyDirection {
    QuicToPeer,
    PeerToQuic,
}

/// The bounded operation that observed a terminal failure or stall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyOperation {
    Read,
    Write,
    Flush,
    Shutdown,
    Delivery,
}

/// An absolute lifecycle deadline whose checked construction failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadlineKind {
    Operation,
    Drain,
    Finalize,
}

/// The durable first terminal cause. It deliberately carries no source error
/// or transported data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalCause {
    SourceEof(CopyDirection),
    OperationFailed {
        direction: CopyDirection,
        operation: CopyOperation,
    },
    OperationStalled {
        direction: CopyDirection,
        operation: CopyOperation,
    },
    Cancelled,
    TaskFailed(CopyDirection),
    ConstructionFailed,
    DeadlineOverflow(DeadlineKind),
    FinalizeTimeout,
}

/// Monotonic lifecycle phase. `Finalized` is visible only after cleanup has
/// established that no bridge-owned task or resource remains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    Running,
    Requested,
    Draining,
    Finalized,
}

/// A consistent read of the lifecycle authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownSnapshot {
    pub phase: Phase,
    pub cause: Option<TerminalCause>,
    pub drain_deadline: Option<Instant>,
    pub finalize_deadline: Option<Instant>,
}

/// Result of an idempotent Request operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestStatus {
    Recorded,
    Existing,
    DeadlineOverflow,
}

/// A lifecycle transition was attempted out of order or with an
/// unrepresentable deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionError {
    InvalidPhase,
    DeadlineOverflow(DeadlineKind),
}

#[derive(Debug)]
struct Inner {
    phase: Phase,
    cause: Option<TerminalCause>,
    drain_deadline: Option<Instant>,
    finalize_deadline: Option<Instant>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Signal {
    revision: u64,
    cancelled: bool,
}

impl Signal {
    pub(crate) fn cancelled(self) -> bool {
        self.cancelled
    }
}

#[derive(Debug)]
struct Shared {
    inner: Mutex<Inner>,
    signal: watch::Sender<Signal>,
}

/// Cloneable handle to the single lifecycle authority for one bridge.
#[derive(Clone)]
pub struct Shutdown {
    shared: Arc<Shared>,
}

impl Shutdown {
    pub fn new() -> Self {
        let (signal, _) = watch::channel(Signal {
            revision: 0,
            cancelled: false,
        });
        Self {
            shared: Arc::new(Shared {
                inner: Mutex::new(Inner {
                    phase: Phase::Running,
                    cause: None,
                    drain_deadline: None,
                    finalize_deadline: None,
                }),
                signal,
            }),
        }
    }

    /// Record the first cause and freeze the drain deadline at this call's
    /// observation instant. Later calls cannot move either value.
    pub fn request(&self, cause: TerminalCause, drain_timeout: Duration) -> RequestStatus {
        let mut inner = self.lock();
        if inner.phase != Phase::Running {
            return RequestStatus::Existing;
        }
        let now = Instant::now();

        let (stored_cause, deadline, status) = match now.checked_add(drain_timeout) {
            Some(deadline) => (cause, deadline, RequestStatus::Recorded),
            None => (
                TerminalCause::DeadlineOverflow(DeadlineKind::Drain),
                now,
                RequestStatus::DeadlineOverflow,
            ),
        };
        inner.cause = Some(stored_cause);
        inner.drain_deadline = Some(deadline);
        inner.phase = Phase::Requested;
        drop(inner);
        self.notify(false);
        status
    }

    /// Advance Request to Drain without recomputing its absolute deadline.
    pub fn begin_drain(&self) -> bool {
        let mut inner = self.lock();
        if inner.phase != Phase::Requested {
            return false;
        }
        inner.phase = Phase::Draining;
        drop(inner);
        self.notify(false);
        true
    }

    /// Idempotent external cancellation. Cancellation is fatal to both copy
    /// directions even when another terminal cause already won.
    pub fn cancel(&self, drain_timeout: Duration) -> RequestStatus {
        let status = self.request(TerminalCause::Cancelled, drain_timeout);
        self.begin_drain();
        self.notify(true);
        status
    }

    /// Freeze the one finalize deadline without claiming cleanup is complete.
    pub fn begin_finalize(&self, timeout: Duration) -> Result<Instant, TransitionError> {
        let mut inner = self.lock();
        match inner.phase {
            Phase::Draining => {
                if let Some(deadline) = inner.finalize_deadline {
                    return Ok(deadline);
                }
                let now = Instant::now();
                let deadline = match now.checked_add(timeout) {
                    Some(deadline) => deadline,
                    None => {
                        inner.finalize_deadline = Some(now);
                        drop(inner);
                        self.notify(false);
                        return Err(TransitionError::DeadlineOverflow(DeadlineKind::Finalize));
                    }
                };
                inner.finalize_deadline = Some(deadline);
                drop(inner);
                self.notify(false);
                Ok(deadline)
            }
            Phase::Finalized => inner.finalize_deadline.ok_or(TransitionError::InvalidPhase),
            Phase::Running | Phase::Requested => Err(TransitionError::InvalidPhase),
        }
    }

    /// Publish the Finalized postcondition after the resource owner is empty.
    pub(crate) fn complete_finalize(&self) -> bool {
        let mut inner = self.lock();
        if inner.phase != Phase::Draining || inner.finalize_deadline.is_none() {
            return false;
        }
        inner.phase = Phase::Finalized;
        drop(inner);
        self.notify(false);
        true
    }

    pub fn snapshot(&self) -> ShutdownSnapshot {
        let inner = self.lock();
        ShutdownSnapshot {
            phase: inner.phase,
            cause: inner.cause,
            drain_deadline: inner.drain_deadline,
            finalize_deadline: inner.finalize_deadline,
        }
    }

    pub fn phase(&self) -> Phase {
        self.snapshot().phase
    }

    pub fn cause(&self) -> Option<TerminalCause> {
        self.snapshot().cause
    }

    pub fn drain_deadline(&self) -> Option<Instant> {
        self.snapshot().drain_deadline
    }

    pub fn finalize_deadline(&self) -> Option<Instant> {
        self.snapshot().finalize_deadline
    }

    pub fn accepting_work(&self) -> bool {
        self.phase() == Phase::Running
    }

    pub(crate) fn request_clean(
        &self,
        cause: TerminalCause,
        drain_timeout: Duration,
    ) -> RequestStatus {
        let status = self.request(cause, drain_timeout);
        self.begin_drain();
        status
    }

    pub(crate) fn request_fatal(
        &self,
        cause: TerminalCause,
        drain_timeout: Duration,
    ) -> RequestStatus {
        let status = self.request(cause, drain_timeout);
        self.begin_drain();
        self.notify(true);
        status
    }

    pub(crate) fn stop_directions(&self) {
        self.notify(true);
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<Signal> {
        self.shared.signal.subscribe()
    }

    /// Run one non-awaiting admission action while Request is excluded. This
    /// is used to launch both copy tasks as one linearized pair.
    pub(crate) fn with_running_admission<T>(&self, action: impl FnOnce() -> T) -> Option<T> {
        let inner = self.lock();
        if inner.phase != Phase::Running {
            return None;
        }
        let output = action();
        drop(inner);
        Some(output)
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        match self.shared.inner.lock() {
            Ok(inner) => inner,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn notify(&self, cancel: bool) {
        self.shared.signal.send_modify(|signal| {
            signal.revision = signal.revision.wrapping_add(1);
            signal.cancelled |= cancel;
        });
    }
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Shutdown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shutdown")
            .field("snapshot", &self.snapshot())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};

    #[tokio::test(start_paused = true)]
    async fn deadlines_and_phases_are_monotonic_and_idempotent() {
        let shutdown = Shutdown::new();
        let start = Instant::now();
        assert_eq!(
            shutdown.request(
                TerminalCause::SourceEof(CopyDirection::QuicToPeer),
                Duration::from_secs(10),
            ),
            RequestStatus::Recorded
        );
        assert_eq!(shutdown.phase(), Phase::Requested);
        let drain = shutdown.drain_deadline().unwrap();
        assert_eq!(drain, start + Duration::from_secs(10));

        tokio::time::advance(Duration::from_secs(3)).await;
        assert_eq!(
            shutdown.request(TerminalCause::Cancelled, Duration::from_secs(90)),
            RequestStatus::Existing
        );
        assert_eq!(shutdown.drain_deadline(), Some(drain));
        assert_eq!(
            shutdown.cause(),
            Some(TerminalCause::SourceEof(CopyDirection::QuicToPeer))
        );

        assert!(shutdown.begin_drain());
        assert!(!shutdown.begin_drain());
        let finalize = shutdown.begin_finalize(Duration::from_secs(5)).unwrap();
        assert_eq!(shutdown.phase(), Phase::Draining);
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(
            shutdown.begin_finalize(Duration::from_secs(50)).unwrap(),
            finalize
        );
        assert_eq!(shutdown.finalize_deadline(), Some(finalize));
        assert!(shutdown.complete_finalize());
        assert!(!shutdown.complete_finalize());
        assert_eq!(shutdown.phase(), Phase::Finalized);
    }

    #[tokio::test(start_paused = true)]
    async fn later_fatal_cancel_wakes_both_without_replacing_eof() {
        let shutdown = Shutdown::new();
        let mut first = shutdown.subscribe();
        let mut second = shutdown.subscribe();
        shutdown.request_clean(
            TerminalCause::SourceEof(CopyDirection::PeerToQuic),
            Duration::from_secs(4),
        );
        let deadline = shutdown.drain_deadline();
        shutdown.cancel(Duration::from_secs(40));
        shutdown.cancel(Duration::from_secs(400));

        first.changed().await.unwrap();
        second.changed().await.unwrap();
        assert!(first.borrow_and_update().cancelled());
        assert!(second.borrow_and_update().cancelled());
        assert_eq!(shutdown.drain_deadline(), deadline);
        assert_eq!(
            shutdown.cause(),
            Some(TerminalCause::SourceEof(CopyDirection::PeerToQuic))
        );
    }

    #[test]
    fn concurrent_requests_have_exactly_one_winner() {
        let shutdown = Shutdown::new();
        let barrier = Arc::new(Barrier::new(12));
        let winners = Arc::new(AtomicUsize::new(0));
        let mut threads = Vec::new();
        for index in 0..12 {
            let shutdown = shutdown.clone();
            let barrier = barrier.clone();
            let winners = winners.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                let direction = if index % 2 == 0 {
                    CopyDirection::QuicToPeer
                } else {
                    CopyDirection::PeerToQuic
                };
                if shutdown.request(
                    TerminalCause::OperationFailed {
                        direction,
                        operation: CopyOperation::Read,
                    },
                    Duration::from_secs(2),
                ) == RequestStatus::Recorded
                {
                    winners.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(winners.load(Ordering::SeqCst), 1);
        assert!(shutdown.cause().is_some());
        assert_eq!(shutdown.phase(), Phase::Requested);
    }

    #[test]
    fn pair_admission_is_atomic_against_request() {
        let shutdown = Shutdown::new();
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let launches = Arc::new(AtomicUsize::new(0));

        let worker = {
            let shutdown = shutdown.clone();
            let entered = entered.clone();
            let release = release.clone();
            let launches = launches.clone();
            std::thread::spawn(move || {
                shutdown.with_running_admission(|| {
                    launches.fetch_add(1, Ordering::SeqCst);
                    entered.wait();
                    release.wait();
                    launches.fetch_add(1, Ordering::SeqCst);
                })
            })
        };
        entered.wait();
        let requester = {
            let shutdown = shutdown.clone();
            std::thread::spawn(move || {
                shutdown.cancel(Duration::from_secs(1));
            })
        };
        release.wait();
        assert!(worker.join().unwrap().is_some());
        requester.join().unwrap();
        assert_eq!(launches.load(Ordering::SeqCst), 2);

        let rejected = shutdown.with_running_admission(|| {
            launches.fetch_add(1, Ordering::SeqCst);
        });
        assert!(rejected.is_none());
        assert_eq!(launches.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn poisoned_mutex_is_recovered_without_panicking_lifecycle_calls() {
        let shutdown = Shutdown::new();
        let poisoner = shutdown.clone();
        let result = std::thread::spawn(move || {
            let _guard = poisoner.shared.inner.lock().unwrap();
            panic!("poison lifecycle mutex for recovery test");
        })
        .join();
        assert!(result.is_err());
        assert_eq!(
            shutdown.request(TerminalCause::Cancelled, Duration::from_secs(1)),
            RequestStatus::Recorded
        );
        assert_eq!(shutdown.phase(), Phase::Requested);
    }
}
