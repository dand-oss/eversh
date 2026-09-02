#![no_main]

use everssh::shutdown::{
    CopyDirection, CopyOperation, DeadlineKind, Phase, RequestStatus, Shutdown, ShutdownSnapshot,
    TerminalCause, TransitionError,
};
use libfuzzer_sys::fuzz_target;
use std::time::Duration;

const MAX_STEPS: usize = 256;

#[derive(Clone, Copy)]
enum Timeout {
    Finite(Duration),
    Overflow,
}

impl Timeout {
    fn finite(selector: u8) -> Self {
        Self::Finite(Duration::from_millis(u64::from(selector >> 4)))
    }

    fn duration(self) -> Duration {
        match self {
            Self::Finite(duration) => duration,
            Self::Overflow => Duration::MAX,
        }
    }

    fn is_overflow(self) -> bool {
        matches!(self, Self::Overflow)
    }
}

struct Model {
    shutdown: Shutdown,
    phase: Phase,
    cause: Option<TerminalCause>,
    drain_frozen: bool,
    finalize_frozen: bool,
    drain_anchor: Option<ShutdownSnapshot>,
    finalize_anchor: Option<ShutdownSnapshot>,
}

impl Model {
    fn new() -> Self {
        let model = Self {
            shutdown: Shutdown::new(),
            phase: Phase::Running,
            cause: None,
            drain_frozen: false,
            finalize_frozen: false,
            drain_anchor: None,
            finalize_anchor: None,
        };
        model.verify_current();
        model
    }

    fn request(&mut self, cause: TerminalCause, timeout: Timeout) {
        let before = self.shutdown.snapshot();
        let was_running = self.phase == Phase::Running;
        let expected = if was_running {
            if timeout.is_overflow() {
                RequestStatus::DeadlineOverflow
            } else {
                RequestStatus::Recorded
            }
        } else {
            RequestStatus::Existing
        };

        let actual = self.shutdown.request(cause, timeout.duration());
        assert_eq!(actual, expected, "request returned the wrong typed status");

        if was_running {
            self.phase = Phase::Requested;
            self.cause = Some(if timeout.is_overflow() {
                TerminalCause::DeadlineOverflow(DeadlineKind::Drain)
            } else {
                cause
            });
            self.drain_frozen = true;
            self.capture_drain_anchor();
        }
        self.verify_after(before);
    }

    fn cancel(&mut self, timeout: Timeout) {
        let before = self.shutdown.snapshot();
        let was_running = self.phase == Phase::Running;
        let expected = if was_running {
            if timeout.is_overflow() {
                RequestStatus::DeadlineOverflow
            } else {
                RequestStatus::Recorded
            }
        } else {
            RequestStatus::Existing
        };

        let actual = self.shutdown.cancel(timeout.duration());
        assert_eq!(actual, expected, "cancel returned the wrong typed status");

        if was_running {
            self.cause = Some(if timeout.is_overflow() {
                TerminalCause::DeadlineOverflow(DeadlineKind::Drain)
            } else {
                TerminalCause::Cancelled
            });
            self.drain_frozen = true;
            self.capture_drain_anchor();
        }
        if matches!(self.phase, Phase::Running | Phase::Requested) {
            self.phase = Phase::Draining;
        }
        self.verify_after(before);
    }

    fn begin_drain(&mut self) {
        let before = self.shutdown.snapshot();
        let should_advance = self.phase == Phase::Requested;
        let actual = self.shutdown.begin_drain();
        assert_eq!(
            actual, should_advance,
            "begin_drain returned the wrong transition result"
        );
        if should_advance {
            self.phase = Phase::Draining;
        }
        self.verify_after(before);
    }

    fn begin_finalize(&mut self, timeout: Timeout) {
        let before = self.shutdown.snapshot();
        let actual = self.shutdown.begin_finalize(timeout.duration());
        let mut newly_frozen = false;

        match self.phase {
            Phase::Running | Phase::Requested => assert_eq!(
                actual,
                Err(TransitionError::InvalidPhase),
                "begin_finalize accepted an invalid ordering"
            ),
            Phase::Draining => {
                if self.finalize_frozen {
                    let deadline = self
                        .finalize_anchor
                        .expect("the model must retain its finalize anchor")
                        .finalize_deadline
                        .expect("a finalize anchor must contain a deadline");
                    assert_eq!(
                        actual,
                        Ok(deadline),
                        "begin_finalize moved a frozen deadline"
                    );
                } else {
                    newly_frozen = true;
                    self.finalize_frozen = true;
                    if timeout.is_overflow() {
                        assert_eq!(
                            actual,
                            Err(TransitionError::DeadlineOverflow(DeadlineKind::Finalize)),
                            "begin_finalize returned the wrong overflow transition"
                        );
                    } else {
                        assert!(
                            actual.is_ok(),
                            "a finite finalize deadline was unexpectedly rejected"
                        );
                    }
                }
            }
            Phase::Finalized => {
                if self.finalize_frozen {
                    let deadline = self
                        .finalize_anchor
                        .expect("the model must retain its finalize anchor")
                        .finalize_deadline
                        .expect("a finalize anchor must contain a deadline");
                    assert_eq!(actual, Ok(deadline));
                } else {
                    assert_eq!(actual, Err(TransitionError::InvalidPhase));
                }
            }
        }

        if newly_frozen {
            let snapshot = self.shutdown.snapshot();
            assert!(
                snapshot.finalize_deadline.is_some(),
                "a finalize transition did not freeze its deadline"
            );
            if let Ok(deadline) = actual {
                assert_eq!(snapshot.finalize_deadline, Some(deadline));
            }
            assert!(self.finalize_anchor.is_none());
            self.finalize_anchor = Some(snapshot);
        }
        self.verify_after(before);
    }

    fn capture_drain_anchor(&mut self) {
        let snapshot = self.shutdown.snapshot();
        assert!(
            snapshot.drain_deadline.is_some(),
            "a request did not freeze its drain deadline"
        );
        assert!(self.drain_anchor.is_none());
        self.drain_anchor = Some(snapshot);
    }

    fn verify_after(&self, before: ShutdownSnapshot) {
        let after = self.shutdown.snapshot();
        assert!(after.phase >= before.phase, "shutdown phase regressed");
        self.verify_snapshot(after);
    }

    fn verify_current(&self) {
        self.verify_snapshot(self.shutdown.snapshot());
    }

    fn verify_snapshot(&self, snapshot: ShutdownSnapshot) {
        assert_eq!(snapshot.phase, self.phase, "phase diverged from the model");
        assert_eq!(snapshot.cause, self.cause, "first cause was replaced");
        assert_eq!(
            snapshot.drain_deadline.is_some(),
            self.drain_frozen,
            "drain deadline presence diverged from the model"
        );
        assert_eq!(
            snapshot.finalize_deadline.is_some(),
            self.finalize_frozen,
            "finalize deadline presence diverged from the model"
        );
        assert_eq!(self.drain_anchor.is_some(), self.drain_frozen);
        assert_eq!(self.finalize_anchor.is_some(), self.finalize_frozen);

        if let Some(anchor) = self.drain_anchor {
            assert_eq!(
                snapshot.drain_deadline, anchor.drain_deadline,
                "drain deadline moved after Request"
            );
        }
        if let Some(anchor) = self.finalize_anchor {
            assert_eq!(
                snapshot.finalize_deadline, anchor.finalize_deadline,
                "finalize deadline moved after being frozen"
            );
        }

        assert_eq!(self.shutdown.phase(), snapshot.phase);
        assert_eq!(self.shutdown.cause(), snapshot.cause);
        assert_eq!(self.shutdown.drain_deadline(), snapshot.drain_deadline);
        assert_eq!(
            self.shutdown.finalize_deadline(),
            snapshot.finalize_deadline
        );
        assert_eq!(
            self.shutdown.accepting_work(),
            snapshot.phase == Phase::Running,
            "only Running may accept work"
        );
    }
}

fn direction(byte: u8) -> CopyDirection {
    if byte & 0x80 == 0 {
        CopyDirection::QuicToPeer
    } else {
        CopyDirection::PeerToQuic
    }
}

fn operation(byte: u8) -> CopyOperation {
    match (byte >> 4) & 0x07 {
        0 => CopyOperation::Read,
        1 => CopyOperation::Write,
        2 => CopyOperation::Flush,
        3 => CopyOperation::Shutdown,
        _ => CopyOperation::Delivery,
    }
}

fn deadline_kind(byte: u8) -> DeadlineKind {
    match (byte >> 4) % 3 {
        0 => DeadlineKind::Operation,
        1 => DeadlineKind::Drain,
        _ => DeadlineKind::Finalize,
    }
}

fn selected_cause(selector: u8) -> TerminalCause {
    match selector & 0x0f {
        0 => TerminalCause::SourceEof(CopyDirection::QuicToPeer),
        1 => TerminalCause::SourceEof(CopyDirection::PeerToQuic),
        2 => TerminalCause::OperationFailed {
            direction: CopyDirection::QuicToPeer,
            operation: CopyOperation::Read,
        },
        3 => TerminalCause::OperationFailed {
            direction: CopyDirection::PeerToQuic,
            operation: CopyOperation::Write,
        },
        4 => TerminalCause::OperationStalled {
            direction: CopyDirection::QuicToPeer,
            operation: CopyOperation::Flush,
        },
        5 => TerminalCause::OperationStalled {
            direction: CopyDirection::PeerToQuic,
            operation: CopyOperation::Shutdown,
        },
        6 => TerminalCause::OperationStalled {
            direction: CopyDirection::QuicToPeer,
            operation: CopyOperation::Delivery,
        },
        7 => TerminalCause::Cancelled,
        8 => TerminalCause::TaskFailed(CopyDirection::QuicToPeer),
        9 => TerminalCause::TaskFailed(CopyDirection::PeerToQuic),
        10 => TerminalCause::PathFailed,
        11 => TerminalCause::RouteSupervisorFailed,
        12 => TerminalCause::ConstructionFailed,
        13 => TerminalCause::DeadlineOverflow(DeadlineKind::Operation),
        14 => TerminalCause::DeadlineOverflow(DeadlineKind::Finalize),
        _ => TerminalCause::FinalizeTimeout,
    }
}

fn apply_byte(model: &mut Model, byte: u8) {
    let finite = Timeout::finite(byte);
    match byte & 0x0f {
        0 => model.request(TerminalCause::SourceEof(direction(byte)), finite),
        1 => model.request(
            TerminalCause::OperationFailed {
                direction: direction(byte),
                operation: operation(byte),
            },
            finite,
        ),
        2 => model.request(
            TerminalCause::OperationStalled {
                direction: direction(byte),
                operation: operation(byte),
            },
            finite,
        ),
        3 => model.request(TerminalCause::TaskFailed(direction(byte)), finite),
        4 => model.request(TerminalCause::PathFailed, finite),
        5 => model.request(TerminalCause::RouteSupervisorFailed, finite),
        6 => model.request(TerminalCause::ConstructionFailed, finite),
        7 => model.request(TerminalCause::DeadlineOverflow(deadline_kind(byte)), finite),
        8 => model.request(TerminalCause::FinalizeTimeout, finite),
        9 => model.cancel(finite),
        10 => model.request(selected_cause(byte >> 4), finite),
        11 => model.begin_drain(),
        12 => model.begin_finalize(finite),
        13 => model.begin_finalize(Timeout::Overflow),
        14 => model.request(selected_cause(byte >> 4), Timeout::Overflow),
        _ => model.cancel(Timeout::Overflow),
    }
}

fn exercise_idempotence(model: &mut Model) {
    model.begin_finalize(Timeout::Finite(Duration::ZERO));
    model.begin_finalize(Timeout::Overflow);
    model.request(
        TerminalCause::PathFailed,
        Timeout::Finite(Duration::from_millis(1)),
    );
    model.request(TerminalCause::RouteSupervisorFailed, Timeout::Overflow);
    model.begin_drain();
    model.begin_drain();
    model.begin_finalize(Timeout::Finite(Duration::from_millis(1)));
    model.begin_finalize(Timeout::Overflow);
}

fuzz_target!(|data: &[u8]| {
    let mut model = Model::new();
    for &byte in data.iter().take(MAX_STEPS) {
        apply_byte(&mut model, byte);
    }
    exercise_idempotence(&mut model);
});
