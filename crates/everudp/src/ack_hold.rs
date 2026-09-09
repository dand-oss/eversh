//! Deterministic policy for the optional input-ACK wire hold.
//!
//! This module deliberately owns no timer and performs no allocation.  The
//! link integration owns one `Sleep` and calls [`AckHold::deadline`] while an
//! ACK record is eligible to be held.  A completed record must call
//! [`AckHold::reset`] before the next record can arm a hold.

use std::time::Duration;
use tokio::time::Instant;

use crate::wire::Kind;

const HOLD: Duration = Duration::from_millis(1);

/// Whether an input ACK may be held for the optional wire coalescing window.
///
/// The predicate is intentionally narrow: only a standalone input ACK with
/// no partial write, exactly one pending control operation, no ready output,
/// and valid output state can be delayed.  Every other case must flush
/// immediately so control traffic and output delivery retain their ordering
/// and liveness guarantees.
pub(crate) const fn eligible(
    kind: Kind,
    written: usize,
    control_operations: usize,
    output_ready: bool,
    output_valid: bool,
) -> bool {
    matches!(kind, Kind::AckInput)
        && written == 0
        && control_operations == 1
        && !output_ready
        && output_valid
}

/// State for one optional ACK-hold record.
///
/// The first eligible poll arms a fixed deadline.  Subsequent eligible polls
/// return that same deadline, so activity cannot extend the hold indefinitely.
/// Once the deadline is reached the hold is released until the owner resets
/// this state for the next completed record.
#[derive(Debug, Default)]
pub(crate) struct AckHold {
    deadline: Option<Instant>,
    released: bool,
}

impl AckHold {
    /// Return the deadline for the current record, if the hold is still armed.
    ///
    /// An ineligible poll cancels an armed hold.  Expiration is inclusive: a
    /// poll at exactly the deadline releases the record and returns `None`.
    pub(crate) fn deadline(&mut self, now: Instant, eligible: bool) -> Option<Instant> {
        if !eligible {
            self.deadline = None;
            self.released = true;
            return None;
        }

        if self.released {
            return None;
        }

        let deadline = *self.deadline.get_or_insert_with(|| now + HOLD);
        if now >= deadline {
            self.deadline = None;
            self.released = true;
            None
        } else {
            Some(deadline)
        }
    }

    /// Begin tracking a fresh record after the previous one completed.
    pub(crate) fn reset(&mut self) {
        self.deadline = None;
        self.released = false;
    }
}

#[cfg(test)]
mod tests {
    use super::{eligible, AckHold, HOLD};
    use crate::wire::Kind;
    use std::time::Duration;
    use tokio::time::Instant;

    #[test]
    fn initial_hold_arms_one_fixed_deadline() {
        let now = Instant::now();
        let mut hold = AckHold::default();

        assert_eq!(hold.deadline(now, true), Some(now + HOLD));
    }

    #[test]
    fn repeated_polls_do_not_extend_deadline() {
        let now = Instant::now();
        let later = now + Duration::from_micros(100);
        let mut hold = AckHold::default();

        let first = hold.deadline(now, true).expect("initial deadline");
        assert_eq!(hold.deadline(later, true), Some(first));
    }

    #[test]
    fn deadline_boundary_releases() {
        let now = Instant::now();
        let mut hold = AckHold::default();
        let deadline = hold.deadline(now, true).expect("initial deadline");

        assert_eq!(hold.deadline(deadline, true), None);
    }

    #[test]
    fn expired_hold_stays_released_until_reset() {
        let now = Instant::now();
        let mut hold = AckHold::default();
        let deadline = hold.deadline(now, true).expect("initial deadline");

        assert_eq!(hold.deadline(deadline, true), None);
        assert_eq!(hold.deadline(deadline + HOLD, true), None);
    }

    #[test]
    fn ineligible_clears_and_reset_arms_next_record() {
        let now = Instant::now();
        let mut hold = AckHold::default();
        hold.deadline(now, true).expect("initial deadline");

        assert_eq!(hold.deadline(now + Duration::from_micros(100), false), None);
        let rearmed = now + Duration::from_micros(200);
        assert_eq!(hold.deadline(rearmed, true), None);

        hold.reset();
        let next = now + Duration::from_secs(1);
        assert_eq!(hold.deadline(next, true), Some(next + HOLD));
    }

    #[test]
    fn eligibility_requires_all_ack_hold_conditions() {
        let kinds = [
            Kind::ClientHello,
            Kind::ServerHello,
            Kind::AckInput,
            Kind::AckOutput,
            Kind::Gap,
            Kind::LinkStatus,
            Kind::Detach,
            Kind::Kill,
            Kind::ProtocolClose,
            Kind::Input,
            Kind::Resize,
            Kind::Signal,
            Kind::InputClose,
            Kind::Output,
            Kind::Ownership,
            Kind::Exit,
        ];

        for kind in kinds {
            for written in [0, 1, 2] {
                for operations in [0, 1, 2] {
                    for output_ready in [false, true] {
                        for output_valid in [false, true] {
                            let expected = matches!(kind, Kind::AckInput)
                                && written == 0
                                && operations == 1
                                && !output_ready
                                && output_valid;
                            assert_eq!(
                                eligible(
                                    kind,
                                    written,
                                    operations,
                                    output_ready,
                                    output_valid,
                                ),
                                expected,
                                "unexpected eligibility for {kind:?}, written={written}, operations={operations}, output_ready={output_ready}, output_valid={output_valid}"
                            );
                        }
                    }
                }
            }
        }
    }
}
