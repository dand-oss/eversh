//! Fixed-storage accumulation of non-overlapping diagnostic phase intervals.
//! Clock sampling belongs to the caller; failed samples invalidate the step.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Pump,
    Send,
    Segment,
    Receive,
    EventDrain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stamp {
    pub wall_ns: u64,
    pub cpu_ns: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Total {
    pub calls: u64,
    pub wall_ns: u64,
    pub cpu_ns: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Timings {
    totals: [Total; 5],
    pending: Option<(Phase, Stamp)>,
    previous: Option<Stamp>,
    invalid: bool,
    overflow: bool,
}

impl Timings {
    pub fn begin(&mut self, phase: Phase, stamp: Option<Stamp>) {
        let stamp = self.validate(stamp);
        if self.pending.is_some() {
            self.invalid = true;
        }
        self.pending = stamp.map(|stamp| (phase, stamp));
    }

    pub fn end(&mut self, phase: Phase, stamp: Option<Stamp>) {
        let stamp = self.validate(stamp);
        let pending = self.pending.take();
        let (Some((expected, start)), Some(end)) = (pending, stamp) else {
            self.invalid = true;
            return;
        };
        if phase != expected {
            self.invalid = true;
            return;
        }
        let (Some(wall), Some(cpu)) = (
            end.wall_ns.checked_sub(start.wall_ns),
            end.cpu_ns.checked_sub(start.cpu_ns),
        ) else {
            self.invalid = true;
            return;
        };
        let total = &mut self.totals[phase as usize];
        let next = (
            total.calls.checked_add(1),
            total.wall_ns.checked_add(wall),
            total.cpu_ns.checked_add(cpu),
        );
        match next {
            (Some(calls), Some(wall_ns), Some(cpu_ns)) => {
                *total = Total {
                    calls,
                    wall_ns,
                    cpu_ns,
                };
            }
            _ => {
                self.invalid = true;
                self.overflow = true;
            }
        }
    }

    fn validate(&mut self, stamp: Option<Stamp>) -> Option<Stamp> {
        match stamp {
            Some(stamp) => {
                if self.previous.is_some_and(|previous| {
                    stamp.wall_ns < previous.wall_ns || stamp.cpu_ns < previous.cpu_ns
                }) {
                    self.invalid = true;
                }
                self.previous = Some(stamp);
                Some(stamp)
            }
            None => {
                self.invalid = true;
                None
            }
        }
    }

    pub fn valid(&self) -> bool {
        !self.invalid && !self.overflow && self.pending.is_none()
    }

    pub fn overflow(&self) -> bool {
        self.overflow
    }

    pub fn totals(&self) -> &[Total; 5] {
        &self.totals
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stamp(wall_ns: u64, cpu_ns: u64) -> Option<Stamp> {
        Some(Stamp { wall_ns, cpu_ns })
    }

    #[test]
    fn repeated_phases_accumulate_without_counting_interphase_gaps() {
        let mut timing = Timings::default();
        for (i, phase) in [
            Phase::Pump,
            Phase::Send,
            Phase::Segment,
            Phase::Receive,
            Phase::EventDrain,
            Phase::Pump,
        ]
        .into_iter()
        .enumerate()
        {
            let t = i as u64 * 100;
            timing.begin(phase, stamp(t, t));
            assert!(!timing.valid());
            timing.end(phase, stamp(t + 20, t + 10));
        }
        assert!(timing.valid());
        assert!(!timing.overflow());
        assert_eq!(
            timing.totals()[0],
            Total {
                calls: 2,
                wall_ns: 40,
                cpu_ns: 20
            }
        );
        for total in &timing.totals()[1..] {
            assert_eq!(
                *total,
                Total {
                    calls: 1,
                    wall_ns: 20,
                    cpu_ns: 10
                }
            );
        }
    }

    #[test]
    fn malformed_pairs_and_each_clock_failure_are_sticky_invalid() {
        for case in 0..7 {
            let mut timing = Timings::default();
            timing.begin(Phase::Pump, stamp(10, 10));
            match case {
                0 => timing.end(Phase::Send, stamp(20, 20)),
                1 => timing.begin(Phase::Pump, stamp(20, 20)),
                2 => timing.end(Phase::Pump, None),
                3 => timing.end(Phase::Pump, stamp(9, 20)),
                4 => timing.end(Phase::Pump, stamp(20, 9)),
                5 => {
                    timing = Timings::default();
                    timing.end(Phase::Pump, stamp(20, 20));
                }
                _ => {
                    timing = Timings::default();
                    timing.begin(Phase::Pump, None);
                }
            }
            timing.begin(Phase::Receive, stamp(30, 30));
            timing.end(Phase::Receive, stamp(40, 40));
            assert!(!timing.valid(), "case {case}");
        }
    }

    #[test]
    fn each_total_overflow_invalidates_without_wrapping() {
        for field in 0..3 {
            let mut timing = Timings::default();
            let total = &mut timing.totals[0];
            match field {
                0 => total.calls = u64::MAX,
                1 => total.wall_ns = u64::MAX,
                _ => total.cpu_ns = u64::MAX,
            }
            let before = *total;
            timing.begin(Phase::Pump, stamp(0, 0));
            timing.end(Phase::Pump, stamp(1, 1));
            assert!(timing.overflow());
            assert!(!timing.valid());
            assert_eq!(timing.totals()[0], before);
        }
    }
}
