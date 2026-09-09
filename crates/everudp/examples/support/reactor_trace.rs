//! Bounded diagnostic observations for the disposable floor reactor.
//!
//! This recorder is deliberately separate from protocol behavior.  It stores
//! only fixed-vocabulary counters, clock stamps, and link outcome flags; it
//! never stores payloads, tokens, or terminal data.  The normal reactor path
//! does not construct or touch this type.
//!
//! Step intervals include the caller's event drain, not just reactor service.
//! The client records only turns with an outstanding input sequence; admission
//! and pre-input idle turns are excluded. `transmits_generated` counts connection
//! poll_transmit output, not stateless receive responses: idle classification
//! must also inspect receive, segment, endpoint, timer, and application work.

use std::io::{self, Write};

use super::phase_timing::{Phase as TimingPhase, Stamp as TimingStamp, Timings};
use everudp::floor_reactor::{StepEdge, StepPhase, StepResult, StepWork};

use super::native_trace::{identity, monotonic_ns, thread_cpu_ns, thread_id};

const CALIBRATION_SAMPLES: usize = 16;

/// High-level point at which an observed reactor turn was sampled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    LoopTop,
    InitialPostOffer,
    RetryPostOffer,
}

impl Phase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::LoopTop => "loop_top",
            Self::InitialPostOffer => "initial_post_offer",
            Self::RetryPostOffer => "retry_post_offer",
        }
    }
}

/// Input/output anchors associated with the observed turns.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Anchor {
    InputRead,
    SinkAccepted,
}

impl Anchor {
    const fn as_str(self) -> &'static str {
        match self {
            Self::InputRead => "input_read",
            Self::SinkAccepted => "sink_accepted",
        }
    }
}

/// One observation supplied by the caller after a reactor turn.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Observation {
    pub phase: Phase,
    pub sequence: u64,
    pub timer_due: bool,
    pub work: StepWork,
    pub result: StepResult,
    pub events_drained: u64,
    pub application_ready: bool,
}

#[derive(Clone, Copy)]
pub struct Stamp {
    wall_ns: u64,
    cpu_ns: u64,
    valid: bool,
}

#[derive(Clone, Copy)]
// Inline records deliberately trade space for allocation-free capture. Boxing
// the step variant would allocate in the measured path; the ring is bounded.
#[allow(clippy::large_enum_variant)]
enum Event {
    Step {
        begin: Stamp,
        end: Stamp,
        observation: Observation,
        partitions: Option<Timings>,
    },
    Anchor {
        stamp: Stamp,
        kind: Anchor,
        sequence: u64,
    },
}

/// Fixed-capacity, thread-bound reactor recorder.
pub struct ReactorTrace {
    events: Vec<Event>,
    capacity: usize,
    invalid: bool,
    overflow: bool,
    last_wall_ns: Option<u64>,
    last_cpu_ns: Option<u64>,
    pid: u32,
    tid: u64,
    boot_id: String,
    namespace_dev: u64,
    namespace_ino: u64,
    calibration_ns: [u64; CALIBRATION_SAMPLES],
    partitioned: bool,
    phase_timing: Timings,
    _thread_bound: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl ReactorTrace {
    /// Construct a recorder and perform identity/clock calibration up front.
    pub fn new(capacity: usize) -> Self {
        let identity_value = identity();
        let mut calibration_ns = [0; CALIBRATION_SAMPLES];
        let mut invalid = identity_value.is_none();
        for sample in &mut calibration_ns {
            match (thread_cpu_ns(), thread_cpu_ns()) {
                (Ok(before), Ok(after)) => match after.checked_sub(before) {
                    Some(delta) => *sample = delta,
                    None => invalid = true,
                },
                _ => invalid = true,
            }
        }
        let (boot_id, namespace_dev, namespace_ino) = identity_value.unwrap_or_default();
        Self {
            events: Vec::with_capacity(capacity),
            capacity,
            invalid,
            overflow: false,
            last_wall_ns: None,
            last_cpu_ns: None,
            pid: std::process::id(),
            tid: thread_id(),
            boot_id,
            namespace_dev,
            namespace_ino,
            calibration_ns,
            partitioned: false,
            phase_timing: Timings::default(),
            _thread_bound: std::marker::PhantomData,
        }
    }

    /// Construct the version-2 recorder with fixed per-phase accumulators.
    /// The v1 constructor and byte schema remain unchanged.
    pub fn new_partitioned(capacity: usize) -> Self {
        let mut trace = Self::new(capacity);
        trace.partitioned = true;
        trace
    }

    /// Whether this recorder emits the partitioned v2 schema.
    pub fn is_partitioned(&self) -> bool {
        self.partitioned
    }

    /// Capture the beginning of a caller-owned observed reactor step.
    pub fn begin_step(&mut self) -> Stamp {
        let stamp = self.capture();
        if self.partitioned {
            self.phase_timing = Timings::default();
        }
        stamp
    }

    /// Record one low-level reactor phase edge using the recorder's native
    /// monotonic/thread CPU clocks. Sampling failures remain sticky-invalid.
    pub fn record_phase(&mut self, phase: StepPhase, edge: StepEdge) {
        if !self.partitioned {
            return;
        }
        let stamp = self.capture();
        let stamp = stamp.valid.then_some(TimingStamp {
            wall_ns: stamp.wall_ns,
            cpu_ns: stamp.cpu_ns,
        });
        let phase = match phase {
            StepPhase::PumpDrive => TimingPhase::Pump,
            StepPhase::Send => TimingPhase::Send,
            StepPhase::Segment => TimingPhase::Segment,
            StepPhase::Receive => TimingPhase::Receive,
        };
        match edge {
            StepEdge::Begin => self.phase_timing.begin(phase, stamp),
            StepEdge::End => self.phase_timing.end(phase, stamp),
        }
    }

    /// Begin/end the caller-owned event-drain phase.
    pub fn begin_drain(&mut self) {
        if self.partitioned {
            let stamp = self.capture();
            let stamp = stamp.valid.then_some(TimingStamp {
                wall_ns: stamp.wall_ns,
                cpu_ns: stamp.cpu_ns,
            });
            self.phase_timing.begin(TimingPhase::EventDrain, stamp);
        }
    }

    /// Finish the caller-owned event-drain phase.
    pub fn end_drain(&mut self) {
        if self.partitioned {
            let stamp = self.capture();
            let stamp = stamp.valid.then_some(TimingStamp {
                wall_ns: stamp.wall_ns,
                cpu_ns: stamp.cpu_ns,
            });
            self.phase_timing.end(TimingPhase::EventDrain, stamp);
        }
    }

    /// Finish and retain one observed reactor step if capacity remains.
    pub fn finish_step(&mut self, stamp: Stamp, observation: Observation) {
        if observation.work.overflow || observation.work.pump.overflow {
            self.invalid = true;
            self.overflow = true;
        }
        let partitions = if self.partitioned {
            if !self.phase_timing.valid() {
                self.invalid = true;
            }
            if self.phase_timing.overflow() {
                self.invalid = true;
                self.overflow = true;
            }
            Some(self.phase_timing)
        } else {
            None
        };
        let end = self.capture();
        self.push(Event::Step {
            begin: stamp,
            end,
            observation,
            partitions,
        });
    }

    /// Capture a fixed-vocabulary input/output anchor.
    pub fn anchor(&mut self, kind: Anchor, sequence: u64) {
        let stamp = self.capture();
        self.push(Event::Anchor {
            stamp,
            kind,
            sequence,
        });
    }

    /// Serialize the diagnostic schema after the run has ended.
    pub fn write_json(&self, mut writer: impl Write, run_succeeded: bool) -> io::Result<()> {
        let valid = run_succeeded && !self.invalid && !self.overflow;
        let (schema_version, protocol) = if self.partitioned {
            (2, "everudp-reactor-partitions-v2")
        } else {
            (1, "everudp-reactor-work-v1")
        };
        write!(
            writer,
            "{{\"schema_version\":{schema_version},\"protocol\":\"{protocol}\",\"diagnostic_only\":true,\"wall_clock\":\"CLOCK_MONOTONIC\",\"cpu_clock\":\"CLOCK_THREAD_CPUTIME_ID\",\"sample_order\":\"wall_then_cpu_not_simultaneous\",\"valid\":{},\"run_succeeded\":{},\"capacity\":{},\"overflow\":{},\"identity\":{{\"pid\":{},\"tid\":{},\"boot_id\":\"{}\",\"time_namespace_dev\":{},\"time_namespace_ino\":{}}},\"cpu_clock_calibration_ns\":[",
            valid,
            run_succeeded,
            self.capacity,
            self.overflow,
            self.pid,
            self.tid,
            self.boot_id,
            self.namespace_dev,
            self.namespace_ino
        )?;
        for (index, value) in self.calibration_ns.iter().enumerate() {
            if index != 0 {
                writer.write_all(b",")?;
            }
            write!(writer, "{value}")?;
        }
        writer.write_all(b"],\"events\":[")?;
        for (index, event) in self.events.iter().enumerate() {
            if index != 0 {
                writer.write_all(b",")?;
            }
            self.write_event(&mut writer, *event)?;
        }
        writer.write_all(b"]}\n")
    }

    fn capture(&mut self) -> Stamp {
        self.capture_results(monotonic_ns(), thread_cpu_ns())
    }

    fn capture_results(&mut self, wall: io::Result<u64>, cpu: io::Result<u64>) -> Stamp {
        match (wall, cpu) {
            (Ok(wall_ns), Ok(cpu_ns)) => self.capture_values(wall_ns, cpu_ns),
            _ => {
                self.invalid = true;
                Stamp {
                    wall_ns: 0,
                    cpu_ns: 0,
                    valid: false,
                }
            }
        }
    }

    fn capture_values(&mut self, wall_ns: u64, cpu_ns: u64) -> Stamp {
        if self.last_wall_ns.is_some_and(|last| wall_ns < last)
            || self.last_cpu_ns.is_some_and(|last| cpu_ns < last)
        {
            self.invalid = true;
        }
        self.last_wall_ns = Some(wall_ns);
        self.last_cpu_ns = Some(cpu_ns);
        Stamp {
            wall_ns,
            cpu_ns,
            valid: true,
        }
    }

    fn push(&mut self, event: Event) {
        if self.events.len() >= self.capacity {
            self.invalid = true;
            self.overflow = true;
            return;
        }
        self.events.push(event);
    }

    fn write_event(&self, writer: &mut impl Write, event: Event) -> io::Result<()> {
        match event {
            Event::Anchor {
                stamp,
                kind,
                sequence,
            } => write!(
                writer,
                "{{\"kind\":\"anchor\",\"anchor\":\"{}\",\"sequence\":{},\"begin_time_ns\":{},\"begin_cpu_time_ns\":{},\"end_time_ns\":{},\"end_cpu_time_ns\":{},\"clock_valid\":{}}}",
                kind.as_str(),
                sequence,
                stamp.wall_ns,
                stamp.cpu_ns,
                stamp.wall_ns,
                stamp.cpu_ns,
                stamp.valid
            ),
            Event::Step {
                begin,
                end,
                observation,
                partitions,
            } => {
                let work = observation.work;
                let pump = work.pump;
                let mut encoded = Vec::new();
                write!(
                    &mut encoded,
                    "{{\"kind\":\"step\",\"phase\":\"{}\",\"sequence\":{},\"timer_due\":{},\"begin_time_ns\":{},\"begin_cpu_time_ns\":{},\"end_time_ns\":{},\"end_cpu_time_ns\":{},\"clock_valid\":{},\"pump_drive_calls\":{},\"send_attempts\":{},\"send_accepted\":{},\"send_would_block\":{},\"send_interrupted\":{},\"receive_calls\":{},\"receive_batches\":{},\"receive_datagrams\":{},\"receive_empty\":{},\"receive_would_block\":{},\"retained_gro_segments_delivered\":{},\"overflow\":{},\"events_drained\":{},\"application_ready\":{},\"pump\":{{\"deferred_receives\":{},\"deferred_receives_queued\":{},\"timers_handled\":{},\"endpoint_events\":{},\"application_events_enqueued\":{},\"transmits_generated\":{},\"connections_retired\":{},\"overflow\":{}}},\"result\":{{\"work\":{},\"exhausted\":{},\"write_blocked\":{}}}}}",
                    observation.phase.as_str(),
                    observation.sequence,
                    observation.timer_due,
                    begin.wall_ns,
                    begin.cpu_ns,
                    end.wall_ns,
                    end.cpu_ns,
                    begin.valid && end.valid,
                    work.pump_drive_calls,
                    work.send_attempts,
                    work.send_accepted,
                    work.send_would_block,
                    work.send_interrupted,
                    work.receive_calls,
                    work.receive_batches,
                    work.receive_datagrams,
                    work.receive_empty,
                    work.receive_would_block,
                    work.retained_gro_segments_delivered,
                    work.overflow,
                    observation.events_drained,
                    observation.application_ready,
                    pump.deferred_receives,
                    pump.deferred_receives_queued,
                    pump.timers_handled,
                    pump.endpoint_events,
                    pump.application_events_enqueued,
                    pump.transmits_generated,
                    pump.connections_retired,
                    pump.overflow,
                    observation.result.work,
                    observation.result.exhausted,
                    observation.result.write_blocked
                )?;
                if let Some(timings) = partitions {
                    // The base event already contains its closing brace. Trim
                    // that brace while adding the v2 partition object; v1
                    // writes the bytes unchanged below.
                    encoded.pop();
                    writer.write_all(&encoded)?;
                    writer.write_all(b",\"partitions\":")?;
                    write_partitions(writer, timings)?;
                    writer.write_all(b"}")
                } else {
                    writer.write_all(&encoded)
                }
            }
        }
    }
}

fn write_partitions(writer: &mut impl Write, timings: Timings) -> io::Result<()> {
    const PHASES: [(TimingPhase, &str); 5] = [
        (TimingPhase::Pump, "pump"),
        (TimingPhase::Send, "send"),
        (TimingPhase::Segment, "segment"),
        (TimingPhase::Receive, "receive"),
        (TimingPhase::EventDrain, "event_drain"),
    ];
    write!(
        writer,
        "{{\"valid\":{},\"overflow\":{},\"phases\":{{",
        timings.valid(),
        timings.overflow()
    )?;
    for (index, (phase, name)) in PHASES.iter().enumerate() {
        if index != 0 {
            writer.write_all(b",")?;
        }
        let total = timings.totals()[*phase as usize];
        write!(
            writer,
            "\"{}\":{{\"calls\":{},\"wall_ns\":{},\"cpu_ns\":{}}}",
            name, total.calls, total.wall_ns, total.cpu_ns
        )?;
    }
    writer.write_all(b"}}")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Opt-in fixture output lets the network analyzer tests validate the actual
    // Rust serializer without introducing a JSON dependency into this crate.
    #[test]
    fn complete_json_export_fixtures() {
        for partitioned in [false, true] {
            let mut trace = if partitioned {
                ReactorTrace::new_partitioned(2)
            } else {
                ReactorTrace::new(2)
            };
            let stamp = trace.begin_step();
            if partitioned {
                trace.record_phase(StepPhase::PumpDrive, StepEdge::Begin);
                trace.record_phase(StepPhase::PumpDrive, StepEdge::End);
                trace.begin_drain();
                trace.end_drain();
            }
            trace.finish_step(stamp, observation(StepWork::default()));
            let mut output = Vec::new();
            trace.write_json(&mut output, true).expect("fixture export");
            if std::env::var_os("EVERUDP_PRINT_JSON_FIXTURES").is_some() {
                println!(
                    "REACTOR_JSON_FIXTURE:{}",
                    String::from_utf8(output).expect("UTF-8")
                );
            }
        }
    }

    fn result() -> StepResult {
        StepResult {
            work: 1,
            exhausted: false,
            write_blocked: false,
        }
    }

    fn observation(work: StepWork) -> Observation {
        Observation {
            phase: Phase::LoopTop,
            sequence: 1,
            timer_due: false,
            work,
            result: result(),
            events_drained: 0,
            application_ready: false,
        }
    }

    #[test]
    fn startup_calibration_and_fixed_schema_are_present() {
        let mut trace = ReactorTrace::new(2);
        assert!(!trace.invalid);
        assert_eq!(trace.pid, std::process::id());
        assert_eq!(trace.tid, thread_id());
        let (boot_id, dev, ino) = identity().expect("clock identity");
        assert_eq!(
            (&trace.boot_id, trace.namespace_dev, trace.namespace_ino),
            (&boot_id, dev, ino)
        );
        assert_eq!(trace.calibration_ns.len(), CALIBRATION_SAMPLES);
        let stamp = trace.begin_step();
        assert!(stamp.valid && stamp.wall_ns > 0 && stamp.cpu_ns > 0);
        let mut output = Vec::new();
        trace.write_json(&mut output, true).expect("json");
        let text = String::from_utf8(output).expect("utf8");
        assert!(text.contains("\"schema_version\":1"));
        assert!(text.contains("everudp-reactor-work-v1"));
        assert!(text.contains("CLOCK_MONOTONIC"));
        assert!(text.contains("cpu_clock_calibration_ns"));
        assert!(!text.contains("payload") && !text.contains("token"));
    }

    #[test]
    fn clock_failures_and_regressions_independently_invalidate() {
        for (wall, cpu) in [
            (Ok(9), Ok(11)),
            (Ok(11), Ok(9)),
            (Err(io::Error::other("wall failure")), Ok(11)),
            (Ok(11), Err(io::Error::other("cpu failure"))),
        ] {
            let mut trace = ReactorTrace::new(2);
            assert!(!trace.invalid);
            trace.capture_results(Ok(10), Ok(10));
            trace.capture_results(wall, cpu);
            assert!(trace.invalid);
            trace.capture_results(Ok(12), Ok(12));
            assert_invalid_export(&trace, true);
        }
    }

    fn assert_invalid_export(trace: &ReactorTrace, run_succeeded: bool) {
        let mut output = Vec::new();
        trace.write_json(&mut output, run_succeeded).expect("json");
        assert!(String::from_utf8(output)
            .expect("utf8")
            .contains("\"valid\":false"));
    }

    #[test]
    fn fixed_capacity_overflow_invalidates_without_growing() {
        let mut trace = ReactorTrace::new(1);
        let pointer = trace.events.as_ptr();
        let capacity = trace.events.capacity();
        let first = trace.begin_step();
        trace.finish_step(first, observation(StepWork::default()));
        assert!(!trace.invalid && !trace.overflow);
        let second = trace.begin_step();
        trace.finish_step(second, observation(StepWork::default()));
        assert_eq!(trace.events.as_ptr(), pointer);
        assert_eq!(trace.events.capacity(), capacity);
        assert!(trace.overflow && trace.invalid);
        assert_eq!(trace.events.len(), 1);
        assert_invalid_export(&trace, true);
    }

    #[test]
    fn each_counter_overflow_independently_invalidates() {
        for nested in [false, true] {
            let mut trace = ReactorTrace::new(2);
            let mut work = StepWork::default();
            if nested {
                work.pump.overflow = true;
            } else {
                work.overflow = true;
            }
            let stamp = trace.begin_step();
            trace.finish_step(stamp, observation(work));
            assert!(trace.invalid && trace.overflow);
            assert_eq!(trace.events.len(), 1);
            assert_invalid_export(&trace, true);
        }
    }

    #[test]
    fn failed_run_invalidates_otherwise_valid_recording() {
        let trace = ReactorTrace::new(2);
        assert!(!trace.invalid && !trace.overflow);
        assert_invalid_export(&trace, false);
    }

    #[test]
    fn anchors_and_phases_use_distinct_fixed_vocabulary() {
        let mut trace = ReactorTrace::new(4);
        trace.anchor(Anchor::InputRead, 1);
        let stamp = trace.begin_step();
        trace.finish_step(
            stamp,
            Observation {
                phase: Phase::RetryPostOffer,
                sequence: 1,
                timer_due: true,
                work: StepWork::default(),
                result: StepResult {
                    work: 4,
                    exhausted: true,
                    write_blocked: true,
                },
                events_drained: 2,
                application_ready: true,
            },
        );
        trace.anchor(Anchor::SinkAccepted, 1);
        let mut output = Vec::new();
        trace.write_json(&mut output, true).expect("json");
        let text = String::from_utf8(output).expect("utf8");
        assert!(text.contains("\"anchor\":\"input_read\""));
        assert!(text.contains("\"phase\":\"retry_post_offer\""));
        assert!(text.contains("\"anchor\":\"sink_accepted\""));
    }

    #[test]
    fn partitioned_schema_is_v2_and_phase_storage_resets_each_step() {
        let mut trace = ReactorTrace::new_partitioned(4);
        assert!(trace.is_partitioned());
        let first = trace.begin_step();
        trace.record_phase(StepPhase::PumpDrive, StepEdge::Begin);
        trace.record_phase(StepPhase::PumpDrive, StepEdge::End);
        trace.begin_drain();
        trace.end_drain();
        trace.finish_step(first, observation(StepWork::default()));
        let second = trace.begin_step();
        trace.record_phase(StepPhase::Receive, StepEdge::Begin);
        trace.record_phase(StepPhase::Receive, StepEdge::End);
        trace.finish_step(second, observation(StepWork::default()));
        let Event::Step {
            partitions: Some(first),
            ..
        } = trace.events[0]
        else {
            panic!("first partition snapshot missing");
        };
        let Event::Step {
            partitions: Some(second),
            ..
        } = trace.events[1]
        else {
            panic!("second partition snapshot missing");
        };
        assert_eq!(first.totals()[TimingPhase::Pump as usize].calls, 1);
        assert_eq!(first.totals()[TimingPhase::Receive as usize].calls, 0);
        assert_eq!(second.totals()[TimingPhase::Pump as usize].calls, 0);
        assert_eq!(second.totals()[TimingPhase::Receive as usize].calls, 1);
        assert_eq!(second.totals()[TimingPhase::EventDrain as usize].calls, 0);

        let mut output = Vec::new();
        trace.write_json(&mut output, true).expect("json");
        let text = String::from_utf8(output).expect("utf8");
        assert!(text.contains("\"schema_version\":2"));
        assert!(text.contains("everudp-reactor-partitions-v2"));
        assert!(text.contains("\"pump\":{\"calls\":1"));
        assert!(text.contains("\"receive\":{\"calls\":1"));
        assert!(text.contains("\"event_drain\":{\"calls\":1"));
    }

    #[test]
    fn partitioned_incomplete_and_clock_failure_invalidate_export() {
        let mut incomplete = ReactorTrace::new_partitioned(2);
        let stamp = incomplete.begin_step();
        incomplete.record_phase(StepPhase::Send, StepEdge::Begin);
        incomplete.finish_step(stamp, observation(StepWork::default()));
        assert_invalid_export(&incomplete, true);

        let mut failed = ReactorTrace::new_partitioned(2);
        failed.capture_results(Ok(10), Ok(10));
        failed.capture_results(Err(io::Error::other("wall failure")), Ok(11));
        let stamp = failed.begin_step();
        failed.record_phase(StepPhase::Receive, StepEdge::Begin);
        failed.record_phase(StepPhase::Receive, StepEdge::End);
        failed.finish_step(stamp, observation(StepWork::default()));
        assert_invalid_export(&failed, true);
    }
}
