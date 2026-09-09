//! Small, synchronous native-clock trace for the opt-in floor experiment.
//!
//! This recorder is deliberately independent of the protocol implementation:
//! it stores only a fixed vocabulary and a sequence number.  It is diagnostic
//! evidence, not a packet or terminal transcript.

use std::io::{self, Write};

const CALIBRATION_SAMPLES: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    TerminalRead,
    Encoded,
    PreOfferReactorStart,
    PreOfferReactorEnd,
    OfferStart,
    OfferEnd,
    PostOfferReactorStart,
    PostOfferReactorEnd,
    SinkAccepted,
}

impl Stage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::TerminalRead => "terminal_read",
            Self::Encoded => "encoded",
            Self::PreOfferReactorStart => "pre_offer_reactor_start",
            Self::PreOfferReactorEnd => "pre_offer_reactor_end",
            Self::OfferStart => "offer_start",
            Self::OfferEnd => "offer_end",
            Self::PostOfferReactorStart => "post_offer_reactor_start",
            Self::PostOfferReactorEnd => "post_offer_reactor_end",
            Self::SinkAccepted => "sink_accepted",
        }
    }
}

#[derive(Clone, Copy)]
struct Event {
    time_ns: u64,
    cpu_ns: u64,
    stage: Stage,
    sequence: u64,
}

/// A fixed-capacity recorder.  Construction performs all identity and clock
/// calibration work; a successful `record` never allocates or locks.
pub struct Trace {
    events: Vec<Event>,
    capacity: usize,
    invalid: bool,
    overflow: bool,
    last_time_ns: Option<u64>,
    last_cpu_ns: Option<u64>,
    pid: u32,
    tid: u64,
    boot_id: String,
    namespace_dev: u64,
    namespace_ino: u64,
    calibration_ns: [u64; CALIBRATION_SAMPLES],
    // CPU samples belong to the constructing thread; prevent moving the
    // recorder to another thread even if that thread has a larger CPU clock.
    _thread_bound: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl Trace {
    pub fn new(capacity: usize) -> Self {
        let identity = identity();
        let mut calibration_ns = [0; CALIBRATION_SAMPLES];
        let mut invalid = identity.is_none();
        for sample in &mut calibration_ns {
            match (thread_cpu_ns(), thread_cpu_ns()) {
                (Ok(before), Ok(after)) => match after.checked_sub(before) {
                    Some(delta) => *sample = delta,
                    None => invalid = true,
                },
                _ => invalid = true,
            }
        }
        let (boot_id, namespace_dev, namespace_ino) = identity.unwrap_or_default();
        Self {
            events: Vec::with_capacity(capacity),
            capacity,
            invalid,
            overflow: false,
            last_time_ns: None,
            last_cpu_ns: None,
            pid: std::process::id(),
            tid: thread_id(),
            boot_id,
            namespace_dev,
            namespace_ino,
            calibration_ns,
            _thread_bound: std::marker::PhantomData,
        }
    }

    pub fn record(&mut self, stage: Stage, sequence: u64) {
        if self.events.len() >= self.capacity {
            self.overflow = true;
            self.invalid = true;
            return;
        }
        let (time_ns, cpu_ns) = match (monotonic_ns(), thread_cpu_ns()) {
            (Ok(time), Ok(cpu)) => (time, cpu),
            _ => {
                self.invalid = true;
                return;
            }
        };
        self.record_sample(stage, sequence, time_ns, cpu_ns);
    }

    fn record_sample(&mut self, stage: Stage, sequence: u64, time_ns: u64, cpu_ns: u64) {
        if self.last_time_ns.is_some_and(|last| time_ns < last)
            || self.last_cpu_ns.is_some_and(|last| cpu_ns < last)
        {
            self.invalid = true;
        }
        self.last_time_ns = Some(time_ns);
        self.last_cpu_ns = Some(cpu_ns);
        if self.events.len() < self.capacity {
            self.events.push(Event {
                time_ns,
                cpu_ns,
                stage,
                sequence,
            });
        } else {
            self.overflow = true;
            self.invalid = true;
        }
    }

    #[cfg(test)]
    fn record_with_clocks(
        &mut self,
        stage: Stage,
        sequence: u64,
        time: io::Result<u64>,
        cpu: io::Result<u64>,
    ) {
        match (time, cpu) {
            (Ok(time_ns), Ok(cpu_ns)) => self.record_sample(stage, sequence, time_ns, cpu_ns),
            _ => self.invalid = true,
        }
    }

    pub fn write_json(&self, mut writer: impl Write, run_succeeded: bool) -> io::Result<()> {
        let valid = run_succeeded && !self.invalid && !self.overflow;
        write!(writer, "{{\"schema_version\":1,\"diagnostic_only\":true,\"wall_clock\":\"CLOCK_MONOTONIC\",\"cpu_clock\":\"CLOCK_THREAD_CPUTIME_ID\",\"sample_order\":\"wall_then_cpu_not_simultaneous\",\"valid\":{},\"run_succeeded\":{},\"capacity\":{},\"overflow\":{},\"identity\":{{\"pid\":{},\"tid\":{},\"boot_id\":\"{}\",\"time_namespace_dev\":{},\"time_namespace_ino\":{}}},\"cpu_clock_calibration_ns\":[", valid, run_succeeded, self.capacity, self.overflow, self.pid, self.tid, self.boot_id, self.namespace_dev, self.namespace_ino)?;
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
            write!(
                writer,
                "{{\"time_ns\":{},\"cpu_time_ns\":{},\"stage\":\"{}\",\"sequence\":{}}}",
                event.time_ns,
                event.cpu_ns,
                event.stage.as_str(),
                event.sequence
            )?;
        }
        writer.write_all(b"]}\n")
    }
}

pub(super) fn identity() -> Option<(String, u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    let boot = boot.trim();
    if boot.len() != 36
        || !boot.as_bytes().iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
    {
        return None;
    }
    let namespace = std::fs::metadata("/proc/self/ns/time").ok()?;
    Some((boot.to_owned(), namespace.dev(), namespace.ino()))
}

pub(super) fn thread_id() -> u64 {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: gettid takes no pointer arguments and uses the target ABI's
        // syscall number supplied by libc, not an x86-specific constant.
        unsafe { libc::syscall(libc::SYS_gettid) as u64 }
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::process::id() as u64
    }
}

#[cfg(target_os = "linux")]
fn clock_ns(clock: i32) -> io::Result<u64> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: value is a writable timespec with the platform's libc layout.
    if unsafe { libc::clock_gettime(clock, &mut value) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid clock value",
        ));
    }
    (value.tv_sec as u64)
        .checked_mul(1_000_000_000)
        .and_then(|v| v.checked_add(value.tv_nsec as u64))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "clock overflow"))
}

#[cfg(not(target_os = "linux"))]
fn clock_ns(_clock: i32) -> io::Result<u64> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native clocks require Linux",
    ))
}
pub(super) fn monotonic_ns() -> io::Result<u64> {
    clock_ns(libc::CLOCK_MONOTONIC)
}
pub(super) fn thread_cpu_ns() -> io::Result<u64> {
    clock_ns(libc::CLOCK_THREAD_CPUTIME_ID)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn calibrated_sample_is_finite() {
        let mut trace = Trace::new(1);
        assert!(!trace.invalid);
        assert!(trace.calibration_ns.iter().any(|sample| *sample > 0));
        trace.record(Stage::TerminalRead, 0);
        assert!(!trace.invalid);
        assert!(trace.events[0].time_ns > 0);
        assert_eq!(trace.tid, thread_id());
    }
    #[test]
    fn records_retain_storage_and_overflow_invalidates_export() {
        let mut trace = Trace::new(2);
        let pointer = trace.events.as_ptr();
        let capacity = trace.events.capacity();
        for sequence in 0..10 {
            trace.record_sample(Stage::TerminalRead, sequence, sequence, sequence);
        }
        assert_eq!(trace.events.len(), 2);
        assert_eq!(trace.events.as_ptr(), pointer);
        assert_eq!(trace.events.capacity(), capacity);
        let mut output = Vec::new();
        trace.write_json(&mut output, true).unwrap();
        assert!(String::from_utf8(output)
            .unwrap()
            .contains("\"valid\":false"));
    }
    #[test]
    fn zero_capacity_is_sticky_invalid() {
        let mut t = Trace::new(0);
        t.record_sample(Stage::TerminalRead, 0, 1, 1);
        t.record(Stage::Encoded, 0);
        assert!(t.overflow && t.invalid);
    }
    #[test]
    fn regression_is_sticky_invalid() {
        let mut t = Trace::new(2);
        t.record_sample(Stage::TerminalRead, 0, 10, 10);
        t.record_sample(Stage::Encoded, 0, 9, 11);
        assert!(t.invalid);
    }
    #[test]
    fn clock_failure_is_sticky_invalid() {
        let mut t = Trace::new(1);
        t.record_with_clocks(
            Stage::TerminalRead,
            0,
            Err(io::Error::other("clock")),
            Ok(1),
        );
        assert!(t.invalid);
    }
    #[test]
    fn output_is_bounded_vocabulary() {
        let mut t = Trace::new(1);
        t.record_sample(Stage::SinkAccepted, 4, 1, 2);
        let mut out = Vec::new();
        t.write_json(&mut out, true).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("sink_accepted") && !text.contains("payload"));
    }
}
