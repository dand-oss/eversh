//! Opt-in production boundary recorder. No payload, credentials or packet claims.
//! Recording uses bounded preallocated storage; export belongs after measurement.

use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const CAPACITY: usize = 32_768;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    ClientInputQueued,
    ClientInputWritten,
    GatewayInputPrepared,
    GatewayInputAccepted,
    GatewayOutputQueued,
    ClientOutputStaged,
    ClientOutputAccepted,
}

impl Stage {
    fn name(self) -> &'static str {
        match self {
            Self::ClientInputQueued => "client_input_queued",
            Self::ClientInputWritten => "client_input_written",
            Self::GatewayInputPrepared => "gateway_input_prepared",
            Self::GatewayInputAccepted => "gateway_input_accepted",
            Self::GatewayOutputQueued => "gateway_output_queued",
            Self::ClientOutputStaged => "client_output_staged",
            Self::ClientOutputAccepted => "client_output_accepted",
        }
    }
}

#[derive(Clone, Copy)]
struct Event {
    stage: Stage,
    epoch: u64,
    sequence: u64,
    ns: u64,
}

pub struct Trace {
    events: Vec<Event>,
    invalid: bool,
    overflow: bool,
    boot: String,
    namespace: (u64, u64),
    pid: u32,
}

/// Private, exclusive artifact owned by the measured association. Drop exports
/// after its last event. Missing/truncated artifacts must fail trace validation;
/// diagnostic I/O failure never changes terminal delivery semantics.
pub struct FileTrace {
    trace: Trace,
    file: std::fs::File,
    #[cfg(feature = "path-io-diagnostics")]
    _io_trace: Option<crate::io_trace::Guard>,
}

impl FileTrace {
    pub fn create(path: &Path) -> io::Result<Self> {
        let trace = Trace::new()?;
        let file = std::fs::File::from(everpty::sys::create_exclusive_private(path)?);
        #[cfg(feature = "path-io-diagnostics")]
        let io_trace = match std::env::var_os("EVERUDP_PATH_IO_TRACE") {
            None => None,
            Some(value) if value == "0" => None,
            Some(value) if value == "1" => Some(crate::io_trace::Guard::create(path)?),
            Some(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "EVERUDP_PATH_IO_TRACE must be 0 or 1 when set",
                ));
            }
        };
        Ok(Self {
            trace,
            file,
            #[cfg(feature = "path-io-diagnostics")]
            _io_trace: io_trace,
        })
    }

    pub fn record(&mut self, stage: Stage, epoch: u64, sequence: u64) {
        self.trace.record(stage, epoch, sequence);
    }

    pub fn invalidate(&mut self) {
        self.trace.invalid = true;
    }
}

impl Drop for FileTrace {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.trace.invalid = true;
        }
        let _ = self.trace.export(&mut self.file);
    }
}

impl Trace {
    pub fn new() -> io::Result<Self> {
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        let boot = boot.trim().to_owned();
        if boot.len() != 36 || !boot.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid boot identity",
            ));
        }
        let namespace = std::fs::metadata("/proc/self/ns/time")?;
        let mut events = Vec::new();
        events
            .try_reserve_exact(CAPACITY)
            .map_err(io::Error::other)?;
        Ok(Self {
            events,
            invalid: false,
            overflow: false,
            boot,
            namespace: (namespace.dev(), namespace.ino()),
            pid: std::process::id(),
        })
    }

    pub fn record(&mut self, stage: Stage, epoch: u64, sequence: u64) {
        self.record_at(stage, epoch, sequence, monotonic_ns().ok());
    }

    fn record_at(&mut self, stage: Stage, epoch: u64, sequence: u64, ns: Option<u64>) {
        let Some(ns) = ns else {
            self.invalid = true;
            return;
        };
        if self.events.last().is_some_and(|last| ns < last.ns) {
            self.invalid = true;
        }
        if self.events.len() == CAPACITY {
            self.overflow = true;
            self.invalid = true;
            return;
        }
        self.events.push(Event {
            stage,
            epoch,
            sequence,
            ns,
        });
    }

    /// Writes only after measurement. An export error invalidates the artifact.
    /// Clock equality requires matching boot and time-namespace identities.
    pub fn export(&self, mut out: impl Write) -> io::Result<()> {
        writeln!(out, "{{\"schema_version\":1,\"diagnostic_only\":true,\"clock\":\"CLOCK_MONOTONIC\",\"valid\":{},\"overflow\":{},\"pid\":{},\"boot_id\":\"{}\",\"namespace_dev\":{},\"namespace_ino\":{},\"events\":[", !self.invalid, self.overflow, self.pid, self.boot, self.namespace.0, self.namespace.1)?;
        for (index, event) in self.events.iter().enumerate() {
            writeln!(
                out,
                "{}{{\"stage\":\"{}\",\"epoch\":{},\"sequence\":{},\"time_ns\":{}}}",
                if index == 0 { "" } else { "," },
                event.stage.name(),
                event.epoch,
                event.sequence,
                event.ns
            )?;
        }
        writeln!(out, "]}}")
    }
}

fn monotonic_ns() -> io::Result<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is writable storage of the required size; the clock is fixed.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let seconds = u64::try_from(ts.tv_sec).ok();
    let nanos = u64::try_from(ts.tv_nsec)
        .ok()
        .filter(|n| *n < 1_000_000_000);
    seconds
        .zip(nanos)
        .and_then(|(s, n)| s.checked_mul(1_000_000_000)?.checked_add(n))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid clock"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_storage_and_overflow_are_explicit() {
        let mut trace = Trace::new().expect("trace");
        let storage = trace.events.as_ptr();
        for sequence in 0..CAPACITY as u64 {
            trace.record_at(Stage::ClientInputQueued, 3, sequence, Some(sequence));
        }
        assert!(!trace.invalid);
        trace.record_at(Stage::ClientInputQueued, 3, 0, Some(CAPACITY as u64));
        assert!(trace.invalid && trace.overflow);
        assert_eq!(trace.events.len(), CAPACITY);
        assert_eq!(trace.events.as_ptr(), storage);
    }

    #[test]
    fn failed_or_reversed_clock_is_sticky() {
        for bad in [None, Some(4)] {
            let mut trace = Trace::new().expect("trace");
            trace.record_at(Stage::GatewayInputAccepted, 2, 9, Some(5));
            trace.record_at(Stage::GatewayInputAccepted, 2, 10, bad);
            trace.record_at(Stage::GatewayInputAccepted, 2, 11, Some(6));
            assert!(trace.invalid);
            assert!(!trace.overflow);
        }
    }

    #[test]
    fn export_preserves_typed_boundary_and_clock_identity() {
        let mut trace = Trace::new().expect("trace");
        trace.record_at(Stage::ClientOutputAccepted, 2, 7, Some(99));
        let mut out = Vec::new();
        trace.export(&mut out).expect("export");
        let out = String::from_utf8(out).expect("utf8");
        assert!(out.contains("\"diagnostic_only\":true"));
        assert!(out.contains("\"valid\":true"));
        assert!(out.contains(
            "\"stage\":\"client_output_accepted\",\"epoch\":2,\"sequence\":7,\"time_ns\":99"
        ));
        assert!(out.contains(&trace.boot));
        assert!(out.ends_with("]}\n"));
    }
}
