//! Bounded, opt-in timing trace for the authenticated floor diagnostic.
//!
//! This recorder intentionally contains only stage names, process-relative
//! monotonic timestamps, optional sequence numbers and scoped thread-CPU
//! timestamps. CPU samples include recorder/clock overhead and are taken
//! separately from wall samples; they are not exact descheduling measurements.
//! It must not capture
//! terminal bytes, credentials, addresses, or arbitrary caller strings.  The
//! successful hot `record` path uses the capacity reserved by [`Trace::new`] and does not
//! allocate after construction.

#[cfg(feature = "floor-diagnostics")]
use super::floor_resources::ResourceSnapshot;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Instant;

/// Fixed vocabulary used by floor latency traces.
///
/// Keeping this as an enum prevents a trace caller from accidentally putting
/// payloads or secrets in the evidence file.  The serialized spelling is part
/// of the small diagnostic JSON schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceStage {
    #[cfg(feature = "floor-diagnostics")]
    UdpReceive,
    #[cfg(feature = "floor-diagnostics")]
    ReceiveCopy,
    #[cfg(feature = "floor-diagnostics")]
    DriverPoll,
    #[cfg(feature = "floor-diagnostics")]
    DriverService,
    #[cfg(feature = "floor-diagnostics")]
    InlineCallbackEnter,
    #[cfg(feature = "floor-diagnostics")]
    InlineCallbackExit,
    #[cfg(feature = "floor-diagnostics")]
    InlineResponseQueued,
    #[cfg(feature = "floor-diagnostics")]
    InlineResponseBlocked,
    #[cfg(feature = "floor-diagnostics")]
    InlineDriverWakeRequested,
    #[cfg(feature = "floor-diagnostics")]
    TransmitPoll,
    #[cfg(feature = "floor-diagnostics")]
    TransmitAccepted,
    #[cfg(feature = "floor-diagnostics")]
    TransmitBlocked,
    #[cfg(feature = "floor-diagnostics")]
    TransmitError,
    #[cfg(feature = "floor-diagnostics")]
    ProtocolTransmitStart,
    #[cfg(feature = "floor-diagnostics")]
    ProtocolTransmitReady,
    #[cfg(feature = "floor-diagnostics")]
    ProtocolTransmitIdle,
    BootstrapStart,
    BootstrapComplete,
    TerminalRead,
    ProtocolOffer,
    WireEncoded,
    CallbackEnter,
    CallbackExit,
    WireDecoded,
    SinkAccepted,
    Retry,
    BufferBlocked,
}

impl TraceStage {
    /// Stable, allocation-free spelling for the JSON schema.
    pub const fn as_str(self) -> &'static str {
        match self {
            #[cfg(feature = "floor-diagnostics")]
            Self::UdpReceive => "udp_receive_poll_ready",
            #[cfg(feature = "floor-diagnostics")]
            Self::ReceiveCopy => "udp_receive_copy_complete",
            #[cfg(feature = "floor-diagnostics")]
            Self::DriverPoll => "connection_driver_poll",
            #[cfg(feature = "floor-diagnostics")]
            Self::DriverService => "connection_driver_service",
            #[cfg(feature = "floor-diagnostics")]
            Self::InlineCallbackEnter => "inline_callback_enter",
            #[cfg(feature = "floor-diagnostics")]
            Self::InlineCallbackExit => "inline_callback_exit",
            #[cfg(feature = "floor-diagnostics")]
            Self::InlineResponseQueued => "inline_response_queued",
            #[cfg(feature = "floor-diagnostics")]
            Self::InlineResponseBlocked => "inline_response_blocked",
            #[cfg(feature = "floor-diagnostics")]
            Self::InlineDriverWakeRequested => "inline_driver_wake_requested",
            #[cfg(feature = "floor-diagnostics")]
            Self::TransmitPoll => "udp_send_poll",
            #[cfg(feature = "floor-diagnostics")]
            Self::TransmitAccepted => "udp_send_poll_accepted",
            #[cfg(feature = "floor-diagnostics")]
            Self::TransmitBlocked => "udp_send_poll_blocked",
            #[cfg(feature = "floor-diagnostics")]
            Self::TransmitError => "udp_send_poll_error",
            #[cfg(feature = "floor-diagnostics")]
            Self::ProtocolTransmitStart => "protocol_transmit_start",
            #[cfg(feature = "floor-diagnostics")]
            Self::ProtocolTransmitReady => "protocol_transmit_ready",
            #[cfg(feature = "floor-diagnostics")]
            Self::ProtocolTransmitIdle => "protocol_transmit_idle",
            Self::BootstrapStart => "bootstrap_start",
            Self::BootstrapComplete => "bootstrap_complete",
            Self::TerminalRead => "terminal_read",
            Self::ProtocolOffer => "protocol_offer",
            Self::WireEncoded => "wire_encoded",
            Self::CallbackEnter => "callback_enter",
            Self::CallbackExit => "callback_exit",
            Self::WireDecoded => "wire_decoded",
            Self::SinkAccepted => "sink_accepted",
            Self::Retry => "retry",
            Self::BufferBlocked => "buffer_blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TraceEvent {
    elapsed_ns: u64,
    stage: TraceStage,
    sequence: Option<u64>,
    connection: Option<usize>,
    thread: std::thread::ThreadId,
    allocation_requests: Option<(u64, u64)>,
    thread_cpu_ns: Option<u64>,
}

struct TraceState {
    events: Vec<TraceEvent>,
    limit: usize,
    overflow: bool,
    valid: bool,
}

/// A fixed-capacity timing recorder suitable for an opt-in floor run.
pub struct Trace {
    started: Instant,
    pid: u32,
    capacity: usize,
    state: Mutex<TraceState>,
    contention: AtomicBool,
    #[cfg(feature = "floor-diagnostics")]
    resource_start: Mutex<Option<(u64, ResourceSnapshot)>>,
    #[cfg(feature = "floor-diagnostics")]
    resource_failed: AtomicBool,
    #[cfg(feature = "floor-diagnostics")]
    clock_calibration: Option<(
        std::thread::ThreadId,
        [u64; super::floor_resources::CPU_CLOCK_CALIBRATION_SAMPLES],
    )>,
    #[cfg(feature = "floor-diagnostics")]
    clock_origin: Option<(
        super::floor_resources::ClockAnchor,
        super::floor_resources::ClockIdentity,
    )>,
}

impl Trace {
    /// Construct a recorder with space for at most `capacity` events.
    ///
    /// All event storage is reserved here so [`Trace::record`] does not need
    /// to allocate.  A zero-capacity recorder is valid and records only its
    /// sticky overflow status.
    pub fn new(capacity: usize) -> Self {
        #[cfg(feature = "floor-diagnostics")]
        let calibration = super::floor_resources::calibrate_thread_clock()
            .ok()
            .map(|samples| (std::thread::current().id(), samples));
        #[cfg(feature = "floor-diagnostics")]
        let valid = calibration.is_some();
        #[cfg(not(feature = "floor-diagnostics"))]
        let valid = true;
        #[cfg(feature = "floor-diagnostics")]
        let clock_origin = super::floor_resources::clock_identity()
            .ok()
            .and_then(|identity| {
                super::floor_resources::clock_anchor()
                    .ok()
                    .map(|anchor| (anchor, identity))
            });
        #[cfg(feature = "floor-diagnostics")]
        let started = clock_origin
            .as_ref()
            .map_or_else(Instant::now, |(anchor, _)| anchor.instant);
        #[cfg(not(feature = "floor-diagnostics"))]
        let started = Instant::now();
        Self {
            started,
            pid: std::process::id(),
            capacity,
            contention: AtomicBool::new(false),
            #[cfg(feature = "floor-diagnostics")]
            resource_start: Mutex::new(None),
            #[cfg(feature = "floor-diagnostics")]
            resource_failed: AtomicBool::new(false),
            #[cfg(feature = "floor-diagnostics")]
            clock_calibration: calibration,
            #[cfg(feature = "floor-diagnostics")]
            clock_origin,
            state: Mutex::new(TraceState {
                events: Vec::with_capacity(capacity),
                limit: capacity,
                overflow: false,
                valid,
            }),
        }
    }

    /// Startup/export only; no extra clock call on the event recorder path.
    #[cfg(feature = "floor-diagnostics")]
    fn clock_alignment_json(&self) -> String {
        let invalid = || "{\"valid\":false}".to_owned();
        let Some((start, identity)) = &self.clock_origin else {
            return invalid();
        };
        let Ok(end_identity) = super::floor_resources::clock_identity() else {
            return invalid();
        };
        if *identity != end_identity {
            return invalid();
        }
        let Ok(end) = super::floor_resources::clock_anchor() else {
            return invalid();
        };
        let Some(elapsed) = end.instant.checked_duration_since(start.instant) else {
            return invalid();
        };
        let Ok(elapsed_ns) = u64::try_from(elapsed.as_nanos()) else {
            return invalid();
        };
        let Some(end_lower) = end.lower_ns.checked_sub(elapsed_ns) else {
            return invalid();
        };
        let Some(end_upper) = end.upper_ns.checked_sub(elapsed_ns) else {
            return invalid();
        };
        // Diagnostic resolution budget, not a latency gate. Wide sampling
        // brackets cannot resolve the local handoff and must remain unavailable.
        if start
            .upper_ns
            .checked_sub(start.lower_ns)
            .is_none_or(|width| width > 10_000)
            || end.upper_ns - end.lower_ns > 10_000
            || start.lower_ns.max(end_lower) > start.upper_ns.min(end_upper)
        {
            return invalid();
        }
        format!("{{\"valid\":true,\"clock\":\"CLOCK_MONOTONIC\",\"identity\":{{\"boot_id\":\"{}\",\"time_namespace_dev\":{},\"time_namespace_ino\":{}}},\"start\":{{\"elapsed_ns\":0,\"lower_ns\":{},\"upper_ns\":{}}},\"end\":{{\"elapsed_ns\":{elapsed_ns},\"lower_ns\":{},\"upper_ns\":{}}}}}", identity.boot_id, identity.time_namespace_dev, identity.time_namespace_ino, start.lower_ns, start.upper_ns, end.lower_ns, end.upper_ns)
    }

    /// Begin a process-only resource window after warmup. Retransmitted
    /// warmup responses do not restart it. Never called per measured event.
    #[cfg(feature = "floor-diagnostics")]
    pub fn start_resources(&self) {
        let Ok(mut start) = self.resource_start.try_lock() else {
            self.resource_failed.store(true, Ordering::Relaxed);
            return;
        };
        if start.is_none() {
            match ResourceSnapshot::capture() {
                Ok(snapshot) => {
                    *start = Some((
                        self.started
                            .elapsed()
                            .as_nanos()
                            .try_into()
                            .unwrap_or(u64::MAX),
                        snapshot,
                    ));
                }
                Err(_) => self.resource_failed.store(true, Ordering::Relaxed),
            }
        }
    }

    #[cfg(feature = "floor-diagnostics")]
    fn resource_json(&self) -> String {
        let invalid = || "{\"valid\":false}".to_owned();
        if self.resource_failed.load(Ordering::Relaxed) {
            return invalid();
        }
        let Ok(start) = self.resource_start.lock() else {
            return invalid();
        };
        let Some((started_ns, before)) = *start else {
            return "null".to_owned();
        };
        let Ok(after) = ResourceSnapshot::capture() else {
            return invalid();
        };
        let finished_ns: u64 = self
            .started
            .elapsed()
            .as_nanos()
            .try_into()
            .unwrap_or(u64::MAX);
        let Ok(delta) = after.delta_since(before) else {
            return invalid();
        };
        // Formatting happens after the end snapshot, outside the measured
        // resource window. RSS is a lifetime high-water value, not a delta.
        format!("{{\"valid\":true,\"scope\":\"RUSAGE_SELF\",\"window\":\"after-warmup-to-export\",\"started_elapsed_ns\":{started_ns},\"finished_elapsed_ns\":{finished_ns},\"user_cpu_ns\":{},\"system_cpu_ns\":{},\"voluntary_context_switches\":{},\"involuntary_context_switches\":{},\"lifetime_max_rss_kib\":{}}}", delta.user_cpu_ns, delta.system_cpu_ns, delta.voluntary_context_switches, delta.involuntary_context_switches, delta.max_rss_kib)
    }

    /// Record one typed stage marker.
    ///
    /// If the fixed buffer is full, the event is dropped and `overflow` is
    /// permanently set.  A poisoned mutex is treated as invalid evidence and
    /// never causes a panic.
    pub fn record(&self, stage: TraceStage, sequence: Option<u64>) {
        self.record_context(stage, sequence, None);
    }

    /// Process-local noQ connection identity, never a payload sequence or a
    /// cross-process packet identifier.
    #[cfg(feature = "floor-diagnostics")]
    pub fn record_connection(&self, stage: TraceStage, connection: usize) {
        self.record_context(stage, None, Some(connection));
    }

    fn record_context(&self, stage: TraceStage, sequence: Option<u64>, connection: Option<usize>) {
        let elapsed_ns = self
            .started
            .elapsed()
            .as_nanos()
            .try_into()
            .unwrap_or(u64::MAX);

        match self.state.try_lock() {
            Ok(mut state) => record_locked(&mut state, elapsed_ns, stage, sequence, connection),
            Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                let mut state = poisoned.into_inner();
                state.valid = false;
                record_locked(&mut state, elapsed_ns, stage, sequence, connection);
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                self.contention.store(true, Ordering::Relaxed);
            }
        }
    }

    /// Write the trace JSON object to `writer`.
    ///
    /// The output uses only the standard library and a fixed vocabulary of
    /// stage strings.  If the recorder mutex was poisoned, the object is
    /// emitted with `valid:false` so consumers fail closed.
    pub fn write_json(&self, writer: impl Write) -> io::Result<()> {
        let mut writer = writer;
        #[cfg(feature = "floor-diagnostics")]
        let resources = self.resource_json();
        #[cfg(not(feature = "floor-diagnostics"))]
        let resources = "null";
        #[cfg(feature = "floor-diagnostics")]
        let calibration = match &self.clock_calibration {
            Some((thread, samples)) => format!("{{\"clock\":\"CLOCK_THREAD_CPUTIME_ID\",\"method\":\"back-to-back-thread-clock-read-deltas\",\"thread\":\"{thread:?}\",\"samples_ns\":{samples:?}}}"),
            None => "null".to_owned(),
        };
        #[cfg(not(feature = "floor-diagnostics"))]
        let calibration = "null";
        #[cfg(feature = "floor-diagnostics")]
        let alignment = self.clock_alignment_json();
        #[cfg(not(feature = "floor-diagnostics"))]
        let alignment = "null";
        #[cfg(feature = "floor-diagnostics")]
        let metadata = (resources.as_str(), calibration.as_str(), alignment.as_str());
        #[cfg(not(feature = "floor-diagnostics"))]
        let metadata = (resources, calibration, alignment);
        match self.state.lock() {
            Ok(state) => write_locked(
                &mut writer,
                self.pid,
                self.capacity,
                state.overflow,
                state.valid && !self.contention.load(Ordering::Relaxed),
                &state.events,
                metadata,
            ),
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                state.valid = false;
                write_locked(
                    &mut writer,
                    self.pid,
                    self.capacity,
                    state.overflow,
                    state.valid,
                    &state.events,
                    metadata,
                )
            }
        }
    }
}

fn record_locked(
    state: &mut TraceState,
    elapsed_ns: u64,
    stage: TraceStage,
    sequence: Option<u64>,
    connection: Option<usize>,
) {
    if state.events.len() >= state.limit {
        state.overflow = true;
        state.valid = false;
        return;
    }
    #[cfg(feature = "floor-diagnostics")]
    let allocation_requests = {
        let (calls, bytes, overflow) = super::floor_alloc::snapshot();
        state.valid &= !overflow;
        Some((calls, bytes))
    };
    #[cfg(not(feature = "floor-diagnostics"))]
    let allocation_requests = None;
    #[cfg(feature = "floor-diagnostics")]
    let thread_cpu_ns = if matches!(
        stage,
        TraceStage::TransmitPoll
            | TraceStage::TransmitAccepted
            | TraceStage::TransmitBlocked
            | TraceStage::TransmitError
            | TraceStage::ProtocolTransmitStart
            | TraceStage::ProtocolTransmitReady
            | TraceStage::ProtocolTransmitIdle
    ) {
        cpu_sample(state, super::floor_resources::thread_cpu_ns())
    } else {
        None
    };
    #[cfg(not(feature = "floor-diagnostics"))]
    let thread_cpu_ns = None;
    state.events.push(TraceEvent {
        elapsed_ns,
        stage,
        sequence,
        connection,
        thread: std::thread::current().id(),
        allocation_requests,
        thread_cpu_ns,
    });
}

#[cfg(feature = "floor-diagnostics")]
fn cpu_sample(state: &mut TraceState, sample: io::Result<u64>) -> Option<u64> {
    match sample {
        Ok(value) => Some(value),
        Err(_) => {
            state.valid = false;
            None
        }
    }
}

fn write_locked(
    writer: &mut impl Write,
    pid: u32,
    capacity: usize,
    overflow: bool,
    valid: bool,
    events: &[TraceEvent],
    metadata: (&str, &str, &str),
) -> io::Result<()> {
    let (resources, calibration, alignment) = metadata;
    write!(
        writer,
        "{{\"schema_version\":1,\"clock_domain\":\"process-relative-monotonic\",\"pid\":{},\"overflow\":{},\"valid\":{},\"capacity\":{},\"resource_window\":{resources},\"cpu_clock_calibration\":{calibration},\"clock_alignment\":{alignment},\"events\":[",
        pid,
        overflow,
        valid,
        capacity
    )?;

    for (index, event) in events.iter().enumerate() {
        if index != 0 {
            writer.write_all(b",")?;
        }
        write!(
            writer,
            "{{\"elapsed_ns\":{},\"stage\":\"{}\"",
            event.elapsed_ns,
            event.stage.as_str()
        )?;
        match event.sequence {
            Some(sequence) => write!(writer, ",\"sequence\":{}", sequence)?,
            None => writer.write_all(b",\"sequence\":null")?,
        }
        match event.connection {
            Some(connection) => write!(writer, ",\"connection\":{connection}")?,
            None => writer.write_all(b",\"connection\":null")?,
        }
        match event.thread_cpu_ns {
            Some(value) => write!(writer, ",\"thread_cpu_ns\":{value}")?,
            None => writer.write_all(b",\"thread_cpu_ns\":null")?,
        }
        write!(
            writer,
            ",\"thread\":\"{:?}\",\"rust_allocation_requests\":",
            event.thread
        )?;
        match event.allocation_requests {
            Some((calls, bytes)) => {
                write!(writer, "{{\"calls\":{calls},\"requested_bytes\":{bytes}}}")?
            }
            None => writer.write_all(b"null")?,
        }
        writer.write_all(b"}")?;
    }
    writer.write_all(b"]}")
}

#[cfg(test)]
mod tests {
    use super::{Trace, TraceStage};
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::Arc;
    use std::thread;

    #[cfg(feature = "floor-diagnostics")]
    #[test]
    fn clock_alignment_rejects_missing_identity_and_drift() {
        let mut trace = Trace::new(1);
        let original = trace.clock_origin.clone();
        trace.clock_origin = None;
        assert_eq!(trace.clock_alignment_json(), "{\"valid\":false}");
        trace.clock_origin = original;
        let saved = trace.clock_origin.clone();
        let (start, _) = trace.clock_origin.as_mut().unwrap();
        start.upper_ns = start.lower_ns + 10_001;
        assert_eq!(trace.clock_alignment_json(), "{\"valid\":false}");
        trace.clock_origin = saved;
        let (_, identity) = trace.clock_origin.as_mut().unwrap();
        identity.time_namespace_ino ^= 1;
        assert_eq!(trace.clock_alignment_json(), "{\"valid\":false}");
        identity_restore_and_drift(&mut trace);
    }

    #[cfg(feature = "floor-diagnostics")]
    fn identity_restore_and_drift(trace: &mut Trace) {
        let (start, identity) = trace.clock_origin.as_mut().unwrap();
        identity.time_namespace_ino ^= 1;
        start.lower_ns += 1_000_000_000;
        start.upper_ns += 1_000_000_000;
        assert_eq!(trace.clock_alignment_json(), "{\"valid\":false}");
    }

    fn json(trace: &Trace) -> String {
        let mut bytes = Vec::new();
        trace.write_json(&mut bytes).expect("write trace JSON");
        String::from_utf8(bytes).expect("UTF-8 trace JSON")
    }

    #[test]
    fn serializes_typed_events_without_payload_fields() {
        let trace = Trace::new(2);
        trace.record(TraceStage::ProtocolOffer, Some(7));
        trace.record(TraceStage::SinkAccepted, None);
        let output = json(&trace);
        assert!(output.contains("\"clock_domain\":\"process-relative-monotonic\""));
        assert!(output.contains("\"stage\":\"protocol_offer\""));
        assert!(output.contains("\"stage\":\"sink_accepted\""));
        assert!(output.contains("\"sequence\":7"));
        assert!(output.contains("\"sequence\":null"));
        assert!(!output.contains("payload"));
        assert!(!output.contains("secret"));
    }

    #[cfg(all(feature = "floor-diagnostics", target_os = "linux"))]
    #[test]
    fn sender_boundaries_capture_thread_cpu_only_for_scoped_stages() {
        let trace = Trace::new(3);
        trace.record(TraceStage::TransmitPoll, None);
        trace.record(TraceStage::TransmitAccepted, None);
        trace.record(TraceStage::ProtocolOffer, Some(1));
        let output = json(&trace);
        assert_eq!(output.matches("\"thread_cpu_ns\":").count(), 3);
        assert_eq!(output.matches("\"thread_cpu_ns\":null").count(), 1);
        assert!(output.contains("\"valid\":true"));
        assert!(output.contains("\"cpu_clock_calibration\":{\"clock\":\"CLOCK_THREAD_CPUTIME_ID\""));
        assert!(output.contains("\"method\":\"back-to-back-thread-clock-read-deltas\""));
    }

    #[cfg(feature = "floor-diagnostics")]
    #[test]
    fn cpu_clock_failure_invalidates_trace_permanently() {
        let trace = Trace::new(1);
        {
            let mut state = trace.state.lock().unwrap();
            assert_eq!(
                super::cpu_sample(&mut state, Err(std::io::ErrorKind::Unsupported.into())),
                None
            );
            assert_eq!(super::cpu_sample(&mut state, Ok(1)), Some(1));
            assert!(!state.valid);
        }
        assert!(json(&trace).contains("\"valid\":false"));
    }

    #[test]
    fn overflow_is_bounded_and_sticky() {
        let trace = Trace::new(1);
        trace.record(TraceStage::CallbackEnter, Some(1));
        trace.record(TraceStage::CallbackExit, Some(2));
        trace.record(TraceStage::Retry, Some(3));
        let output = json(&trace);
        assert!(output.contains("\"overflow\":true"));
        assert!(output.contains("\"valid\":false"));
        assert_eq!(output.matches("\"stage\"").count(), 1);
        assert!(output.contains("\"sequence\":1"));
        assert!(!output.contains("\"sequence\":2"));
    }

    #[test]
    fn zero_capacity_records_no_events() {
        let trace = Trace::new(0);
        trace.record(TraceStage::BufferBlocked, None);
        let output = json(&trace);
        assert!(output.contains("\"capacity\":0"));
        assert!(output.contains("\"overflow\":true"));
        assert!(output.contains("\"valid\":false"));
        assert!(output.ends_with("\"events\":[]}"));
    }

    #[test]
    fn poisoned_lock_fails_closed_without_panicking() {
        let trace = Arc::new(Trace::new(4));
        let poisoned = Arc::clone(&trace);
        let _ = catch_unwind(AssertUnwindSafe(move || {
            let _guard = poisoned.state.lock().expect("lock");
            panic!("poison test");
        }));
        trace.record(TraceStage::CallbackExit, None);
        let output = json(&trace);
        assert!(output.contains("\"valid\":false"));
    }

    #[test]
    fn concurrent_recording_stays_within_capacity() {
        let trace = Arc::new(Trace::new(32));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let trace = Arc::clone(&trace);
            handles.push(thread::spawn(move || {
                for _ in 0..32 {
                    trace.record(TraceStage::CallbackEnter, None);
                }
            }));
        }
        for handle in handles {
            handle.join().expect("recording thread");
        }
        let output = json(&trace);
        assert!(output.contains("\"valid\":false"));
        assert!(output.matches("\"stage\"").count() <= 32);
    }

    #[test]
    fn contention_never_blocks_and_invalidates_capture() {
        let trace = Trace::new(4);
        let guard = trace.state.lock().expect("hold recorder");
        trace.record(TraceStage::CallbackEnter, None);
        drop(guard);
        let output = json(&trace);
        assert!(output.contains("\"valid\":false"));
        assert!(!output.contains("\"stage\""));
    }

    #[cfg(all(feature = "floor-diagnostics", target_os = "linux"))]
    #[test]
    fn resources_start_once_and_report_explicit_window() {
        let trace = Trace::new(4);
        assert!(json(&trace).contains("\"resource_window\":null"));
        trace.start_resources();
        let first = *trace.resource_start.lock().expect("start");
        trace.start_resources();
        assert_eq!(*trace.resource_start.lock().expect("start"), first);
        let output = json(&trace);
        assert!(output.contains("\"window\":\"after-warmup-to-export\""));
        assert!(output.contains("\"scope\":\"RUSAGE_SELF\""));
        assert!(output.contains("\"lifetime_max_rss_kib\":"));
    }

    #[cfg(feature = "floor-diagnostics")]
    #[test]
    fn resource_contention_invalidates_resource_window() {
        let trace = Trace::new(4);
        let guard = trace.resource_start.lock().expect("hold resource start");
        trace.start_resources();
        drop(guard);
        assert!(json(&trace).contains("\"resource_window\":{\"valid\":false}"));
    }
}
