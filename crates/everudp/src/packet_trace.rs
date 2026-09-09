//! Bounded packet/stream correlation diagnostics.
//!
//! This recorder is deliberately independent from [`super::io_trace`].  noQ
//! has one process-wide callback for each diagnostic family, so installing the
//! packet callback never replaces the I/O callback.  The callback does only a
//! checked monotonic clock read and atomic stores into a fixed set of slots;
//! JSON is assembled after measurement.
//!
//! The `values` array has a fixed meaning for each event (and contains no
//! payload, address, credential, key, or wire timestamp):
//!
//! * `packet_transmit_*`: `[connection, cookie, bytes, segment_size]`;
//! * `datagram_received`: `[cookie, bytes]`;
//! * `packet_built`/`packet_authenticated`: `[connection, cookie, packet_number,
//!   number_space, packet_offset, packet_len, direction]`;
//! * `packet_protection_start`/`packet_protection_end`: `[connection, cookie,
//!   packet_number, number_space, direction]`;
//! * `packet_frames_start`/`packet_frames_end`: `[connection, cookie,
//!   packet_number, number_space, direction]`;
//! * `stream_sent`/`stream_received`: `[connection, cookie, packet_number,
//!   number_space, stream, offset, length, fin]`;
//! * `unsupported_path`: `[connection, cookie, path]`;
//! * `operation`: `[connection, stream, epoch, sequence, kind, offset, len]`;
//! * `packet_trace_invalid`: `[]`.
//!
//! Number-space values are Initial=1, Handshake=2, Data=3; direction is
//! Send=1 and Receive=2.  `segment_size == 0` means that no GSO size was
//! supplied.  An unrepresentable value, clock failure, missing publication,
//! callback overflow, or an unknown packet-protocol variant invalidates the
//! artifact.  Older runtime timing events are intentionally ignored.

use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::OnceLock;

const CAPACITY: usize = 65_536;
const MAX_VALUES: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum Kind {
    PacketTransmitPoll = 1,
    PacketTransmitBlocked,
    PacketTransmitError,
    PacketTransmitAccepted,
    DatagramReceived,
    PacketTraceInvalid,
    PacketBuilt,
    PacketAuthenticated,
    UnsupportedPath,
    StreamSent,
    StreamReceived,
    Operation,
    PacketProtectionStart,
    PacketProtectionEnd,
    PacketFramesStart,
    PacketFramesEnd,
}

impl Kind {
    fn value_count(self) -> usize {
        match self {
            Self::PacketTransmitPoll
            | Self::PacketTransmitBlocked
            | Self::PacketTransmitError
            | Self::PacketTransmitAccepted => 4,
            Self::DatagramReceived => 2,
            Self::PacketTraceInvalid => 0,
            Self::PacketBuilt | Self::PacketAuthenticated | Self::Operation => 7,
            Self::PacketProtectionStart | Self::PacketProtectionEnd => 5,
            Self::PacketFramesStart | Self::PacketFramesEnd => 5,
            Self::UnsupportedPath => 3,
            Self::StreamSent | Self::StreamReceived => 8,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::PacketTransmitPoll => "packet_transmit_poll",
            Self::PacketTransmitBlocked => "packet_transmit_blocked",
            Self::PacketTransmitError => "packet_transmit_error",
            Self::PacketTransmitAccepted => "packet_transmit_accepted",
            Self::DatagramReceived => "datagram_received",
            Self::PacketTraceInvalid => "packet_trace_invalid",
            Self::PacketBuilt => "packet_built",
            Self::PacketAuthenticated => "packet_authenticated",
            Self::UnsupportedPath => "unsupported_path",
            Self::StreamSent => "stream_sent",
            Self::StreamReceived => "stream_received",
            Self::Operation => "operation",
            Self::PacketProtectionStart => "packet_protection_start",
            Self::PacketProtectionEnd => "packet_protection_end",
            Self::PacketFramesStart => "packet_frames_start",
            Self::PacketFramesEnd => "packet_frames_end",
        }
    }

    fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::PacketTransmitPoll,
            2 => Self::PacketTransmitBlocked,
            3 => Self::PacketTransmitError,
            4 => Self::PacketTransmitAccepted,
            5 => Self::DatagramReceived,
            6 => Self::PacketTraceInvalid,
            7 => Self::PacketBuilt,
            8 => Self::PacketAuthenticated,
            9 => Self::UnsupportedPath,
            10 => Self::StreamSent,
            11 => Self::StreamReceived,
            12 => Self::Operation,
            13 => Self::PacketProtectionStart,
            14 => Self::PacketProtectionEnd,
            15 => Self::PacketFramesStart,
            16 => Self::PacketFramesEnd,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Operation {
    pub connection: usize,
    pub stream: u64,
    pub epoch: u64,
    pub sequence: u64,
    pub kind: u8,
    pub offset: u64,
    pub len: u64,
}

struct Slot {
    published: AtomicBool,
    kind: AtomicU8,
    timestamp_ns: AtomicU64,
    value_len: AtomicU8,
    values: [AtomicU64; MAX_VALUES],
}

impl Slot {
    fn new() -> Self {
        Self {
            published: AtomicBool::new(false),
            kind: AtomicU8::new(0),
            timestamp_ns: AtomicU64::new(0),
            value_len: AtomicU8::new(0),
            values: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

struct Recorder {
    slots: Vec<Slot>,
    next: AtomicUsize,
    in_flight: AtomicUsize,
    active: AtomicBool,
    invalid: AtomicBool,
    overflow: AtomicBool,
    boot_id: String,
    namespace: (u64, u64),
    pid: u32,
}

impl Recorder {
    fn with_capacity(capacity: usize) -> io::Result<Self> {
        if capacity == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "zero capacity"));
        }
        let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .to_owned();
        if boot_id.len() != 36
            || !boot_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid boot identity",
            ));
        }
        let namespace = std::fs::metadata("/proc/self/ns/time")?;
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(capacity)
            .map_err(io::Error::other)?;
        slots.resize_with(capacity, Slot::new);
        Ok(Self {
            slots,
            next: AtomicUsize::new(0),
            in_flight: AtomicUsize::new(0),
            active: AtomicBool::new(true),
            invalid: AtomicBool::new(false),
            overflow: AtomicBool::new(false),
            boot_id,
            namespace: (namespace.dev(), namespace.ino()),
            pid: std::process::id(),
        })
    }

    #[inline]
    fn record(&self, kind: Kind, values: &[u64]) {
        self.record_with_clock(kind, values, monotonic_ns);
    }

    #[cfg(test)]
    fn record_at(&self, kind: Kind, values: &[u64], timestamp: Option<u64>) {
        self.record_with_clock(kind, values, || timestamp);
    }

    #[inline]
    fn record_with_clock(&self, kind: Kind, values: &[u64], clock: impl FnOnce() -> Option<u64>) {
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        if !self.active.load(Ordering::SeqCst) {
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            return;
        }
        if values.len() != kind.value_count() {
            self.invalid.store(true, Ordering::Relaxed);
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            return;
        }
        if matches!(kind, Kind::UnsupportedPath | Kind::PacketTraceInvalid) {
            self.invalidate();
        }
        let index = self.next.fetch_add(1, Ordering::Relaxed);
        let Some(slot) = self.slots.get(index) else {
            self.overflow.store(true, Ordering::Relaxed);
            self.invalid.store(true, Ordering::Relaxed);
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            return;
        };
        let Some(timestamp_ns) = clock() else {
            self.invalid.store(true, Ordering::Relaxed);
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            return;
        };
        slot.kind.store(kind as u8, Ordering::Relaxed);
        slot.timestamp_ns.store(timestamp_ns, Ordering::Relaxed);
        slot.value_len.store(values.len() as u8, Ordering::Relaxed);
        for (index, value) in values.iter().copied().enumerate() {
            slot.values[index].store(value, Ordering::Relaxed);
        }
        slot.published.store(true, Ordering::Release);
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
    }

    fn invalidate(&self) {
        self.invalid.store(true, Ordering::Release);
    }

    fn export(&self, mut out: impl Write) -> io::Result<()> {
        self.active.store(false, Ordering::SeqCst);
        if self.in_flight.load(Ordering::SeqCst) != 0 {
            self.invalid.store(true, Ordering::Release);
        }
        let count = self.next.load(Ordering::Acquire).min(self.slots.len());
        let mut valid =
            !self.invalid.load(Ordering::Acquire) && !self.overflow.load(Ordering::Acquire);
        let mut events = String::new();
        let mut previous = None;
        let mut emitted = 0usize;
        for slot in self.slots.iter().take(count) {
            if !slot.published.load(Ordering::Acquire) {
                valid = false;
                continue;
            }
            let Some(kind) = Kind::from_u8(slot.kind.load(Ordering::Relaxed)) else {
                valid = false;
                continue;
            };
            let timestamp = slot.timestamp_ns.load(Ordering::Relaxed);
            if previous.is_some_and(|last| timestamp < last) {
                valid = false;
            }
            previous = Some(timestamp);
            let value_len = usize::from(slot.value_len.load(Ordering::Relaxed));
            if value_len != kind.value_count() {
                valid = false;
                continue;
            }
            use std::fmt::Write as _;
            write!(
                events,
                "{}{{\"event\":\"{}\",\"time_ns\":{},\"values\":[",
                if emitted == 0 { "" } else { "," },
                kind.name(),
                timestamp
            )
            .map_err(io::Error::other)?;
            for (index, value) in slot.values.iter().take(value_len).enumerate() {
                write!(
                    events,
                    "{}{}",
                    if index == 0 { "" } else { "," },
                    value.load(Ordering::Relaxed)
                )
                .map_err(io::Error::other)?;
            }
            events.push_str("]}");
            emitted += 1;
        }
        if !valid {
            self.invalid.store(true, Ordering::Release);
        }
        writeln!(
            out,
            "{{\"schema_version\":1,\"trace_kind\":\"quic_packets\",\"diagnostic_only\":true,\"clock\":\"CLOCK_MONOTONIC\",\"valid\":{},\"overflow\":{},\"pid\":{},\"boot_id\":\"{}\",\"namespace_dev\":{},\"namespace_ino\":{},\"events\":[{}]}}",
            valid,
            self.overflow.load(Ordering::Acquire),
            self.pid,
            self.boot_id,
            self.namespace.0,
            self.namespace.1,
            events
        )
    }
}

static ACTIVE: OnceLock<Recorder> = OnceLock::new();

/// Invalidate a recording without altering terminal delivery behavior.
pub(crate) fn invalidate() {
    if let Some(recorder) = ACTIVE.get() {
        recorder.invalidate();
    }
}

/// Forward a noQ runtime diagnostic event to the active packet recorder.
pub(crate) fn record_runtime(event: noq::diagnostic::Event) {
    let Some(recorder) = ACTIVE.get() else {
        return;
    };
    runtime_event(recorder, event);
}

fn runtime_event(recorder: &Recorder, event: noq::diagnostic::Event) {
    use noq::diagnostic::{Event, TransmitOutcome};
    match event {
        Event::DatagramReceived { cookie, bytes } => {
            let Some(bytes) = u64::try_from(bytes).ok() else {
                recorder.invalidate();
                return;
            };
            recorder.record(Kind::DatagramReceived, &[cookie, bytes]);
        }
        Event::PacketTransmit {
            connection,
            cookie,
            bytes,
            segment_size,
            outcome,
        } => {
            let (Some(connection), Some(bytes), Some(segment_size)) = (
                u64::try_from(connection).ok(),
                u64::try_from(bytes).ok(),
                segment_size.map_or(Some(0), |value| u64::try_from(value).ok()),
            ) else {
                recorder.invalidate();
                return;
            };
            let kind = match outcome {
                TransmitOutcome::Poll => Kind::PacketTransmitPoll,
                TransmitOutcome::Blocked => Kind::PacketTransmitBlocked,
                TransmitOutcome::Error => Kind::PacketTransmitError,
                TransmitOutcome::Accepted => Kind::PacketTransmitAccepted,
            };
            recorder.record(kind, &[connection, cookie, bytes, segment_size]);
        }
        Event::PacketTraceInvalid => recorder.record(Kind::PacketTraceInvalid, &[]),
        // These are intentionally owned by io_trace, or are old runtime
        // timing markers with no packet identity.
        Event::UdpReceive
        | Event::ReceiveCopy
        | Event::DriverPoll
        | Event::DriverService { .. }
        | Event::InlineCallbackEnter { .. }
        | Event::InlineCallbackExit { .. }
        | Event::InlineResponseQueued { .. }
        | Event::InlineResponseBlocked { .. }
        | Event::InlineDriverWakeRequested { .. }
        | Event::TransmitPoll
        | Event::ProtocolTransmitStart { .. }
        | Event::ProtocolTransmitReady { .. }
        | Event::ProtocolTransmitIdle { .. }
        | Event::TransmitAccepted
        | Event::TransmitBlocked
        | Event::TransmitError
        | Event::StreamReadable { .. } => {}
        _ => recorder.invalidate(),
    }
}

/// Record an application operation against the eventual QUIC stream range.
pub(crate) fn record_operation(operation: Operation) {
    let Some(recorder) = ACTIVE.get() else {
        return;
    };
    let Some(connection) = u64::try_from(operation.connection).ok() else {
        recorder.invalidate();
        return;
    };
    recorder.record(
        Kind::Operation,
        &[
            connection,
            operation.stream,
            operation.epoch,
            operation.sequence,
            u64::from(operation.kind),
            operation.offset,
            operation.len,
        ],
    );
}

pub(crate) struct Guard {
    recorder: &'static Recorder,
    file: std::fs::File,
}

impl Guard {
    pub(crate) fn create(path: &Path) -> io::Result<Self> {
        if ACTIVE.get().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "packet trace already active",
            ));
        }
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(".packets.json");
        let sidecar = PathBuf::from(sidecar);
        let mut file = std::fs::File::from(everpty::sys::create_exclusive_private(&sidecar)?);
        if ACTIVE.set(Recorder::with_capacity(CAPACITY)?).is_err() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "packet trace already active",
            ));
        }
        let recorder = ACTIVE.get().expect("recorder installed");
        if let Err(error) = noq::packet_diagnostic::install(record_proto) {
            recorder.invalidate();
            let _ = recorder.export(&mut file);
            return Err(io::Error::other(format!(
                "packet diagnostic install failed: {error:?}"
            )));
        }
        Ok(Self { recorder, file })
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.recorder.invalidate();
        }
        let _ = self.recorder.export(&mut self.file);
    }
}

fn record_proto(event: noq::packet_diagnostic::Event) {
    let Some(recorder) = ACTIVE.get() else {
        return;
    };
    proto_event(recorder, event);
}

fn proto_event(recorder: &Recorder, event: noq::packet_diagnostic::Event) {
    use noq::packet_diagnostic::{Direction, Event, NumberSpace};
    let number_space = |space: NumberSpace| match space {
        NumberSpace::Initial => 1,
        NumberSpace::Handshake => 2,
        NumberSpace::Data => 3,
    };
    let direction = |value: Direction| match value {
        Direction::Send => 1,
        Direction::Receive => 2,
    };
    match event {
        Event::PacketBuilt {
            context,
            packet_number,
            number_space: space,
            packet_offset,
            packet_len,
        } => {
            let (Some(connection), Some(offset), Some(len)) = (
                u64::try_from(context.connection).ok(),
                u64::try_from(packet_offset).ok(),
                u64::try_from(packet_len).ok(),
            ) else {
                recorder.invalidate();
                return;
            };
            recorder.record(
                Kind::PacketBuilt,
                &[
                    connection,
                    context.cookie,
                    packet_number,
                    number_space(space),
                    offset,
                    len,
                    direction(context.direction),
                ],
            );
        }
        Event::PacketAuthenticated {
            context,
            packet_number,
            number_space: space,
            packet_offset,
            packet_len,
        } => {
            let (Some(connection), Some(offset), Some(len)) = (
                u64::try_from(context.connection).ok(),
                u64::try_from(packet_offset).ok(),
                u64::try_from(packet_len).ok(),
            ) else {
                recorder.invalidate();
                return;
            };
            recorder.record(
                Kind::PacketAuthenticated,
                &[
                    connection,
                    context.cookie,
                    packet_number,
                    number_space(space),
                    offset,
                    len,
                    direction(context.direction),
                ],
            );
        }
        Event::PacketProtection {
            context,
            packet_number,
            number_space: space,
            started,
        } => {
            let Some(connection) = u64::try_from(context.connection).ok() else {
                recorder.invalidate();
                return;
            };
            let kind = if started {
                Kind::PacketProtectionStart
            } else {
                Kind::PacketProtectionEnd
            };
            recorder.record(
                kind,
                &[
                    connection,
                    context.cookie,
                    packet_number,
                    number_space(space),
                    direction(context.direction),
                ],
            );
        }
        Event::PacketFrames {
            context,
            packet_number,
            number_space: space,
            started,
        } => {
            let Some(connection) = u64::try_from(context.connection).ok() else {
                recorder.invalidate();
                return;
            };
            let kind = if started {
                Kind::PacketFramesStart
            } else {
                Kind::PacketFramesEnd
            };
            recorder.record(
                kind,
                &[
                    connection,
                    context.cookie,
                    packet_number,
                    number_space(space),
                    direction(context.direction),
                ],
            );
        }
        Event::UnsupportedPath { context, path } => recorder.record(
            Kind::UnsupportedPath,
            &[
                u64::try_from(context.connection).unwrap_or_else(|_| {
                    recorder.invalidate();
                    0
                }),
                context.cookie,
                u64::from(path),
            ],
        ),
        event @ Event::StreamSent { .. } => record_stream(recorder, Kind::StreamSent, event),
        event @ Event::StreamReceived { .. } => {
            record_stream(recorder, Kind::StreamReceived, event)
        }
        _ => recorder.invalidate(),
    }
}

fn record_stream(recorder: &Recorder, kind: Kind, event: noq::packet_diagnostic::Event) {
    use noq::packet_diagnostic::Event;
    let (context, packet_number, space, stream, offset, length, fin) = match event {
        Event::StreamSent {
            context,
            packet_number,
            number_space,
            stream,
            offset,
            length,
            fin,
        }
        | Event::StreamReceived {
            context,
            packet_number,
            number_space,
            stream,
            offset,
            length,
            fin,
        } => (
            context,
            packet_number,
            number_space,
            stream,
            offset,
            length,
            fin,
        ),
        _ => {
            recorder.invalidate();
            return;
        }
    };
    let Some(connection) = u64::try_from(context.connection).ok() else {
        recorder.invalidate();
        return;
    };
    recorder.record(
        kind,
        &[
            connection,
            context.cookie,
            packet_number,
            match space {
                noq::packet_diagnostic::NumberSpace::Initial => 1,
                noq::packet_diagnostic::NumberSpace::Handshake => 2,
                noq::packet_diagnostic::NumberSpace::Data => 3,
            },
            stream,
            offset,
            length,
            if fin { 1 } else { 0 },
        ],
    );
}

fn monotonic_ns() -> Option<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } != 0 {
        return None;
    }
    let seconds = u64::try_from(ts.tv_sec).ok()?;
    let nanos = u64::try_from(ts.tv_nsec)
        .ok()
        .filter(|n| *n < 1_000_000_000)?;
    seconds.checked_mul(1_000_000_000)?.checked_add(nanos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_mapping_is_explicit_and_bounded() {
        let recorder = Recorder::with_capacity(3).expect("recorder");
        recorder.record_at(Kind::PacketTransmitAccepted, &[4, 8, 1200, 0], Some(10));
        recorder.record_at(Kind::StreamReceived, &[4, 8, 9, 3, 7, 11, 13, 1], Some(11));
        recorder.record_at(Kind::Operation, &[4, 7, 2, 19, 1, 11, 13], Some(12));
        let mut output = Vec::new();
        recorder.export(&mut output).expect("export");
        let text = String::from_utf8(output).expect("utf8");
        assert!(text.contains("\"trace_kind\":\"quic_packets\""));
        assert!(text.contains("\"event\":\"packet_transmit_accepted\""));
        assert!(text.contains("\"event\":\"stream_received\""));
        assert!(text.contains("\"event\":\"operation\""));
        assert!(text.contains("\"values\":[4,7,2,19,1,11,13]"));
        assert!(text.contains("\"valid\":true"));
    }

    #[test]
    fn overflow_and_unpublished_slots_invalidate() {
        let recorder = Recorder::with_capacity(1).expect("recorder");
        recorder.record_at(Kind::DatagramReceived, &[1, 2], Some(1));
        recorder.record_at(Kind::DatagramReceived, &[3, 4], Some(2));
        assert!(recorder.overflow.load(Ordering::Acquire));
        let mut output = Vec::new();
        recorder.export(&mut output).expect("export");
        assert!(String::from_utf8(output)
            .expect("utf8")
            .contains("\"valid\":false"));

        let recorder = Recorder::with_capacity(1).expect("recorder");
        recorder.record_at(Kind::DatagramReceived, &[1, 2], Some(1));
        recorder.slots[0].published.store(false, Ordering::Release);
        let mut output = Vec::new();
        recorder.export(&mut output).expect("export");
        assert!(String::from_utf8(output)
            .expect("utf8")
            .contains("\"valid\":false"));
    }

    #[test]
    fn timestamp_regression_invalidates() {
        let recorder = Recorder::with_capacity(2).expect("recorder");
        recorder.record_at(Kind::DatagramReceived, &[1, 2], Some(20));
        recorder.record_at(Kind::DatagramReceived, &[3, 4], Some(19));
        let mut output = Vec::new();
        recorder.export(&mut output).expect("export");
        assert!(String::from_utf8(output)
            .expect("utf8")
            .contains("\"valid\":false"));
    }

    #[test]
    fn runtime_invalid_and_unsupported_path_mark_artifacts_invalid() {
        let recorder = Recorder::with_capacity(2).expect("recorder");
        runtime_event(&recorder, noq::diagnostic::Event::PacketTraceInvalid);
        assert!(recorder.invalid.load(Ordering::Acquire));
        let recorder = Recorder::with_capacity(2).expect("recorder");
        proto_event(
            &recorder,
            noq::packet_diagnostic::Event::UnsupportedPath {
                context: noq::packet_diagnostic::Context {
                    connection: 2,
                    cookie: 3,
                    direction: noq::packet_diagnostic::Direction::Receive,
                },
                path: 1,
            },
        );
        assert!(recorder.invalid.load(Ordering::Acquire));
    }

    #[test]
    fn callbacks_preserve_packet_and_stream_field_order() {
        let recorder = Recorder::with_capacity(3).expect("recorder");
        runtime_event(
            &recorder,
            noq::diagnostic::Event::PacketTransmit {
                connection: 1,
                cookie: 2,
                bytes: 1200,
                segment_size: Some(600),
                outcome: noq::diagnostic::TransmitOutcome::Accepted,
            },
        );
        proto_event(
            &recorder,
            noq::packet_diagnostic::Event::StreamReceived {
                context: noq::packet_diagnostic::Context {
                    connection: 3,
                    cookie: 4,
                    direction: noq::packet_diagnostic::Direction::Receive,
                },
                packet_number: 5,
                number_space: noq::packet_diagnostic::NumberSpace::Data,
                stream: 2,
                offset: 6,
                length: 7,
                fin: true,
            },
        );
        let mut output = Vec::new();
        recorder.export(&mut output).expect("export");
        let text = String::from_utf8(output).expect("utf8");
        assert!(text.contains("\"values\":[1,2,1200,600]"));
        assert!(text.contains("\"values\":[3,4,5,3,2,6,7,1]"));
        assert!(text.contains("\"valid\":true"));
    }

    #[test]
    fn packet_protection_callbacks_preserve_phase_and_field_order() {
        let recorder = Recorder::with_capacity(2).expect("recorder");
        let context = noq::packet_diagnostic::Context {
            connection: 6,
            cookie: 9,
            direction: noq::packet_diagnostic::Direction::Send,
        };
        proto_event(
            &recorder,
            noq::packet_diagnostic::Event::PacketProtection {
                context,
                packet_number: 12,
                number_space: noq::packet_diagnostic::NumberSpace::Data,
                started: true,
            },
        );
        proto_event(
            &recorder,
            noq::packet_diagnostic::Event::PacketProtection {
                context,
                packet_number: 12,
                number_space: noq::packet_diagnostic::NumberSpace::Data,
                started: false,
            },
        );
        let mut output = Vec::new();
        recorder.export(&mut output).expect("export");
        let text = String::from_utf8(output).expect("utf8");
        assert!(text.contains("\"event\":\"packet_protection_start\",\"time_ns\":"));
        assert!(text.contains("\"event\":\"packet_protection_end\",\"time_ns\":"));
        assert_eq!(text.matches("\"values\":[6,9,12,3,1]").count(), 2);
        assert!(text.contains("\"valid\":true"));
    }

    #[test]
    fn packet_frames_callbacks_preserve_phase_and_field_order() {
        let recorder = Recorder::with_capacity(2).expect("recorder");
        let context = noq::packet_diagnostic::Context {
            connection: 6,
            cookie: 9,
            direction: noq::packet_diagnostic::Direction::Send,
        };
        proto_event(
            &recorder,
            noq::packet_diagnostic::Event::PacketFrames {
                context,
                packet_number: 12,
                number_space: noq::packet_diagnostic::NumberSpace::Data,
                started: true,
            },
        );
        proto_event(
            &recorder,
            noq::packet_diagnostic::Event::PacketFrames {
                context,
                packet_number: 12,
                number_space: noq::packet_diagnostic::NumberSpace::Data,
                started: false,
            },
        );
        let mut output = Vec::new();
        recorder.export(&mut output).expect("export");
        let text = String::from_utf8(output).expect("utf8");
        assert!(text.contains("\"event\":\"packet_frames_start\",\"time_ns\":"));
        assert!(text.contains("\"event\":\"packet_frames_end\",\"time_ns\":"));
        assert_eq!(text.matches("\"values\":[6,9,12,3,1]").count(), 2);
        assert!(text.contains("\"valid\":true"));
    }
}
