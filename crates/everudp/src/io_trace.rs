//! Bounded, process-local noQ I/O diagnostics.
//!
//! This recorder is deliberately separate from the path trace.  The callback
//! executes synchronously on noQ's polling thread and therefore only performs
//! checked clock reads and atomic operations on preallocated slots. JSON is
//! produced during guard teardown, never from the callback.

use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::OnceLock;

const CAPACITY: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum Kind {
    UdpReceive = 1,
    ReceiveCopy,
    DriverPoll,
    DriverService,
    ProtocolTransmitStart,
    ProtocolTransmitReady,
    ProtocolTransmitIdle,
    TransmitPoll,
    TransmitAccepted,
    TransmitBlocked,
    TransmitError,
    StreamReadable,
    StdinReady = 13,
    StdinReadStart,
    StdinReadEnd,
    StdinData,
    StdinDispatch,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::UdpReceive => "udp_receive",
            Self::ReceiveCopy => "receive_copy",
            Self::DriverPoll => "driver_poll",
            Self::DriverService => "driver_service",
            Self::ProtocolTransmitStart => "protocol_transmit_start",
            Self::ProtocolTransmitReady => "protocol_transmit_ready",
            Self::ProtocolTransmitIdle => "protocol_transmit_idle",
            Self::TransmitPoll => "transmit_poll",
            Self::TransmitAccepted => "transmit_accepted",
            Self::TransmitBlocked => "transmit_blocked",
            Self::TransmitError => "transmit_error",
            Self::StreamReadable => "stream_readable",
            Self::StdinReady => "stdin_ready",
            Self::StdinReadStart => "stdin_read_start",
            Self::StdinReadEnd => "stdin_read_end",
            Self::StdinData => "stdin_data",
            Self::StdinDispatch => "stdin_dispatch",
        }
    }
}

/// Terminal-edge markers are diagnostic-only and carry no connection or stream
/// identity.  They use the same bounded recorder as noQ events, so recording a
/// marker never allocates, starts a task, or changes terminal behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TerminalStage {
    Ready,
    ReadStart,
    ReadEnd,
    Data,
    Dispatch,
}

impl TerminalStage {
    fn kind(self) -> Kind {
        match self {
            Self::Ready => Kind::StdinReady,
            Self::ReadStart => Kind::StdinReadStart,
            Self::ReadEnd => Kind::StdinReadEnd,
            Self::Data => Kind::StdinData,
            Self::Dispatch => Kind::StdinDispatch,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EventFields {
    kind: Kind,
    connection: Option<usize>,
    stream: Option<u64>,
}

struct Slot {
    published: AtomicBool,
    kind: AtomicU8,
    timestamp_ns: AtomicU64,
    connection: AtomicU64,
    stream: AtomicU64,
    has_connection: AtomicBool,
    has_stream: AtomicBool,
}

impl Slot {
    fn new() -> Self {
        Self {
            published: AtomicBool::new(false),
            kind: AtomicU8::new(0),
            timestamp_ns: AtomicU64::new(0),
            connection: AtomicU64::new(0),
            stream: AtomicU64::new(0),
            has_connection: AtomicBool::new(false),
            has_stream: AtomicBool::new(false),
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
    fn record(&self, event: EventFields) {
        self.record_with_clock(event, monotonic_ns);
    }

    #[cfg(test)]
    fn record_at(&self, event: EventFields, timestamp: Option<u64>) {
        self.record_with_clock(event, || timestamp);
    }

    #[inline]
    fn record_with_clock(&self, event: EventFields, clock: impl FnOnce() -> Option<u64>) {
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        if !self.active.load(Ordering::SeqCst) {
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            return;
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
        slot.kind.store(event.kind as u8, Ordering::Relaxed);
        slot.timestamp_ns.store(timestamp_ns, Ordering::Relaxed);
        if let Some(connection) = event.connection.and_then(|id| u64::try_from(id).ok()) {
            slot.connection.store(connection, Ordering::Relaxed);
            slot.has_connection.store(true, Ordering::Relaxed);
        }
        if let Some(stream) = event.stream {
            slot.stream.store(stream, Ordering::Relaxed);
            slot.has_stream.store(true, Ordering::Relaxed);
        }
        slot.published.store(true, Ordering::Release);
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
    }

    fn export(&self, mut out: impl Write) -> io::Result<()> {
        // Registration precedes the callback's active check and clock read.
        // Never wait for an outstanding callback: its artifact is invalid.
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
        for index in 0..count {
            let slot = &self.slots[index];
            if !slot.published.load(Ordering::Acquire) {
                valid = false;
                continue;
            }
            let kind = match slot.kind.load(Ordering::Relaxed) {
                1 => Kind::UdpReceive,
                2 => Kind::ReceiveCopy,
                3 => Kind::DriverPoll,
                4 => Kind::DriverService,
                5 => Kind::ProtocolTransmitStart,
                6 => Kind::ProtocolTransmitReady,
                7 => Kind::ProtocolTransmitIdle,
                8 => Kind::TransmitPoll,
                9 => Kind::TransmitAccepted,
                10 => Kind::TransmitBlocked,
                11 => Kind::TransmitError,
                12 => Kind::StreamReadable,
                13 => Kind::StdinReady,
                14 => Kind::StdinReadStart,
                15 => Kind::StdinReadEnd,
                16 => Kind::StdinData,
                17 => Kind::StdinDispatch,
                _ => {
                    valid = false;
                    continue;
                }
            };
            let timestamp = slot.timestamp_ns.load(Ordering::Relaxed);
            if previous.is_some_and(|last| timestamp < last) {
                valid = false;
            }
            previous = Some(timestamp);
            use std::fmt::Write as _;
            write!(
                events,
                "{}{{\"stage\":\"{}\",\"time_ns\":{},\"connection\":{},\"stream\":{}}}",
                if emitted == 0 { "" } else { "," },
                kind.name(),
                timestamp,
                if slot.has_connection.load(Ordering::Relaxed) {
                    slot.connection.load(Ordering::Relaxed).to_string()
                } else {
                    "null".to_owned()
                },
                if slot.has_stream.load(Ordering::Relaxed) {
                    slot.stream.load(Ordering::Relaxed).to_string()
                } else {
                    "null".to_owned()
                }
            )
            .map_err(io::Error::other)?;
            emitted += 1;
        }
        if !valid {
            self.invalid.store(true, Ordering::Release);
        }
        writeln!(
            out,
            "{{\"schema_version\":1,\"trace_kind\":\"quic_io\",\"diagnostic_only\":true,\"clock\":\"CLOCK_MONOTONIC\",\"valid\":{},\"overflow\":{},\"pid\":{},\"boot_id\":\"{}\",\"namespace_dev\":{},\"namespace_ino\":{},\"events\":[{}]}}",
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

/// Record a terminal-edge marker when the bounded diagnostic recorder is
/// active.  Terminal markers intentionally have null connection and stream
/// fields: they describe local stdin handling, not a QUIC event.
pub(crate) fn record_terminal(stage: TerminalStage) {
    let Some(recorder) = ACTIVE.get() else {
        return;
    };
    recorder.record(EventFields {
        kind: stage.kind(),
        connection: None,
        stream: None,
    });
}

fn callback(event: noq::diagnostic::Event) {
    #[cfg(feature = "path-packet-diagnostics")]
    crate::packet_trace::record_runtime(event);
    let Some(recorder) = ACTIVE.get() else {
        return;
    };
    let fields = match event {
        noq::diagnostic::Event::UdpReceive => EventFields {
            kind: Kind::UdpReceive,
            connection: None,
            stream: None,
        },
        noq::diagnostic::Event::ReceiveCopy => EventFields {
            kind: Kind::ReceiveCopy,
            connection: None,
            stream: None,
        },
        noq::diagnostic::Event::DriverPoll => EventFields {
            kind: Kind::DriverPoll,
            connection: None,
            stream: None,
        },
        noq::diagnostic::Event::TransmitPoll => EventFields {
            kind: Kind::TransmitPoll,
            connection: None,
            stream: None,
        },
        noq::diagnostic::Event::TransmitAccepted => EventFields {
            kind: Kind::TransmitAccepted,
            connection: None,
            stream: None,
        },
        noq::diagnostic::Event::TransmitBlocked => EventFields {
            kind: Kind::TransmitBlocked,
            connection: None,
            stream: None,
        },
        noq::diagnostic::Event::TransmitError => EventFields {
            kind: Kind::TransmitError,
            connection: None,
            stream: None,
        },
        noq::diagnostic::Event::DriverService { connection } => EventFields {
            kind: Kind::DriverService,
            connection: Some(connection),
            stream: None,
        },
        noq::diagnostic::Event::ProtocolTransmitStart { connection } => EventFields {
            kind: Kind::ProtocolTransmitStart,
            connection: Some(connection),
            stream: None,
        },
        noq::diagnostic::Event::ProtocolTransmitReady { connection } => EventFields {
            kind: Kind::ProtocolTransmitReady,
            connection: Some(connection),
            stream: None,
        },
        noq::diagnostic::Event::ProtocolTransmitIdle { connection } => EventFields {
            kind: Kind::ProtocolTransmitIdle,
            connection: Some(connection),
            stream: None,
        },
        noq::diagnostic::Event::StreamReadable { connection, stream } => EventFields {
            kind: Kind::StreamReadable,
            connection: Some(connection),
            stream: Some(stream),
        },
        _ => return,
    };
    recorder.record(fields);
}

pub(crate) struct Guard {
    recorder: &'static Recorder,
    file: std::fs::File,
    #[cfg(feature = "path-packet-diagnostics")]
    _packet_trace: crate::packet_trace::Guard,
}

impl Guard {
    pub(crate) fn create(path: &Path) -> io::Result<Self> {
        if ACTIVE.get().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "I/O trace already active",
            ));
        }
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(".io.json");
        let sidecar = PathBuf::from(sidecar);
        let mut file = std::fs::File::from(everpty::sys::create_exclusive_private(&sidecar)?);
        if ACTIVE.set(Recorder::with_capacity(CAPACITY)?).is_err() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "I/O trace already active",
            ));
        }
        let recorder = ACTIVE.get().expect("recorder installed");
        #[cfg(feature = "path-packet-diagnostics")]
        let packet_trace = match crate::packet_trace::Guard::create(path) {
            Ok(guard) => guard,
            Err(error) => {
                recorder.invalid.store(true, Ordering::Release);
                let _ = recorder.export(&mut file);
                return Err(error);
            }
        };
        if let Err(error) = noq::diagnostic::install(callback) {
            #[cfg(feature = "path-packet-diagnostics")]
            crate::packet_trace::invalidate();
            recorder.invalid.store(true, Ordering::Release);
            recorder.active.store(false, Ordering::SeqCst);
            let _ = recorder.export(&mut file);
            return Err(io::Error::other(format!(
                "diagnostic install failed: {error:?}"
            )));
        }
        Ok(Self {
            recorder,
            file,
            #[cfg(feature = "path-packet-diagnostics")]
            _packet_trace: packet_trace,
        })
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.recorder.invalid.store(true, Ordering::Release);
        }
        let _ = self.recorder.export(&mut self.file);
    }
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

    // The only test in this executable that activates the process-global hook.
    // Other recorder tests use independent instances, not ACTIVE.
    #[test]
    fn guard_owns_private_sidecar_and_activation_is_one_shot() {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("everudp-io-guard-{}-{unique}", std::process::id()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .expect("private directory");
        let occupied = root.join("occupied.io.json");
        std::fs::write(&occupied, b"preserve").expect("existing sidecar");
        assert!(Guard::create(&root.join("occupied")).is_err());
        assert_eq!(
            std::fs::read(&occupied).expect("existing bytes"),
            b"preserve"
        );
        assert!(
            ACTIVE.get().is_none(),
            "failed file creation installed recorder"
        );

        let base = root.join("client.json");
        let sidecar = root.join("client.json.io.json");
        let guard = Guard::create(&base).expect("guard");
        assert_eq!(
            std::fs::metadata(&sidecar)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        callback(noq::diagnostic::Event::StreamReadable {
            connection: 7,
            stream: 2,
        });
        #[cfg(feature = "path-packet-diagnostics")]
        callback(noq::diagnostic::Event::PacketTransmit {
            connection: 7,
            cookie: 11,
            bytes: 128,
            segment_size: None,
            outcome: noq::diagnostic::TransmitOutcome::Accepted,
        });
        assert!(Guard::create(&root.join("second")).is_err());
        assert!(!root.join("second.io.json").exists());
        drop(guard);
        let exported = std::fs::read_to_string(&sidecar).expect("sidecar export");
        assert!(exported.contains("\"trace_kind\":\"quic_io\""));
        assert!(exported.contains("\"valid\":true"));
        assert!(exported.contains("\"stage\":\"stream_readable\""));
        assert!(exported.contains("\"connection\":7,\"stream\":2"));
        assert!(Guard::create(&base).is_err());
        let recorder = ACTIVE.get().expect("recorder");
        let count = recorder.next.load(Ordering::Acquire);
        callback(noq::diagnostic::Event::DriverPoll);
        assert_eq!(count, recorder.next.load(Ordering::Acquire));
        assert_eq!(
            exported,
            std::fs::read_to_string(&sidecar).expect("unchanged export")
        );

        std::fs::remove_file(&occupied).expect("remove owned fixture");
        std::fs::remove_file(&sidecar).expect("remove owned sidecar");
        #[cfg(feature = "path-packet-diagnostics")]
        {
            let packets = root.join("client.json.packets.json");
            assert_eq!(
                std::fs::metadata(&packets)
                    .expect("packet metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            let text = std::fs::read_to_string(&packets).expect("packet export");
            assert!(text.contains("\"trace_kind\":\"quic_packets\""));
            assert!(text.contains("\"event\":\"packet_transmit_accepted\""));
            assert!(text.contains("\"values\":[7,11,128,0]"));
            std::fs::remove_file(packets).expect("remove owned packet sidecar");
        }
        std::fs::remove_dir(&root).expect("remove empty owned directory");
    }

    #[test]
    fn bounded_storage_and_optional_ids_export() {
        let recorder = Recorder::with_capacity(2).expect("recorder");
        recorder.record(EventFields {
            kind: Kind::DriverPoll,
            connection: None,
            stream: None,
        });
        recorder.record(EventFields {
            kind: Kind::StreamReadable,
            connection: Some(4),
            stream: Some(7),
        });
        let mut out = Vec::new();
        recorder.export(&mut out).expect("export");
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("\"stage\":\"driver_poll\""));
        assert!(text.contains("\"connection\":4,\"stream\":7"));
        assert!(!text.contains("payload"));
    }

    #[test]
    fn terminal_stages_export_with_null_ids() {
        let recorder = Recorder::with_capacity(5).expect("recorder");
        for stage in [
            TerminalStage::Ready,
            TerminalStage::ReadStart,
            TerminalStage::ReadEnd,
            TerminalStage::Data,
            TerminalStage::Dispatch,
        ] {
            recorder.record(EventFields {
                kind: stage.kind(),
                connection: None,
                stream: None,
            });
        }
        let mut out = Vec::new();
        recorder.export(&mut out).expect("export");
        let text = String::from_utf8(out).expect("utf8");
        for name in [
            "stdin_ready",
            "stdin_read_start",
            "stdin_read_end",
            "stdin_data",
            "stdin_dispatch",
        ] {
            assert!(text.contains(&format!("\"stage\":\"{name}\"")));
        }
        assert_eq!(
            text.matches("\"connection\":null,\"stream\":null").count(),
            5
        );
    }

    #[test]
    fn overflow_and_unpublished_slots_invalidate() {
        let recorder = Recorder::with_capacity(1).expect("recorder");
        recorder.record(EventFields {
            kind: Kind::DriverPoll,
            connection: None,
            stream: None,
        });
        recorder.record(EventFields {
            kind: Kind::DriverPoll,
            connection: None,
            stream: None,
        });
        assert!(recorder.overflow.load(Ordering::Acquire));
        let mut out = Vec::new();
        recorder.export(&mut out).expect("export");
        assert!(String::from_utf8(out)
            .expect("utf8")
            .contains("\"valid\":false"));
    }

    #[test]
    fn clock_failure_is_sticky() {
        let recorder = Recorder::with_capacity(2).expect("recorder");
        recorder.record_at(
            EventFields {
                kind: Kind::DriverPoll,
                connection: None,
                stream: None,
            },
            None,
        );
        assert!(recorder.invalid.load(Ordering::Acquire));
    }

    #[test]
    fn unpublished_reserved_slot_invalidates_export() {
        let recorder = Recorder::with_capacity(1).expect("recorder");
        assert_eq!(recorder.next.fetch_add(1, Ordering::Relaxed), 0);
        let mut out = Vec::new();
        recorder.export(&mut out).expect("export");
        assert!(String::from_utf8(out)
            .expect("utf8")
            .contains("\"valid\":false"));
    }

    #[test]
    fn in_flight_before_reservation_invalidates_export() {
        let recorder = Recorder::with_capacity(1).expect("recorder");
        recorder.in_flight.store(1, Ordering::SeqCst);
        let mut out = Vec::new();
        recorder.export(&mut out).expect("export");
        assert!(String::from_utf8(out)
            .expect("utf8")
            .contains("\"valid\":false"));
        assert!(recorder.invalid.load(Ordering::Acquire));
    }

    #[test]
    fn regressed_clock_and_publication_gap_stay_invalid() {
        let event = EventFields {
            kind: Kind::DriverPoll,
            connection: None,
            stream: None,
        };
        for timestamps in [[Some(2), Some(1)], [None, Some(1)]] {
            let recorder = Recorder::with_capacity(2).expect("recorder");
            let storage = recorder.slots.as_ptr();
            for timestamp in timestamps {
                recorder.record_at(event, timestamp);
            }
            assert_eq!(storage, recorder.slots.as_ptr());
            let mut out = Vec::new();
            recorder.export(&mut out).expect("export");
            let text = String::from_utf8(out).expect("utf8");
            assert!(text.contains("\"valid\":false"));
            assert!(!text.contains("\"events\":[,"));
            assert!(recorder.invalid.load(Ordering::Acquire));
            recorder.record_with_clock(event, || panic!("stopped recorder sampled clock"));
        }
    }
}
