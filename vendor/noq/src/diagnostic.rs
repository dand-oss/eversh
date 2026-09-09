//! Opt-in, process-local timing hooks for noQ I/O attribution.
//!
//! This module is diagnostic-only. Events contain no packet data, addresses,
//! credentials, or other wire information, and are not part of noQ's
//! transport behavior or protocol API. The hook is disabled at compile time
//! unless the `diagnostic-events` feature is enabled.
//!
//! Install at most one callback for the process with [`install`]. The callback
//! runs synchronously on the runtime thread polling noQ. It must not block,
//! panic, or call back into noQ (including through another thread that waits
//! for the callback), because most events occur while a connection state lock
//! is held. `DriverPoll` is emitted at the poll entry immediately before lock
//! acquisition, while `DriverService` is emitted after the connection state
//! lock has been acquired. Events describe userspace poll boundaries; in
//! particular, `Transmit*` events do not mean that a packet reached the kernel
//! or wire.

use std::sync::OnceLock;

/// Result of a userspace UDP send poll, never a wire timestamp.
#[cfg(feature = "packet-diagnostics")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransmitOutcome {
    /// About to call the UDP sender.
    Poll,
    /// Sender retained no acceptance; the same cookie will be retried.
    Blocked,
    /// Sender returned an error.
    Error,
    /// Sender accepted the entire transmit at its userspace boundary.
    Accepted,
}

#[cfg(feature = "packet-diagnostics")]
pub(crate) fn next_packet_cookie() -> Option<u64> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    take_packet_cookie(&NEXT, Ordering::Relaxed)
}

#[cfg(feature = "packet-diagnostics")]
fn take_packet_cookie(
    next: &std::sync::atomic::AtomicU64,
    order: std::sync::atomic::Ordering,
) -> Option<u64> {
    next.fetch_update(order, order, |value| value.checked_add(1))
        .ok()
}

/// A noQ runtime boundary useful for diagnosing userspace latency.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Event {
    /// One received UDP segment is ready for endpoint processing, after the
    /// socket poll and owned-buffer copy. This is not kernel arrival time.
    #[cfg(feature = "packet-diagnostics")]
    DatagramReceived {
        /// Process-unique segment cookie, before a connection is identified.
        cookie: u64,
        /// Complete encrypted segment size, before protocol processing.
        bytes: usize,
    },
    /// Correlated userspace send boundary. A cookie identifies one complete
    /// transmit buffer, which may contain coalesced packets and GSO segments.
    /// It is retained across blocked polls, not regenerated on retry.
    #[cfg(feature = "packet-diagnostics")]
    PacketTransmit {
        /// Local connection handle, not a wire connection ID.
        connection: usize,
        /// Process-unique nonzero transmit identity.
        cookie: u64,
        /// Total bytes in the transmit buffer.
        bytes: usize,
        /// GSO segment size when applicable.
        segment_size: Option<usize>,
        /// Outcome at the userspace sender boundary.
        outcome: TransmitOutcome,
    },
    /// Cookie exhaustion makes packet correlation invalid; delivery continues.
    #[cfg(feature = "packet-diagnostics")]
    PacketTraceInvalid,
    /// The UDP socket returned successfully from a receive poll.
    UdpReceive,
    /// An owned receive buffer was copied for protocol processing.
    ReceiveCopy,
    /// A connection driver entered its poll method.
    DriverPoll,
    /// A reliable stream became protocol-readable immediately before noQ
    /// attempts to wake a blocked reader (there may be no registered waker).
    /// The stream identifier is the local QUIC stream id; this does not imply
    /// that an application task ran. Fresh-stream `Opened` events are separate,
    /// and this marker is not a one-to-one record of application reads.
    #[cfg(feature = "diagnostic-events")]
    StreamReadable {
        /// The local noQ connection handle.
        connection: usize,
        /// The local QUIC stream identifier.
        stream: u64,
    },
    /// A connection driver began servicing a connection after acquiring its
    /// state lock. The identifier is the local noQ connection handle, not a
    /// wire or application-level sequence number.
    #[cfg(feature = "diagnostic-events")]
    DriverService {
        /// The local noQ connection handle.
        connection: usize,
    },
    /// An inline application callback is about to run.
    #[cfg(feature = "diagnostic-events")]
    InlineCallbackEnter {
        /// The local noQ connection handle.
        connection: usize,
    },
    /// An inline application callback returned.
    #[cfg(feature = "diagnostic-events")]
    InlineCallbackExit {
        /// The local noQ connection handle.
        connection: usize,
    },
    /// An inline callback response was accepted into the connection's
    /// datagram send queue.
    #[cfg(feature = "diagnostic-events")]
    InlineResponseQueued {
        /// The local noQ connection handle.
        connection: usize,
    },
    /// An inline callback response could not yet be queued and was retained
    /// for a later driver pass.
    #[cfg(feature = "diagnostic-events")]
    InlineResponseBlocked {
        /// The local noQ connection handle.
        connection: usize,
    },
    /// The endpoint requested that the connection driver be woken. This is a
    /// request marker, not confirmation that a task actually ran.
    #[cfg(feature = "diagnostic-events")]
    InlineDriverWakeRequested {
        /// The local noQ connection handle.
        connection: usize,
    },
    /// A connection is about to poll its UDP sender.
    TransmitPoll,
    /// A connection is about to invoke the protocol's transmit poll.
    #[cfg(feature = "diagnostic-events")]
    ProtocolTransmitStart {
        /// The local noQ connection handle.
        connection: usize,
    },
    /// The protocol's transmit poll produced a datagram.
    #[cfg(feature = "diagnostic-events")]
    ProtocolTransmitReady {
        /// The local noQ connection handle.
        connection: usize,
    },
    /// The protocol's transmit poll had no datagram ready.
    #[cfg(feature = "diagnostic-events")]
    ProtocolTransmitIdle {
        /// The local noQ connection handle.
        connection: usize,
    },
    /// The UDP sender accepted a transmit from the userspace poll boundary.
    TransmitAccepted,
    /// The UDP sender reported that a transmit would block.
    TransmitBlocked,
    /// The UDP sender returned an I/O error for a transmit.
    TransmitError,
}

/// Error returned when another diagnostic callback is already installed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallError {
    /// The process-wide callback was already set.
    AlreadyInstalled,
}

static CALLBACK: OnceLock<fn(Event)> = OnceLock::new();

/// Install the process-wide diagnostic callback.
///
/// Installation is one-shot and thread-safe. The callback is invoked
/// synchronously on noQ's runtime polling thread, and must not block, panic,
/// or re-enter noQ. Calling this function a second time returns
/// [`InstallError::AlreadyInstalled`].
pub fn install(callback: fn(Event)) -> Result<(), InstallError> {
    CALLBACK
        .set(callback)
        .map_err(|_| InstallError::AlreadyInstalled)
}

/// Emit an event when a callback has been installed.
#[inline]
pub(crate) fn emit(event: Event) {
    if let Some(callback) = CALLBACK.get().copied() {
        callback(event);
    }
}

#[cfg(test)]
mod tests {
    use super::{Event, InstallError, emit, install};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[cfg(feature = "packet-diagnostics")]
    #[test]
    fn packet_cookie_exhaustion_never_wraps_or_reuses() {
        use std::sync::atomic::AtomicU64;
        let next = AtomicU64::new(u64::MAX - 1);
        assert_eq!(
            super::take_packet_cookie(&next, Ordering::Relaxed),
            Some(u64::MAX - 1)
        );
        assert_eq!(super::take_packet_cookie(&next, Ordering::Relaxed), None);
        assert_eq!(super::take_packet_cookie(&next, Ordering::Relaxed), None);
        assert_eq!(next.load(Ordering::Relaxed), u64::MAX);
    }

    static DRIVER_POLLS: AtomicUsize = AtomicUsize::new(0);
    #[cfg(feature = "diagnostic-events")]
    static DRIVER_SERVICES: AtomicUsize = AtomicUsize::new(0);
    #[cfg(feature = "diagnostic-events")]
    static PROTOCOL_TRANSMIT_STARTS: AtomicUsize = AtomicUsize::new(0);
    #[cfg(feature = "diagnostic-events")]
    static PROTOCOL_TRANSMIT_READIES: AtomicUsize = AtomicUsize::new(0);
    #[cfg(feature = "diagnostic-events")]
    static PROTOCOL_TRANSMIT_IDLES: AtomicUsize = AtomicUsize::new(0);

    fn record(event: Event) {
        match event {
            Event::DriverPoll => {
                DRIVER_POLLS.fetch_add(1, Ordering::Relaxed);
            }
            #[cfg(feature = "diagnostic-events")]
            Event::DriverService { .. } => {
                DRIVER_SERVICES.fetch_add(1, Ordering::Relaxed);
            }
            #[cfg(feature = "diagnostic-events")]
            Event::ProtocolTransmitStart { .. } => {
                PROTOCOL_TRANSMIT_STARTS.fetch_add(1, Ordering::Relaxed);
            }
            #[cfg(feature = "diagnostic-events")]
            Event::ProtocolTransmitReady { .. } => {
                PROTOCOL_TRANSMIT_READIES.fetch_add(1, Ordering::Relaxed);
            }
            #[cfg(feature = "diagnostic-events")]
            Event::ProtocolTransmitIdle { .. } => {
                PROTOCOL_TRANSMIT_IDLES.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    #[test]
    fn install_is_one_shot_and_emits() {
        assert_eq!(install(record), Ok(()));
        assert_eq!(install(record), Err(InstallError::AlreadyInstalled));
        let before = DRIVER_POLLS.load(Ordering::Relaxed);
        emit(Event::DriverPoll);
        // Other connection tests may emit concurrently after installation.
        assert!(DRIVER_POLLS.load(Ordering::Relaxed) > before);
        #[cfg(feature = "diagnostic-events")]
        {
            let before = DRIVER_SERVICES.load(Ordering::Relaxed);
            emit(Event::DriverService { connection: 7 });
            assert!(DRIVER_SERVICES.load(Ordering::Relaxed) > before);
            let starts = PROTOCOL_TRANSMIT_STARTS.load(Ordering::Relaxed);
            let readies = PROTOCOL_TRANSMIT_READIES.load(Ordering::Relaxed);
            let idles = PROTOCOL_TRANSMIT_IDLES.load(Ordering::Relaxed);
            emit(Event::ProtocolTransmitStart { connection: 7 });
            emit(Event::ProtocolTransmitReady { connection: 7 });
            emit(Event::ProtocolTransmitIdle { connection: 7 });
            assert!(PROTOCOL_TRANSMIT_STARTS.load(Ordering::Relaxed) > starts);
            assert!(PROTOCOL_TRANSMIT_READIES.load(Ordering::Relaxed) > readies);
            assert!(PROTOCOL_TRANSMIT_IDLES.load(Ordering::Relaxed) > idles);
        }
    }
}
