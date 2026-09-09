//! Opt-in, payload-free protocol construction and authentication hooks.
//!
//! This module is diagnostic-only. Events contain packet numbers, packet and
//! stream ranges, and a caller-supplied connection/cookie context; they never
//! contain payload bytes, addresses, credentials, keys, or wire timestamps.
//! The module is compiled only with the `packet-diagnostics` feature, which is
//! disabled by default.
//!
//! `PacketBuilt` describes protocol construction in userspace. It does not
//! mean that a UDP send was accepted by the operating system or reached the
//! wire. `PacketAuthenticated` describes successful protocol decryption and
//! authentication after a datagram was accepted for processing; it does not
//! identify the kernel receive wakeup or a wall-clock receive time.
//!
//! Install at most one callback with [`install`]. The callback is synchronous,
//! must not block or panic, and should do only bounded work. The callback is
//! process-wide; the context is thread-local so events from independent
//! protocol threads cannot be attributed to one another accidentally.

use std::{cell::Cell, sync::OnceLock};

/// Direction of the UDP operation that owns a diagnostic context.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Direction {
    /// A locally constructed packet or sent stream range.
    Send,
    /// A received and authenticated packet or received stream range.
    Receive,
}

/// Caller-owned identity for correlating protocol events with an outer
/// connection and one transmit/receive datagram operation.
///
/// `cookie` is opaque to noq-proto. Callers should allocate a non-zero unique
/// value and retain it across buffered-transmit/retry paths. NoQ does not
/// generate, persist, or interpret the cookie.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Context {
    /// Local noQ connection handle (not a wire identifier).
    pub connection: usize,
    /// Caller-assigned transmit or receive datagram cookie.
    pub cookie: u64,
    /// Direction of the operation represented by this context.
    pub direction: Direction,
}

/// QUIC packet number space.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum NumberSpace {
    /// Initial packet number space.
    Initial,
    /// Handshake packet number space.
    Handshake,
    /// Application-data packet number space (including 0-RTT where relevant
    /// to the caller's packet builder).
    Data,
}

/// A payload-free event suitable for bounded correlation.
///
/// Every event carries an explicit [`Context`]. Use one of the `emit_*`
/// helpers while inside [`with_context`]; if no context is installed, the
/// helper intentionally emits nothing rather than creating an ambiguous
/// record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Event {
    /// Entry or return of synchronous packet and header protection.
    /// This is a userspace boundary, not exclusive CPU time.
    PacketProtection {
        /// Outer connection and datagram cookie.
        context: Context,
        /// QUIC packet number.
        packet_number: u64,
        /// Packet number space.
        number_space: NumberSpace,
        /// True immediately before protection, false immediately after.
        started: bool,
    },
    /// Entry or return of ordinary packet frame selection and serialization.
    /// This is a userspace boundary, not exclusive CPU time. Events are
    /// emitted only for the primary path by the connection packet builder.
    PacketFrames {
        /// Outer connection and datagram cookie.
        context: Context,
        /// QUIC packet number.
        packet_number: u64,
        /// QUIC packet number space.
        number_space: NumberSpace,
        /// True immediately before frame population, false immediately after.
        started: bool,
    },
    /// A packet was constructed by protocol logic in userspace.
    PacketBuilt {
        /// Outer connection and datagram cookie.
        context: Context,
        /// QUIC packet number.
        packet_number: u64,
        /// Packet number space.
        number_space: NumberSpace,
        /// Absolute offset within the complete transmit buffer, including
        /// preceding GSO segments and coalesced packets.
        packet_offset: usize,
        /// Packet length in bytes.
        packet_len: usize,
    },
    /// A packet was successfully authenticated for protocol processing.
    PacketAuthenticated {
        /// Outer connection and datagram cookie.
        context: Context,
        /// QUIC packet number.
        packet_number: u64,
        /// Packet number space.
        number_space: NumberSpace,
        /// Offset of the packet within the containing datagram.
        packet_offset: usize,
        /// Packet length in bytes.
        packet_len: usize,
    },
    /// An authenticated packet arrived on a path that this schema cannot
    /// identify. Packet and stream events for that path are suppressed.
    UnsupportedPath {
        /// Outer connection and datagram cookie.
        context: Context,
        /// Internal noQ path identifier, retained only to make the omission
        /// explicit to the caller.
        path: u32,
    },
    /// A stream range was included in a locally built packet.
    StreamSent {
        /// Outer connection and datagram cookie.
        context: Context,
        /// QUIC packet number carrying the range.
        packet_number: u64,
        /// Packet number space.
        number_space: NumberSpace,
        /// QUIC stream identifier.
        stream: u64,
        /// Stream byte offset.
        offset: u64,
        /// Number of stream bytes represented by this range.
        length: u64,
        /// Whether this range carries FIN.
        fin: bool,
    },
    /// A stream range was authenticated from a received packet.
    StreamReceived {
        /// Outer connection and datagram cookie.
        context: Context,
        /// QUIC packet number carrying the range.
        packet_number: u64,
        /// Packet number space.
        number_space: NumberSpace,
        /// QUIC stream identifier.
        stream: u64,
        /// Stream byte offset.
        offset: u64,
        /// Number of stream bytes represented by this range.
        length: u64,
        /// Whether this range carries FIN.
        fin: bool,
    },
}

/// Error returned when another diagnostic callback is already installed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallError {
    /// The process-wide callback was already set.
    AlreadyInstalled,
}

static CALLBACK: OnceLock<fn(Event)> = OnceLock::new();

thread_local! {
    static CONTEXT: Cell<Option<Context>> = const { Cell::new(None) };
}

/// Install the process-wide diagnostic callback.
///
/// Installation is one-shot and thread-safe. The callback runs synchronously
/// on the thread that emits the event. It must not block, panic, or re-enter
/// the protocol. Calling this function a second time returns
/// [`InstallError::AlreadyInstalled`].
pub fn install(callback: fn(Event)) -> Result<(), InstallError> {
    CALLBACK
        .set(callback)
        .map_err(|_| InstallError::AlreadyInstalled)
}

/// Run `f` with a thread-local context for protocol event attribution.
///
/// Nested scopes restore the previous context. Restoration is performed by a
/// drop guard, including when `f` unwinds with a panic. The closure is
/// synchronous so no context can accidentally cross an async task boundary.
pub fn with_context<R>(context: Context, f: impl FnOnce() -> R) -> R {
    let previous = CONTEXT.with(|slot| slot.replace(Some(context)));
    let restore = Restore { previous };
    let result = f();
    drop(restore);
    result
}

/// Run synchronous work whose original datagram identity is unavailable.
/// Nested work must not inherit an unrelated caller's receive cookie.
pub fn without_context<R>(f: impl FnOnce() -> R) -> R {
    let previous = CONTEXT.with(|slot| slot.replace(None));
    let restore = Restore { previous };
    let result = f();
    drop(restore);
    result
}

struct Restore {
    previous: Option<Context>,
}

impl Drop for Restore {
    fn drop(&mut self) {
        CONTEXT.with(|slot| slot.set(self.previous));
    }
}

/// Return the current thread-local context, if one is installed.
#[inline]
pub fn current_context() -> Option<Context> {
    CONTEXT.with(Cell::get)
}

#[inline]
fn emit(event: Event) {
    if let Some(callback) = CALLBACK.get().copied() {
        callback(event);
    }
}

/// Emit a packet-protection boundary using the current send context.
#[inline]
pub fn emit_packet_protection(packet_number: u64, number_space: NumberSpace, started: bool) {
    let Some(context) = current_context().filter(|context| context.direction == Direction::Send)
    else {
        return;
    };
    emit(Event::PacketProtection {
        context,
        packet_number,
        number_space,
        started,
    });
}

/// Emit an ordinary packet frame-selection boundary using the current send context.
#[inline]
pub fn emit_packet_frames(packet_number: u64, number_space: NumberSpace, started: bool) {
    let Some(context) = current_context().filter(|context| context.direction == Direction::Send)
    else {
        return;
    };
    emit(Event::PacketFrames {
        context,
        packet_number,
        number_space,
        started,
    });
}

/// Emit a packet-construction event using the current context.
#[inline]
pub fn emit_packet_built(
    packet_number: u64,
    number_space: NumberSpace,
    packet_offset: usize,
    packet_len: usize,
) {
    let Some(context) = current_context().filter(|context| context.direction == Direction::Send)
    else {
        return;
    };
    emit(Event::PacketBuilt {
        context,
        packet_number,
        number_space,
        packet_offset,
        packet_len,
    });
}

/// Emit a packet-authentication event using the current context.
#[inline]
pub fn emit_packet_authenticated(
    packet_number: u64,
    number_space: NumberSpace,
    packet_offset: usize,
    packet_len: usize,
) {
    let Some(context) = current_context().filter(|context| context.direction == Direction::Receive)
    else {
        return;
    };
    emit(Event::PacketAuthenticated {
        context,
        packet_number,
        number_space,
        packet_offset,
        packet_len,
    });
}

/// Emit a sent stream-range event using the current context.
#[inline]
pub fn emit_stream_sent(
    packet_number: u64,
    number_space: NumberSpace,
    stream: u64,
    offset: u64,
    length: u64,
    fin: bool,
) {
    let Some(context) = current_context().filter(|context| context.direction == Direction::Send)
    else {
        return;
    };
    emit(Event::StreamSent {
        context,
        packet_number,
        number_space,
        stream,
        offset,
        length,
        fin,
    });
}

/// Emit a received stream-range event using the current context.
#[inline]
pub fn emit_stream_received(
    packet_number: u64,
    number_space: NumberSpace,
    stream: u64,
    offset: u64,
    length: u64,
    fin: bool,
) {
    let Some(context) = current_context().filter(|context| context.direction == Direction::Receive)
    else {
        return;
    };
    emit(Event::StreamReceived {
        context,
        packet_number,
        number_space,
        stream,
        offset,
        length,
        fin,
    });
}

/// Emit an explicit marker when an authenticated packet uses a path not
/// representable by the packet/stream event schema.
#[inline]
pub fn emit_unsupported_path(path: u32) {
    let Some(context) = current_context().filter(|context| context.direction == Direction::Receive)
    else {
        return;
    };
    emit(Event::UnsupportedPath { context, path });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{mem::size_of, panic::AssertUnwindSafe, sync::Mutex};

    static EVENTS: Mutex<Vec<Event>> = Mutex::new(Vec::new());

    fn record(event: Event) {
        EVENTS.lock().expect("record lock").push(event);
    }

    #[test]
    fn event_is_copy_and_fixed_capacity() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<Context>();
        assert_copy::<NumberSpace>();
        assert_copy::<Event>();
        // This is deliberately a generous upper bound: the event must remain
        // a stack value with no payload, address, or allocation field.
        assert!(size_of::<Event>() <= 64);
    }

    #[test]
    fn nested_context_restores_outer_context() {
        let outer = Context {
            connection: 3,
            cookie: 7,
            direction: Direction::Send,
        };
        let inner = Context {
            connection: 9,
            cookie: 11,
            direction: Direction::Receive,
        };
        assert_eq!(current_context(), None);
        with_context(outer, || {
            assert_eq!(current_context(), Some(outer));
            without_context(|| assert_eq!(current_context(), None));
            assert_eq!(current_context(), Some(outer));
            with_context(inner, || assert_eq!(current_context(), Some(inner)));
            assert_eq!(current_context(), Some(outer));
        });
        assert_eq!(current_context(), None);
    }

    #[test]
    fn context_restores_when_closure_unwinds() {
        let outer = Context {
            connection: 13,
            cookie: 17,
            direction: Direction::Send,
        };
        let inner = Context {
            connection: 19,
            cookie: 23,
            direction: Direction::Receive,
        };
        with_context(outer, || {
            let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
                with_context(inner, || panic!("diagnostic test unwind"));
            }));
            assert!(result.is_err());
            assert_eq!(current_context(), Some(outer));
        });
        assert_eq!(current_context(), None);
    }

    #[test]
    fn event_helpers_ignore_events_without_context() {
        // This test intentionally does not install a callback: the callback
        // is process-global and another test may own it. The absence of a
        // context is still exercised by the helper's no-op path.
        assert_eq!(current_context(), None);
        emit_packet_built(1, NumberSpace::Initial, 0, 42);
        emit_packet_protection(1, NumberSpace::Initial, true);
        emit_packet_protection(1, NumberSpace::Initial, false);
        emit_packet_frames(1, NumberSpace::Initial, true);
        emit_packet_frames(1, NumberSpace::Initial, false);
        emit_packet_authenticated(1, NumberSpace::Initial, 0, 42);
        emit_stream_sent(1, NumberSpace::Data, 4, 0, 3, false);
        emit_stream_received(1, NumberSpace::Data, 4, 0, 3, false);
    }

    #[test]
    fn callback_is_one_shot_and_receives_enriched_event() {
        // The test harness executes each unit test in one process, so this is
        // the sole installer. It also verifies the duplicate-install contract.
        assert_eq!(install(record), Ok(()));
        assert_eq!(install(record), Err(InstallError::AlreadyInstalled));
        let context = Context {
            connection: 29,
            cookie: 31,
            direction: Direction::Send,
        };
        with_context(context, || emit_packet_built(41, NumberSpace::Data, 5, 99));
        with_context(context, || {
            emit_packet_protection(43, NumberSpace::Data, true);
            emit_packet_protection(43, NumberSpace::Data, false);
            emit_packet_frames(43, NumberSpace::Data, true);
            emit_packet_frames(43, NumberSpace::Data, false);
        });
        with_context(
            Context {
                direction: Direction::Receive,
                ..context
            },
            || {
                emit_packet_protection(47, NumberSpace::Data, true);
                emit_packet_frames(47, NumberSpace::Data, true);
                emit_packet_frames(47, NumberSpace::Data, false);
            },
        );
        let events = EVENTS.lock().expect("record lock");
        let protection: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                Event::PacketProtection {
                    context: got,
                    packet_number,
                    number_space,
                    started,
                } => Some((*got, *packet_number, *number_space, *started)),
                _ => None,
            })
            .collect();
        assert_eq!(
            protection,
            vec![
                (context, 43, NumberSpace::Data, true),
                (context, 43, NumberSpace::Data, false),
            ]
        );
        let frames: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                Event::PacketFrames {
                    context: got,
                    packet_number,
                    number_space,
                    started,
                } => Some((*got, *packet_number, *number_space, *started)),
                _ => None,
            })
            .collect();
        assert_eq!(
            frames,
            vec![
                (context, 43, NumberSpace::Data, true),
                (context, 43, NumberSpace::Data, false),
            ]
        );
        assert!(events.iter().any(|event| {
            matches!(
                event,
                Event::PacketBuilt {
                    context: got,
                    packet_number: 41,
                    packet_offset: 5,
                    packet_len: 99,
                    ..
                } if *got == context
            )
        }));
    }
}
