//! A small, synchronous owner for the `noq-proto` state machine.
//!
//! This module is deliberately only the first slice of the disposable floor
//! experiment.  It owns protocol state and a bounded transmit buffer, but it
//! does not open sockets, spawn tasks, or make any authentication decisions.
//! The socket adapter borrows the bytes in
//! [`FloorPump::pending_transmit`] and calls [`FloorPump::confirm_transmit`]
//! only after the datagram was accepted by the socket.

use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    net::SocketAddr,
    num::NonZeroUsize,
    time::Instant,
};

use bytes::BytesMut;
use noq_proto::{
    ClientConfig, Connection, ConnectionHandle, DatagramEvent, EcnCodepoint, Endpoint,
    EndpointConfig, Event, FourTuple, Incoming, ServerConfig, Transmit,
};

/// The role of a protocol owner.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum FloorRole {
    Client,
    Server,
}

/// Limits which keep the disposable owner finite and fair.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct FloorLimits {
    /// Requested connection count; the experiment always normalizes this to one.
    pub max_connections: usize,
    /// Maximum number of protocol events handled by one [`FloorPump::drive`] call.
    pub max_work: usize,
    /// Maximum UDP payload retained in a pending transmit.
    pub max_transmit_bytes: usize,
}

/// Caller-owned counters for one observed pump drive.
///
/// The normal drive APIs do not touch this type or gather counters. Counter
/// increments saturate and set [`Self::overflow`] instead of wrapping.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct PumpWork {
    /// Deferred datagrams handed from the bounded slot into the endpoint.
    pub deferred_receives: u64,
    /// Datagrams placed into the bounded deferred slot while a transmit is
    /// awaiting confirmation.
    pub deferred_receives_queued: u64,
    /// Calls to a connection's expired timer handler.
    pub timers_handled: u64,
    /// Connection endpoint events passed to the endpoint.
    pub endpoint_events: u64,
    /// Application events added to the ready queue.
    pub application_events_enqueued: u64,
    /// Connection `poll_transmit` results staged for sending. This excludes
    /// stateless endpoint responses generated while processing receives;
    /// receive activity must also be checked when classifying an idle pass.
    pub transmits_generated: u64,
    /// Fully drained connections removed from the association slot.
    pub connections_retired: u64,
    /// At least one counter exceeded its representation; observations invalid.
    pub overflow: bool,
}

impl PumpWork {
    /// Clear counters before beginning another observed drive.
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    fn increment(value: &mut u64, overflow: &mut bool) {
        if let Some(next) = value.checked_add(1) {
            *value = next;
        } else {
            *overflow = true;
        }
    }
}

impl Default for FloorLimits {
    fn default() -> Self {
        Self {
            max_connections: 1,
            max_work: 128,
            max_transmit_bytes: 64 * 1024,
        }
    }
}

/// Errors from the synchronous owner.
#[derive(Debug)]
pub enum FloorError {
    /// The operation is only valid for a client owner.
    WrongRole { expected: FloorRole },
    /// The single connection slot or its previous generation's work is occupied.
    ConnectionLimit,
    /// `noq-proto` rejected a connection operation.
    Connect(Box<noq_proto::ConnectError>),
    /// `noq-proto` rejected an incoming connection.
    Accept(Box<noq_proto::AcceptError>),
    /// Retry could not be generated for this incoming packet.
    Retry(noq_proto::RetryError),
    /// The caller attempted to acknowledge a different transmit than the one pending.
    TransmitMismatch { expected: usize, accepted: usize },
    /// A datagram arrived while a prior transmit is still awaiting socket confirmation.
    /// The caller must retry the receive after [`FloorPump::confirm_transmit`].
    TransmitPending,
    /// The bounded deferred receive slot is full.  Ownership of the datagram
    /// is returned to the caller so it can apply socket-level backpressure.
    ReceiveBackpressure { data: BytesMut },
    /// A protocol transmit exceeded the retained-buffer cap.
    TransmitTooLarge { size: usize, cap: usize },
}

impl fmt::Display for FloorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongRole { expected } => write!(f, "floor owner requires {expected:?} role"),
            Self::ConnectionLimit => f.write_str("floor owner connection limit reached"),
            Self::Connect(e) => write!(f, "connect: {e}"),
            Self::Accept(e) => write!(f, "accept: {e:?}"),
            Self::Retry(e) => write!(f, "retry: {e}"),
            Self::TransmitMismatch { expected, accepted } => {
                write!(f, "transmit accepted {accepted} bytes, expected {expected}")
            }
            Self::TransmitPending => f.write_str("a transmit is awaiting socket confirmation"),
            Self::ReceiveBackpressure { .. } => f.write_str("floor owner receive handoff is full"),
            Self::TransmitTooLarge { size, cap } => {
                write!(f, "transmit of {size} bytes exceeds {cap}-byte cap")
            }
        }
    }
}

impl std::error::Error for FloorError {}

/// A borrowed view of the one datagram which must be accepted before more
/// protocol work is performed.
#[derive(Debug, Clone, Copy)]
pub struct PendingTransmit<'a> {
    transmit: &'a Transmit,
    bytes: &'a [u8],
}

impl PendingTransmit<'_> {
    /// Datagram payload, beginning at byte zero.
    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }

    /// Metadata needed by a UDP socket send operation.
    pub fn transmit(&self) -> &Transmit {
        self.transmit
    }
}

struct OwnedTransmit {
    transmit: Transmit,
    bytes: Vec<u8>,
}

struct InboundDatagram {
    network_path: FourTuple,
    ecn: Option<EcnCodepoint>,
    data: BytesMut,
    now: Instant,
}

struct FloorConnection {
    connection: Connection,
    endpoint_drained: bool,
}

/// A synchronous, bounded owner of one `noq-proto` endpoint.
///
/// `FloorPump` intentionally exposes no socket or async API.  The caller feeds
/// received datagrams through [`receive`](Self::receive), calls [`drive`](Self::drive)
/// with its monotonic clock, and drains pending datagrams.  A pending datagram
/// is never replaced or regenerated until `confirm_transmit` succeeds.
pub struct FloorPump {
    endpoint: Endpoint,
    role: FloorRole,
    limits: FloorLimits,
    connections: BTreeMap<ConnectionHandle, FloorConnection>,
    ready: VecDeque<(ConnectionHandle, Event)>,
    pending: Option<OwnedTransmit>,
    /// One bounded receive slot used while the socket adapter is blocked on a
    /// prior send.  This prevents a generated response from being lost.
    deferred: Option<InboundDatagram>,
    scratch: Vec<u8>,
}

impl FloorPump {
    /// Construct an owner around an already configured endpoint.
    ///
    /// TLS, certificate verification, ALPN, and transport settings remain the
    /// caller's responsibility; this layer never bypasses them.
    pub fn new(endpoint: Endpoint, role: FloorRole, limits: FloorLimits) -> Self {
        let limits = FloorLimits {
            // The floor experiment is intentionally a single-owner design;
            // a caller cannot accidentally turn it into an unbounded server.
            max_connections: 1,
            max_work: limits.max_work.clamp(1, 128),
            max_transmit_bytes: limits.max_transmit_bytes.clamp(1, 64 * 1024),
        };
        Self {
            endpoint,
            role,
            limits,
            connections: BTreeMap::new(),
            ready: VecDeque::with_capacity(limits.max_work),
            pending: None,
            deferred: None,
            scratch: Vec::with_capacity(limits.max_transmit_bytes),
        }
    }

    /// Convenience constructor for a client endpoint.
    pub fn client(config: EndpointConfig, limits: FloorLimits) -> Self {
        Self::client_with_mtud(config, limits, false)
    }

    /// Construct a client owner when the socket adapter guarantees that UDP
    /// packets are never fragmented.
    pub fn client_with_mtud(config: EndpointConfig, limits: FloorLimits, allow_mtud: bool) -> Self {
        Self::new(
            Endpoint::new(std::sync::Arc::new(config), None, allow_mtud),
            FloorRole::Client,
            limits,
        )
    }

    /// Convenience constructor for a server endpoint.
    pub fn server(
        config: EndpointConfig,
        server_config: ServerConfig,
        limits: FloorLimits,
    ) -> Self {
        Self::server_with_mtud(config, server_config, limits, false)
    }

    /// Construct a server owner when the socket adapter guarantees that UDP
    /// packets are never fragmented.
    pub fn server_with_mtud(
        config: EndpointConfig,
        server_config: ServerConfig,
        limits: FloorLimits,
        allow_mtud: bool,
    ) -> Self {
        Self::new(
            Endpoint::new(
                std::sync::Arc::new(config),
                Some(std::sync::Arc::new(server_config)),
                allow_mtud,
            ),
            FloorRole::Server,
            limits,
        )
    }

    /// Number of currently owned connections.
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Mutable access for the future stream adapter.
    pub fn connection_mut(&mut self, handle: ConnectionHandle) -> Option<&mut Connection> {
        self.connections
            .get_mut(&handle)
            .map(|slot| &mut slot.connection)
    }

    /// Initiate a client connection.  The returned handle is also used by
    /// [`connection_mut`](Self::connection_mut) and application events.
    pub fn connect(
        &mut self,
        config: ClientConfig,
        remote: SocketAddr,
        server_name: &str,
        now: Instant,
    ) -> Result<ConnectionHandle, FloorError> {
        if self.role != FloorRole::Client {
            return Err(FloorError::WrongRole {
                expected: FloorRole::Client,
            });
        }
        self.ensure_capacity()?;
        let (handle, connection) = self
            .endpoint
            .connect(now, config, remote, server_name)
            .map_err(|e| FloorError::Connect(Box::new(e)))?;
        self.connections.insert(
            handle,
            FloorConnection {
                connection,
                endpoint_drained: false,
            },
        );
        Ok(handle)
    }

    /// Feed one received UDP datagram to the endpoint.
    ///
    /// Unvalidated incoming connections are retried.  A validated incoming
    /// connection is accepted only while the bounded connection slot is free;
    /// excess connections receive a protocol refusal.  No incoming packet is
    /// silently admitted around the configured TLS/server policy.
    pub fn receive(
        &mut self,
        network_path: FourTuple,
        ecn: Option<EcnCodepoint>,
        data: BytesMut,
        now: Instant,
    ) -> Result<(), FloorError> {
        self.receive_impl(network_path, ecn, data, now, None)
    }

    pub(crate) fn receive_observed(
        &mut self,
        network_path: FourTuple,
        ecn: Option<EcnCodepoint>,
        data: BytesMut,
        now: Instant,
        work: &mut PumpWork,
    ) -> Result<(), FloorError> {
        self.receive_impl(network_path, ecn, data, now, Some(work))
    }

    fn receive_impl(
        &mut self,
        network_path: FourTuple,
        ecn: Option<EcnCodepoint>,
        data: BytesMut,
        now: Instant,
        work: Option<&mut PumpWork>,
    ) -> Result<(), FloorError> {
        if self.pending.is_some() {
            if self.deferred.is_some() {
                // The one-slot receive handoff is full.  The socket adapter
                // must apply backpressure before accepting another datagram.
                return Err(FloorError::ReceiveBackpressure { data });
            }
            self.deferred = Some(InboundDatagram {
                network_path,
                ecn,
                data,
                now,
            });
            if let Some(work) = work {
                PumpWork::increment(&mut work.deferred_receives_queued, &mut work.overflow);
            }
            return Ok(());
        }
        self.receive_ready(network_path, ecn, data, now)
    }

    fn receive_ready(
        &mut self,
        network_path: FourTuple,
        ecn: Option<EcnCodepoint>,
        data: BytesMut,
        now: Instant,
    ) -> Result<(), FloorError> {
        self.scratch.clear();
        let Some(event) = self
            .endpoint
            .handle(now, network_path, ecn, data, &mut self.scratch)
        else {
            return Ok(());
        };
        self.handle_datagram_event(event, now)
    }

    fn handle_datagram_event(
        &mut self,
        event: DatagramEvent,
        now: Instant,
    ) -> Result<(), FloorError> {
        match event {
            DatagramEvent::ConnectionEvent(handle, event) => {
                if let Some(slot) = self.connections.get_mut(&handle) {
                    slot.connection.handle_event(event);
                }
            }
            DatagramEvent::Response(transmit) => self.stage_scratch(transmit)?,
            DatagramEvent::NewConnection(incoming) => self.handle_incoming(incoming, now)?,
        }
        Ok(())
    }

    fn handle_incoming(&mut self, incoming: Incoming, now: Instant) -> Result<(), FloorError> {
        if !incoming.remote_address_validated() {
            self.scratch.clear();
            let transmit = self
                .endpoint
                .retry(incoming, &mut self.scratch)
                .map_err(FloorError::Retry)?;
            return self.stage_scratch(transmit);
        }

        self.scratch.clear();
        if self.ensure_capacity().is_err() {
            let transmit = self.endpoint.refuse(incoming, &mut self.scratch);
            return self.stage_scratch(transmit);
        }

        let (handle, connection) = self
            .endpoint
            .accept(incoming, now, &mut self.scratch, None)
            .map_err(FloorError::Accept)?;
        self.connections.insert(
            handle,
            FloorConnection {
                connection,
                endpoint_drained: false,
            },
        );
        Ok(())
    }

    fn ensure_capacity(&self) -> Result<(), FloorError> {
        // Protocol handles can be reused after endpoint retirement. Do not let
        // old application events or retained I/O acquire a new interpretation.
        if self.connections.len() >= self.limits.max_connections
            || !self.ready.is_empty()
            || self.pending.is_some()
            || self.deferred.is_some()
        {
            Err(FloorError::ConnectionLimit)
        } else {
            Ok(())
        }
    }

    fn stage_scratch(&mut self, transmit: Transmit) -> Result<(), FloorError> {
        if self.pending.is_some() {
            // This is an internal sequencing failure, not successful deferral.
            // Public receive/drive paths must avoid generating a second transmit.
            return Err(FloorError::TransmitPending);
        }
        if self.scratch.len() != transmit.size {
            return Err(FloorError::TransmitMismatch {
                expected: transmit.size,
                accepted: self.scratch.len(),
            });
        }
        if self.scratch.len() > self.limits.max_transmit_bytes {
            return Err(FloorError::TransmitTooLarge {
                size: self.scratch.len(),
                cap: self.limits.max_transmit_bytes,
            });
        }
        self.pending = Some(OwnedTransmit {
            transmit,
            bytes: std::mem::take(&mut self.scratch),
        });
        Ok(())
    }

    /// Borrow the pending datagram.  The borrow remains valid until the next
    /// mutable operation. `drive` may service timers while it remains pending,
    /// but does not replace this payload.
    pub fn pending_transmit(&self) -> Option<PendingTransmit<'_>> {
        self.pending.as_ref().map(|pending| PendingTransmit {
            transmit: &pending.transmit,
            bytes: &pending.bytes,
        })
    }

    /// Confirm that the socket accepted the pending datagram in full.
    pub fn confirm_transmit(&mut self, accepted: usize) -> Result<(), FloorError> {
        let Some(pending) = self.pending.as_ref() else {
            return Err(FloorError::TransmitMismatch {
                expected: 0,
                accepted,
            });
        };
        if accepted != pending.transmit.size || accepted != pending.bytes.len() {
            return Err(FloorError::TransmitMismatch {
                expected: pending.transmit.size,
                accepted,
            });
        }
        let Some(pending) = self.pending.take() else {
            // Keep a defensive error path; exclusive ownership excludes races.
            return Err(FloorError::TransmitMismatch {
                expected: 0,
                accepted,
            });
        };
        // Recycle the owned allocation for the next protocol packet.  No
        // socket call may retain this buffer after a successful confirmation.
        self.scratch = pending.bytes;
        self.scratch.clear();
        Ok(())
    }

    /// Run bounded protocol work and expose application events through
    /// [`poll_event`](Self::poll_event). A pending transmit stops new transmit
    /// generation, but not due timers, until the socket accepts its bytes.
    pub fn drive(&mut self, now: Instant) -> Result<(), FloorError> {
        self.drive_with_max_datagrams(now, NonZeroUsize::MIN)
    }

    /// Run bounded protocol work while recording execution counters in the
    /// caller-owned slot. The slot is reset at the start of this call.
    pub fn drive_observed(&mut self, now: Instant, work: &mut PumpWork) -> Result<(), FloorError> {
        self.drive_with_max_datagrams_observed(now, NonZeroUsize::MIN, work)
    }

    /// Run bounded protocol work, allowing a socket adapter to select its GSO
    /// batch size.  The adapter must still confirm each returned datagram as a
    /// whole; the borrowed buffer remains pinned until confirmation.
    pub fn drive_with_max_datagrams(
        &mut self,
        now: Instant,
        max_datagrams: NonZeroUsize,
    ) -> Result<(), FloorError> {
        self.drive_with_max_datagrams_impl::<false>(now, max_datagrams, None)
    }

    /// Observed variant of [`Self::drive_with_max_datagrams`].
    pub fn drive_with_max_datagrams_observed(
        &mut self,
        now: Instant,
        max_datagrams: NonZeroUsize,
        work: &mut PumpWork,
    ) -> Result<(), FloorError> {
        work.reset();
        self.drive_with_max_datagrams_impl::<true>(now, max_datagrams, Some(work))
    }

    pub(crate) fn drive_with_max_datagrams_observed_into(
        &mut self,
        now: Instant,
        max_datagrams: NonZeroUsize,
        work: &mut PumpWork,
    ) -> Result<(), FloorError> {
        self.drive_with_max_datagrams_impl::<true>(now, max_datagrams, Some(work))
    }

    fn drive_with_max_datagrams_impl<const OBSERVE: bool>(
        &mut self,
        now: Instant,
        max_datagrams: NonZeroUsize,
        mut work: Option<&mut PumpWork>,
    ) -> Result<(), FloorError> {
        let inbound = if self.pending.is_none() {
            self.deferred.take()
        } else {
            None
        };
        if let Some(inbound) = inbound {
            // The deferred slot is bounded and is processed before timers or
            // application work, preserving receive order.
            if OBSERVE {
                if let Some(observed) = work.as_deref_mut() {
                    PumpWork::increment(&mut observed.deferred_receives, &mut observed.overflow);
                }
            }
            self.receive_ready(inbound.network_path, inbound.ecn, inbound.data, inbound.now)?;
            if self.pending.is_some() {
                return Ok(());
            }
        }
        if let Some(handle) = self.connections.keys().next().copied() {
            self.drive_connection::<OBSERVE>(
                handle,
                now,
                self.limits.max_work,
                max_datagrams,
                &mut work,
            )?;
        }
        Ok(())
    }

    fn drive_connection<const OBSERVE: bool>(
        &mut self,
        handle: ConnectionHandle,
        now: Instant,
        budget: usize,
        max_datagrams: NonZeroUsize,
        work_observed: &mut Option<&mut PumpWork>,
    ) -> Result<usize, FloorError> {
        let mut work = 0;
        let mut application_drained = false;
        {
            let Some(slot) = self.connections.get_mut(&handle) else {
                return Ok(0);
            };
            if slot
                .connection
                .poll_timeout()
                .is_some_and(|deadline| deadline <= now)
            {
                slot.connection.handle_timeout(now);
                work += 1;
                if OBSERVE {
                    if let Some(observed) = work_observed.as_deref_mut() {
                        PumpWork::increment(&mut observed.timers_handled, &mut observed.overflow);
                    }
                }
            }
            while work < budget {
                let Some(event) = slot.connection.poll_endpoint_events() else {
                    break;
                };
                if OBSERVE {
                    if let Some(observed) = work_observed.as_deref_mut() {
                        PumpWork::increment(&mut observed.endpoint_events, &mut observed.overflow);
                    }
                }
                slot.endpoint_drained |= event.is_drained();
                let response = self.endpoint.handle_event(handle, event);
                if let Some(response) = response {
                    slot.connection.handle_event(response);
                }
                work += 1;
            }
            while work < budget && self.ready.len() < self.limits.max_work {
                let Some(event) = slot.connection.poll() else {
                    application_drained = true;
                    break;
                };
                self.ready.push_back((handle, event));
                work += 1;
                if OBSERVE {
                    if let Some(observed) = work_observed.as_deref_mut() {
                        PumpWork::increment(
                            &mut observed.application_events_enqueued,
                            &mut observed.overflow,
                        );
                    }
                }
            }
        }
        if application_drained
            && self
                .connections
                .get(&handle)
                .is_some_and(|slot| slot.endpoint_drained)
        {
            self.connections.remove(&handle);
            if OBSERVE {
                if let Some(observed) = work_observed.as_deref_mut() {
                    PumpWork::increment(&mut observed.connections_retired, &mut observed.overflow);
                }
            }
            return Ok(work);
        }
        if work < budget && self.pending.is_none() {
            self.scratch.clear();
            let transmit = self.connections.get_mut(&handle).and_then(|slot| {
                slot.connection
                    .poll_transmit(now, max_datagrams, &mut self.scratch)
            });
            if let Some(transmit) = transmit {
                self.stage_scratch(transmit)?;
                work += 1;
                if OBSERVE {
                    if let Some(observed) = work_observed.as_deref_mut() {
                        PumpWork::increment(
                            &mut observed.transmits_generated,
                            &mut observed.overflow,
                        );
                    }
                }
            }
        }
        Ok(work)
    }

    /// Return the earliest connection timer deadline, if any.
    pub fn next_timeout(&self) -> Option<Instant> {
        self.connections
            .values()
            .filter_map(|slot| slot.connection.poll_timeout())
            .min()
    }

    /// Poll one application-facing connection event in fair FIFO order.
    pub fn poll_event(&mut self) -> Option<(ConnectionHandle, Event)> {
        self.ready.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn limits_are_nonzero_and_default_to_one_connection() {
        let limits = FloorLimits::default();
        assert_eq!(limits.max_connections, 1);
        assert!(limits.max_work > 0);
        assert!(limits.max_transmit_bytes > 0);
        let clamped = FloorLimits {
            max_connections: 0,
            max_work: 0,
            max_transmit_bytes: 0,
        };
        let pump = FloorPump::client(EndpointConfig::default(), clamped);
        assert_eq!(
            pump.limits,
            FloorLimits {
                max_connections: 1,
                max_work: 1,
                max_transmit_bytes: 1
            }
        );
        let pump = FloorPump::client(
            EndpointConfig::default(),
            FloorLimits {
                max_connections: usize::MAX,
                max_work: usize::MAX,
                max_transmit_bytes: usize::MAX,
            },
        );
        assert_eq!(pump.limits, limits);
    }

    fn empty_client() -> FloorPump {
        FloorPump::new(
            Endpoint::new(Arc::new(EndpointConfig::default()), None, false),
            FloorRole::Client,
            FloorLimits::default(),
        )
    }

    fn pending_pump() -> FloorPump {
        let mut pump = empty_client();
        pump.pending = Some(OwnedTransmit {
            transmit: Transmit {
                destination: "127.0.0.1:4433".parse().expect("literal address"),
                ecn: None,
                size: 4,
                segment_size: None,
                src_ip: None,
            },
            bytes: vec![1, 2, 3, 4],
        });
        pump
    }

    #[test]
    fn pending_transmit_stays_pinned_until_full_confirmation_and_recycles() {
        let mut pump = pending_pump();
        let capacity = pump
            .pending_transmit()
            .expect("pending packet")
            .bytes()
            .len();
        assert!(pump.confirm_transmit(3).is_err());
        let view = pump.pending_transmit().expect("packet remains pinned");
        assert_eq!(view.bytes(), &[1, 2, 3, 4]);
        assert!(pump.confirm_transmit(4).is_ok());
        assert!(pump.pending_transmit().is_none());
        assert!(pump.scratch.capacity() >= capacity);
    }

    #[test]
    fn deferred_receive_is_bounded_and_returns_second_datagram() {
        let mut pump = pending_pump();
        let address = "127.0.0.1:4433".parse().expect("literal address");
        let path = FourTuple::new(address, None);
        let first = BytesMut::from(&[0_u8, 1][..]);
        assert!(pump.receive(path, None, first, Instant::now()).is_ok());
        let second = BytesMut::from(&[2_u8, 3][..]);
        let error = pump
            .receive(path, None, second, Instant::now())
            .expect_err("the one-slot handoff must backpressure");
        match error {
            FloorError::ReceiveBackpressure { data } => {
                assert_eq!(&data[..], &[2, 3]);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn observed_deferred_processing_is_not_mistaken_for_idle() {
        let mut pump = pending_pump();
        let mut counts = PumpWork::default();
        let path = FourTuple::new("127.0.0.1:4433".parse().expect("address"), None);
        let now = Instant::now();
        pump.receive_observed(path, None, BytesMut::from(&[0_u8, 1][..]), now, &mut counts)
            .expect("queue deferred packet");
        assert_eq!(counts.deferred_receives_queued, 1);
        assert_eq!(counts.deferred_receives, 0);
        pump.confirm_transmit(4).expect("release pending send");
        pump.drive_observed(now, &mut counts)
            .expect("process deferred packet");
        assert_eq!(counts.deferred_receives, 1);
        assert_eq!(
            counts.deferred_receives_queued, 0,
            "new observation resets counts"
        );
        assert!(pump.deferred.is_none());
        pump.drive_observed(now, &mut counts).expect("idle drive");
        assert_eq!(counts, PumpWork::default());
    }

    #[test]
    fn observed_counter_overflow_is_sticky_until_explicit_reset() {
        let mut counts = PumpWork {
            timers_handled: u64::MAX,
            ..PumpWork::default()
        };
        PumpWork::increment(&mut counts.timers_handled, &mut counts.overflow);
        assert_eq!(counts.timers_handled, u64::MAX);
        assert!(counts.overflow);
        PumpWork::increment(&mut counts.endpoint_events, &mut counts.overflow);
        assert!(counts.overflow);
        counts.reset();
        assert_eq!(counts, PumpWork::default());
    }
}
