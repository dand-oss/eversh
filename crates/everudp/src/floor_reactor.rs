//! A bounded, synchronous socket owner for the disposable floor driver.
//!
//! `FloorReactor` deliberately stops at the UDP/protocol boundary.  It does
//! not perform TLS admission, stream I/O, terminal handling, or application
//! event polling.  The caller owns those concerns through [`FloorPump`].
//! There is one important ownership rule here: a received batch remains in
//! [`FloorSocket`] until every GRO segment has been handed to the pump, and a
//! generated transmit remains in the pump until the socket accepts it.

use std::{fmt, io, time::Instant};

use bytes::BytesMut;
use noq::udp::{EcnCodepoint as UdpEcn, Transmit as UdpTransmit};
use noq_proto::{EcnCodepoint, FourTuple};

use super::{
    floor_pump::{FloorPump, PumpWork},
    floor_socket::FloorSocket,
};

/// Caller-owned counters for one observed reactor step.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct StepWork {
    /// Protocol work accumulated across all pump drives in this step.
    pub pump: PumpWork,
    /// Calls to the bounded protocol driver, including idle calls.
    pub pump_drive_calls: u64,
    /// Attempts to submit a pending transmit to the socket.
    pub send_attempts: u64,
    /// Socket submissions accepted in full (possibly GSO batches).
    pub send_accepted: u64,
    /// Submissions rejected temporarily because the socket would block.
    pub send_would_block: u64,
    /// Interrupted socket submissions, including retries.
    pub send_interrupted: u64,
    /// Socket receive calls, including empty and would-block results.
    pub receive_calls: u64,
    /// Nonempty successful socket receive calls.
    pub receive_batches: u64,
    /// Receive descriptors returned, before GRO segmentation. This is not a
    /// count of physical network packets when GRO combines datagrams.
    pub receive_datagrams: u64,
    /// Successful receive calls returning zero descriptors.
    pub receive_empty: u64,
    /// Socket receive calls reporting no currently available input.
    pub receive_would_block: u64,
    /// Retained receive segments accepted by the pump, possibly deferred there.
    pub retained_gro_segments_delivered: u64,
    /// Any local or nested counter overflowed; the observation is invalid.
    pub overflow: bool,
}

impl StepWork {
    /// Clear counters before beginning another observed reactor step.
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

    fn add(value: &mut u64, amount: u64, overflow: &mut bool) {
        if let Some(next) = value.checked_add(amount) {
            *value = next;
        } else {
            *overflow = true;
        }
    }
}

/// Maximum protocol/receive/send turns performed by one [`FloorReactor::step`].
/// A caller can invoke `step` again after servicing the indicated poll state.
const MAX_TURNS: usize = 64;
/// An interrupted send is harmless, but retrying forever would violate the
/// reactor's bounded-work contract.
const MAX_INTERRUPTED_SENDS: usize = 3;

/// Summary of one bounded reactor turn.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct StepResult {
    /// Number of bounded turns consumed.
    pub work: usize,
    /// True only when the finite turn budget was consumed.  A false result
    /// means the caller should poll (or handle `write_blocked`) before calling
    /// `step` again.
    pub exhausted: bool,
    /// True when a pending datagram could not be written yet.  The exact
    /// datagram remains pinned in the pump.
    pub write_blocked: bool,
}

/// Coarse synchronous operation surrounding one reactor step action.
///
/// These hooks carry no clocks, packet data, addresses, or payloads. They are
/// intended for a caller-owned diagnostic recorder; normal `step` and
/// `step_observed` paths install a no-op hook.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum StepPhase {
    /// One call into the bounded protocol owner.
    PumpDrive,
    /// One raw UDP send attempt.
    Send,
    /// Retained GRO segment processing, including an empty-batch check.
    Segment,
    /// One raw UDP receive call.
    Receive,
}

/// Edge of a hooked reactor operation.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum StepEdge {
    Begin,
    End,
}

/// Errors from the synchronous socket/protocol boundary.
#[derive(Debug)]
pub enum ReactorError {
    /// Protocol state rejected the operation.  Any pending transmit remains
    /// owned by the pump, including when the error came from a send attempt.
    Pump(super::floor_pump::FloorError),
    /// Raw socket receive failure.
    Receive(io::Error),
    /// Raw socket send failure.  This includes EMSGSIZE and every other
    /// non-WouldBlock error; no send error is reported as successful.
    Send(io::Error),
    /// The pump's bounded deferred receive handoff is full.  Preserve the
    /// datagram so a caller can apply its own backpressure policy.
    ReceiveBackpressure { data: BytesMut },
}

impl fmt::Display for ReactorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pump(error) => write!(f, "floor pump: {error}"),
            Self::Receive(error) => write!(f, "UDP receive: {error}"),
            Self::Send(error) => write!(f, "UDP send: {error}"),
            Self::ReceiveBackpressure { .. } => f.write_str("floor receive handoff is full"),
        }
    }
}

impl std::error::Error for ReactorError {}

/// A single-owner, synchronous protocol/socket reactor.
pub struct FloorReactor {
    pump: FloorPump,
    socket: FloorSocket,
    /// Number of descriptors in the currently retained socket batch.
    batch_len: usize,
    /// Current descriptor in that batch.
    batch_index: usize,
    /// Byte offset of the next GRO segment in the current descriptor.
    segment_offset: usize,
    /// Owned copy of the current GRO descriptor, split without per-segment
    /// allocation. The socket receive buffers remain untouched until the
    /// whole batch is consumed.
    slot_data: Option<BytesMut>,
    slot_stride: usize,
    slot_addr: std::net::SocketAddr,
    slot_dst_ip: Option<std::net::IpAddr>,
    slot_ecn: Option<UdpEcn>,
}

impl FloorReactor {
    /// Construct a reactor from an already configured protocol owner and UDP
    /// socket.  Authentication and endpoint configuration stay with `pump`.
    pub fn new(pump: FloorPump, socket: FloorSocket) -> Self {
        Self {
            pump,
            socket,
            batch_len: 0,
            batch_index: 0,
            segment_offset: 0,
            slot_data: None,
            slot_stride: 0,
            slot_addr: "[::]:0".parse().expect("literal unspecified address"),
            slot_dst_ip: None,
            slot_ecn: None,
        }
    }

    /// Mutable protocol access for the caller's handshake and stream layer.
    pub fn pump_mut(&mut self) -> &mut FloorPump {
        &mut self.pump
    }

    /// Shared socket access for polling and route inspection.
    pub fn socket(&self) -> &FloorSocket {
        &self.socket
    }

    /// Earliest protocol timer, if any.
    pub fn next_timeout(&self) -> Option<Instant> {
        self.pump.next_timeout()
    }

    /// Drive protocol and UDP I/O for a finite number of turns.
    ///
    /// A pending transmit is always attempted before another receive.  A
    /// `WouldBlock` leaves the exact bytes and all metadata in place.  GRO
    /// segments are copied into one `BytesMut` at the pump boundary and the
    /// receive batch is not overwritten until its cursor reaches the end.
    pub fn step(&mut self, now: Instant) -> Result<StepResult, ReactorError> {
        self.step_impl::<false, _>(now, None, &mut |_, _| {})
    }

    /// Drive one bounded reactor turn while recording execution counters in
    /// the caller-owned slot. The slot is reset at the start of this call.
    pub fn step_observed(
        &mut self,
        now: Instant,
        work: &mut StepWork,
    ) -> Result<StepResult, ReactorError> {
        work.reset();
        self.step_impl::<true, _>(now, Some(work), &mut |_, _| {})
    }

    /// Observed step with a typed, allocation-free phase hook.
    ///
    /// Each begin has exactly one matching end, including when the underlying
    /// operation returns an error. The hook runs synchronously on this thread;
    /// it must not retain references (the callback receives only `Copy` enums).
    pub fn step_observed_with_hook<F>(
        &mut self,
        now: Instant,
        work: &mut StepWork,
        mut hook: F,
    ) -> Result<StepResult, ReactorError>
    where
        F: FnMut(StepPhase, StepEdge),
    {
        work.reset();
        self.step_impl::<true, F>(now, Some(work), &mut hook)
    }

    fn step_impl<const OBSERVE: bool, F: FnMut(StepPhase, StepEdge)>(
        &mut self,
        now: Instant,
        mut observed: Option<&mut StepWork>,
        hook: &mut F,
    ) -> Result<StepResult, ReactorError> {
        let mut work = 0;
        let mut interrupted = 0;

        while work < MAX_TURNS {
            work += 1;
            // This is intentionally called even while a send is blocked: due
            // timers and endpoint events must remain visible to the caller.
            emit::<OBSERVE, _>(hook, StepPhase::PumpDrive, StepEdge::Begin);
            if OBSERVE {
                let counters = observed
                    .as_deref_mut()
                    .expect("observed reactor has counters");
                StepWork::increment(&mut counters.pump_drive_calls, &mut counters.overflow);
                let drive_result = self.pump.drive_with_max_datagrams_observed_into(
                    now,
                    self.socket.max_transmit_segments(),
                    &mut counters.pump,
                );
                emit::<OBSERVE, _>(hook, StepPhase::PumpDrive, StepEdge::End);
                drive_result.map_err(ReactorError::Pump)?;
                counters.overflow |= counters.pump.overflow;
            } else {
                let drive_result = self
                    .pump
                    .drive_with_max_datagrams(now, self.socket.max_transmit_segments());
                emit::<OBSERVE, _>(hook, StepPhase::PumpDrive, StepEdge::End);
                drive_result.map_err(ReactorError::Pump)?;
            }

            if self.pump.pending_transmit().is_some() {
                // Keep the borrow of the pump entirely inside this block.  A
                // successful socket write must then be able to mutably confirm
                // and recycle the pump's retained allocation.
                let send_result = {
                    let pending = self
                        .pump
                        .pending_transmit()
                        .expect("pending transmit checked above");
                    let transmit = UdpTransmit {
                        destination: pending.transmit().destination,
                        ecn: pending.transmit().ecn.map(to_udp_ecn),
                        contents: pending.bytes(),
                        segment_size: pending.transmit().segment_size,
                        src_ip: pending.transmit().src_ip,
                    };
                    if OBSERVE {
                        let counters = observed
                            .as_deref_mut()
                            .expect("observed reactor has counters");
                        StepWork::increment(&mut counters.send_attempts, &mut counters.overflow);
                    }
                    emit::<OBSERVE, _>(hook, StepPhase::Send, StepEdge::Begin);
                    let result = self.socket.try_send(&transmit);
                    emit::<OBSERVE, _>(hook, StepPhase::Send, StepEdge::End);
                    result.map(|()| pending.bytes().len())
                };
                match send_result {
                    Ok(accepted) => {
                        if OBSERVE {
                            let counters = observed
                                .as_deref_mut()
                                .expect("observed reactor has counters");
                            StepWork::increment(
                                &mut counters.send_accepted,
                                &mut counters.overflow,
                            );
                        }
                        self.pump
                            .confirm_transmit(accepted)
                            .map_err(ReactorError::Pump)?;
                        interrupted = 0;
                        continue;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if OBSERVE {
                            let counters = observed
                                .as_deref_mut()
                                .expect("observed reactor has counters");
                            StepWork::increment(
                                &mut counters.send_would_block,
                                &mut counters.overflow,
                            );
                        }
                        return Ok(StepResult {
                            work,
                            exhausted: false,
                            write_blocked: true,
                        });
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                        if OBSERVE {
                            let counters = observed
                                .as_deref_mut()
                                .expect("observed reactor has counters");
                            StepWork::increment(
                                &mut counters.send_interrupted,
                                &mut counters.overflow,
                            );
                        }
                        interrupted += 1;
                        if interrupted < MAX_INTERRUPTED_SENDS {
                            continue;
                        }
                        return Err(ReactorError::Send(error));
                    }
                    Err(error) => return Err(ReactorError::Send(error)),
                }
            }

            emit::<OBSERVE, _>(hook, StepPhase::Segment, StepEdge::Begin);
            let segment_result = self.advance_segment::<OBSERVE>(now, &mut observed);
            emit::<OBSERVE, _>(hook, StepPhase::Segment, StepEdge::End);
            if segment_result? {
                continue;
            }

            if OBSERVE {
                let counters = observed
                    .as_deref_mut()
                    .expect("observed reactor has counters");
                StepWork::increment(&mut counters.receive_calls, &mut counters.overflow);
            }
            emit::<OBSERVE, _>(hook, StepPhase::Receive, StepEdge::Begin);
            let receive_result = self.socket.receive();
            emit::<OBSERVE, _>(hook, StepPhase::Receive, StepEdge::End);
            match receive_result {
                Ok(count) => {
                    self.batch_len = count;
                    self.batch_index = 0;
                    self.segment_offset = 0;
                    if count == 0 {
                        if OBSERVE {
                            let counters = observed
                                .as_deref_mut()
                                .expect("observed reactor has counters");
                            StepWork::increment(
                                &mut counters.receive_empty,
                                &mut counters.overflow,
                            );
                        }
                        return Ok(StepResult {
                            work,
                            exhausted: false,
                            write_blocked: false,
                        });
                    }
                    if OBSERVE {
                        let counters = observed
                            .as_deref_mut()
                            .expect("observed reactor has counters");
                        StepWork::increment(&mut counters.receive_batches, &mut counters.overflow);
                        StepWork::add(
                            &mut counters.receive_datagrams,
                            count as u64,
                            &mut counters.overflow,
                        );
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if OBSERVE {
                        let counters = observed
                            .as_deref_mut()
                            .expect("observed reactor has counters");
                        StepWork::increment(
                            &mut counters.receive_would_block,
                            &mut counters.overflow,
                        );
                    }
                    return Ok(StepResult {
                        work,
                        exhausted: false,
                        write_blocked: false,
                    });
                }
                Err(error) => return Err(ReactorError::Receive(error)),
            }
        }

        Ok(StepResult {
            work,
            exhausted: true,
            write_blocked: false,
        })
    }

    /// Process at most one retained GRO segment.  Returning `false` means the
    /// current batch is empty and the caller may perform another socket read.
    fn advance_segment<const OBSERVE: bool>(
        &mut self,
        now: Instant,
        observed: &mut Option<&mut StepWork>,
    ) -> Result<bool, ReactorError> {
        while self.batch_index < self.batch_len {
            if self.slot_data.is_none() {
                let Some((meta, bytes)) = self.socket.packet(self.batch_index) else {
                    return Err(ReactorError::Receive(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "UDP receive batch cursor points outside metadata",
                    )));
                };
                if meta.len == 0 {
                    self.batch_index += 1;
                    continue;
                }
                if meta.stride == 0 {
                    // FloorSocket validates this invariant, but keep the
                    // reactor defensive if a future socket implementation
                    // changes it.
                    return Err(ReactorError::Receive(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "UDP receive metadata has zero GRO stride",
                    )));
                }
                self.slot_data = Some(BytesMut::from(bytes));
                self.slot_stride = meta.stride;
                self.slot_addr = meta.addr;
                self.slot_dst_ip = meta.dst_ip;
                self.slot_ecn = meta.ecn;
                self.segment_offset = 0;
            }

            let data = self.slot_data.as_mut().expect("slot initialized");
            let segment_len = self.slot_stride.min(data.len());
            let segment = data.split_to(segment_len);
            self.segment_offset = self.segment_offset.saturating_add(segment_len);
            let path = FourTuple::new(self.slot_addr, self.slot_dst_ip);
            let ecn = self.slot_ecn.map(to_proto_ecn);
            let receive_result = if OBSERVE {
                let counters = observed
                    .as_deref_mut()
                    .expect("observed reactor has counters");
                self.pump
                    .receive_observed(path, ecn, segment, now, &mut counters.pump)
            } else {
                self.pump.receive(path, ecn, segment, now)
            };
            receive_result.map_err(|error| match error {
                super::floor_pump::FloorError::ReceiveBackpressure { data } => {
                    ReactorError::ReceiveBackpressure { data }
                }
                other => ReactorError::Pump(other),
            })?;
            if OBSERVE {
                let counters = observed
                    .as_deref_mut()
                    .expect("observed reactor has counters");
                StepWork::increment(
                    &mut counters.retained_gro_segments_delivered,
                    &mut counters.overflow,
                );
                counters.overflow |= counters.pump.overflow;
            }
            if self.slot_data.as_ref().is_some_and(BytesMut::is_empty) {
                self.batch_index += 1;
                self.segment_offset = 0;
                self.slot_data = None;
            } else {
                // Keep the owned slot and cursor for the next bounded turn.
            }
            return Ok(true);
        }
        self.batch_len = 0;
        self.batch_index = 0;
        self.segment_offset = 0;
        self.slot_data = None;
        Ok(false)
    }
}

fn to_proto_ecn(value: UdpEcn) -> EcnCodepoint {
    match value {
        UdpEcn::Ect0 => EcnCodepoint::Ect0,
        UdpEcn::Ect1 => EcnCodepoint::Ect1,
        UdpEcn::Ce => EcnCodepoint::Ce,
    }
}

#[inline(always)]
fn emit<const OBSERVE: bool, F: FnMut(StepPhase, StepEdge)>(
    hook: &mut F,
    phase: StepPhase,
    edge: StepEdge,
) {
    if OBSERVE {
        hook(phase, edge);
    }
}

fn to_udp_ecn(value: EcnCodepoint) -> UdpEcn {
    match value {
        EcnCodepoint::Ect0 => UdpEcn::Ect0,
        EcnCodepoint::Ect1 => UdpEcn::Ect1,
        EcnCodepoint::Ce => UdpEcn::Ce,
    }
}

#[cfg(test)]
mod observation_tests {
    use super::StepWork;

    #[cfg(feature = "stream-floor")]
    #[test]
    fn blocked_udp_send_retains_exact_packet_until_one_real_acceptance() {
        use super::FloorReactor;
        use crate::floor_pump::{FloorLimits, FloorPump, PendingTransmit};
        use crate::floor_socket::FloorSocket;
        use crate::transport::stream_floor_client_config;
        use crate::{ClientIdentity, GatewayIdentity, Limits};
        use std::net::UdpSocket;
        use std::num::NonZeroUsize;
        use std::time::{Duration, Instant};

        let receiver = UdpSocket::bind("127.0.0.1:0").expect("receiver");
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("bounded receive");
        let endpoint = noq_proto::EndpointConfig::default();
        let socket = FloorSocket::new_stream_floor(
            UdpSocket::bind("127.0.0.1:0").expect("sender"),
            &endpoint,
        )
        .expect("socket adapter");
        let local = socket.local_addr().expect("sender address");
        let mut pump = FloorPump::client(endpoint, FloorLimits::default());
        let server = GatewayIdentity::generate().expect("server identity");
        let client = ClientIdentity::generate().expect("client identity");
        let (config, _) =
            stream_floor_client_config(&client, server.spki_sha256(), &Limits::default())
                .expect("stream profile");
        let now = Instant::now();
        pump.connect(
            config,
            receiver.local_addr().expect("receiver address"),
            "localhost",
            now,
        )
        .expect("connect");
        pump.drive_with_max_datagrams(now, NonZeroUsize::new(1).expect("one datagram"))
            .expect("initial flight");
        let metadata = |pending: PendingTransmit<'_>| {
            let meta = pending.transmit();
            (
                meta.destination,
                meta.ecn,
                meta.size,
                meta.segment_size,
                meta.src_ip,
            )
        };
        let pending = pump.pending_transmit().expect("initial packet");
        let expected = pending.bytes().to_vec();
        let pointer = pending.bytes().as_ptr();
        let expected_metadata = metadata(pending);
        let mut reactor = FloorReactor::new(pump, socket);
        // This datagram must remain in the socket until the retained send is
        // accepted; reading it early could overwrite a retained receive batch.
        receiver
            .send_to(b"queued receive while send blocked", local)
            .expect("queued receive");
        for _ in 0..2 {
            reactor.socket.block_next_send();
            let mut work = StepWork::default();
            let result = reactor.step_observed(now, &mut work).expect("blocked turn");
            assert!(result.write_blocked && !result.exhausted);
            assert_eq!(work.send_attempts, 1);
            assert_eq!(work.send_would_block, 1);
            assert_eq!(work.send_accepted, 0);
            assert_eq!(work.receive_calls, 0);
            let retained = reactor.pump.pending_transmit().expect("packet retained");
            assert_eq!(retained.bytes(), expected);
            assert_eq!(retained.bytes().as_ptr(), pointer);
            assert_eq!(metadata(retained), expected_metadata);
        }
        let mut work = StepWork::default();
        let result = reactor
            .step_observed(now, &mut work)
            .expect("writable retry");
        assert!(!result.write_blocked);
        assert_eq!(work.send_accepted, 1);
        assert_eq!(work.send_would_block, 0);
        assert_eq!(work.receive_datagrams, 1);
        assert!(reactor.pump.pending_transmit().is_none());
        let mut received = [0; 65536];
        let (count, source) = receiver
            .recv_from(&mut received)
            .expect("real UDP delivery");
        assert_eq!(source, local);
        assert_eq!(&received[..count], expected);
        reactor
            .step(now)
            .expect("idle turn before any retransmission timer");
        receiver
            .set_nonblocking(true)
            .expect("nonblocking duplicate check");
        assert_eq!(
            receiver
                .recv_from(&mut received)
                .expect_err("no duplicate acceptance")
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn overflow_does_not_wrap_and_remains_invalid_until_reset() {
        let mut work = StepWork {
            receive_datagrams: u64::MAX - 1,
            ..StepWork::default()
        };
        StepWork::add(&mut work.receive_datagrams, 2, &mut work.overflow);
        assert!(work.overflow);
        assert!(work.receive_datagrams >= u64::MAX - 1);
        StepWork::increment(&mut work.receive_calls, &mut work.overflow);
        assert!(work.overflow);
        work.reset();
        assert_eq!(work, StepWork::default());
    }

    #[test]
    fn segment_error_still_emits_end_edge() {
        use super::{FloorReactor, ReactorError, StepEdge, StepPhase};
        use crate::{
            floor_pump::{FloorLimits, FloorPump},
            floor_socket::FloorSocket,
        };
        let config = noq_proto::EndpointConfig::default();
        let socket = FloorSocket::new(
            std::net::UdpSocket::bind("127.0.0.1:0").expect("loopback socket"),
            &config,
        )
        .expect("UDP socket state");
        let pump = FloorPump::client(config, FloorLimits::default());
        let mut reactor = FloorReactor::new(pump, socket);
        // A retained batch cursor without a received descriptor is invalid.
        reactor.batch_len = 1;
        let mut edges = Vec::new();
        let result = reactor.step_observed_with_hook(
            std::time::Instant::now(),
            &mut StepWork::default(),
            |phase, edge| edges.push((phase, edge)),
        );
        assert!(matches!(result, Err(ReactorError::Receive(_))));
        assert_eq!(
            edges,
            vec![
                (StepPhase::PumpDrive, StepEdge::Begin),
                (StepPhase::PumpDrive, StepEdge::End),
                (StepPhase::Segment, StepEdge::Begin),
                (StepPhase::Segment, StepEdge::End)
            ]
        );
    }
}
