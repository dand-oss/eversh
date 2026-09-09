//! Synchronous, single-owner floor runner used by the disposable benchmark.
//!
//! This is deliberately not the production client or gateway.  After SSH has
//! supplied the bootstrap record it owns one noQ protocol pump and one UDP
//! socket on the calling thread.  Admission, TLS pinning, bounded datagrams,
//! and the exact reliable-datagram framing remain enabled.

use everpty::sys::{poll, PollFd, PollFlags};
use everudp::floor_admission::{AdmissionPoll, ServerAdmission};
use everudp::floor_client_admission::ClientAdmission;
use everudp::floor_pump::{FloorLimits, FloorPump};
use everudp::floor_reactor::FloorReactor;
use everudp::floor_socket::FloorSocket;
use everudp::reliable_datagram::{decode, AckState, Data, Direction, Frame};
use everudp::transport::{floor_client_config, floor_server_config};
use everudp::{
    BootstrapRecord, BootstrapRequest, ClientHello, ClientIdentity, GatewayGeneration,
    GatewayIdentity, InvitationStore, Limits, TerminalEdge, UdpBindPolicy,
};
use noq_proto::{EndpointConfig, Event};
use std::fs::File;
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::fd::AsFd;
use std::os::unix::fs::OpenOptionsExt;
use std::time::Instant;

use super::native_trace::{Stage, Trace};
use super::reactor_trace::{Anchor, Observation, Phase, ReactorTrace};
use super::{encode_packet, protocol_error, FloorResult, PacketPool};

fn record_native(trace: &mut Option<&mut Trace>, stage: Stage, sequence: u64) {
    if let Some(trace) = trace.as_deref_mut() {
        trace.record(stage, sequence);
    }
}

fn client_reactor(
    record: &BootstrapRecord,
    identity: &ClientIdentity,
    limits: &Limits,
) -> FloorResult<(FloorReactor, noq_proto::ConnectionHandle)> {
    let bound = everssh::transport::bind_udp(
        record.endpoint(),
        UdpBindPolicy::RouteSelected,
        &everssh::Limits::default(),
    )?;
    let socket = FloorSocket::new(bound.into_socket(), &EndpointConfig::default())?;
    let allow_mtud = !socket.may_fragment();
    let (config, _pin_mismatch) =
        floor_client_config(identity, record.server_spki_sha256(), limits)?;
    let mut pump = FloorPump::client_with_mtud(
        EndpointConfig::default(),
        FloorLimits::default(),
        allow_mtud,
    );
    let handle = pump.connect(config, record.endpoint(), "localhost", Instant::now())?;
    Ok((FloorReactor::new(pump, socket), handle))
}

fn server_reactor(
    bind_ip: IpAddr,
    identity: &GatewayIdentity,
    limits: &Limits,
) -> FloorResult<FloorReactor> {
    let socket = FloorSocket::new(
        UdpSocket::bind(SocketAddr::new(bind_ip, 0))?,
        &EndpointConfig::default(),
    )?;
    let allow_mtud = !socket.may_fragment();
    let pump = FloorPump::server_with_mtud(
        EndpointConfig::default(),
        floor_server_config(identity, limits)?,
        FloorLimits::default(),
        allow_mtud,
    );
    Ok(FloorReactor::new(pump, socket))
}

#[derive(Default)]
struct EventDrain {
    connected: Option<noq_proto::ConnectionHandle>,
    application_ready: bool,
    events_drained: u64,
}

fn drain_events(reactor: &mut FloorReactor) -> FloorResult<EventDrain> {
    drain_events_impl::<false>(reactor)
}

fn drain_events_impl<const OBSERVE: bool>(reactor: &mut FloorReactor) -> FloorResult<EventDrain> {
    let mut drained = EventDrain::default();
    while let Some((handle, event)) = reactor.pump_mut().poll_event() {
        if OBSERVE {
            drained.events_drained = drained
                .events_drained
                .checked_add(1)
                .ok_or_else(|| protocol_error("floor event count overflow"))?;
        }
        match event {
            Event::Connected => drained.connected = Some(handle),
            Event::DatagramReceived | Event::DatagramsUnblocked => {
                drained.application_ready = true;
            }
            Event::ConnectionLost { reason } => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    format!("floor connection lost: {reason}"),
                )
                .into())
            }
            _ => {}
        }
    }
    Ok(drained)
}

fn client_step(
    reactor: &mut FloorReactor,
    now: Instant,
    sequence: Option<u64>,
    phase: Phase,
    trace: &mut Option<&mut ReactorTrace>,
) -> FloorResult<(everudp::floor_reactor::StepResult, EventDrain)> {
    if let (Some(sequence), Some(trace)) = (sequence, trace.as_deref_mut()) {
        let timer_due = reactor
            .next_timeout()
            .is_some_and(|deadline| deadline <= now);
        let started = trace.begin_step();
        let mut work = everudp::floor_reactor::StepWork::default();
        let (result, events) = if trace.is_partitioned() {
            let result = reactor.step_observed_with_hook(now, &mut work, |phase, edge| {
                trace.record_phase(phase, edge);
            })?;
            trace.begin_drain();
            let events = drain_events_impl::<true>(reactor);
            trace.end_drain();
            (result, events?)
        } else {
            (
                reactor.step_observed(now, &mut work)?,
                drain_events_impl::<true>(reactor)?,
            )
        };
        trace.finish_step(
            started,
            Observation {
                phase,
                sequence,
                timer_due,
                work,
                result,
                events_drained: events.events_drained,
                application_ready: events.application_ready,
            },
        );
        Ok((result, events))
    } else {
        let result = reactor.step(now)?;
        Ok((result, drain_events(reactor)?))
    }
}

fn poll_timeout(
    now: Instant,
    protocol: Option<Instant>,
    application: Option<Instant>,
    immediate: bool,
) -> Option<u32> {
    if immediate {
        return Some(0);
    }
    protocol.into_iter().chain(application).min().map(|at| {
        at.saturating_duration_since(now)
            .as_nanos()
            .div_ceil(1_000_000)
            .try_into()
            .unwrap_or(u32::MAX)
    })
}

#[derive(Default)]
struct ClientPollWork {
    protocol_exhausted: bool,
    drain_limit_hit: bool,
    application_ready: bool,
}

impl ClientPollWork {
    fn immediate(&self) -> bool {
        self.protocol_exhausted || self.drain_limit_hit || self.application_ready
    }
}

fn wait_reactor(
    reactor: &FloorReactor,
    state: everudp::floor_reactor::StepResult,
    deadline: Option<Instant>,
    progressed: bool,
) -> FloorResult<()> {
    if progressed || state.exhausted {
        return Ok(());
    }
    let flags = if state.write_blocked {
        PollFlags::POLLIN | PollFlags::POLLOUT
    } else {
        PollFlags::POLLIN
    };
    let mut fds = [PollFd::new(reactor.socket().as_fd(), flags)];
    poll(
        &mut fds,
        poll_timeout(
            Instant::now(),
            reactor.next_timeout(),
            deadline,
            progressed || state.exhausted,
        ),
    )?;
    Ok(())
}

fn flush_output(edge: &mut TerminalEdge<'_>, pending: &mut Option<u8>) -> FloorResult<bool> {
    let Some(byte) = *pending else {
        return Ok(true);
    };
    match edge.write_stdout(&[byte]) {
        Ok(0) => Err(io::Error::from(io::ErrorKind::WriteZero).into()),
        Ok(1) => {
            *pending = None;
            Ok(true)
        }
        Ok(_) => Err(protocol_error("floor sink accepted invalid byte count").into()),
        Err(everudp::TerminalError::Io(error)) if error.kind() == io::ErrorKind::Interrupted => {
            Ok(true)
        }
        Err(everudp::TerminalError::Io(error)) if error.kind() == io::ErrorKind::WouldBlock => {
            Ok(false)
        }
        Err(error) => Err(error.into()),
    }
}

fn offer(connection: &mut noq_proto::Connection, packet: &bytes::Bytes) -> FloorResult<bool> {
    match connection.datagrams().send(packet.clone(), false) {
        Ok(()) => Ok(true),
        Err(noq_proto::SendDatagramError::Blocked(_)) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Return whether a pending datagram should be offered on this turn.
///
/// An initial packet has no retry deadline and is therefore eligible as soon
/// as it is encoded.  Once an offer is accepted, the deadline is populated;
/// retries remain suppressed until that deadline.  Keeping this predicate
/// separate makes the initial-offer fast path and the retry path share the
/// same backpressure rule.
fn pending_offer_due(deadline: Option<Instant>, now: Instant) -> bool {
    deadline.is_none_or(|at| now >= at)
}

/// Offer the retained packet when its initial/retry deadline permits it.
///
/// The callback is deliberately injected so the initial and retry paths use
/// identical deadline and ownership behavior while tests can exercise
/// WouldBlock without constructing a live QUIC connection.
fn offer_pending<F>(
    pending: &mut Option<(bytes::Bytes, Option<Instant>)>,
    now: Instant,
    mut send: F,
) -> FloorResult<bool>
where
    F: FnMut(&bytes::Bytes) -> FloorResult<bool>,
{
    let Some((packet, deadline)) = pending.as_mut() else {
        return Ok(false);
    };
    if !pending_offer_due(*deadline, now) {
        return Ok(false);
    }
    let accepted = send(packet)?;
    *deadline = accepted.then(|| now + super::RETRANSMIT_DELAY);
    Ok(accepted)
}

fn ensure_native_trace_compatible(trace: Option<&mut Trace>) -> FloorResult<()> {
    if trace.is_some() {
        return Err(protocol_error(
            "native stage tracing is incompatible with initial-offer scheduling",
        )
        .into());
    }
    Ok(())
}

/// Run one authenticated synchronous client floor after SSH bootstrap.
pub fn run_client(
    record: BootstrapRecord,
    identity: ClientIdentity,
    hello: ClientHello,
) -> FloorResult<()> {
    let mut diagnostic = super::NATIVE_TRACE_PATH
        .get()
        .map(|path| {
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            Ok::<_, io::Error>((Trace::new(8192), file))
        })
        .transpose()?;
    let mut reactor_diagnostic = super::REACTOR_TRACE_PATH
        .get()
        .map(|path| (path, false))
        .or_else(|| super::PARTITION_TRACE_PATH.get().map(|path| (path, true)))
        .map(|(path, partitioned)| {
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            let trace = if partitioned {
                ReactorTrace::new_partitioned(8192)
            } else {
                ReactorTrace::new(8192)
            };
            Ok::<_, io::Error>((trace, file))
        })
        .transpose()?;
    let result = run_client_inner(
        record,
        identity,
        hello,
        diagnostic.as_mut().map(|(trace, _)| trace),
        reactor_diagnostic.as_mut().map(|(trace, _)| trace),
    );
    if let Some((trace, file)) = diagnostic {
        let mut writer = io::BufWriter::new(file);
        trace.write_json(&mut writer, result.is_ok())?;
        writer.flush()?;
    }
    if let Some((trace, file)) = reactor_diagnostic {
        let mut writer = io::BufWriter::new(file);
        trace.write_json(&mut writer, result.is_ok())?;
        writer.flush()?;
    }
    result
}

fn run_client_inner(
    record: BootstrapRecord,
    identity: ClientIdentity,
    hello: ClientHello,
    mut trace: Option<&mut Trace>,
    mut reactor_trace: Option<&mut ReactorTrace>,
) -> FloorResult<()> {
    // The native stage trace schema intentionally records the old
    // pre-offer interval.  Initial input now takes the offer fast path below,
    // so exporting that schema would produce a plausible-looking but
    // semantically false trace.  Keep the diagnostic opt-in explicit until a
    // separately reviewed schema revision describes this schedule.
    ensure_native_trace_compatible(trace.as_deref_mut())?;
    if hello.association_id() != record.association_id()
        || hello.generation() != record.generation()
    {
        return Err(protocol_error("floor client bootstrap identity mismatch").into());
    }
    let limits = Limits::default();
    let (mut reactor, handle) = client_reactor(&record, &identity, &limits)?;
    let admission_deadline = Instant::now() + limits.initial_udp_budget();
    let mut admission = ClientAdmission::new(&hello, &limits, admission_deadline)?;
    let stdin = io::stdin();
    let stdout = io::stdout();
    let stderr = io::stderr();
    let mut terminal = TerminalEdge::stage(stdin.as_fd(), stdout.as_fd(), stderr.as_fd())?;
    let mut pool = PacketPool::new();
    let mut input = [0_u8; 64 * 1024];
    let mut sequence = 0_u64;
    let mut expected: Option<(u64, u8)> = None;
    let mut pending_input: Option<(bytes::Bytes, Option<Instant>)> = None;
    let mut pending_output: Option<u8> = None;
    let mut delivered_base = 0_u64;
    let mut ready = false;
    loop {
        let now = Instant::now();
        let traced_attempt = trace
            .as_ref()
            .and(pending_input.as_ref())
            .filter(|(_, deadline)| deadline.is_none_or(|at| now >= at))
            .and(expected.map(|(sequence, _)| sequence));
        if let Some(sequence) = traced_attempt {
            record_native(&mut trace, Stage::PreOfferReactorStart, sequence);
        }
        let (mut state, events) = client_step(
            &mut reactor,
            now,
            expected.map(|(sequence, _)| sequence),
            Phase::LoopTop,
            &mut reactor_trace,
        )?;
        if let Some(sequence) = traced_attempt {
            record_native(&mut trace, Stage::PreOfferReactorEnd, sequence);
        }
        let mut progressed = state.exhausted || events.application_ready;
        if !ready {
            let connection = reactor
                .pump_mut()
                .connection_mut(handle)
                .ok_or_else(|| protocol_error("floor client retired during admission"))?;
            match admission.poll(connection, Instant::now())? {
                AdmissionPoll::Ready { .. } => {
                    ready = true;
                    progressed = true;
                }
                AdmissionPoll::Pending {
                    progressed: made_progress,
                } => progressed |= made_progress,
            }
            if ready {
                terminal.activate(everudp::wire::ConnectionRole::Writer)?;
            }
        }
        if !ready {
            wait_reactor(&reactor, state, Some(admission_deadline), progressed)?;
            continue;
        }
        let drain_limit_hit;
        {
            let connection = reactor
                .pump_mut()
                .connection_mut(handle)
                .ok_or_else(|| protocol_error("floor client retired"))?;
            let mut drained = 0;
            for _ in 0..32 {
                let Some(packet) = connection.datagrams().recv() else {
                    break;
                };
                drained += 1;
                let Frame::Data(data) = decode(Direction::GatewayToClient, &packet, &limits)?
                else {
                    return Err(protocol_error("floor client received non-data frame").into());
                };
                let Data {
                    epoch: 1,
                    kind: everudp::wire::Kind::Output,
                    sequence: received,
                    payload,
                    acknowledgement,
                    ..
                } = data
                else {
                    return Err(protocol_error("floor output epoch mismatch").into());
                };
                if received < delivered_base {
                    continue;
                }
                let Some((wanted, byte)) = expected else {
                    return Err(protocol_error("floor output without input").into());
                };
                let next = received
                    .checked_add(1)
                    .ok_or_else(|| protocol_error("floor sequence overflow"))?;
                if received != wanted
                    || payload != [byte]
                    || acknowledgement
                        != (AckState {
                            epoch: 1,
                            base: next,
                            bits: 0,
                        })
                {
                    return Err(protocol_error("floor output frame mismatch").into());
                }
                // A retry can echo again while stdout is blocked. Validation
                // above guarantees the same byte; retain exactly one copy.
                pending_output = Some(byte);
            }
            drain_limit_hit = drained == 32;
        }
        if pending_output.is_some() {
            match flush_output(&mut terminal, &mut pending_output)? {
                true if pending_output.is_none() => {
                    record_native(&mut trace, Stage::SinkAccepted, sequence);
                    if let Some(trace) = reactor_trace.as_deref_mut() {
                        trace.anchor(Anchor::SinkAccepted, sequence);
                    }
                    expected = None;
                    pending_input = None;
                    delivered_base = sequence
                        .checked_add(1)
                        .ok_or_else(|| protocol_error("floor sequence overflow"))?;
                    sequence = delivered_base;
                }
                _ => {}
            }
        }
        let mut poll_work = ClientPollWork {
            protocol_exhausted: state.exhausted,
            drain_limit_hit,
            application_ready: false,
        };
        let now = Instant::now();
        let retry_due = pending_input
            .as_ref()
            .is_some_and(|(_, deadline)| pending_offer_due(*deadline, now));
        if retry_due {
            let connection = reactor
                .pump_mut()
                .connection_mut(handle)
                .ok_or_else(|| protocol_error("floor client retired during retry"))?;
            record_native(&mut trace, Stage::OfferStart, sequence);
            let accepted =
                offer_pending(&mut pending_input, now, |packet| offer(connection, packet))?;
            record_native(&mut trace, Stage::OfferEnd, sequence);
            if accepted {
                record_native(&mut trace, Stage::PostOfferReactorStart, sequence);
                let (next_state, events) = client_step(
                    &mut reactor,
                    now,
                    Some(sequence),
                    Phase::RetryPostOffer,
                    &mut reactor_trace,
                )?;
                state = next_state;
                record_native(&mut trace, Stage::PostOfferReactorEnd, sequence);
                poll_work.protocol_exhausted |= state.exhausted;
                // Sending can also receive an echo into the protocol's
                // application queue. The socket may no longer be readable.
                poll_work.application_ready |= events.application_ready;
            }
        }
        let write_blocked = state.write_blocked;
        let read_input = expected.is_none() && pending_input.is_none() && pending_output.is_none();
        let (stdin_ready, signal_ready) = {
            let mut fds = [
                PollFd::new(
                    reactor.socket().as_fd(),
                    if write_blocked {
                        PollFlags::POLLIN | PollFlags::POLLOUT
                    } else {
                        PollFlags::POLLIN
                    },
                ),
                PollFd::new(terminal.signal_fd()?, PollFlags::POLLIN),
                PollFd::new(
                    stdin.as_fd(),
                    if read_input {
                        PollFlags::POLLIN
                    } else {
                        PollFlags::empty()
                    },
                ),
                PollFd::new(
                    stdout.as_fd(),
                    if pending_output.is_some() {
                        PollFlags::POLLOUT
                    } else {
                        PollFlags::empty()
                    },
                ),
            ];
            let timeout = pending_input.as_ref().and_then(|(_, deadline)| *deadline);
            poll(
                &mut fds,
                poll_timeout(
                    Instant::now(),
                    reactor.next_timeout(),
                    timeout,
                    poll_work.immediate(),
                ),
            )?;
            (
                fds[2].revents().is_some_and(|events| {
                    events.intersects(PollFlags::POLLIN | PollFlags::POLLHUP)
                }),
                fds[1]
                    .revents()
                    .is_some_and(|events| events.intersects(PollFlags::POLLIN)),
            )
        };
        if signal_ready
            && matches!(
                terminal.next_signal_event()?,
                Some(everudp::TerminalEvent::Cancel(_))
            )
        {
            return Ok(());
        }
        if stdin_ready {
            let count = terminal.read_stdin(&mut input)?;
            if count == 0 {
                return Ok(());
            }
            if count != 1 {
                return Err(protocol_error("floor benchmark requires one-byte input").into());
            }
            record_native(&mut trace, Stage::TerminalRead, sequence);
            if let Some(trace) = reactor_trace.as_deref_mut() {
                trace.anchor(Anchor::InputRead, sequence);
            }
            let packet = encode_packet(
                &mut pool,
                Direction::ClientToGateway,
                sequence,
                AckState {
                    epoch: 1,
                    base: sequence,
                    bits: 0,
                },
                &input[..count],
            )?;
            record_native(&mut trace, Stage::Encoded, sequence);
            pending_input = Some((packet.clone(), None));
            pool.retire(packet);
            expected = Some((sequence, input[0]));

            // The first packet is ready now; offer it before the next loop's
            // unconditional protocol service.  A blocked offer keeps the
            // deadline as None, so the next turn services the protocol and
            // retries without dropping or rebuilding the exact packet.
            let offer_now = Instant::now();
            let accepted = {
                let connection = reactor
                    .pump_mut()
                    .connection_mut(handle)
                    .ok_or_else(|| protocol_error("floor client retired during initial offer"))?;
                offer_pending(&mut pending_input, offer_now, |packet| {
                    offer(connection, packet)
                })?
            };
            if accepted {
                // A send can make the protocol immediately readable.  Keep a
                // bounded post-offer service turn so the echo is not delayed,
                // while preserving the normal reactor/error handling path.
                // The next loop unconditionally steps and drains datagrams
                // before polling, so it recomputes readiness even if this
                // turn already consumed the socket's readable edge.
                let _ = client_step(
                    &mut reactor,
                    offer_now,
                    Some(sequence),
                    Phase::InitialPostOffer,
                    &mut reactor_trace,
                )?;
            }
        }
    }
}

/// Run one authenticated synchronous server floor and emit one bootstrap line.
pub fn run_server(bind_ip: IpAddr, request: BootstrapRequest, mut output: File) -> FloorResult<()> {
    let limits = Limits::default();
    let identity = GatewayIdentity::generate()?;
    let generation = GatewayGeneration::generate()?;
    let mut invitations = InvitationStore::new(request.session(), generation, &limits)?;
    let ticket = invitations.issue(
        request.association_id(),
        request.role(),
        request.client_spki_sha256(),
        everpty::sys::clock_monotonic_ms()?,
    )?;
    let mut reactor = server_reactor(bind_ip, &identity, &limits)?;
    let record = BootstrapRecord::new(
        reactor.socket().local_addr()?,
        identity.spki_sha256(),
        ticket.token().clone(),
        request.association_id(),
        generation,
        std::process::id(),
    )?;
    output.write_all(record.encode().as_str().as_bytes())?;
    output.flush()?;
    drop(output);
    let admission_deadline = Instant::now() + limits.initial_udp_budget();
    let mut admission = ServerAdmission::new(limits, admission_deadline)?;
    let mut handle = None;
    let mut pool = PacketPool::new();
    let mut pending_echo: Option<bytes::Bytes> = None;
    loop {
        let now = Instant::now();
        if admission.admitted_hello().is_none() && now >= admission_deadline {
            return Err(protocol_error("floor server admission timed out").into());
        }
        let state = reactor.step(now)?;
        let events = drain_events(&mut reactor)?;
        if let Some(new_handle) = events.connected {
            handle.get_or_insert(new_handle);
        }
        let Some(connection_handle) = handle else {
            wait_reactor(&reactor, state, Some(admission_deadline), false)?;
            continue;
        };
        let connection = reactor
            .pump_mut()
            .connection_mut(connection_handle)
            .ok_or_else(|| protocol_error("floor server retired during admission"))?;
        let mut progressed = events.application_ready;
        if admission.admitted_hello().is_none() {
            match admission.poll(
                connection,
                &mut invitations,
                Instant::now(),
                everpty::sys::clock_monotonic_ms()?,
            )? {
                AdmissionPoll::Ready { .. } => progressed = true,
                AdmissionPoll::Pending { progressed } => {
                    wait_reactor(&reactor, state, Some(admission_deadline), progressed)?;
                    continue;
                }
            }
        }
        if let Some(hello) = admission.admitted_hello() {
            if hello.association_id() != request.association_id() || hello.role() != request.role()
            {
                return Err(protocol_error("floor server association mismatch").into());
            }
        }
        for _ in 0..32 {
            if let Some(packet) = pending_echo.as_ref() {
                if !offer(connection, packet)? {
                    break;
                }
                pool.retire(pending_echo.take().expect("pending echo"));
                progressed = true;
            }
            let Some(packet) = connection.datagrams().recv() else {
                break;
            };
            progressed = true;
            let Frame::Data(data) = decode(Direction::ClientToGateway, &packet, &limits)? else {
                return Err(protocol_error("floor server received non-data frame").into());
            };
            if data.epoch != 1
                || data.kind != everudp::wire::Kind::Input
                || data.payload.len() != 1
                || data.acknowledgement
                    != (AckState {
                        epoch: 1,
                        base: data.sequence,
                        bits: 0,
                    })
            {
                return Err(protocol_error("floor input frame mismatch").into());
            }
            let next = data
                .sequence
                .checked_add(1)
                .ok_or_else(|| protocol_error("floor sequence overflow"))?;
            let echoed = encode_packet(
                &mut pool,
                Direction::GatewayToClient,
                data.sequence,
                AckState {
                    epoch: 1,
                    base: next,
                    bits: 0,
                },
                data.payload,
            )?;
            pending_echo = Some(echoed);
        }
        wait_reactor(&reactor, state, None, progressed)?;
    }
}

#[cfg(test)]
mod tests {
    use super::{ensure_native_trace_compatible, offer_pending, pending_offer_due, poll_timeout};
    use bytes::Bytes;
    use std::time::{Duration, Instant};

    #[test]
    fn pending_client_work_polls_terminal_without_blocking() {
        for mask in 0..8 {
            let work = super::ClientPollWork {
                protocol_exhausted: mask & 1 != 0,
                drain_limit_hit: mask & 2 != 0,
                application_ready: mask & 4 != 0,
            };
            let now = Instant::now();
            // Zero timeout still executes terminal poll and handles signals;
            // it must not become a continue that starves terminal descriptors.
            assert_eq!(
                poll_timeout(
                    now,
                    None,
                    Some(now + Duration::from_millis(2)),
                    work.immediate()
                ),
                Some(if mask == 0 { 2 } else { 0 }),
                "work mask {mask}",
            );
        }
    }

    #[test]
    fn polling_services_protocol_and_retry_deadlines_without_fixed_delay() {
        let now = Instant::now();
        let retry = now + super::super::RETRANSMIT_DELAY;
        let protocol = now + Duration::from_millis(1);
        assert_eq!(
            poll_timeout(now, Some(protocol), Some(retry), false),
            Some(1)
        );
        assert_eq!(
            poll_timeout(now, Some(retry), Some(protocol), false),
            Some(1)
        );
        assert_eq!(poll_timeout(now, None, Some(retry), false), Some(2));
        assert_eq!(poll_timeout(now, None, None, false), None);
        assert_eq!(poll_timeout(now, None, None, true), Some(0));
        assert_eq!(poll_timeout(now, Some(retry), None, true), Some(0));
        assert_eq!(poll_timeout(retry, None, Some(protocol), false), Some(0));
    }

    #[test]
    fn fractional_deadline_does_not_busy_spin() {
        let now = Instant::now();
        assert_eq!(
            poll_timeout(now, Some(now + Duration::from_micros(1)), None, false),
            Some(1)
        );
    }

    #[test]
    fn initial_offer_is_due_without_a_retry_deadline() {
        let now = Instant::now();
        assert!(pending_offer_due(None, now));
    }

    #[test]
    fn retry_offer_waits_for_deadline_but_blocked_initial_offer_remains_due() {
        let now = Instant::now();
        let retry_at = now + Duration::from_millis(1);
        assert!(!pending_offer_due(Some(retry_at), now));
        assert!(pending_offer_due(Some(retry_at), retry_at));
        // A WouldBlock initial offer leaves its deadline unset.  The next
        // service turn may retry the same retained packet immediately.
        assert!(pending_offer_due(None, now));
    }

    #[test]
    fn initial_offer_retains_exact_packet_when_send_is_blocked() {
        let now = Instant::now();
        let packet = Bytes::from_static(b"initial");
        let mut pending = Some((packet.clone(), None));
        let mut seen = None;
        assert!(!offer_pending(&mut pending, now, |candidate| {
            seen = Some(candidate.clone());
            Ok(false)
        })
        .expect("blocked offer"));
        assert_eq!(seen, Some(packet.clone()));
        assert_eq!(pending, Some((packet, None)));
    }

    #[test]
    fn accepted_initial_offer_sets_retry_deadline_and_preserves_packet() {
        let now = Instant::now();
        let packet = Bytes::from_static(b"accepted");
        let mut pending = Some((packet.clone(), None));
        assert!(offer_pending(&mut pending, now, |candidate| {
            assert_eq!(candidate, &packet);
            Ok(true)
        })
        .expect("accepted offer"));
        let (retained, deadline) = pending.expect("retained until acknowledgement");
        assert_eq!(retained, packet);
        assert_eq!(deadline, Some(now + super::super::RETRANSMIT_DELAY));
    }

    #[test]
    fn native_trace_is_rejected_for_initial_offer_schedule() {
        let mut trace = super::super::native_trace::Trace::new(1);
        let error = ensure_native_trace_compatible(Some(&mut trace)).expect_err("trace rejected");
        assert!(error.to_string().contains("initial-offer scheduling"));
        ensure_native_trace_compatible(None).expect("untraced candidate");
    }

    #[test]
    fn pending_offer_skips_early_retry_and_retains_packet_on_error() {
        let now = Instant::now();
        let deadline = now + super::super::RETRANSMIT_DELAY;
        let packet = Bytes::from_static(b"retry");
        let mut pending = Some((packet.clone(), Some(deadline)));
        assert!(
            !offer_pending(&mut pending, now, |_| panic!("early retry sent")).expect("not due")
        );
        let error = offer_pending(&mut pending, deadline, |candidate| {
            assert_eq!(candidate.as_ptr(), packet.as_ptr());
            Err(std::io::Error::from(std::io::ErrorKind::ConnectionAborted).into())
        });
        assert!(error.is_err());
        assert_eq!(pending, Some((packet, Some(deadline))));
    }

    #[test]
    fn blocked_offer_retries_same_storage_then_waits_until_accepted_deadline() {
        let now = Instant::now();
        let packet = Bytes::from_static(b"blocked");
        let mut pending = Some((packet.clone(), None));
        for accepted in [false, false, true] {
            assert_eq!(
                offer_pending(&mut pending, now, |candidate| {
                    assert_eq!(candidate.as_ptr(), packet.as_ptr());
                    Ok(accepted)
                })
                .expect("offer"),
                accepted
            );
        }
        assert!(
            !offer_pending(&mut pending, now, |_| panic!("accepted input sent twice"))
                .expect("retry suppressed")
        );
        assert_eq!(
            pending,
            Some((packet, Some(now + super::super::RETRANSMIT_DELAY)))
        );
    }
}
