//! Native roles for the reliable-stream experiment. No runtime is constructed
//! here; SSH acquisition completes and drops its runtime before client entry.

use super::{invalid, stream_profile, validate, Result, Runtime, SESSION_LIMIT};
use everpty::sys::{poll, PollFd, PollFlags};
use everudp::floor_pump::{FloorLimits, FloorPump};
use everudp::floor_reactor::FloorReactor;
use everudp::floor_socket::FloorSocket;
use everudp::stream_floor_fd::Descriptor;
use everudp::stream_floor_native::{
    NativeClientHandshake, NativeHandshakePoll, NativeServerHandshake,
};
use everudp::stream_floor_native_client::NativeClient;
use everudp::stream_floor_native_echo::{NativeEchoPoll, NativeServerEcho};
use everudp::stream_floor_native_run::{run_until, RunOutcome};
use everudp::transport::{stream_floor_client_config, stream_floor_server_config};
use everudp::wire::ConnectionRole;
use everudp::{
    BootstrapRecord, BootstrapRequest, ClientHello, ClientIdentity, GatewayGeneration,
    GatewayIdentity, InvitationStore, Limits, TerminalEdge, TerminalEvent,
};
use noq_proto::{ConnectionHandle, EndpointConfig, Event};
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::fd::{AsFd, BorrowedFd};
use std::time::{Duration, Instant};

fn wait_udp(
    reactor: &FloorReactor,
    immediate: bool,
    blocked: bool,
    deadline: Instant,
) -> Result<()> {
    let at = if immediate {
        Instant::now()
    } else {
        reactor
            .next_timeout()
            .map_or(deadline, |at| at.min(deadline))
    };
    let millis = at
        .saturating_duration_since(Instant::now())
        .as_nanos()
        .div_ceil(1_000_000)
        .min(u128::from(u32::MAX)) as u32;
    let mut fds = [PollFd::new(
        reactor.socket().as_fd(),
        PollFlags::POLLIN
            | if blocked {
                PollFlags::POLLOUT
            } else {
                PollFlags::empty()
            },
    )];
    match poll(&mut fds, Some(millis)) {
        Err(error) if error.kind() == io::ErrorKind::Interrupted => return Ok(()),
        result => {
            result?;
        }
    }
    if fds[0]
        .revents()
        .unwrap_or(PollFlags::empty())
        .intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL)
    {
        return Err(invalid("native UDP poll failed").into());
    }
    Ok(())
}

fn close(reactor: &mut FloorReactor, handle: ConnectionHandle, failed: bool) {
    if let Some(connection) = reactor.pump_mut().connection_mut(handle) {
        connection.close(
            Instant::now(),
            noq_proto::VarInt::from_u32(if failed { 0x4555 } else { 0 }),
            bytes::Bytes::from_static(b"stream-floor role finished"),
        );
    }
    let _ = reactor.step(Instant::now());
}

pub fn client(record: BootstrapRecord, identity: ClientIdentity, hello: ClientHello) -> Result<()> {
    let socket = everssh::transport::bind_udp(
        record.endpoint(),
        everssh::transport::UdpBindPolicy::RouteSelected,
        &everssh::Limits::default(),
    )?
    .into_socket();
    let stdin = io::stdin();
    let stdout = io::stdout();
    let stderr = io::stderr();
    client_on_fds(
        record,
        identity,
        hello,
        stdin.as_fd(),
        stdout.as_fd(),
        stderr.as_fd(),
        socket,
    )
}

pub(super) fn client_on_fds(
    record: BootstrapRecord,
    identity: ClientIdentity,
    hello: ClientHello,
    stdin: BorrowedFd<'_>,
    stdout: BorrowedFd<'_>,
    stderr: BorrowedFd<'_>,
    socket: UdpSocket,
) -> Result<()> {
    let limits = Limits::default();
    let endpoint = EndpointConfig::default();
    let socket = FloorSocket::new_stream_floor(socket, &endpoint)?;
    let mut pump =
        FloorPump::client_with_mtud(endpoint, FloorLimits::default(), !socket.may_fragment());
    let (config, mismatch) =
        stream_floor_client_config(&identity, record.server_spki_sha256(), &limits)?;
    stream_profile::client(
        Runtime::Native,
        &config,
        socket.max_transmit_segments().get(),
    )?;
    let handle = pump.connect(config, record.endpoint(), "localhost", Instant::now())?;
    let mut reactor = FloorReactor::new(pump, socket);
    let result: Result<()> = (|| {
        let deadline = Instant::now() + limits.initial_udp_budget();
        let mut handshake = NativeClientHandshake::new(hello, limits, deadline)?;
        let mut retained = Vec::with_capacity(128);
        let control = loop {
            if Instant::now() >= deadline {
                return Err(invalid("native admission deadline").into());
            }
            let before = reactor.step(Instant::now())?;
            while let Some((owner, event)) = reactor.pump_mut().poll_event() {
                if owner != handle || matches!(event, Event::ConnectionLost { .. }) {
                    return Err(invalid("native admission connection failed").into());
                }
                if retained.len() == 128 {
                    return Err(invalid("native admission event cap").into());
                }
                retained.push(event);
            }
            let state = handshake.poll(
                reactor
                    .pump_mut()
                    .connection_mut(handle)
                    .ok_or_else(|| invalid("missing connection"))?,
                Instant::now(),
            );
            let after = reactor.step(Instant::now())?;
            let mut new_event = false;
            while let Some((owner, event)) = reactor.pump_mut().poll_event() {
                if owner != handle || matches!(event, Event::ConnectionLost { .. }) {
                    return Err(invalid("native admission connection failed").into());
                }
                if retained.len() == 128 {
                    return Err(invalid("native admission event cap").into());
                }
                retained.push(event);
                new_event = true;
            }
            let state = state?;
            if let NativeHandshakePoll::Ready { stream } = state {
                break stream;
            }
            wait_udp(
                &reactor,
                before.exhausted
                    || after.exhausted
                    || new_event
                    || matches!(
                        state,
                        NativeHandshakePoll::Pending {
                            progressed: true,
                            ..
                        }
                    ),
                after.write_blocked,
                deadline,
            )?;
        };
        if mismatch.observed() {
            return Err(invalid("native SPKI mismatch").into());
        }
        let mut client = NativeClient::new(control, limits)?;
        for event in retained {
            client.event(
                reactor
                    .pump_mut()
                    .connection_mut(handle)
                    .ok_or_else(|| invalid("missing connection"))?,
                &event,
                Instant::now(),
            )?;
        }
        let mut terminal = TerminalEdge::stage(stdin, stdout, stderr)?;
        terminal.activate(ConnectionRole::Writer)?;
        let result: Result<()> = (|| {
            let mut input = Descriptor::new(stdin)?;
            let mut output = Descriptor::new(stdout)?;
            let deadline = Instant::now() + SESSION_LIMIT;
            loop {
                match run_until(
                    &mut reactor,
                    handle,
                    &mut client,
                    &mut input,
                    &mut output,
                    Some(terminal.signal_fd()?),
                    deadline,
                )? {
                    RunOutcome::Complete { .. } => return Ok(()),
                    RunOutcome::Signal => {
                        while let Some(event) = terminal.next_signal_event()? {
                            if matches!(event, TerminalEvent::Cancel(_)) {
                                return Err(io::Error::from(io::ErrorKind::Interrupted).into());
                            }
                            // The echo floor has no remote PTY to resize.
                        }
                    }
                }
            }
        })();
        let restored = terminal.deactivate();
        result?;
        restored?;
        Ok(())
    })();
    close(&mut reactor, handle, result.is_err());
    result
}

pub fn server(bind_ip: IpAddr, token: String, mut output: std::fs::File) -> Result<()> {
    let request = BootstrapRequest::decode_token(&token)?;
    validate(&request)?;
    let limits = Limits::default();
    let identity = GatewayIdentity::generate()?;
    let generation = GatewayGeneration::generate()?;
    let endpoint = EndpointConfig::default();
    let socket =
        FloorSocket::new_stream_floor(UdpSocket::bind(SocketAddr::new(bind_ip, 0))?, &endpoint)?;
    let address = socket.local_addr()?;
    let config = stream_floor_server_config(&identity, &limits)?;
    stream_profile::server(
        Runtime::Native,
        &config,
        socket.max_transmit_segments().get(),
    )?;
    let pump = FloorPump::server_with_mtud(
        endpoint,
        config,
        FloorLimits::default(),
        !socket.may_fragment(),
    );
    let mut reactor = FloorReactor::new(pump, socket);
    let mut invitations = InvitationStore::new(request.session(), generation, &limits)?;
    let ticket = invitations.issue(
        request.association_id(),
        request.role(),
        request.client_spki_sha256(),
        everpty::sys::clock_monotonic_ms()?,
    )?;
    let record = BootstrapRecord::new(
        address,
        identity.spki_sha256(),
        ticket.token().clone(),
        request.association_id(),
        generation,
        std::process::id(),
    )?;
    output.write_all(record.encode().as_str().as_bytes())?;
    output.flush()?;
    drop(output);
    let mut handle = None;
    let result: Result<()> = (|| {
        let mut deadline = Instant::now() + Duration::from_secs(20);
        let mut handshake = None;
        let mut retained = Vec::with_capacity(128);
        let mut echo: Option<NativeServerEcho> = None;
        let mut pending = None;
        loop {
            if Instant::now() >= deadline {
                return Err(invalid("native server deadline").into());
            }
            let before = reactor.step(Instant::now())?;
            let mut had_events = false;
            while let Some((owner, event)) =
                pending.take().or_else(|| reactor.pump_mut().poll_event())
            {
                had_events = true;
                if let Some(handle) = handle {
                    if owner != handle {
                        return Err(invalid("unexpected native connection").into());
                    }
                } else {
                    handle = Some(owner);
                    deadline = Instant::now() + limits.initial_udp_budget();
                    handshake = Some(NativeServerHandshake::new(limits, deadline)?);
                }
                if let Event::ConnectionLost { reason } = &event {
                    // Same lifecycle policy as ordinary: normal peer close ends
                    // the server, but is not a transcript/delivery receipt.
                    return if echo.is_some()
                        && matches!(reason, noq_proto::ConnectionError::ApplicationClosed(close) if close.error_code == noq_proto::VarInt::from_u32(0))
                    {
                        Ok(())
                    } else {
                        Err(invalid("native server connection failed").into())
                    };
                }
                if let Some(echo) = echo.as_mut() {
                    echo.event(
                        reactor
                            .pump_mut()
                            .connection_mut(owner)
                            .ok_or_else(|| invalid("missing connection"))?,
                        &event,
                        Instant::now(),
                    )?;
                } else {
                    if retained.len() == 128 {
                        return Err(invalid("native server admission event cap").into());
                    }
                    retained.push(event);
                }
            }
            let mut progressed = false;
            if let Some(handle) = handle {
                let connection = reactor
                    .pump_mut()
                    .connection_mut(handle)
                    .ok_or_else(|| invalid("missing connection"))?;
                if let Some(echo) = echo.as_mut() {
                    progressed = matches!(
                        echo.poll(connection, Instant::now())?,
                        NativeEchoPoll::Pending {
                            progressed: true,
                            ..
                        }
                    );
                } else if let Some(handshake) = handshake.as_mut() {
                    let state = handshake.poll(
                        connection,
                        &mut invitations,
                        Instant::now(),
                        everpty::sys::clock_monotonic_ms()?,
                    )?;
                    match state {
                        NativeHandshakePoll::Ready { stream } => {
                            let mut app = NativeServerEcho::new(stream, limits)?;
                            for event in retained.drain(..) {
                                app.event(connection, &event, Instant::now())?;
                            }
                            echo = Some(app);
                            deadline = Instant::now() + SESSION_LIMIT;
                            progressed = true;
                        }
                        NativeHandshakePoll::Pending {
                            progressed: progress,
                            ..
                        } => progressed = progress,
                    }
                }
            }
            let after = reactor.step(Instant::now())?;
            pending = reactor.pump_mut().poll_event();
            wait_udp(
                &reactor,
                before.exhausted
                    || after.exhausted
                    || had_events
                    || progressed
                    || pending.is_some(),
                after.write_blocked,
                deadline,
            )?;
        }
    })();
    if result.is_err() {
        if let Some(handle) = handle {
            close(&mut reactor, handle, true);
        }
    }
    result
}
