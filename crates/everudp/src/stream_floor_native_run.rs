//! Synchronous descriptor/protocol owner for an admitted native stream client.
//! No Tokio driver or helper thread is used. Terminal activation and signal
//! interpretation belong to the caller; a signal returns with ownership intact.

use crate::floor_reactor::FloorReactor;
use crate::stream_floor_fd::Descriptor;
use crate::stream_floor_native_client::{ClientPoll, NativeClient};
use crate::transport::TransportError;
use everpty::sys::{poll, PollFd, PollFlags};
use noq_proto::ConnectionHandle;
use std::io;
use std::os::fd::{AsFd, BorrowedFd};
use std::time::Instant;

#[derive(Debug, PartialEq, Eq)]
pub enum RunOutcome {
    Complete {
        bytes: u64,
    },
    /// Caller must consume the signal, then either resume this owner or close it.
    Signal,
}

/// Run an already authenticated client until local delivery, signal readiness,
/// error, or the caller's experiment deadline. The reactor is retained on return
/// so the caller can coordinate clean connection shutdown after local delivery.
pub fn run_until(
    reactor: &mut FloorReactor,
    handle: ConnectionHandle,
    client: &mut NativeClient,
    input: &mut Descriptor<'_>,
    output: &mut Descriptor<'_>,
    signal: Option<BorrowedFd<'_>>,
    deadline: Instant,
) -> Result<RunOutcome, TransportError> {
    let result = run_inner(reactor, handle, client, input, output, signal, deadline);
    if result.is_err() {
        if let Some(connection) = reactor.pump_mut().connection_mut(handle) {
            connection.close(
                Instant::now(),
                noq_proto::VarInt::from_u32(0x4555),
                bytes::Bytes::from_static(b"everudp stream-floor owner failed"),
            );
        }
        // Best effort close transmission; preserve the original failure.
        let _ = reactor.step(Instant::now());
    }
    result
}

fn events(
    reactor: &mut FloorReactor,
    handle: ConnectionHandle,
    client: &mut NativeClient,
) -> Result<bool, TransportError> {
    let mut any = false;
    while let Some((owner, event)) = reactor.pump_mut().poll_event() {
        if owner != handle {
            return Err(TransportError::Rejected);
        }
        let connection = reactor
            .pump_mut()
            .connection_mut(handle)
            .ok_or(TransportError::Connection)?;
        client.event(connection, &event, Instant::now())?;
        any = true;
    }
    Ok(any)
}

fn run_inner(
    reactor: &mut FloorReactor,
    handle: ConnectionHandle,
    client: &mut NativeClient,
    input: &mut Descriptor<'_>,
    output: &mut Descriptor<'_>,
    signal: Option<BorrowedFd<'_>>,
    deadline: Instant,
) -> Result<RunOutcome, TransportError> {
    loop {
        if Instant::now() >= deadline {
            return Err(TransportError::Io(io::ErrorKind::TimedOut.into()));
        }
        let before = reactor
            .step(Instant::now())
            .map_err(|error| TransportError::Io(io::Error::other(error)))?;
        events(reactor, handle, client)?;
        let connection = reactor
            .pump_mut()
            .connection_mut(handle)
            .ok_or(TransportError::Connection)?;
        let state = client.poll(connection, Instant::now(), input, output)?;
        // Finalized receive credit and FIN/ACK work must reach the reactor even
        // when the application reports completion.
        let after = reactor
            .step(Instant::now())
            .map_err(|error| TransportError::Io(io::Error::other(error)))?;
        let new_events = events(reactor, handle, client)?;
        if let ClientPoll::Complete { bytes } = state {
            return Ok(RunOutcome::Complete { bytes });
        }
        let immediate = before.exhausted
            || after.exhausted
            || new_events
            || matches!(
                state,
                ClientPoll::Pending {
                    progressed: true,
                    ..
                }
            );
        let (read_input, write_output) = client.local_interests();
        let ready = wait(
            reactor.socket().as_fd(),
            read_input.then(|| input.as_fd()),
            write_output.then(|| output.as_fd()),
            signal,
            after.write_blocked,
            if immediate {
                Instant::now()
            } else {
                reactor
                    .next_timeout()
                    .map_or(deadline, |at| at.min(deadline))
            },
        )?;
        if ready.signal {
            return Ok(RunOutcome::Signal);
        }
        if ready.input {
            client.local_input_ready();
        }
        if ready.output {
            client.local_output_ready();
        }
    }
}

#[derive(Default)]
struct Ready {
    input: bool,
    output: bool,
    signal: bool,
}

fn wait(
    udp: BorrowedFd<'_>,
    input: Option<BorrowedFd<'_>>,
    output: Option<BorrowedFd<'_>>,
    signal: Option<BorrowedFd<'_>>,
    udp_blocked: bool,
    deadline: Instant,
) -> io::Result<Ready> {
    // Absent entries use UDP with no requested events, never an always-writable
    // terminal. Error events still wake the owner and are treated as failures.
    let mut fds = [
        PollFd::new(
            udp,
            PollFlags::POLLIN
                | if udp_blocked {
                    PollFlags::POLLOUT
                } else {
                    PollFlags::empty()
                },
        ),
        PollFd::new(
            input.unwrap_or(udp),
            if input.is_some() {
                PollFlags::POLLIN
            } else {
                PollFlags::empty()
            },
        ),
        PollFd::new(
            output.unwrap_or(udp),
            if output.is_some() {
                PollFlags::POLLOUT
            } else {
                PollFlags::empty()
            },
        ),
        PollFd::new(
            signal.unwrap_or(udp),
            if signal.is_some() {
                PollFlags::POLLIN
            } else {
                PollFlags::empty()
            },
        ),
    ];
    let remaining = deadline.saturating_duration_since(Instant::now());
    let millis = remaining.as_nanos().div_ceil(1_000_000);
    match poll(&mut fds, Some(millis.min(u128::from(u32::MAX)) as u32)) {
        Err(error) if error.kind() == io::ErrorKind::Interrupted => return Ok(Ready::default()),
        result => {
            result?;
        }
    }
    let flags = fds.map(|fd| fd.revents().unwrap_or(PollFlags::empty()));
    if flags
        .iter()
        .any(|flags| flags.intersects(PollFlags::POLLNVAL | PollFlags::POLLERR))
        || flags[0].contains(PollFlags::POLLHUP)
    {
        return Err(io::Error::other("stream-floor descriptor poll failed"));
    }
    Ok(Ready {
        input: input.is_some() && flags[1].intersects(PollFlags::POLLIN | PollFlags::POLLHUP),
        output: output.is_some() && flags[2].intersects(PollFlags::POLLOUT | PollFlags::POLLHUP),
        signal: signal.is_some() && flags[3].intersects(PollFlags::POLLIN | PollFlags::POLLHUP),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{Shutdown, UdpSocket};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    #[test]
    fn local_readiness_preserves_eof_and_signal_ownership() {
        let udp = UdpSocket::bind("127.0.0.1:0").expect("UDP");
        let (input, mut peer) = UnixStream::pair().expect("input");
        let (signal, mut signal_peer) = UnixStream::pair().expect("signal");
        let ready = wait(udp.as_fd(), None, None, None, false, Instant::now()).expect("idle");
        assert!(!ready.input && !ready.output && !ready.signal);
        peer.write_all(b"x").expect("input write");
        signal_peer.write_all(b"s").expect("signal write");
        let ready = wait(
            udp.as_fd(),
            Some(input.as_fd()),
            None,
            Some(signal.as_fd()),
            false,
            Instant::now() + Duration::from_secs(1),
        )
        .expect("ready");
        assert!(ready.input && ready.signal && !ready.output);
        let mut input = Descriptor::new(input.as_fd()).expect("input descriptor");
        let mut signal = Descriptor::new(signal.as_fd()).expect("signal descriptor");
        let mut byte = [0];
        assert_eq!(input.read(&mut byte).expect("input retained"), 1);
        assert_eq!(byte, *b"x");
        assert_eq!(signal.read(&mut byte).expect("signal retained"), 1);
        assert_eq!(byte, *b"s");
        peer.shutdown(Shutdown::Write).expect("EOF");
        let ready = wait(
            udp.as_fd(),
            Some(input.as_fd()),
            None,
            None,
            false,
            Instant::now() + Duration::from_secs(1),
        )
        .expect("EOF readiness");
        assert!(ready.input);
        assert_eq!(input.read(&mut byte).expect("actual EOF"), 0);
    }

    #[test]
    fn saturated_output_waits_until_peer_drains() {
        let udp = UdpSocket::bind("127.0.0.1:0").expect("UDP");
        let (output, peer) = UnixStream::pair().expect("output");
        let mut output = Descriptor::new(output.as_fd()).expect("output descriptor");
        let mut peer = Descriptor::new(peer.as_fd()).expect("peer descriptor");
        let block = [42; 16384];
        let mut sent = 0;
        let mut blocked = false;
        for _ in 0..1024 {
            match output.write(&block) {
                Ok(count) => sent += count,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    blocked = true;
                    break;
                }
                result => panic!("unexpected write: {result:?}"),
            }
        }
        assert!(
            blocked && sent > 0,
            "real socket must saturate within bound"
        );
        let ready = wait(
            udp.as_fd(),
            None,
            Some(output.as_fd()),
            None,
            false,
            Instant::now(),
        )
        .expect("blocked readiness");
        assert!(!ready.output);
        let mut received = 0;
        let mut bytes = [0; 16384];
        while received < sent {
            let count = peer.read(&mut bytes).expect("drain queued bytes");
            assert!(count > 0);
            assert!(bytes[..count].iter().all(|byte| *byte == 42));
            received += count;
        }
        let ready = wait(
            udp.as_fd(),
            None,
            Some(output.as_fd()),
            None,
            false,
            Instant::now() + Duration::from_secs(1),
        )
        .expect("rearmed output");
        assert!(ready.output);
        assert_eq!(output.write(b"tail").expect("resume write"), 4);
    }
}
