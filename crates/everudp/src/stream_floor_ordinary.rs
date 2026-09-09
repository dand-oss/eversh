//! Ordinary noQ stream-floor admission and control-stream retention.
//!
//! This is intentionally only the authenticated control handshake.  The
//! caller receives the same control streams after admission and owns all
//! subsequent application scheduling.  Reads are bounded to the current
//! record, so dropping the handshake reader cannot consume a following
//! control record.

use crate::stream_floor_app::EchoRelay;
use crate::stream_floor_handshake::{ClientHandshake, ServerHandshake};
use crate::stream_floor_io::{ReadProgress, RecordReader, RecordWriter};
use crate::stream_floor_protocol::StreamLayout;
use crate::stream_floor_protocol::{stream_role, validate_negotiated_profile};
use crate::transport::{stream_floor_authorize_initial, TransportError, CONTROL_STREAM_PRIORITY};
use crate::wire::StreamRole;
use crate::{ClientHello, InvitationStore, Limits};
use noq::{Connection, RecvStream, SendStream};
use std::future::Future;
use std::task::{Context, Poll};
use std::time::Duration;

const CLOSE_CODE: noq::VarInt = noq::VarInt::from_u32(0x4555);
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);

/// The established control stream pair returned after the initial handshake.
/// The connection is retained because subsequent stream admission belongs to
/// the caller, not to this disposable handshake helper.
pub struct OrdinaryControl {
    pub connection: Connection,
    pub send: SendStream,
    pub recv: RecvStream,
}

impl OrdinaryControl {
    pub fn close(self) {
        self.connection
            .close(CLOSE_CODE, b"everudp stream-floor close");
    }
}

/// Run the client side of the stream-floor handshake on an established TLS
/// connection.  The server reply must be fully written and validated before
/// this returns successfully.
pub async fn client_handshake(
    connection: Connection,
    hello: ClientHello,
    limits: Limits,
) -> Result<OrdinaryControl, TransportError> {
    client_handshake_until(connection, hello, limits, DEFAULT_HANDSHAKE_TIMEOUT).await
}

/// Bounded client handshake with an explicit timeout.
pub async fn client_handshake_until(
    connection: Connection,
    hello: ClientHello,
    limits: Limits,
    timeout: Duration,
) -> Result<OrdinaryControl, TransportError> {
    let failed = connection.clone();
    let result = tokio::time::timeout(timeout, client_inner(connection, hello, limits)).await;
    let result = match result {
        Ok(result) => result,
        Err(_) => Err(TransportError::Timeout),
    };
    if result.is_err() {
        failed.close(CLOSE_CODE, b"everudp stream-floor handshake failed");
    }
    result
}

/// Run the server side of the stream-floor handshake on an established TLS
/// connection.  Invitation/SPKI authorization executes after TLS completion,
/// and the monotonic timestamp is sampled immediately at that callback.
pub async fn server_handshake(
    connection: Connection,
    invitations: &mut InvitationStore,
    limits: Limits,
) -> Result<OrdinaryControl, TransportError> {
    server_handshake_until(connection, invitations, limits, DEFAULT_HANDSHAKE_TIMEOUT).await
}

/// Bounded server handshake with an explicit timeout.
pub async fn server_handshake_until(
    connection: Connection,
    invitations: &mut InvitationStore,
    limits: Limits,
    timeout: Duration,
) -> Result<OrdinaryControl, TransportError> {
    let failed = connection.clone();
    let result = tokio::time::timeout(timeout, server_inner(connection, invitations, limits)).await;
    let result = match result {
        Ok(result) => result,
        Err(_) => Err(TransportError::Timeout),
    };
    if result.is_err() {
        failed.close(CLOSE_CODE, b"everudp stream-floor handshake failed");
    }
    result
}

async fn client_inner(
    connection: Connection,
    hello: ClientHello,
    limits: Limits,
) -> Result<OrdinaryControl, TransportError> {
    validate_negotiated_profile(connection.handshake_data(), connection.max_datagram_size())?;
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|_| TransportError::Stream)?;
    require_control_stream(send.id(), recv.id())?;
    send.set_priority(CONTROL_STREAM_PRIORITY)
        .map_err(|_| TransportError::Stream)?;

    let mut handshake = ClientHandshake::new(hello, limits)?;
    write_pending(handshake.outgoing()?, &mut send).await?;

    let mut reader = RecordReader::new(crate::wire::StreamRole::Control, limits)
        .map_err(TransportError::from)?;
    let record = read_record(&mut reader, &mut recv).await?;
    handshake.receive_reply(record)?;
    reader.consume_record();
    if !handshake.ready() {
        return Err(TransportError::Rejected);
    }
    Ok(OrdinaryControl {
        connection,
        send,
        recv,
    })
}

async fn server_inner(
    connection: Connection,
    invitations: &mut InvitationStore,
    limits: Limits,
) -> Result<OrdinaryControl, TransportError> {
    validate_negotiated_profile(connection.handshake_data(), connection.max_datagram_size())?;
    let (mut send, mut recv) = connection
        .accept_bi()
        .await
        .map_err(|_| TransportError::Stream)?;
    require_control_stream(send.id(), recv.id())?;
    send.set_priority(CONTROL_STREAM_PRIORITY)
        .map_err(|_| TransportError::Stream)?;

    let mut reader = RecordReader::new(StreamRole::Control, limits)?;
    let record = read_record(&mut reader, &mut recv).await?;
    let mut handshake = ServerHandshake::new(limits)?;
    handshake.receive_hello(record, |hello| {
        // This callback is synchronous and holds no mutex across an await.
        let now_ms = everpty::sys::clock_monotonic_ms()?;
        let takeover = stream_floor_authorize_initial(&connection, hello, invitations, now_ms)?;
        if takeover {
            // The disposable floor has no takeover state machine.  Do not
            // silently turn an authenticated takeover into an ordinary writer.
            return Err(TransportError::Rejected);
        }
        Ok(false)
    })?;
    reader.consume_record();
    write_pending(handshake.outgoing()?, &mut send).await?;
    handshake.finish_reply()?;
    if !handshake.ready() {
        return Err(TransportError::Rejected);
    }
    Ok(OrdinaryControl {
        connection,
        send,
        recv,
    })
}

fn require_control_stream(send: noq::StreamId, recv: noq::StreamId) -> Result<(), TransportError> {
    if send != recv || stream_role(send)? != StreamRole::Control {
        return Err(TransportError::Rejected);
    }
    Ok(())
}

/// Serve the disposable three-stream echo after successful admission. Control
/// progress is independent of input/output backpressure. Returns only after the
/// final output FIN is acknowledged. This does not prove local sink delivery:
/// the caller must retain the returned control owner until the client completes
/// delivery and closes the connection, rather than dropping control at FIN ACK.
pub async fn serve_echo(
    mut control: OrdinaryControl,
    limits: Limits,
) -> Result<OrdinaryControl, TransportError> {
    let connection = control.connection.clone();
    let control_stopped = control.send.stopped();
    let result = tokio::select! {
        biased;
        _ = control_stopped => Err(TransportError::Stream),
        _ = connection.accept_bi() => Err(TransportError::Rejected),
        result = serve_echo_inner(&mut control, limits) => result,
    };
    if result.is_err() {
        connection.close(CLOSE_CODE, b"everudp stream-floor echo failed");
    }
    result.map(|()| control)
}

async fn serve_echo_inner(
    control: &mut OrdinaryControl,
    limits: Limits,
) -> Result<(), TransportError> {
    let mut layout = StreamLayout::default();
    if layout.register(control.send.id())? != StreamRole::Control
        || control.send.id() != control.recv.id()
    {
        return Err(TransportError::Rejected);
    }
    let mut output = control
        .connection
        .open_uni()
        .await
        .map_err(|_| TransportError::Stream)?;
    if layout.register(output.id())? != StreamRole::Output {
        return Err(TransportError::Rejected);
    }
    output
        .set_priority(crate::transport::OUTPUT_STREAM_PRIORITY)
        .map_err(|_| TransportError::Stream)?;
    let mut control_echo = EchoRelay::control(limits)?;
    let connection = control.connection.clone();
    let mut incoming = std::pin::pin!(connection.accept_uni());
    let mut input = std::future::poll_fn(|cx| {
        let progressed =
            match poll_echo(&mut control_echo, &mut control.recv, &mut control.send, cx) {
                Ok((progressed, false)) => progressed,
                Ok((_, true)) => return Poll::Ready(Err(TransportError::Stream)),
                Err(error) => return Poll::Ready(Err(error)),
            };
        match incoming.as_mut().poll(cx) {
            Poll::Ready(result) => Poll::Ready(result.map_err(|_| TransportError::Stream)),
            Poll::Pending => {
                if progressed {
                    cx.waker().wake_by_ref();
                }
                Poll::Pending
            }
        }
    })
    .await?;
    if layout.register(input.id())? != StreamRole::Input || !layout.complete() {
        return Err(TransportError::Rejected);
    }
    let mut data_echo = EchoRelay::new(limits)?;
    // The output writer may have no pending application record when the peer
    // stops it. Observe that event independently of subsequent write attempts.
    let output_stopped = output.stopped();
    let transfer = async {
        std::future::poll_fn(|cx| {
            let control_progress =
                match poll_echo(&mut control_echo, &mut control.recv, &mut control.send, cx) {
                    Ok((progressed, false)) => progressed,
                    Ok((_, true)) => return Poll::Ready(Err(TransportError::Stream)),
                    Err(error) => return Poll::Ready(Err(error)),
                };
            match poll_echo(&mut data_echo, &mut input, &mut output, cx) {
                Ok((_, true)) => Poll::Ready(Ok(())),
                Ok((progressed, false)) => {
                    if progressed || control_progress {
                        cx.waker().wake_by_ref();
                    }
                    Poll::Pending
                }
                Err(error) => Poll::Ready(Err(error)),
            }
        })
        .await?;
        output.finish().map_err(|_| TransportError::Stream)?;
        match output.stopped().await {
            Ok(None) => Ok(()),
            _ => Err(TransportError::Stream),
        }
    };
    tokio::select! {
        biased;
        _ = connection.accept_uni() => Err(TransportError::Rejected),
        error = async {
            match output_stopped.await {
                // Normal FIN acknowledgment is owned by transfer's final await.
                Ok(None) => std::future::pending::<TransportError>().await,
                _ => TransportError::Stream,
            }
        } => Err(error),
        result = transfer => result,
    }
}

/// One read and one write at most per turn. Pending relies on registered stream
/// wakers; positive progress reschedules through the runtime's fairness budget.
fn poll_echo(
    relay: &mut EchoRelay,
    recv: &mut RecvStream,
    send: &mut SendStream,
    cx: &mut Context<'_>,
) -> Result<(bool, bool), TransportError> {
    let mut progressed = false;
    if let Some(reader) = relay.input() {
        match reader.poll_read_ordinary(recv, cx) {
            Poll::Ready(Ok(ReadProgress::CleanEof)) => return Ok((false, true)),
            Poll::Ready(Ok(ReadProgress::Consumed(count))) => progressed |= count != 0,
            Poll::Ready(Ok(ReadProgress::Record(_))) => progressed |= relay.stage()?,
            Poll::Ready(Err(error)) => return Err(error.into()),
            Poll::Pending => {}
        }
    }
    if let Some(writer) = relay.output() {
        match writer.poll_write_ordinary(send, cx) {
            Poll::Ready(Ok(written)) => progressed |= written.accepted != 0,
            Poll::Ready(Err(error)) => return Err(error.into()),
            Poll::Pending => {}
        }
        progressed |= relay.complete_output()?;
    }
    Ok((progressed, false))
}

async fn write_pending(
    writer: &mut RecordWriter,
    stream: &mut SendStream,
) -> Result<(), TransportError> {
    while !writer.is_complete() {
        std::future::poll_fn(|cx| writer.poll_write_ordinary(stream, cx))
            .await
            .map_err(TransportError::from)?;
    }
    Ok(())
}

async fn read_record<'a>(
    reader: &'a mut RecordReader,
    stream: &'a mut RecvStream,
) -> Result<crate::wire::Record<'a>, TransportError> {
    loop {
        match std::future::poll_fn(|cx| reader.poll_read_ordinary(stream, cx))
            .await
            .map_err(TransportError::from)?
        {
            ReadProgress::Record(_) => {
                return reader.record().ok_or(TransportError::Rejected);
            }
            ReadProgress::Consumed(_) => continue,
            ReadProgress::CleanEof => return Err(TransportError::Stream),
        }
    }
}
