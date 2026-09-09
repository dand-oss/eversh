//! Ordinary client data loop for the disposable reliable-stream comparison.
//! Local adapters must expose unbuffered read/write acceptance. Terminal mode
//! activation and cancellation belong to the caller, after validated admission.

use crate::stream_floor_app::{InputSource, OutputSink};
use crate::stream_floor_io::ReadProgress;
use crate::stream_floor_ordinary::OrdinaryControl;
use crate::stream_floor_protocol::StreamLayout;
use crate::transport::{TransportError, INPUT_STREAM_PRIORITY};
use crate::wire::StreamRole;
use crate::Limits;
use std::future::Future;
use std::pin::Pin;
use std::task::Poll;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Return retained control ownership and the fully delivered byte count. The
/// caller must coordinate peer completion before closing/dropping the owner.
pub async fn run<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut control: OrdinaryControl,
    local_input: &mut R,
    local_output: &mut W,
    limits: Limits,
) -> Result<(OrdinaryControl, u64), TransportError> {
    let connection = control.connection.clone();
    let control_stopped = control.send.stopped();
    let result = tokio::select! {
        biased;
        _ = control_stopped => Err(TransportError::Stream),
        _ = connection.accept_bi() => Err(TransportError::Rejected),
        result = transfer(&mut control, local_input, local_output, limits) => result,
    };
    match result {
        Ok(bytes) => Ok((control, bytes)),
        Err(error) => {
            connection.close(
                noq::VarInt::from_u32(0x4555),
                b"everudp stream-floor client failed",
            );
            Err(error)
        }
    }
}

async fn transfer<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    control: &mut OrdinaryControl,
    local_input: &mut R,
    local_output: &mut W,
    limits: Limits,
) -> Result<u64, TransportError> {
    let mut layout = StreamLayout::default();
    if layout.register(control.send.id())? != StreamRole::Control
        || control.send.id() != control.recv.id()
    {
        return Err(TransportError::Rejected);
    }
    let connection = control.connection.clone();
    let mut input = connection
        .open_uni()
        .await
        .map_err(|_| TransportError::Stream)?;
    if layout.register(input.id())? != StreamRole::Input {
        return Err(TransportError::Rejected);
    }
    input
        .set_priority(INPUT_STREAM_PRIORITY)
        .map_err(|_| TransportError::Stream)?;
    let mut input_stopped = std::pin::pin!(input.stopped());
    let mut incoming = std::pin::pin!(connection.accept_uni());
    let mut extra = std::pin::pin!(connection.accept_uni());
    let mut output: Option<noq::RecvStream> = None;
    let mut source = InputSource::new(limits)?;
    let mut sink = OutputSink::new(limits)?;
    let mut input_fin = false;
    let mut input_acked = false;
    let mut output_eof = false;
    std::future::poll_fn(|cx| {
        // No unsolicited control response is legal: this client sends no pings.
        match control.recv.poll_read(cx, &mut [0_u8; 1]) {
            Poll::Ready(_) => return Poll::Ready(Err(TransportError::Stream)),
            Poll::Pending => {}
        }
        if output.is_some() && extra.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(TransportError::Rejected));
        }
        let mut progressed = false;
        if !input_acked {
            match input_stopped.as_mut().poll(cx) {
                Poll::Ready(Ok(None)) if input_fin => input_acked = true,
                Poll::Ready(_) => return Poll::Ready(Err(TransportError::Stream)),
                Poll::Pending => {}
            }
        }
        if let Some(buffer) = source.buffer() {
            let mut read = ReadBuf::new(buffer);
            match Pin::new(&mut *local_input).poll_read(cx, &mut read) {
                Poll::Ready(Ok(())) => {
                    let count = read.filled().len();
                    source.commit_read(count)?;
                    progressed = true;
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(TransportError::Io(error))),
                Poll::Pending => {}
            }
        }
        let writer = source.writer().ok_or(TransportError::Rejected)?;
        if !writer.is_complete() {
            match writer.poll_write_ordinary(&mut input, cx) {
                Poll::Ready(Ok(written)) => progressed |= written.accepted != 0,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                Poll::Pending => {}
            }
        }
        if source.finish_ready() && !input_fin {
            input.finish().map_err(|_| TransportError::Stream)?;
            input_fin = true;
            progressed = true;
        }
        if output.is_none() {
            match incoming.as_mut().poll(cx) {
                Poll::Ready(Ok(stream)) => {
                    if layout.register(stream.id())? != StreamRole::Output {
                        return Poll::Ready(Err(TransportError::Rejected));
                    }
                    output = Some(stream);
                    progressed = true;
                }
                Poll::Ready(Err(_)) => return Poll::Ready(Err(TransportError::Stream)),
                Poll::Pending => {}
            }
        }
        if let Some(output) = output.as_mut().filter(|_| !output_eof) {
            if let Some(reader) = sink.reader() {
                match reader.poll_read_ordinary(output, cx) {
                    Poll::Ready(Ok(ReadProgress::Record(_))) => progressed |= sink.stage()?,
                    Poll::Ready(Ok(ReadProgress::Consumed(count))) => progressed |= count != 0,
                    Poll::Ready(Ok(ReadProgress::CleanEof)) => output_eof = true,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                    Poll::Pending => {}
                }
            }
        }
        if let Some(bytes) = sink.pending() {
            match Pin::new(&mut *local_output).poll_write(cx, bytes) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(TransportError::Io(
                        std::io::ErrorKind::WriteZero.into(),
                    )))
                }
                Poll::Ready(Ok(count)) => {
                    sink.commit(count)?;
                    progressed = true;
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(TransportError::Io(error))),
                Poll::Pending => {}
            }
        }
        if output_eof {
            if !input_fin || sink.bytes_delivered() != source.bytes_read() {
                return Poll::Ready(Err(TransportError::Rejected));
            }
            if input_acked && layout.complete() {
                return Poll::Ready(Ok(sink.bytes_delivered()));
            }
        }
        if progressed {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    })
    .await
}
