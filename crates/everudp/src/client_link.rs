//! Live client ownership of the three direction-implied QUIC streams.

use crate::actor::{LinkError, RecordReader};
use crate::client::{
    ClientAssociation, ClientError, OutputDisposition, OutputOperation, OutputStage,
};
use crate::handshake::ServerHello;
use crate::queues::{DeliveryDecision, QueueError};
use crate::transport::{
    ClientSession, ASSOCIATION_CAPACITY_CLOSE_CODE, CONTROL_STREAM_PRIORITY, INPUT_STREAM_PRIORITY,
    WRITER_BUSY_CLOSE_CODE,
};
use crate::wire::{Ack, EpochGap, Kind, StreamRole};
use crate::{Limits, WireError};
#[cfg(feature = "datagram-spike")]
use bytes::Bytes;
use noq::{Connection, RecvStream, SendStream, VarInt};
use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

const CLOSE_CODE: VarInt = VarInt::from_u32(0x4555);
const RESUME_CLOSE_CODE: VarInt = VarInt::from_u32(0x4552);
const NORMAL_LINK_CLOSE_REASON: &[u8] = b"everudp link closed";

#[derive(Debug)]
pub enum ClientLinkError {
    Client(ClientError),
    Framing(LinkError),
    Protocol(WireError),
    Timeout,
    StreamOpen,
    StreamRead,
    StreamWrite,
    ServerHelloMissing,
    UnexpectedControl(Kind),
    ControlBackpressure,
    WriterBusy,
    AssociationCapacity,
    Sink(io::Error),
}

impl fmt::Display for ClientLinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client(error) => write!(formatter, "{error}"),
            Self::Framing(error) => write!(formatter, "{error}"),
            Self::Protocol(error) => write!(formatter, "{error}"),
            Self::Timeout => formatter.write_str("everudp client link deadline expired"),
            Self::StreamOpen => formatter.write_str("everudp client stream open failed"),
            Self::StreamRead => formatter.write_str("everudp client stream read failed"),
            Self::StreamWrite => formatter.write_str("everudp client stream write failed"),
            Self::ServerHelloMissing => formatter.write_str("everudp SERVER_HELLO missing"),
            Self::UnexpectedControl(_) => {
                formatter.write_str("unexpected everudp client control record")
            }
            Self::ControlBackpressure => {
                formatter.write_str("everudp client control queue is full")
            }
            Self::WriterBusy => formatter.write_str("everudp gateway writer is busy"),
            Self::AssociationCapacity => {
                formatter.write_str("everudp gateway association capacity is exhausted")
            }
            Self::Sink(error) => write!(
                formatter,
                "everudp output sink rejected an operation: {error}"
            ),
        }
    }
}

impl std::error::Error for ClientLinkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Client(error) => Some(error),
            Self::Framing(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::Sink(error) => Some(error),
            _ => None,
        }
    }
}

impl ClientLinkError {
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::Timeout | Self::StreamOpen | Self::StreamRead | Self::StreamWrite
        ) || matches!(
            self,
            Self::Framing(LinkError::StreamOpen | LinkError::StreamRead | LinkError::StreamWrite)
        )
    }
}

#[cfg(test)]
mod classification_tests {
    use super::{finish_control_result, ClientLinkError, CLOSE_CODE};
    use crate::{LinkError, WireError};

    #[test]
    fn only_link_loss_is_transient_and_protocol_truncation_is_terminal() {
        assert!(ClientLinkError::Timeout.is_transient());
        assert!(ClientLinkError::StreamRead.is_transient());
        assert!(ClientLinkError::Framing(LinkError::StreamWrite).is_transient());
        assert!(!ClientLinkError::Framing(LinkError::StreamEndedMidRecord).is_transient());
        assert!(!ClientLinkError::Protocol(WireError::VersionUnsupported(99)).is_transient());
        assert!(!ClientLinkError::ServerHelloMissing.is_transient());
    }

    #[test]
    fn terminal_ack_accepts_only_the_gateway_normal_close_race() {
        let normal_close = noq::StoppedError::ConnectionLost(
            noq::ConnectionError::ApplicationClosed(noq::ApplicationClose {
                error_code: CLOSE_CODE,
                reason: b"everudp link closed".as_slice().into(),
            }),
        );
        assert!(finish_control_result(Err(normal_close)).is_ok());

        let rejected_close = noq::StoppedError::ConnectionLost(
            noq::ConnectionError::ApplicationClosed(noq::ApplicationClose {
                error_code: CLOSE_CODE,
                reason: b"everudp resume rejected".as_slice().into(),
            }),
        );
        assert!(matches!(
            finish_control_result(Err(rejected_close)),
            Err(ClientLinkError::StreamWrite)
        ));
        assert!(matches!(
            finish_control_result(Ok(Some(CLOSE_CODE))),
            Err(ClientLinkError::StreamWrite)
        ));
    }
}

impl From<ClientError> for ClientLinkError {
    fn from(value: ClientError) -> Self {
        Self::Client(value)
    }
}

impl From<LinkError> for ClientLinkError {
    fn from(value: LinkError) -> Self {
        Self::Framing(value)
    }
}

impl From<WireError> for ClientLinkError {
    fn from(value: WireError) -> Self {
        Self::Protocol(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientInputFlush {
    Observer,
    Idle,
    Sent { records: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientControlReceipt {
    InputAck(Ack),
    Gap { gap: EpochGap, newly_reported: bool },
    Duplicate { sequence: u64 },
    Finished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientOutputReceipt {
    Delivered {
        kind: Kind,
        sequence: u64,
        acknowledgement: u64,
    },
    Duplicate {
        sequence: u64,
        acknowledgement: u64,
    },
    Finished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientOutputStageReceipt {
    Staged { kind: Kind, sequence: u64 },
    Duplicate { sequence: u64, acknowledgement: u64 },
    Finished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientInboundReceipt {
    Control(ClientControlReceipt),
    OutputStreamOpened,
    Output(ClientOutputStageReceipt),
    OutputPending,
}

#[derive(Debug)]
pub struct ResumeLinkFailure {
    error: ClientLinkError,
    association: ClientAssociation,
}

impl ResumeLinkFailure {
    pub fn into_parts(self) -> (ClientLinkError, ClientAssociation) {
        (self.error, self.association)
    }
}

struct PreparedLink {
    connection: Connection,
    control_send: SendStream,
    control_recv: RecvStream,
    input_send: Option<SendStream>,
    control_reader: RecordReader,
    output_reader: RecordReader,
    control_buffer: Box<[u8]>,
    input_buffer: Box<[u8]>,
    next_input_sequence: u64,
}

#[derive(Debug, Clone, Copy)]
struct PendingWrite {
    kind: Kind,
    sequence: u64,
    wire_len: usize,
    written: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutboundStep {
    Idle,
    Progress,
    Record,
}

pub struct ClientLink {
    connection: Connection,
    #[cfg(feature = "path-packet-diagnostics")]
    diagnostic_connection: usize,
    #[cfg(feature = "path-packet-diagnostics")]
    input_offsets: crate::packet_offsets::Cursor,
    control_send: SendStream,
    control_recv: RecvStream,
    input_send: Option<SendStream>,
    output_recv: Option<RecvStream>,
    output_accept:
        Pin<Box<dyn std::future::Future<Output = Result<RecvStream, noq::ConnectionError>> + Send>>,
    association: ClientAssociation,
    limits: Limits,
    control_reader: RecordReader,
    output_reader: RecordReader,
    control_buffer: Box<[u8]>,
    input_buffer: Box<[u8]>,
    next_input_sequence: u64,
    input_finished: bool,
    control_pending: Option<PendingWrite>,
    input_pending: Option<PendingWrite>,
    #[cfg(feature = "datagram-spike")]
    fast_input_floor: u64,
    #[cfg(feature = "datagram-spike")]
    stream_output_epoch: u64,
    #[cfg(feature = "datagram-spike")]
    fast_output_through: u64,
}

impl ClientLink {
    /// Validates the server's first control record before returning. Callers
    /// may activate terminal raw mode only after this succeeds.
    pub async fn finish_initial(
        session: ClientSession,
        mut association: ClientAssociation,
        limits: Limits,
    ) -> Result<Self, ClientLinkError> {
        let deadline = tokio::time::Instant::now() + limits.initial_udp_budget();
        let prepared = Self::prepare_until(session, &mut association, limits, deadline).await?;
        Ok(Self::from_prepared(prepared, association, limits))
    }

    pub async fn finish_initial_until(
        session: ClientSession,
        mut association: ClientAssociation,
        limits: Limits,
        deadline: tokio::time::Instant,
    ) -> Result<Self, ClientLinkError> {
        let prepared = Self::prepare_until(session, &mut association, limits, deadline).await?;
        Ok(Self::from_prepared(prepared, association, limits))
    }

    pub async fn finish_resume(
        session: ClientSession,
        association: ClientAssociation,
        limits: Limits,
    ) -> Result<Self, ClientLinkError> {
        Self::try_finish_resume(session, association, limits)
            .await
            .map_err(|failure| failure.error)
    }

    pub async fn try_finish_resume(
        session: ClientSession,
        mut association: ClientAssociation,
        limits: Limits,
    ) -> Result<Self, ResumeLinkFailure> {
        let deadline = tokio::time::Instant::now() + limits.initial_udp_budget();
        match Self::prepare_until(session, &mut association, limits, deadline).await {
            Ok(prepared) => Ok(Self::from_prepared(prepared, association, limits)),
            Err(error) => Err(ResumeLinkFailure { error, association }),
        }
    }

    async fn prepare_until(
        session: ClientSession,
        association: &mut ClientAssociation,
        limits: Limits,
        deadline: tokio::time::Instant,
    ) -> Result<PreparedLink, ClientLinkError> {
        #[cfg(feature = "path-diagnostics")]
        let diagnostic_connection = session.diagnostic_connection();
        tokio::time::timeout_at(deadline, Self::prepare_inner(session, association, limits))
            .await
            .map_err(|_| {
                #[cfg(feature = "path-diagnostics")]
                crate::exit_trace::connection_counters(
                    "client-prepare-timeout",
                    &diagnostic_connection,
                );
                ClientLinkError::Timeout
            })?
    }

    async fn prepare_inner(
        session: ClientSession,
        association: &mut ClientAssociation,
        limits: Limits,
    ) -> Result<PreparedLink, ClientLinkError> {
        limits
            .validate()
            .map_err(WireError::from)
            .map_err(ClientLinkError::from)?;
        association.start_link();
        let (connection, control_send, mut control_recv) = session.into_parts();
        control_send
            .set_priority(CONTROL_STREAM_PRIORITY)
            .map_err(|_| ClientLinkError::StreamOpen)?;
        let mut control_reader = RecordReader::new(StreamRole::Control, limits)?;
        crate::exit_trace::record("client-prepare-wait-server-hello");
        let received = control_reader.receive(&mut control_recv, &limits).await;
        let record = match received {
            Ok(Some(record)) => record,
            Ok(None) => {
                return Err(initial_server_rejection(&connection)
                    .unwrap_or(ClientLinkError::ServerHelloMissing));
            }
            Err(error) => {
                return Err(initial_server_rejection(&connection)
                    .unwrap_or_else(|| ClientLinkError::from(error)));
            }
        };
        apply_server_hello_record(association, record)?;
        crate::exit_trace::record("client-prepare-server-hello-applied");
        control_reader.consume();

        let input_send = if association.role() == crate::wire::ConnectionRole::Writer {
            crate::exit_trace::record("client-prepare-wait-input-stream");
            let stream = connection
                .open_uni()
                .await
                .map_err(|_| ClientLinkError::StreamOpen)?;
            crate::exit_trace::record("client-prepare-input-stream-open");
            stream
                .set_priority(INPUT_STREAM_PRIORITY)
                .map_err(|_| ClientLinkError::StreamOpen)?;
            Some(stream)
        } else {
            None
        };
        let next_input_sequence = association
            .first_unacknowledged_input()
            .unwrap_or_else(|| association.next_input_sequence());
        Ok(PreparedLink {
            connection,
            control_send,
            control_recv,
            input_send,
            control_reader,
            output_reader: RecordReader::new(StreamRole::Output, limits)?,
            control_buffer: fixed_buffer(limits.control_frame_max + crate::wire::HEADER_LEN)?,
            input_buffer: fixed_buffer(limits.terminal_frame_max + crate::wire::HEADER_LEN)?,
            next_input_sequence,
        })
    }

    fn from_prepared(
        prepared: PreparedLink,
        association: ClientAssociation,
        limits: Limits,
    ) -> Self {
        #[cfg(feature = "datagram-spike")]
        let fast_input_floor = association.next_input_sequence();
        #[cfg(feature = "datagram-spike")]
        let (stream_output_epoch, fast_output_through) = association.output_position();
        // AcceptUni owns a Notify registration. Keep it across driver polls;
        // dropping a pending acceptance would unregister the only wakeup.
        // This allocates once per link, never once per terminal record.
        let output_connection = prepared.connection.clone();
        let output_accept = Box::pin(async move { output_connection.accept_uni().await });
        #[cfg(feature = "path-packet-diagnostics")]
        let diagnostic_connection = prepared.connection.diagnostic_id();
        Self {
            connection: prepared.connection,
            #[cfg(feature = "path-packet-diagnostics")]
            diagnostic_connection,
            #[cfg(feature = "path-packet-diagnostics")]
            input_offsets: crate::packet_offsets::Cursor::default(),
            control_send: prepared.control_send,
            control_recv: prepared.control_recv,
            input_send: prepared.input_send,
            output_recv: None,
            output_accept,
            association,
            limits,
            control_reader: prepared.control_reader,
            output_reader: prepared.output_reader,
            control_buffer: prepared.control_buffer,
            input_buffer: prepared.input_buffer,
            next_input_sequence: prepared.next_input_sequence,
            input_finished: false,
            control_pending: None,
            input_pending: None,
            #[cfg(feature = "datagram-spike")]
            fast_input_floor,
            #[cfg(feature = "datagram-spike")]
            stream_output_epoch,
            #[cfg(feature = "datagram-spike")]
            fast_output_through,
        }
    }

    pub fn association(&self) -> &ClientAssociation {
        &self.association
    }

    pub fn association_mut(&mut self) -> &mut ClientAssociation {
        &mut self.association
    }

    /// Test-only flow-control injection. This changes the transport's send
    /// window, never the product transport profile, and lets driver tests
    /// exercise cancellation-safe partial writes against a real QUIC stream.
    #[cfg(test)]
    pub(crate) fn set_test_send_window(&self, window: u64) {
        self.connection.set_send_window(window);
    }

    /// Advances at most one write on each independent outbound stream. The
    /// pending records and their byte cursors live on the link, so cancelling
    /// this poll never causes an accepted prefix to be emitted again.
    pub(crate) fn poll_outbound(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Result<bool, ClientLinkError>> {
        let control = self.poll_control_step(context);
        match control {
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(OutboundStep::Idle)) | Poll::Pending => {}
            Poll::Ready(Ok(OutboundStep::Progress | OutboundStep::Record)) => {}
        }

        let input = self.poll_input_step(context);
        match input {
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(OutboundStep::Progress | OutboundStep::Record)) => Poll::Ready(Ok(true)),
            Poll::Ready(Ok(OutboundStep::Idle)) | Poll::Pending => {
                if matches!(
                    control,
                    Poll::Ready(Ok(OutboundStep::Progress | OutboundStep::Record))
                ) {
                    Poll::Ready(Ok(true))
                } else if matches!(control, Poll::Ready(Ok(OutboundStep::Idle)))
                    && matches!(input, Poll::Ready(Ok(OutboundStep::Idle)))
                {
                    Poll::Ready(Ok(false))
                } else {
                    Poll::Pending
                }
            }
        }
    }

    fn poll_control_step(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Result<OutboundStep, ClientLinkError>> {
        if self.control_pending.is_none() {
            if self.association.control().unacknowledged_operations() == 0 {
                return Poll::Ready(Ok(OutboundStep::Idle));
            }
            let copy = match self.association.copy_control(&mut self.control_buffer) {
                Ok(copy) => copy,
                Err(error) => return Poll::Ready(Err(error.into())),
            };
            self.control_pending = Some(PendingWrite {
                kind: copy.kind,
                sequence: copy.sequence,
                wire_len: copy.wire_len,
                written: 0,
            });
        }

        let pending = self.control_pending.as_mut().expect("control pending");
        let written = match Pin::new(&mut self.control_send).poll_write(
            context,
            &self.control_buffer[pending.written..pending.wire_len],
        ) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(0) | Err(_)) => {
                return Poll::Ready(Err(ClientLinkError::StreamWrite));
            }
            Poll::Ready(Ok(written)) => written,
        };
        pending.written += written;
        if pending.written < pending.wire_len {
            return Poll::Ready(Ok(OutboundStep::Progress));
        }
        let next_expected = match pending.sequence.checked_add(1) {
            Some(sequence) => sequence,
            None => {
                return Poll::Ready(Err(ClientError::Queue(QueueError::SequenceOverflow).into()))
            }
        };
        self.control_pending = None;
        if let Err(error) = self.association.acknowledge_control_sent(next_expected) {
            return Poll::Ready(Err(error.into()));
        }
        Poll::Ready(Ok(OutboundStep::Record))
    }

    fn poll_input_step(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Result<OutboundStep, ClientLinkError>> {
        if self.input_send.is_none() || self.input_finished {
            return Poll::Ready(Ok(OutboundStep::Idle));
        }
        if self.input_pending.is_none() {
            if let Some(first) = self.association.first_unacknowledged_input() {
                self.next_input_sequence = self.next_input_sequence.max(first);
            }
            if self.next_input_sequence >= self.association.next_input_sequence() {
                return Poll::Ready(Ok(OutboundStep::Idle));
            }
            let copy = match self
                .association
                .copy_input(self.next_input_sequence, &mut self.input_buffer)
            {
                Ok(copy) => copy,
                Err(error) => return Poll::Ready(Err(error.into())),
            };
            #[cfg(feature = "datagram-spike")]
            if copy.kind == Kind::Input && copy.sequence >= self.fast_input_floor {
                send_fast_datagram_copy_poll(
                    &self.connection,
                    crate::wire::FastDirection::ClientToGateway,
                    copy.kind,
                    self.association.input_epoch(),
                    copy.sequence,
                    &self.input_buffer[crate::wire::HEADER_LEN..copy.wire_len],
                    context,
                );
            }
            #[cfg(feature = "path-packet-diagnostics")]
            if let Some((offset, len)) = self.input_offsets.reserve(copy.wire_len) {
                crate::packet_trace::record_operation(crate::packet_trace::Operation {
                    connection: self.diagnostic_connection,
                    stream: self
                        .input_send
                        .as_ref()
                        .expect("writer input stream")
                        .id()
                        .into(),
                    epoch: self.association.input_epoch(),
                    sequence: copy.sequence,
                    kind: copy.kind as u8,
                    offset,
                    len,
                });
            } else {
                crate::packet_trace::invalidate();
            }
            self.input_pending = Some(PendingWrite {
                kind: copy.kind,
                sequence: copy.sequence,
                wire_len: copy.wire_len,
                written: 0,
            });
        }

        let pending = self.input_pending.as_mut().expect("input pending");
        let send = self.input_send.as_mut().expect("writer input stream");
        let written = match Pin::new(send).poll_write(
            context,
            &self.input_buffer[pending.written..pending.wire_len],
        ) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(0) | Err(_)) => {
                return Poll::Ready(Err(ClientLinkError::StreamWrite));
            }
            Poll::Ready(Ok(written)) => written,
        };
        pending.written += written;
        if pending.written < pending.wire_len {
            return Poll::Ready(Ok(OutboundStep::Progress));
        }
        let kind = pending.kind;
        let sequence = pending.sequence;
        self.input_pending = None;
        #[cfg(feature = "path-diagnostics")]
        if kind == Kind::Input {
            self.association.trace_input_written(sequence);
        }
        self.next_input_sequence = match sequence.checked_add(1) {
            Some(sequence) => sequence,
            None => {
                return Poll::Ready(Err(ClientError::Queue(QueueError::SequenceOverflow).into()))
            }
        };
        if kind == Kind::InputClose {
            if self
                .input_send
                .as_mut()
                .expect("writer input stream")
                .finish()
                .is_err()
            {
                return Poll::Ready(Err(ClientLinkError::StreamWrite));
            }
            self.input_finished = true;
        }
        #[cfg(feature = "stream-flush-spike")]
        if self.connection.flush_transmit_now(context).is_err() {
            return Poll::Ready(Err(ClientLinkError::StreamWrite));
        }
        Poll::Ready(Ok(OutboundStep::Record))
    }

    pub async fn flush_input(&mut self) -> Result<ClientInputFlush, ClientLinkError> {
        let mut sent = 0usize;
        if self.input_send.is_none() {
            return Ok(ClientInputFlush::Observer);
        }
        loop {
            let step = std::future::poll_fn(|context| self.poll_input_step(context)).await?;
            match step {
                OutboundStep::Idle => break,
                OutboundStep::Progress => {}
                OutboundStep::Record => sent += 1,
            }
        }
        Ok(if sent == 0 {
            ClientInputFlush::Idle
        } else {
            ClientInputFlush::Sent { records: sent }
        })
    }

    pub async fn flush_control(&mut self) -> Result<usize, ClientLinkError> {
        let mut sent = 0usize;
        loop {
            match std::future::poll_fn(|context| self.poll_control_step(context)).await? {
                OutboundStep::Idle => break,
                OutboundStep::Progress => {}
                OutboundStep::Record => sent += 1,
            }
        }
        Ok(sent)
    }

    /// Finishes the client control stream and waits for transport-level proof
    /// that every queued acknowledgement reached the peer. Terminal outcomes
    /// use this before releasing the last connection owner, because merely
    /// dropping a live QUIC stream can race its final application ACKs.
    pub async fn finish_control_delivery(
        &mut self,
        deadline: Duration,
    ) -> Result<(), ClientLinkError> {
        self.finish_control_bounded(deadline, false).await
    }

    /// Bounds the initial queue drain as well as the final detach delivery.
    pub(crate) async fn finish_detach_delivery(
        &mut self,
        deadline: Duration,
    ) -> Result<(), ClientLinkError> {
        self.finish_control_bounded(deadline, true).await
    }

    async fn finish_control_bounded(
        &mut self,
        deadline: Duration,
        detach: bool,
    ) -> Result<(), ClientLinkError> {
        let result = tokio::time::timeout(deadline, async {
            if detach {
                self.flush_control().await?;
                self.association.queue_detach()?;
            }
            self.finish_control_inner().await
        })
        .await;
        match result {
            Ok(result) => result,
            Err(_) => {
                // A pending write may have accepted a prefix. A failed final
                // delivery ends this byte stream instead of retrying it. Persistent
                // association replay remains owned until sink acknowledgement.
                self.connection
                    .close(RESUME_CLOSE_CODE, b"everudp control delivery timed out");
                Err(ClientLinkError::Timeout)
            }
        }
    }

    async fn finish_control_inner(&mut self) -> Result<(), ClientLinkError> {
        self.flush_control().await?;
        self.control_send
            .finish()
            .map_err(|_| ClientLinkError::StreamWrite)?;
        finish_control_result(self.control_send.stopped().await)
    }

    pub async fn receive_control(&mut self) -> Result<ClientControlReceipt, ClientLinkError> {
        let Some(record) = self
            .control_reader
            .receive(&mut self.control_recv, &self.limits)
            .await?
        else {
            return Ok(ClientControlReceipt::Finished);
        };
        match self
            .association
            .begin_server_control(record.header.sequence)?
        {
            DeliveryDecision::Duplicate => {
                let sequence = record.header.sequence;
                self.control_reader.consume();
                return Ok(ClientControlReceipt::Duplicate { sequence });
            }
            DeliveryDecision::Deliver => {}
        }
        let result = match record.header.kind {
            Kind::AckInput => {
                let acknowledgement = Ack::decode_exact(record.payload, Kind::AckInput)?;
                self.association.accept_input_ack(acknowledgement)?;
                ClientControlReceipt::InputAck(acknowledgement)
            }
            Kind::Gap => {
                let gap = EpochGap::decode_exact(record.payload)?;
                let newly_reported = self.association.apply_gap(gap)?;
                ClientControlReceipt::Gap {
                    gap,
                    newly_reported,
                }
            }
            kind => {
                self.association
                    .abort_server_control(record.header.sequence)?;
                return Err(ClientLinkError::UnexpectedControl(kind));
            }
        };
        self.association
            .commit_server_control(record.header.sequence)?;
        self.control_reader.consume();
        Ok(result)
    }

    pub async fn receive_output<F>(
        &mut self,
        mut sink: F,
    ) -> Result<ClientOutputReceipt, ClientLinkError>
    where
        F: FnMut(OutputOperation<'_>) -> io::Result<()>,
    {
        if self.output_recv.is_none() {
            self.output_recv = Some(
                self.connection
                    .accept_uni()
                    .await
                    .map_err(|_| ClientLinkError::StreamOpen)?,
            );
        }
        let output = self.output_recv.as_mut().expect("output stream accepted");
        let Some(record) = self.output_reader.receive(output, &self.limits).await? else {
            return Ok(ClientOutputReceipt::Finished);
        };
        let kind = record.header.kind;
        let sequence = record.header.sequence;
        let disposition = self
            .association
            .begin_output(kind, sequence, record.payload)?;
        if !self.association.can_queue_output_ack() {
            if matches!(disposition, OutputDisposition::Deliver(_)) {
                self.association.abort_output(sequence)?;
            }
            return Err(ClientLinkError::ControlBackpressure);
        }
        let receipt = match disposition {
            OutputDisposition::Deliver(operation) => {
                if let Err(error) = sink(operation) {
                    self.association.abort_output(sequence)?;
                    return Err(ClientLinkError::Sink(error));
                }
                let acknowledgement = self.association.commit_output(sequence)?;
                ClientOutputReceipt::Delivered {
                    kind,
                    sequence,
                    acknowledgement: acknowledgement.next_expected,
                }
            }
            OutputDisposition::Duplicate { acknowledgement } => {
                self.association.repeat_output_ack(acknowledgement)?;
                ClientOutputReceipt::Duplicate {
                    sequence,
                    acknowledgement,
                }
            }
        };
        self.output_reader.consume();
        Ok(receipt)
    }

    /// Reads whichever inbound QUIC stream becomes ready first. Output is
    /// copied into the association's persistent staging buffer but is not
    /// acknowledged; the terminal driver advances and commits it only after
    /// stdout accepts every byte.
    // Only ignored fast-lane datagrams retry this loop. Stream-only builds
    // return after one operation but share the same cancellation-safe body.
    #[cfg_attr(not(feature = "datagram-spike"), allow(clippy::never_loop))]
    pub async fn next_inbound(&mut self) -> Result<ClientInboundReceipt, ClientLinkError> {
        if self.association.has_pending_output() {
            return Ok(ClientInboundReceipt::OutputPending);
        }
        loop {
            if self.output_recv.is_none() {
                #[cfg(feature = "datagram-spike")]
                let connection = &self.connection;
                let control_reader = &mut self.control_reader;
                let control_recv = &mut self.control_recv;
                let limits = &self.limits;
                enum Ready {
                    #[cfg(feature = "datagram-spike")]
                    Fast(Result<Bytes, noq::ConnectionError>),
                    Output(Result<RecvStream, noq::ConnectionError>),
                }

                // `Record` borrows the reader, so it cannot be stored in the
                // local enum. Handle control inline and use the enum only for
                // independently owned datagram/stream-open outcomes.
                #[cfg(feature = "datagram-spike")]
                let ready = tokio::select! {
                    biased;
                    control = control_reader.receive(control_recv, limits) => {
                        let receipt = apply_control_record(&mut self.association, control?)?;
                        control_reader.consume();
                        return Ok(ClientInboundReceipt::Control(receipt));
                    }
                    output = self.output_accept.as_mut() => Ready::Output(output),
                    datagram = connection.read_datagram() => Ready::Fast(datagram),
                };
                #[cfg(not(feature = "datagram-spike"))]
                let ready = tokio::select! {
                    biased;
                    control = control_reader.receive(control_recv, limits) => {
                        let receipt = apply_control_record(&mut self.association, control?)?;
                        control_reader.consume();
                        return Ok(ClientInboundReceipt::Control(receipt));
                    }
                    output = self.output_accept.as_mut() => Ready::Output(output),
                };
                match ready {
                    #[cfg(feature = "datagram-spike")]
                    Ready::Fast(Ok(datagram)) => {
                        if let Some(receipt) =
                            stage_fast_output_record(&mut self.association, &datagram)?
                        {
                            if let ClientOutputStageReceipt::Staged { sequence, .. } = receipt {
                                self.fast_output_through = sequence.saturating_add(1);
                            }
                            return Ok(ClientInboundReceipt::Output(receipt));
                        }
                        continue;
                    }
                    #[cfg(feature = "datagram-spike")]
                    Ready::Fast(Err(_)) => return Err(ClientLinkError::StreamRead),
                    Ready::Output(output) => {
                        self.output_recv = Some(output.map_err(|_| ClientLinkError::StreamOpen)?);
                        return Ok(ClientInboundReceipt::OutputStreamOpened);
                    }
                }
            }

            #[cfg(feature = "datagram-spike")]
            let connection = &self.connection;
            let control_reader = &mut self.control_reader;
            let control_recv = &mut self.control_recv;
            let output_reader = &mut self.output_reader;
            let output_recv = self
                .output_recv
                .as_mut()
                .expect("output stream established");
            let limits = &self.limits;
            enum Ready<'a> {
                #[cfg(feature = "datagram-spike")]
                Fast(Result<Bytes, noq::ConnectionError>),
                Control(Result<Option<crate::wire::Record<'a>>, LinkError>),
                Output(Result<Option<crate::wire::Record<'a>>, LinkError>),
            }
            let ready = {
                #[cfg(feature = "datagram-spike")]
                {
                    tokio::select! {
                        biased;
                        datagram = connection.read_datagram() => Ready::Fast(datagram),
                        control = control_reader.receive(control_recv, limits) => Ready::Control(control),
                        output = output_reader.receive(output_recv, limits) => Ready::Output(output),
                    }
                }
                #[cfg(not(feature = "datagram-spike"))]
                {
                    tokio::select! {
                        biased;
                        control = control_reader.receive(control_recv, limits) => Ready::Control(control),
                        output = output_reader.receive(output_recv, limits) => Ready::Output(output),
                    }
                }
            };
            match ready {
                #[cfg(feature = "datagram-spike")]
                Ready::Fast(Ok(datagram)) => {
                    if let Some(receipt) =
                        stage_fast_output_record(&mut self.association, &datagram)?
                    {
                        if let ClientOutputStageReceipt::Staged { sequence, .. } = receipt {
                            self.fast_output_through = sequence.saturating_add(1);
                        }
                        return Ok(ClientInboundReceipt::Output(receipt));
                    }
                }
                #[cfg(feature = "datagram-spike")]
                Ready::Fast(Err(_)) => return Err(ClientLinkError::StreamRead),
                Ready::Control(control) => {
                    let receipt = apply_control_record(&mut self.association, control?)?;
                    control_reader.consume();
                    return Ok(ClientInboundReceipt::Control(receipt));
                }
                Ready::Output(output) => {
                    let output = output?;
                    #[cfg(feature = "datagram-spike")]
                    if output.as_ref().is_some_and(|_| {
                        self.association.output_position().0 != self.stream_output_epoch
                    }) {
                        output_reader.consume();
                        continue;
                    }
                    #[cfg(feature = "datagram-spike")]
                    let suppress_duplicate_ack = output
                        .as_ref()
                        .is_some_and(|record| record.header.sequence < self.fast_output_through);
                    #[cfg(not(feature = "datagram-spike"))]
                    let suppress_duplicate_ack = false;
                    let receipt =
                        stage_output_record(&mut self.association, output, suppress_duplicate_ack)?;
                    output_reader.consume();
                    return Ok(ClientInboundReceipt::Output(receipt));
                }
            }
        }
    }

    pub fn close(self) {
        self.connection
            .close(CLOSE_CODE, b"everudp client link closed");
    }

    pub fn into_resumable_association(self) -> ClientAssociation {
        self.connection
            .close(RESUME_CLOSE_CODE, b"everudp client link will resume");
        self.association
    }

    pub async fn wait_closed(&self) {
        let _ = self.connection.closed().await;
    }
}

#[cfg(feature = "datagram-spike")]
fn send_fast_datagram_copy_poll(
    connection: &Connection,
    direction: crate::wire::FastDirection,
    kind: Kind,
    epoch: u64,
    sequence: u64,
    payload: &[u8],
    context: &mut Context<'_>,
) {
    let mut encoded =
        [0_u8; crate::wire::FAST_DATAGRAM_HEADER_LEN + crate::wire::FAST_DATAGRAM_PAYLOAD_MAX];
    let Ok(used) =
        crate::wire::encode_fast_datagram(direction, kind, epoch, sequence, payload, &mut encoded)
    else {
        return;
    };
    if connection
        .max_datagram_size()
        .is_some_and(|maximum| used <= maximum)
        && connection
            .send_datagram(Bytes::copy_from_slice(&encoded[..used]))
            .is_ok()
    {
        let _ = connection.flush_transmit_now(context);
    }
}

#[cfg(feature = "datagram-spike")]
fn stage_fast_output_record(
    association: &mut ClientAssociation,
    bytes: &[u8],
) -> Result<Option<ClientOutputStageReceipt>, ClientLinkError> {
    let Ok(record) =
        crate::wire::decode_fast_datagram(crate::wire::FastDirection::GatewayToClient, bytes)
    else {
        return Ok(None);
    };
    let (epoch, next_expected) = association.output_position();
    if record.epoch != epoch || record.sequence > next_expected {
        return Ok(None);
    }
    let receipt = match association.stage_output(record.kind, record.sequence, record.payload)? {
        OutputStage::Staged { kind, sequence } => {
            ClientOutputStageReceipt::Staged { kind, sequence }
        }
        OutputStage::Duplicate {
            sequence,
            acknowledgement,
        } => ClientOutputStageReceipt::Duplicate {
            sequence,
            acknowledgement,
        },
    };
    Ok(Some(receipt))
}

fn finish_control_result(
    result: Result<Option<VarInt>, noq::StoppedError>,
) -> Result<(), ClientLinkError> {
    match result {
        Ok(None) => Ok(()),
        Err(noq::StoppedError::ConnectionLost(noq::ConnectionError::ApplicationClosed(close)))
            if close.error_code == CLOSE_CODE
                && close.reason.as_ref() == NORMAL_LINK_CLOSE_REASON =>
        {
            Ok(())
        }
        Ok(Some(_)) | Err(_) => Err(ClientLinkError::StreamWrite),
    }
}

fn initial_server_rejection(connection: &Connection) -> Option<ClientLinkError> {
    let noq::ConnectionError::ApplicationClosed(close) = connection.close_reason()? else {
        return None;
    };
    if close.error_code == WRITER_BUSY_CLOSE_CODE {
        Some(ClientLinkError::WriterBusy)
    } else if close.error_code == ASSOCIATION_CAPACITY_CLOSE_CODE {
        Some(ClientLinkError::AssociationCapacity)
    } else {
        None
    }
}

fn apply_control_record(
    association: &mut ClientAssociation,
    record: Option<crate::wire::Record<'_>>,
) -> Result<ClientControlReceipt, ClientLinkError> {
    let Some(record) = record else {
        return Ok(ClientControlReceipt::Finished);
    };
    match association.begin_server_control(record.header.sequence)? {
        DeliveryDecision::Duplicate => {
            return Ok(ClientControlReceipt::Duplicate {
                sequence: record.header.sequence,
            });
        }
        DeliveryDecision::Deliver => {}
    }
    let receipt = match record.header.kind {
        Kind::AckInput => {
            let acknowledgement = Ack::decode_exact(record.payload, Kind::AckInput)?;
            association.accept_input_ack(acknowledgement)?;
            ClientControlReceipt::InputAck(acknowledgement)
        }
        Kind::Gap => {
            let gap = EpochGap::decode_exact(record.payload)?;
            let newly_reported = association.apply_gap(gap)?;
            ClientControlReceipt::Gap {
                gap,
                newly_reported,
            }
        }
        kind => {
            association.abort_server_control(record.header.sequence)?;
            return Err(ClientLinkError::UnexpectedControl(kind));
        }
    };
    association.commit_server_control(record.header.sequence)?;
    Ok(receipt)
}

fn apply_server_hello_record(
    association: &mut ClientAssociation,
    record: crate::wire::Record<'_>,
) -> Result<(), ClientLinkError> {
    if record.header.kind != Kind::ServerHello {
        return Err(ClientLinkError::ServerHelloMissing);
    }
    match association.begin_server_control(record.header.sequence)? {
        DeliveryDecision::Duplicate => return Err(ClientLinkError::ServerHelloMissing),
        DeliveryDecision::Deliver => {}
    }
    let result = ServerHello::decode_exact(record.payload)
        .map_err(ClientError::from)
        .and_then(|hello| association.apply_server_hello(hello));
    if let Err(error) = result {
        association.abort_server_control(record.header.sequence)?;
        return Err(error.into());
    }
    association.commit_server_control(record.header.sequence)?;
    Ok(())
}

fn stage_output_record(
    association: &mut ClientAssociation,
    record: Option<crate::wire::Record<'_>>,
    suppress_duplicate_ack: bool,
) -> Result<ClientOutputStageReceipt, ClientLinkError> {
    let Some(record) = record else {
        return Ok(ClientOutputStageReceipt::Finished);
    };
    match association.stage_output(record.header.kind, record.header.sequence, record.payload)? {
        OutputStage::Staged { kind, sequence } => {
            Ok(ClientOutputStageReceipt::Staged { kind, sequence })
        }
        OutputStage::Duplicate {
            sequence,
            acknowledgement,
        } => {
            if !suppress_duplicate_ack {
                association.repeat_staged_duplicate(acknowledgement)?;
            }
            Ok(ClientOutputStageReceipt::Duplicate {
                sequence,
                acknowledgement,
            })
        }
    }
}

impl fmt::Debug for ClientLink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientLink")
            .field("association", &self.association)
            .field("next_input_sequence", &self.next_input_sequence)
            .field("input_finished", &self.input_finished)
            .field("payload", &"<REDACTED>")
            .finish()
    }
}

fn fixed_buffer(length: usize) -> Result<Box<[u8]>, ClientLinkError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| ClientError::Queue(QueueError::Allocation))?;
    bytes.resize(length, 0);
    Ok(bytes.into_boxed_slice())
}

#[cfg(test)]
mod backpressure_tests {
    use super::*;
    use crate::{
        ClientEndpoint, ClientHello, ClientIdentity, GatewayEndpoint, GatewayGeneration,
        GatewayIdentity, GatewayLifecycle, GatewayLink, GatewayReplaySlabs, InvitationStore,
        ResumePosition,
    };
    use everssh::association::AssociationId;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};

    #[tokio::test(flavor = "current_thread")]
    async fn control_delivery_deadline_includes_blocked_flush() {
        blocked_delivery(false).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn detach_delivery_deadline_includes_initial_blocked_flush() {
        blocked_delivery(true).await;
    }

    struct Links {
        _server: GatewayEndpoint,
        _endpoint: ClientEndpoint,
        gateway: GatewayLink,
        client: ClientLink,
        slabs: GatewayReplaySlabs,
    }

    async fn connected_links() -> Links {
        let limits = Limits::default();
        let id = AssociationId::from_bytes([61; 16]).expect("association");
        let generation = GatewayGeneration::from_bytes([62; 16]).expect("generation");
        let role = crate::wire::ConnectionRole::Writer;
        let store = Arc::new(Mutex::new(
            InvitationStore::new("deadline", generation, &limits).expect("store"),
        ));
        let server_identity = GatewayIdentity::generate().expect("server identity");
        let client_identity = ClientIdentity::generate().expect("client identity");
        let loopback = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let server = GatewayEndpoint::bind(loopback, &server_identity, Arc::clone(&store), limits)
            .expect("server");
        let ticket = store
            .lock()
            .expect("store lock")
            .issue(
                id,
                role,
                client_identity.spki_sha256(),
                everpty::sys::clock_monotonic_ms().expect("clock"),
            )
            .expect("ticket");
        let hello = ClientHello::initial(
            id,
            generation,
            role,
            ResumePosition {
                input_epoch: 0,
                next_input: 0,
                output_epoch: 0,
                next_output: 0,
                delivered_output_ack: 0,
            },
            ticket.token().clone(),
        )
        .expect("hello");
        let endpoint = ClientEndpoint::bind(
            loopback,
            &client_identity,
            server_identity.spki_sha256(),
            limits,
        )
        .expect("endpoint");
        let (admitted, session) = tokio::join!(
            server.accept_initial(),
            endpoint.connect_initial(server.local_addr(), &hello)
        );
        let mut lifecycle = GatewayLifecycle::new(&limits).expect("lifecycle");
        let mut slabs = GatewayReplaySlabs::new(&limits).expect("slabs");
        let association = ClientAssociation::new(id, generation, role, limits).expect("client");
        let (gateway, client) = tokio::join!(
            GatewayLink::accept_initial(
                admitted.expect("admission"),
                &mut lifecycle,
                &mut slabs,
                limits
            ),
            ClientLink::finish_initial(session.expect("session"), association, limits),
        );
        let (gateway, _) = gateway.expect("gateway link");
        Links {
            _server: server,
            _endpoint: endpoint,
            gateway,
            client: client.expect("client link"),
            slabs,
        }
    }

    async fn blocked_delivery(detach: bool) {
        let mut links = connected_links().await;
        let client = &mut links.client;
        // Exercise a real blocked QUIC write without exceeding the replay cap.
        // This is test-only flow-control injection, not a product profile change.
        client.connection.set_send_window(0);
        client.association.queue_detach().expect("detach");
        let result = tokio::time::timeout(Duration::from_secs(1), async {
            if detach {
                client
                    .finish_detach_delivery(Duration::from_millis(20))
                    .await
            } else {
                client
                    .finish_control_delivery(Duration::from_millis(20))
                    .await
            }
        })
        .await
        .expect("flush must be inside the delivery deadline");
        assert!(matches!(result, Err(ClientLinkError::Timeout)));
        assert!(
            client.connection.close_reason().is_some(),
            "a timed-out partial write must not be retried on the same stream"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn partial_input_write_resumes_at_accepted_byte_offset() {
        let mut links = connected_links().await;
        tokio::time::timeout(Duration::from_secs(3), async {
            let client = &mut links.client;
            client
                .association
                .queue_input(b"exact partial record")
                .expect("input");
            client.connection.set_send_window(1);
            let step = std::future::poll_fn(|cx| client.poll_input_step(cx))
                .await
                .expect("prefix");
            assert!(matches!(step, OutboundStep::Progress));
            assert_eq!(
                client
                    .input_pending
                    .as_ref()
                    .expect("partial record")
                    .written,
                1
            );
            assert_eq!(client.next_input_sequence, 0);
            client.connection.set_send_window(0);
            let blocked = std::future::poll_fn(|cx| Poll::Ready(client.poll_input_step(cx))).await;
            assert!(blocked.is_pending());
            assert_eq!(
                client
                    .input_pending
                    .as_ref()
                    .expect("retained prefix")
                    .written,
                1
            );
            client
                .connection
                .set_send_window(Limits::default().queue_bytes_per_direction as u64);
            client.flush_input().await.expect("finish record");
            assert!(client.input_pending.is_none());
            assert_eq!(client.association.ambiguous_input_operations(), 1);
            let mut delivered = Vec::new();
            links
                .gateway
                .receive_input(&mut links.slabs, |operation| {
                    let crate::InputOperation::Bytes(bytes) = operation else {
                        panic!("input kind")
                    };
                    delivered.extend_from_slice(bytes);
                    Ok(())
                })
                .await
                .expect("decode exact record");
            assert_eq!(delivered, b"exact partial record");
            links
                .gateway
                .flush_control(&mut links.slabs)
                .await
                .expect("sink ACK");
            assert!(matches!(
                client.receive_control().await.expect("ACK"),
                ClientControlReceipt::InputAck(_)
            ));
            assert_eq!(client.association.ambiguous_input_operations(), 0);
            assert_eq!(
                client.flush_input().await.expect("no repeat"),
                ClientInputFlush::Idle
            );
        })
        .await
        .expect("partial write deadline");
    }
}
