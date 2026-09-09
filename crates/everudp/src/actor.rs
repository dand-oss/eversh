//! Live ownership of one authenticated everudp QUIC connection.
//!
//! The actor keeps all framing storage for the connection and advances
//! application acknowledgements only after the injected sink accepts a whole
//! operation. It deliberately does not own terminal policy or a terminal
//! model; the gateway runner supplies the local `everpty` sink.

use crate::association::{
    AssociationError, ControlDisposition, GatewayAssociation, InputDisposition, InputOperation,
};
use crate::gateway::{GatewayAction, GatewayLifecycle};
use crate::queues::{GatewayReplaySlabs, QueueError};
use crate::transport::{
    AdmittedConnection, CONTROL_STREAM_PRIORITY, OUTPUT_STREAM_PRIORITY, WRITER_BUSY_CLOSE_CODE,
};
use crate::wire::{decode_record, Ack, ConnectionRole, Kind, Record, StreamRole};
use crate::{Limits, WireError};
#[cfg(feature = "datagram-spike")]
use bytes::Bytes;
use noq::{Connection, RecvStream, SendStream, VarInt};
use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

const CLOSE_CODE: VarInt = VarInt::from_u32(0x4555);
const RESUME_CLOSE_CODE: VarInt = VarInt::from_u32(0x4552);

#[derive(Debug)]
pub enum LinkError {
    Association(AssociationError),
    Protocol(WireError),
    StreamOpen,
    StreamRead,
    StreamWrite,
    OutputResumeRequired,
    StreamEndedMidRecord,
    ObserverInputStream,
    InputCloseMissing,
    InputAfterClose,
    ControlBackpressure,
    Sink(io::Error),
}

impl fmt::Display for LinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Association(error) => write!(formatter, "{error}"),
            Self::Protocol(error) => write!(formatter, "{error}"),
            Self::StreamOpen => formatter.write_str("everudp stream open failed"),
            Self::StreamRead => formatter.write_str("everudp stream read failed"),
            Self::StreamWrite => formatter.write_str("everudp stream write failed"),
            Self::OutputResumeRequired => {
                formatter.write_str("everudp output epoch requires a fresh link")
            }
            Self::StreamEndedMidRecord => {
                formatter.write_str("everudp stream ended within a record")
            }
            Self::ObserverInputStream => {
                formatter.write_str("everudp observer opened an input stream")
            }
            Self::InputCloseMissing => {
                formatter.write_str("everudp input stream ended without INPUT_CLOSE")
            }
            Self::InputAfterClose => {
                formatter.write_str("everudp input operation followed INPUT_CLOSE")
            }
            Self::ControlBackpressure => {
                formatter.write_str("everudp control acknowledgement queue is full")
            }
            Self::Sink(error) => write!(
                formatter,
                "everudp input sink rejected an operation: {error}"
            ),
        }
    }
}

impl std::error::Error for LinkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Association(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::Sink(error) => Some(error),
            _ => None,
        }
    }
}

impl From<AssociationError> for LinkError {
    fn from(value: AssociationError) -> Self {
        Self::Association(value)
    }
}

impl From<WireError> for LinkError {
    fn from(value: WireError) -> Self {
        Self::Protocol(value)
    }
}

impl From<QueueError> for LinkError {
    fn from(value: QueueError) -> Self {
        Self::Association(AssociationError::Queue(value))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputReceipt {
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
pub enum ControlReceipt {
    OutputAck {
        acknowledgement: Ack,
        disposition: ControlDisposition,
    },
    Finished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFlush {
    Idle,
    Sent { records: usize },
    Discarding,
}

#[derive(Debug)]
pub struct GatewayResumeFailure {
    error: LinkError,
    association: GatewayAssociation,
}

impl GatewayResumeFailure {
    pub fn into_parts(self) -> (LinkError, GatewayAssociation) {
        (self.error, self.association)
    }
}

/// One complete inbound record copied into link-owned fixed storage. The
/// gateway can wait for this without borrowing replay slabs, so PTY output
/// remains independently drainable in the same event loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputSource {
    Stream,
    Fast,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkInbound {
    InputStreamOpened,
    Input {
        kind: Kind,
        sequence: u64,
        payload_len: usize,
        source: InputSource,
    },
    Control {
        kind: Kind,
        sequence: u64,
        payload_len: usize,
    },
    InputFinished,
    ControlFinished,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PreparedInput<'a> {
    operation: InputOperation<'a>,
    kind: Kind,
    sequence: u64,
}

impl<'a> PreparedInput<'a> {
    pub fn operation(&self) -> InputOperation<'a> {
        self.operation
    }

    pub fn token(&self) -> PreparedInputToken {
        PreparedInputToken {
            kind: self.kind,
            sequence: self.sequence,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreparedInputToken {
    kind: Kind,
    sequence: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum InboundApply<'a> {
    None,
    Detach,
    Receipt(InputReceipt),
    Deliver(PreparedInput<'a>),
}

/// Live stream owner for one admitted writer or observer connection.
pub struct GatewayLink {
    connection: Connection,
    #[cfg(feature = "path-packet-diagnostics")]
    diagnostic_connection: usize,
    #[cfg(feature = "path-packet-diagnostics")]
    output_offsets: crate::packet_offsets::Cursor,
    control_send: SendStream,
    control_recv: RecvStream,
    input_recv: Option<RecvStream>,
    incoming_uni: Option<tokio::task::JoinHandle<Result<RecvStream, noq::ConnectionError>>>,
    input_finished: bool,
    output_send: SendStream,
    association: GatewayAssociation,
    limits: Limits,
    control_reader: RecordReader,
    input_reader: RecordReader,
    control_buffer: Box<[u8]>,
    output_buffer: Box<[u8]>,
    input_event_buffer: Box<[u8]>,
    control_event_buffer: Box<[u8]>,
    control_pending: Option<PendingWrite>,
    #[cfg(feature = "input-ack-hold-spike")]
    ack_hold: crate::ack_hold::AckHold,
    #[cfg(feature = "input-ack-hold-spike")]
    ack_hold_timer: Pin<Box<tokio::time::Sleep>>,
    output_pending: Option<PendingWrite>,
    next_output_sequence: u64,
    output_epoch: u64,
    output_reset: bool,
    #[cfg(feature = "datagram-spike")]
    fast_output_floor: u64,
    #[cfg(feature = "datagram-spike")]
    fast_input_through: u64,
}

struct GatewayLinkStorage {
    control_reader: RecordReader,
    input_reader: RecordReader,
    control_buffer: Box<[u8]>,
    output_buffer: Box<[u8]>,
    input_event_buffer: Box<[u8]>,
    control_event_buffer: Box<[u8]>,
}

struct GatewayOpenFailure {
    error: LinkError,
    association: GatewayAssociation,
}

#[derive(Debug, Clone, Copy)]
struct PendingWrite {
    #[cfg(feature = "input-ack-hold-spike")]
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
    Discarding { reset: bool },
}

impl GatewayLink {
    /// Commits the authenticated association, sends `SERVER_HELLO`, and
    /// establishes the direction-implied stream layout. Writer ownership has
    /// already been cryptographically admitted before this function can be
    /// called because `AdmittedConnection` is unforgeable outside transport.
    pub async fn accept_initial(
        admitted: AdmittedConnection,
        lifecycle: &mut GatewayLifecycle,
        slabs: &mut GatewayReplaySlabs,
        limits: Limits,
    ) -> Result<(Self, GatewayAction), LinkError> {
        let (link, action) = Self::prepare_initial(admitted, lifecycle, slabs, limits).await?;
        let link = link.commit_prepared_initial(lifecycle, slabs).await?;
        Ok((link, action))
    }

    /// Reserves an authenticated initial association and establishes its QUIC
    /// stream layout without releasing `SERVER_HELLO`. The persistent gateway
    /// uses this boundary to claim its `everpty` writer transactionally before
    /// the client treats the direct-UDP association as committed.
    pub(crate) async fn prepare_initial(
        admitted: AdmittedConnection,
        lifecycle: &mut GatewayLifecycle,
        slabs: &mut GatewayReplaySlabs,
        limits: Limits,
    ) -> Result<(Self, GatewayAction), LinkError> {
        limits.validate().map_err(WireError::from)?;
        let (association, action) = match GatewayAssociation::establish(&admitted, lifecycle, slabs)
        {
            Ok(established) => established,
            Err(error) => {
                crate::exit_trace::record("gateway-prepare-establish-error");
                admitted.close();
                return Err(error.into());
            }
        };
        crate::exit_trace::record("gateway-prepare-established");
        match Self::open_uncommitted(admitted, association, slabs, limits).await {
            Ok(link) => Ok((link, action)),
            Err(failure) => {
                failure.association.rollback_initial(lifecycle, slabs)?;
                Err(failure.error)
            }
        }
    }

    pub async fn accept_resume(
        admitted: AdmittedConnection,
        association: GatewayAssociation,
        lifecycle: &mut GatewayLifecycle,
        slabs: &mut GatewayReplaySlabs,
        limits: Limits,
    ) -> Result<(Self, GatewayAction), LinkError> {
        Self::try_accept_resume(admitted, association, lifecycle, slabs, limits)
            .await
            .map_err(|failure| failure.error)
    }

    /// Attempts one resume without consuming the durable association on a
    /// rejected or interrupted replacement connection.
    pub async fn try_accept_resume(
        admitted: AdmittedConnection,
        mut association: GatewayAssociation,
        lifecycle: &mut GatewayLifecycle,
        slabs: &mut GatewayReplaySlabs,
        limits: Limits,
    ) -> Result<(Self, GatewayAction), GatewayResumeFailure> {
        if let Err(error) = limits.validate().map_err(WireError::from) {
            admitted.close();
            return Err(GatewayResumeFailure {
                error: error.into(),
                association,
            });
        }
        let action = match association.resume(&admitted, lifecycle, slabs) {
            Ok(action) => action,
            Err(error) => {
                admitted.close();
                return Err(GatewayResumeFailure {
                    error: error.into(),
                    association,
                });
            }
        };
        Self::open(admitted, association, slabs, limits)
            .await
            .map(|link| (link, action))
            .map_err(|failure| GatewayResumeFailure {
                error: failure.error,
                association: failure.association,
            })
    }

    async fn open(
        admitted: AdmittedConnection,
        association: GatewayAssociation,
        slabs: &mut GatewayReplaySlabs,
        limits: Limits,
    ) -> Result<Self, GatewayOpenFailure> {
        let mut link = Self::open_uncommitted(admitted, association, slabs, limits).await?;
        match link.flush_control(slabs).await {
            Ok(_) => Ok(link),
            Err(error) => Err(GatewayOpenFailure {
                error,
                association: link.into_failed_association(),
            }),
        }
    }

    async fn open_uncommitted(
        admitted: AdmittedConnection,
        association: GatewayAssociation,
        slabs: &mut GatewayReplaySlabs,
        limits: Limits,
    ) -> Result<Self, GatewayOpenFailure> {
        let storage = match prepare_gateway_link_storage(limits) {
            Ok(storage) => storage,
            Err(error) => return Err(GatewayOpenFailure { error, association }),
        };
        let output = match association.output(slabs) {
            Ok(output) => output,
            Err(error) => {
                return Err(GatewayOpenFailure {
                    error: error.into(),
                    association,
                })
            }
        };
        let output_epoch = output.epoch();
        let next_output_sequence = output
            .first_unacknowledged_sequence()
            .unwrap_or_else(|| output.next_sequence());
        #[cfg(feature = "datagram-spike")]
        let fast_output_floor = output.next_sequence();
        #[cfg(feature = "datagram-spike")]
        let (_, fast_input_through) = association.input_position();
        let (connection, control_send, control_recv, _) = admitted.into_parts();
        if control_send.set_priority(CONTROL_STREAM_PRIORITY).is_err() {
            return Err(GatewayOpenFailure {
                error: LinkError::StreamOpen,
                association,
            });
        }

        crate::exit_trace::record("gateway-prepare-wait-output-stream");
        let output_send =
            match tokio::time::timeout(limits.initial_udp_budget(), connection.open_uni()).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(_)) | Err(_) => {
                    connection.close(CLOSE_CODE, b"everudp stream open failed");
                    return Err(GatewayOpenFailure {
                        error: LinkError::StreamOpen,
                        association,
                    });
                }
            };
        crate::exit_trace::record("gateway-prepare-output-stream-open");
        if output_send.set_priority(OUTPUT_STREAM_PRIORITY).is_err() {
            connection.close(CLOSE_CODE, b"everudp stream priority failed");
            return Err(GatewayOpenFailure {
                error: LinkError::StreamOpen,
                association,
            });
        }
        let incoming_connection = connection.clone();
        let incoming_uni = tokio::spawn(async move { incoming_connection.accept_uni().await });
        #[cfg(feature = "path-packet-diagnostics")]
        let diagnostic_connection = connection.diagnostic_id();
        Ok(Self {
            connection,
            #[cfg(feature = "path-packet-diagnostics")]
            diagnostic_connection,
            #[cfg(feature = "path-packet-diagnostics")]
            output_offsets: crate::packet_offsets::Cursor::default(),
            control_send,
            control_recv,
            input_recv: None,
            incoming_uni: Some(incoming_uni),
            input_finished: false,
            output_send,
            association,
            limits,
            control_reader: storage.control_reader,
            input_reader: storage.input_reader,
            control_buffer: storage.control_buffer,
            output_buffer: storage.output_buffer,
            input_event_buffer: storage.input_event_buffer,
            control_event_buffer: storage.control_event_buffer,
            control_pending: None,
            #[cfg(feature = "input-ack-hold-spike")]
            ack_hold: crate::ack_hold::AckHold::default(),
            #[cfg(feature = "input-ack-hold-spike")]
            ack_hold_timer: Box::pin(tokio::time::sleep(std::time::Duration::ZERO)),
            output_pending: None,
            next_output_sequence,
            output_epoch,
            output_reset: false,
            #[cfg(feature = "datagram-spike")]
            fast_output_floor,
            #[cfg(feature = "datagram-spike")]
            fast_input_through,
        })
    }

    /// Releases `SERVER_HELLO` after the gateway's persistent PTY writer is
    /// ready. Failure rolls back every initial association resource.
    pub(crate) async fn commit_prepared_initial(
        mut self,
        lifecycle: &mut GatewayLifecycle,
        slabs: &mut GatewayReplaySlabs,
    ) -> Result<Self, LinkError> {
        crate::exit_trace::record("gateway-prepare-flush-server-hello");
        if let Err(error) = self.flush_control(slabs).await {
            let association = self.into_failed_association();
            association.rollback_initial(lifecycle, slabs)?;
            return Err(error);
        }
        crate::exit_trace::record("gateway-prepare-server-hello-flushed");
        Ok(self)
    }

    /// Rejects a prepared association before `SERVER_HELLO`, preserving the
    /// pre-commit exit distinction used by `--transport auto`.
    pub(crate) fn reject_prepared_writer_busy(
        mut self,
        lifecycle: &mut GatewayLifecycle,
        slabs: &mut GatewayReplaySlabs,
    ) -> Result<(), LinkError> {
        self.abort_incoming_uni();
        self.connection
            .close(WRITER_BUSY_CLOSE_CODE, b"everudp writer is busy");
        self.association.rollback_initial(lifecycle, slabs)?;
        Ok(())
    }

    /// Aborts a prepared association before `SERVER_HELLO` and rolls back its
    /// lifecycle and replay reservations.
    pub(crate) fn abort_prepared_initial(
        mut self,
        lifecycle: &mut GatewayLifecycle,
        slabs: &mut GatewayReplaySlabs,
    ) -> Result<(), LinkError> {
        self.abort_incoming_uni();
        self.connection
            .close(CLOSE_CODE, b"everudp PTY writer activation failed");
        self.association.rollback_initial(lifecycle, slabs)?;
        Ok(())
    }

    pub fn association(&self) -> &GatewayAssociation {
        &self.association
    }

    /// Reports an output epoch transition before the gateway admits another
    /// input operation on this link. Once output has overrun, accepting input
    /// on the old link could discard the application's response and still ACK
    /// the keystroke, making it impossible for resume to replay safely.
    pub(crate) fn output_resume_required(
        &self,
        slabs: &GatewayReplaySlabs,
    ) -> Result<bool, LinkError> {
        if self.association.role() == ConnectionRole::Observer {
            return Ok(false);
        }
        let output = self.association.output(slabs)?;
        Ok(output.is_discarding() || output.epoch() != self.output_epoch)
    }

    /// Waits for a complete control/input record while keeping replay state
    /// unborrowed. Payload bytes are copied into fixed link-owned storage and
    /// exposed only to [`GatewayLink::apply_inbound`].
    // Only ignored fast-lane datagrams retry this loop. Stream-only builds
    // return after one operation but share the same cancellation-safe body.
    #[cfg_attr(not(feature = "datagram-spike"), allow(clippy::never_loop))]
    pub async fn next_inbound(&mut self) -> Result<LinkInbound, LinkError> {
        enum Ready {
            #[cfg(feature = "datagram-spike")]
            Fast(Result<Bytes, noq::ConnectionError>),
            Control(Result<Option<(Kind, u64, usize)>, LinkError>),
            Input(Result<Option<(Kind, u64, usize)>, LinkError>),
            Open(Result<RecvStream, LinkError>),
        }

        loop {
            if self.association.role() == ConnectionRole::Observer {
                let incoming = self
                    .incoming_uni
                    .as_mut()
                    .expect("observer input guard is live");
                let ready = tokio::select! {
                    control = self.control_reader.receive_copy(&mut self.control_recv, &self.limits, &mut self.control_event_buffer) => Ready::Control(control),
                    input = incoming => Ready::Open(match input {
                        Ok(Ok(stream)) => Ok(stream),
                        Ok(Err(_)) | Err(_) => Err(LinkError::StreamOpen),
                    }),
                };
                return match ready {
                    Ready::Control(Ok(Some((kind, sequence, payload_len)))) => {
                        Ok(LinkInbound::Control {
                            kind,
                            sequence,
                            payload_len,
                        })
                    }
                    Ready::Control(Ok(None)) => Ok(LinkInbound::ControlFinished),
                    Ready::Control(Err(error)) => Err(error),
                    Ready::Open(Ok(_)) => Err(LinkError::ObserverInputStream),
                    Ready::Open(Err(_)) => Err(LinkError::StreamOpen),
                    Ready::Input(_) => unreachable!("observer never polls input"),
                    #[cfg(feature = "datagram-spike")]
                    Ready::Fast(_) => unreachable!("observer never polls fast input"),
                };
            }

            if self.input_finished {
                return match self
                    .control_reader
                    .receive_copy(
                        &mut self.control_recv,
                        &self.limits,
                        &mut self.control_event_buffer,
                    )
                    .await?
                {
                    Some((kind, sequence, payload_len)) => Ok(LinkInbound::Control {
                        kind,
                        sequence,
                        payload_len,
                    }),
                    None => Ok(LinkInbound::ControlFinished),
                };
            }

            if self.input_recv.is_none() {
                #[cfg(feature = "datagram-spike")]
                let connection = &self.connection;
                let incoming = self
                    .incoming_uni
                    .as_mut()
                    .expect("writer input accept is live");
                let ready = {
                    #[cfg(feature = "datagram-spike")]
                    {
                        tokio::select! {
                            biased;
                            datagram = connection.read_datagram() => Ready::Fast(datagram),
                            control = self.control_reader.receive_copy(&mut self.control_recv, &self.limits, &mut self.control_event_buffer) => Ready::Control(control),
                            input = incoming => Ready::Open(match input {
                                Ok(Ok(stream)) => Ok(stream),
                                Ok(Err(_)) | Err(_) => Err(LinkError::StreamOpen),
                            }),
                        }
                    }
                    #[cfg(not(feature = "datagram-spike"))]
                    {
                        tokio::select! {
                            control = self.control_reader.receive_copy(&mut self.control_recv, &self.limits, &mut self.control_event_buffer) => Ready::Control(control),
                            input = incoming => Ready::Open(match input {
                                Ok(Ok(stream)) => Ok(stream),
                                Ok(Err(_)) | Err(_) => Err(LinkError::StreamOpen),
                            }),
                        }
                    }
                };
                match ready {
                    #[cfg(feature = "datagram-spike")]
                    Ready::Fast(Ok(datagram)) => {
                        if let Some((kind, sequence, payload_len)) = copy_fast_input_record(
                            &self.association,
                            &datagram,
                            &mut self.input_event_buffer,
                        ) {
                            self.fast_input_through =
                                self.fast_input_through.max(sequence.saturating_add(1));
                            return Ok(LinkInbound::Input {
                                kind,
                                sequence,
                                payload_len,
                                source: InputSource::Fast,
                            });
                        }
                    }
                    #[cfg(feature = "datagram-spike")]
                    Ready::Fast(Err(_)) => return Err(LinkError::StreamRead),
                    Ready::Control(Ok(Some((kind, sequence, payload_len)))) => {
                        return Ok(LinkInbound::Control {
                            kind,
                            sequence,
                            payload_len,
                        });
                    }
                    Ready::Control(Ok(None)) => return Ok(LinkInbound::ControlFinished),
                    Ready::Control(Err(error)) => return Err(error),
                    Ready::Open(Ok(input)) => {
                        self.incoming_uni = None;
                        self.input_recv = Some(input);
                        return Ok(LinkInbound::InputStreamOpened);
                    }
                    Ready::Open(Err(_)) => return Err(LinkError::StreamOpen),
                    Ready::Input(_) => unreachable!("input stream is not open"),
                }
                #[cfg(feature = "datagram-spike")]
                continue;
            }

            #[cfg(feature = "datagram-spike")]
            let connection = &self.connection;
            let input = self.input_recv.as_mut().expect("writer input is open");
            let ready = {
                #[cfg(feature = "datagram-spike")]
                {
                    tokio::select! {
                        biased;
                        datagram = connection.read_datagram() => Ready::Fast(datagram),
                        control = self.control_reader.receive_copy(&mut self.control_recv, &self.limits, &mut self.control_event_buffer) => Ready::Control(control),
                        input = self.input_reader.receive_copy(input, &self.limits, &mut self.input_event_buffer) => Ready::Input(input),
                    }
                }
                #[cfg(not(feature = "datagram-spike"))]
                {
                    tokio::select! {
                        control = self.control_reader.receive_copy(&mut self.control_recv, &self.limits, &mut self.control_event_buffer) => Ready::Control(control),
                        input = self.input_reader.receive_copy(input, &self.limits, &mut self.input_event_buffer) => Ready::Input(input),
                    }
                }
            };
            match ready {
                #[cfg(feature = "datagram-spike")]
                Ready::Fast(Ok(datagram)) => {
                    if let Some((kind, sequence, payload_len)) = copy_fast_input_record(
                        &self.association,
                        &datagram,
                        &mut self.input_event_buffer,
                    ) {
                        self.fast_input_through =
                            self.fast_input_through.max(sequence.saturating_add(1));
                        return Ok(LinkInbound::Input {
                            kind,
                            sequence,
                            payload_len,
                            source: InputSource::Fast,
                        });
                    }
                }
                #[cfg(feature = "datagram-spike")]
                Ready::Fast(Err(_)) => return Err(LinkError::StreamRead),
                Ready::Control(Ok(Some((kind, sequence, payload_len)))) => {
                    return Ok(LinkInbound::Control {
                        kind,
                        sequence,
                        payload_len,
                    });
                }
                Ready::Control(Ok(None)) => return Ok(LinkInbound::ControlFinished),
                Ready::Control(Err(error)) => return Err(error),
                Ready::Input(Ok(Some((kind, sequence, payload_len)))) => {
                    return Ok(LinkInbound::Input {
                        kind,
                        sequence,
                        payload_len,
                        source: InputSource::Stream,
                    });
                }
                Ready::Input(Ok(None)) if self.association.input_closed() => {
                    self.input_finished = true;
                    return Ok(LinkInbound::InputFinished);
                }
                Ready::Input(Ok(None)) => return Err(LinkError::InputCloseMissing),
                Ready::Input(Err(error)) => return Err(error),
                Ready::Open(_) => unreachable!("both streams are already selected"),
            }
        }
    }

    pub(crate) fn is_fast_stream_duplicate(&self, event: &LinkInbound) -> bool {
        #[cfg(feature = "datagram-spike")]
        {
            matches!(
                event,
                LinkInbound::Input {
                    sequence,
                    source: InputSource::Stream,
                    ..
                } if *sequence < self.fast_input_through
            )
        }
        #[cfg(not(feature = "datagram-spike"))]
        {
            let _ = event;
            false
        }
    }

    /// Applies a previously returned record and advances acknowledgements
    /// only after the supplied everpty sink accepts a whole input operation.
    pub fn apply_inbound<F>(
        &mut self,
        event: LinkInbound,
        slabs: &mut GatewayReplaySlabs,
        mut sink: F,
    ) -> Result<Option<InputReceipt>, LinkError>
    where
        F: FnMut(InputOperation<'_>) -> io::Result<()>,
    {
        match self.prepare_inbound(event, slabs)? {
            InboundApply::None | InboundApply::Detach => Ok(None),
            InboundApply::Receipt(receipt) => Ok(Some(receipt)),
            InboundApply::Deliver(prepared) => {
                let token = prepared.token();
                if let Err(error) = sink(prepared.operation()) {
                    self.abort_prepared_input(token)?;
                    return Err(LinkError::Sink(error));
                }
                self.commit_prepared_input(token, slabs).map(Some)
            }
        }
    }

    pub fn prepare_inbound(
        &mut self,
        event: LinkInbound,
        slabs: &mut GatewayReplaySlabs,
    ) -> Result<InboundApply<'_>, LinkError> {
        match event {
            LinkInbound::InputStreamOpened | LinkInbound::ControlFinished => Ok(InboundApply::None),
            LinkInbound::InputFinished => {
                if self.association.input_closed() {
                    Ok(InboundApply::Receipt(InputReceipt::Finished))
                } else {
                    Err(LinkError::InputCloseMissing)
                }
            }
            LinkInbound::Control {
                kind,
                sequence,
                payload_len,
            } => match kind {
                Kind::AckOutput => {
                    let acknowledgement = Ack::decode_exact(
                        &self.control_event_buffer[..payload_len],
                        Kind::AckOutput,
                    )?;
                    self.association
                        .accept_output_ack(sequence, acknowledgement, slabs)?;
                    Ok(InboundApply::None)
                }
                Kind::Detach => match self.association.accept_detach(sequence)? {
                    ControlDisposition::Applied => Ok(InboundApply::Detach),
                    ControlDisposition::Duplicate => Ok(InboundApply::None),
                },
                _ => Err(WireError::KindNotAllowed {
                    kind,
                    stream: StreamRole::Control,
                }
                .into()),
            },
            LinkInbound::Input {
                kind,
                sequence,
                payload_len,
                source: _,
            } => {
                let disposition = self.association.begin_input(
                    kind,
                    sequence,
                    &self.input_event_buffer[..payload_len],
                )?;
                if !self.association.can_queue_input_ack(slabs) {
                    if matches!(disposition, InputDisposition::Deliver(_)) {
                        self.association.abort_input(sequence)?;
                    }
                    return Err(LinkError::ControlBackpressure);
                }
                match disposition {
                    InputDisposition::Deliver(operation) => {
                        if self.association.input_closed() {
                            self.association.abort_input(sequence)?;
                            return Err(LinkError::InputAfterClose);
                        }
                        #[cfg(feature = "path-diagnostics")]
                        if kind == Kind::Input {
                            slabs.trace_boundary(
                                crate::path_trace::Stage::GatewayInputPrepared,
                                self.association.input_position().0,
                                sequence,
                            );
                        }
                        Ok(InboundApply::Deliver(PreparedInput {
                            operation,
                            kind,
                            sequence,
                        }))
                    }
                    InputDisposition::Duplicate { acknowledgement } => {
                        self.association.repeat_input_ack(acknowledgement, slabs)?;
                        Ok(InboundApply::Receipt(InputReceipt::Duplicate {
                            sequence,
                            acknowledgement,
                        }))
                    }
                }
            }
        }
    }

    pub fn commit_prepared_input(
        &mut self,
        token: PreparedInputToken,
        slabs: &mut GatewayReplaySlabs,
    ) -> Result<InputReceipt, LinkError> {
        let acknowledgement = self.association.commit_input(token.sequence, slabs)?;
        #[cfg(feature = "path-diagnostics")]
        if token.kind == Kind::Input {
            // Production caller commits only after PtySession accepts the
            // whole operation; this is not a remote-application render marker.
            slabs.trace_boundary(
                crate::path_trace::Stage::GatewayInputAccepted,
                acknowledgement.epoch,
                token.sequence,
            );
        }
        if token.kind == Kind::InputClose {
            self.association.mark_input_closed();
        }
        Ok(InputReceipt::Delivered {
            kind: token.kind,
            sequence: token.sequence,
            acknowledgement: acknowledgement.next_expected,
        })
    }

    pub fn abort_prepared_input(&mut self, token: PreparedInputToken) -> Result<(), LinkError> {
        self.association
            .abort_input(token.sequence)
            .map_err(Into::into)
    }

    /// Sends every queued control record and retires it after QUIC accepts the
    /// complete record. Control state is reconstructed by each resume hello;
    /// terminal exactly-once history remains in the input/output queues.
    pub async fn flush_control(
        &mut self,
        slabs: &mut GatewayReplaySlabs,
    ) -> Result<usize, LinkError> {
        let mut sent = 0usize;
        loop {
            match std::future::poll_fn(|context| self.poll_control_step(slabs, context)).await? {
                OutboundStep::Idle => break,
                OutboundStep::Record => sent += 1,
                OutboundStep::Progress => {}
                OutboundStep::Discarding { .. } => {
                    unreachable!("control streams never discard")
                }
            }
        }
        Ok(sent)
    }

    /// Reads and delivers exactly one ordered input operation. The supplied
    /// sink is invoked before the cumulative ACK advances. A sink error aborts
    /// the pending delivery and never acknowledges it.
    pub async fn receive_input<F>(
        &mut self,
        slabs: &mut GatewayReplaySlabs,
        mut sink: F,
    ) -> Result<InputReceipt, LinkError>
    where
        F: FnMut(InputOperation<'_>) -> io::Result<()>,
    {
        if self.association.role() != ConnectionRole::Writer {
            return Err(LinkError::ObserverInputStream);
        }
        if self.input_recv.is_none() {
            self.input_recv = Some(self.accept_input_stream().await?);
        }
        let input = self
            .input_recv
            .as_mut()
            .expect("writer input just accepted");
        let Some(record) = self.input_reader.receive(input, &self.limits).await? else {
            return if self.association.input_closed() {
                Ok(InputReceipt::Finished)
            } else {
                Err(LinkError::InputCloseMissing)
            };
        };
        let kind = record.header.kind;
        let sequence = record.header.sequence;
        let disposition = self
            .association
            .begin_input(kind, sequence, record.payload)?;
        if !self.association.can_queue_input_ack(slabs) {
            if matches!(disposition, InputDisposition::Deliver(_)) {
                self.association.abort_input(sequence)?;
            }
            return Err(LinkError::ControlBackpressure);
        }
        let receipt = match disposition {
            InputDisposition::Deliver(operation) => {
                if self.association.input_closed() {
                    self.association.abort_input(sequence)?;
                    return Err(LinkError::InputAfterClose);
                }
                if let Err(error) = sink(operation) {
                    self.association.abort_input(sequence)?;
                    return Err(LinkError::Sink(error));
                }
                let acknowledgement = self.association.commit_input(sequence, slabs)?;
                if kind == Kind::InputClose {
                    self.association.mark_input_closed();
                }
                InputReceipt::Delivered {
                    kind,
                    sequence,
                    acknowledgement: acknowledgement.next_expected,
                }
            }
            InputDisposition::Duplicate { acknowledgement } => {
                self.association.repeat_input_ack(acknowledgement, slabs)?;
                InputReceipt::Duplicate {
                    sequence,
                    acknowledgement,
                }
            }
        };
        self.input_reader.consume();
        Ok(receipt)
    }

    /// Applies one client control record. Output ACKs are epoch-bound and
    /// idempotent; other control commands are introduced with gateway command
    /// wiring rather than silently ignored here.
    pub async fn receive_control(
        &mut self,
        slabs: &mut GatewayReplaySlabs,
    ) -> Result<ControlReceipt, LinkError> {
        let Some(record) = self
            .control_reader
            .receive(&mut self.control_recv, &self.limits)
            .await?
        else {
            return Ok(ControlReceipt::Finished);
        };
        let receipt = match record.header.kind {
            Kind::AckOutput => {
                let acknowledgement = Ack::decode_exact(record.payload, Kind::AckOutput)?;
                let disposition = self.association.accept_output_ack(
                    record.header.sequence,
                    acknowledgement,
                    slabs,
                )?;
                ControlReceipt::OutputAck {
                    acknowledgement,
                    disposition,
                }
            }
            kind => {
                return Err(WireError::KindNotAllowed {
                    kind,
                    stream: StreamRole::Control,
                }
                .into());
            }
        };
        self.control_reader.consume();
        Ok(receipt)
    }

    /// Sends all presently retained output records. Records remain retained
    /// until a client ACK arrives. An overrun resets the stale output stream;
    /// a resumed connection will create the replacement stream and emit GAP.
    pub async fn flush_output(
        &mut self,
        slabs: &GatewayReplaySlabs,
    ) -> Result<OutputFlush, LinkError> {
        let mut sent = 0usize;
        loop {
            match std::future::poll_fn(|context| self.poll_output_step(slabs, context)).await? {
                OutboundStep::Idle => break,
                OutboundStep::Record => sent += 1,
                OutboundStep::Progress => {}
                OutboundStep::Discarding { .. } => return Ok(OutputFlush::Discarding),
            }
        }
        Ok(if sent == 0 {
            OutputFlush::Idle
        } else {
            OutputFlush::Sent { records: sent }
        })
    }

    /// Advances at most one cancellation-safe write on each independent
    /// outbound stream. A flow-controlled peer registers its waker and gives
    /// the gateway loop back immediately, so another association and the PTY
    /// remain runnable.
    pub(crate) fn poll_outbound(
        &mut self,
        slabs: &mut GatewayReplaySlabs,
        context: &mut Context<'_>,
    ) -> Poll<Result<bool, LinkError>> {
        let control = self.poll_control_step(slabs, context);
        match control {
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(OutboundStep::Progress | OutboundStep::Record | OutboundStep::Idle))
            | Poll::Pending => {}
            Poll::Ready(Ok(OutboundStep::Discarding { .. })) => {
                unreachable!("control streams never discard")
            }
        }

        let control_progress = matches!(
            control,
            Poll::Ready(Ok(OutboundStep::Progress | OutboundStep::Record))
        );
        let output = self.poll_output_step(slabs, context);
        match output {
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(OutboundStep::Progress | OutboundStep::Record)) => Poll::Ready(Ok(true)),
            Poll::Ready(Ok(OutboundStep::Discarding { reset })) => {
                Poll::Ready(Ok(reset || control_progress))
            }
            Poll::Ready(Ok(OutboundStep::Idle)) | Poll::Pending => {
                if control_progress {
                    Poll::Ready(Ok(true))
                } else if matches!(control, Poll::Ready(Ok(OutboundStep::Idle)))
                    && matches!(output, Poll::Ready(Ok(OutboundStep::Idle)))
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
        slabs: &mut GatewayReplaySlabs,
        context: &mut Context<'_>,
    ) -> Poll<Result<OutboundStep, LinkError>> {
        if self.control_pending.is_none() {
            let copy = {
                let control = match self.association.control(slabs) {
                    Ok(control) => control,
                    Err(error) => return Poll::Ready(Err(error.into())),
                };
                if control.unacknowledged_operations() == 0 {
                    return Poll::Ready(Ok(OutboundStep::Idle));
                }
                match control.copy_unacked(0, &mut self.control_buffer) {
                    Ok(copy) => copy,
                    Err(error) => return Poll::Ready(Err(error.into())),
                }
            };
            self.control_pending = Some(PendingWrite {
                #[cfg(feature = "input-ack-hold-spike")]
                kind: copy.kind,
                sequence: copy.sequence,
                wire_len: copy.wire_len,
                written: 0,
            });
        }

        #[cfg(feature = "input-ack-hold-spike")]
        match self.poll_input_ack_hold(slabs, context) {
            Ok(true) => return Poll::Pending,
            Ok(false) => {}
            Err(error) => return Poll::Ready(Err(error)),
        }
        let pending = self.control_pending.as_mut().expect("control pending");
        let written = match Pin::new(&mut self.control_send).poll_write(
            context,
            &self.control_buffer[pending.written..pending.wire_len],
        ) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(0) | Err(_)) => return Poll::Ready(Err(LinkError::StreamWrite)),
            Poll::Ready(Ok(written)) => written,
        };
        pending.written += written;
        if pending.written < pending.wire_len {
            return Poll::Ready(Ok(OutboundStep::Progress));
        }
        let next_expected = match pending.sequence.checked_add(1) {
            Some(sequence) => sequence,
            None => return Poll::Ready(Err(QueueError::SequenceOverflow.into())),
        };
        self.control_pending = None;
        #[cfg(feature = "input-ack-hold-spike")]
        self.ack_hold.reset();
        if let Err(error) = self
            .association
            .acknowledge_control_sent(next_expected, slabs)
        {
            return Poll::Ready(Err(error.into()));
        }
        Poll::Ready(Ok(OutboundStep::Record))
    }

    #[cfg(feature = "input-ack-hold-spike")]
    fn poll_input_ack_hold(
        &mut self,
        slabs: &GatewayReplaySlabs,
        context: &mut Context<'_>,
    ) -> Result<bool, LinkError> {
        let pending = self.control_pending.as_ref().expect("control pending");
        let control = self.association.control(slabs)?;
        let output = self.association.output(slabs)?;
        let eligible = crate::ack_hold::eligible(
            pending.kind,
            pending.written,
            control.unacknowledged_operations(),
            self.output_pending.is_some() || self.next_output_sequence < output.next_sequence(),
            !output.is_discarding() && output.epoch() == self.output_epoch,
        );
        let now = tokio::time::Instant::now();
        let Some(deadline) = self.ack_hold.deadline(now, eligible) else {
            return Ok(false);
        };
        if self.ack_hold_timer.deadline() != deadline {
            self.ack_hold_timer.as_mut().reset(deadline);
        }
        if std::future::Future::poll(self.ack_hold_timer.as_mut(), context).is_pending() {
            Ok(true)
        } else {
            self.ack_hold.deadline(now, false);
            Ok(false)
        }
    }

    fn poll_output_step(
        &mut self,
        slabs: &GatewayReplaySlabs,
        context: &mut Context<'_>,
    ) -> Poll<Result<OutboundStep, LinkError>> {
        let output = match self.association.output(slabs) {
            Ok(output) => output,
            Err(error) => return Poll::Ready(Err(error.into())),
        };
        if output.is_discarding() || output.epoch() != self.output_epoch {
            self.output_pending = None;
            let reset = !self.output_reset;
            if reset {
                let _ = self.output_send.reset(CLOSE_CODE);
                self.output_reset = true;
            }
            return Poll::Ready(Ok(OutboundStep::Discarding { reset }));
        }
        // An ACK can retire the last record before this reliable sender polls
        // (for example after fast-lane delivery). An empty queue's committed
        // frontier is next_sequence, not the previous send cursor.
        let first = output
            .first_unacknowledged_sequence()
            .unwrap_or_else(|| output.next_sequence());
        self.next_output_sequence = self.next_output_sequence.max(first);
        if self.output_pending.is_none() {
            if self.next_output_sequence >= output.next_sequence() {
                return Poll::Ready(Ok(OutboundStep::Idle));
            }
            let copy =
                match output.copy_sequence(self.next_output_sequence, &mut self.output_buffer) {
                    Ok(copy) => copy,
                    Err(error) => return Poll::Ready(Err(error.into())),
                };
            #[cfg(feature = "datagram-spike")]
            if copy.kind == Kind::Output && copy.sequence >= self.fast_output_floor {
                send_fast_datagram_copy(
                    &self.connection,
                    crate::wire::FastDirection::GatewayToClient,
                    copy.kind,
                    output.epoch(),
                    copy.sequence,
                    &self.output_buffer[crate::wire::HEADER_LEN..copy.wire_len],
                    context,
                );
                self.fast_output_floor = copy.sequence.saturating_add(1);
            }
            #[cfg(feature = "path-packet-diagnostics")]
            if let Some((offset, len)) = self.output_offsets.reserve(copy.wire_len) {
                crate::packet_trace::record_operation(crate::packet_trace::Operation {
                    connection: self.diagnostic_connection,
                    stream: self.output_send.id().into(),
                    epoch: output.epoch(),
                    sequence: copy.sequence,
                    kind: copy.kind as u8,
                    offset,
                    len,
                });
            } else {
                crate::packet_trace::invalidate();
            }
            self.output_pending = Some(PendingWrite {
                #[cfg(feature = "input-ack-hold-spike")]
                kind: copy.kind,
                sequence: copy.sequence,
                wire_len: copy.wire_len,
                written: 0,
            });
        }

        let pending = self.output_pending.as_mut().expect("output pending");
        let written = match Pin::new(&mut self.output_send).poll_write(
            context,
            &self.output_buffer[pending.written..pending.wire_len],
        ) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(0) | Err(_)) => return Poll::Ready(Err(LinkError::StreamWrite)),
            Poll::Ready(Ok(written)) => written,
        };
        pending.written += written;
        if pending.written < pending.wire_len {
            return Poll::Ready(Ok(OutboundStep::Progress));
        }
        self.next_output_sequence = match pending.sequence.checked_add(1) {
            Some(sequence) => sequence,
            None => return Poll::Ready(Err(QueueError::SequenceOverflow.into())),
        };
        self.output_pending = None;
        // Offer a complete reliable output record without waiting for another
        // task turn. The protocol still owns pacing, congestion and blocked
        // transmits; application replay is not retired by this operation.
        #[cfg(feature = "stream-flush-spike")]
        if self.connection.flush_transmit_now(context).is_err() {
            return Poll::Ready(Err(LinkError::StreamWrite));
        }
        Poll::Ready(Ok(OutboundStep::Record))
    }

    /// Offers freshly queued PTY output to the unreliable fast lane before
    /// the gateway loop schedules its authoritative replay-stream copy.
    #[cfg(feature = "datagram-spike")]
    pub(crate) async fn send_fresh_output_fast(
        &mut self,
        slabs: &GatewayReplaySlabs,
        payload: &[u8],
    ) {
        let Some((epoch, sequence)) = self.association.output(slabs).ok().and_then(|output| {
            (!output.is_discarding() && output.epoch() == self.output_epoch)
                .then(|| {
                    output
                        .next_sequence()
                        .checked_sub(1)
                        .map(|sequence| (output.epoch(), sequence))
                })
                .flatten()
        }) else {
            return;
        };
        if sequence < self.fast_output_floor {
            return;
        }
        send_fast_datagram_copy_async(
            &self.connection,
            crate::wire::FastDirection::GatewayToClient,
            Kind::Output,
            epoch,
            sequence,
            payload,
        )
        .await;
        self.fast_output_floor = sequence.saturating_add(1);
    }

    /// Waits for a protocol-invalid observer input stream. A live gateway run
    /// loop selects this future alongside control/output work.
    pub async fn reject_observer_input(&mut self) -> Result<(), LinkError> {
        if self.association.role() != ConnectionRole::Observer {
            return Ok(());
        }
        self.accept_input_stream().await?;
        Err(LinkError::ObserverInputStream)
    }

    async fn accept_input_stream(&mut self) -> Result<RecvStream, LinkError> {
        let incoming = self.incoming_uni.take().ok_or(LinkError::StreamOpen)?;
        incoming
            .await
            .map_err(|_| LinkError::StreamOpen)?
            .map_err(|_| LinkError::StreamOpen)
    }

    pub fn close(mut self) {
        self.abort_incoming_uni();
        self.connection.close(CLOSE_CODE, b"everudp link closed");
    }

    pub fn into_resumable_association(mut self) -> GatewayAssociation {
        self.abort_incoming_uni();
        self.connection
            .close(RESUME_CLOSE_CODE, b"everudp link will resume");
        self.association
    }

    fn into_failed_association(mut self) -> GatewayAssociation {
        self.abort_incoming_uni();
        self.connection
            .close(CLOSE_CODE, b"everudp link establishment failed");
        self.association
    }

    fn abort_incoming_uni(&mut self) {
        if let Some(incoming) = self.incoming_uni.take() {
            incoming.abort();
        }
    }
}

fn prepare_gateway_link_storage(limits: Limits) -> Result<GatewayLinkStorage, LinkError> {
    Ok(GatewayLinkStorage {
        control_reader: RecordReader::new(StreamRole::Control, limits)?,
        input_reader: RecordReader::new(StreamRole::Input, limits)?,
        control_buffer: fixed_buffer(limits.control_frame_max + crate::wire::HEADER_LEN)?,
        output_buffer: fixed_buffer(limits.terminal_frame_max + crate::wire::HEADER_LEN)?,
        input_event_buffer: fixed_buffer(limits.terminal_frame_max)?,
        control_event_buffer: fixed_buffer(limits.control_frame_max)?,
    })
}

impl fmt::Debug for GatewayLink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayLink")
            .field("association", &self.association)
            .field("output_epoch", &self.output_epoch)
            .field("next_output_sequence", &self.next_output_sequence)
            .field("output_reset", &self.output_reset)
            .field("payload", &"<REDACTED>")
            .finish()
    }
}

#[cfg(feature = "datagram-spike")]
fn send_fast_datagram_copy(
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
async fn send_fast_datagram_copy_async(
    connection: &Connection,
    direction: crate::wire::FastDirection,
    kind: Kind,
    epoch: u64,
    sequence: u64,
    payload: &[u8],
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
        let _ = std::future::poll_fn(|context| Poll::Ready(connection.flush_transmit_now(context)))
            .await;
    }
}

#[cfg(feature = "datagram-spike")]
fn copy_fast_input_record(
    association: &GatewayAssociation,
    bytes: &[u8],
    output: &mut [u8],
) -> Option<(Kind, u64, usize)> {
    if association.role() != ConnectionRole::Writer || association.input_closed() {
        return None;
    }
    let record =
        crate::wire::decode_fast_datagram(crate::wire::FastDirection::ClientToGateway, bytes)
            .ok()?;
    let (epoch, next_expected) = association.input_position();
    if record.epoch != epoch
        || record.sequence > next_expected
        || record.payload.len() > output.len()
    {
        return None;
    }
    output[..record.payload.len()].copy_from_slice(record.payload);
    Some((record.kind, record.sequence, record.payload.len()))
}

pub(crate) struct RecordReader {
    stream: StreamRole,
    bytes: Box<[u8]>,
    filled: usize,
    total: Option<usize>,
}

impl RecordReader {
    pub(crate) fn new(stream: StreamRole, limits: Limits) -> Result<Self, LinkError> {
        let payload = match stream {
            StreamRole::Control => limits.control_frame_max,
            StreamRole::Input | StreamRole::Output => limits.terminal_frame_max,
        };
        Ok(Self {
            stream,
            bytes: fixed_buffer(payload + crate::wire::HEADER_LEN)?,
            filled: 0,
            total: None,
        })
    }

    pub(crate) async fn receive<'a>(
        &'a mut self,
        recv: &mut RecvStream,
        limits: &Limits,
    ) -> Result<Option<Record<'a>>, LinkError> {
        loop {
            let target = if self.filled < crate::wire::HEADER_LEN {
                crate::wire::HEADER_LEN
            } else {
                match self.total {
                    Some(total) => total,
                    None => match decode_record(
                        self.stream,
                        &self.bytes[..crate::wire::HEADER_LEN],
                        limits,
                    ) {
                        Ok((_, consumed)) => {
                            self.total = Some(consumed);
                            consumed
                        }
                        Err(WireError::Incomplete { needed, .. }) => {
                            if needed > self.bytes.len() {
                                return Err(WireError::OutputTooSmall {
                                    needed,
                                    available: self.bytes.len(),
                                }
                                .into());
                            }
                            self.total = Some(needed);
                            needed
                        }
                        Err(error) => return Err(error.into()),
                    },
                }
            };
            if self.filled == target {
                let (record, consumed) = decode_record(self.stream, &self.bytes[..target], limits)?;
                debug_assert_eq!(consumed, target);
                return Ok(Some(record));
            }
            let read = recv
                .read(&mut self.bytes[self.filled..target])
                .await
                .map_err(|_| LinkError::StreamRead)?;
            match read {
                Some(0) | None if self.filled == 0 => return Ok(None),
                Some(0) | None => return Err(LinkError::StreamEndedMidRecord),
                Some(count) => self.filled += count,
            }
        }
    }

    async fn receive_copy(
        &mut self,
        recv: &mut RecvStream,
        limits: &Limits,
        output: &mut [u8],
    ) -> Result<Option<(Kind, u64, usize)>, LinkError> {
        let copied = {
            let Some(record) = self.receive(recv, limits).await? else {
                return Ok(None);
            };
            let payload_len = record.payload.len();
            if payload_len > output.len() {
                return Err(WireError::OutputTooSmall {
                    needed: payload_len,
                    available: output.len(),
                }
                .into());
            }
            output[..payload_len].copy_from_slice(record.payload);
            (record.header.kind, record.header.sequence, payload_len)
        };
        self.consume();
        Ok(Some(copied))
    }

    pub(crate) fn consume(&mut self) {
        self.bytes[..self.filled].fill(0);
        self.filled = 0;
        self.total = None;
    }
}

impl Drop for RecordReader {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

fn fixed_buffer(length: usize) -> Result<Box<[u8]>, LinkError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| LinkError::Association(AssociationError::Queue(QueueError::Allocation)))?;
    bytes.resize(length, 0);
    Ok(bytes.into_boxed_slice())
}
