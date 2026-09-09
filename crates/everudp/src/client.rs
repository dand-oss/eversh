//! Allocation-stable client association state, independent of terminal I/O.

use crate::handshake::{ClientHello, HandshakeError, ResumePosition, ServerHello};
use crate::queues::{DeliveryDecision, DeliveryGate, FrameCopy, QueueError, ReplayRing};
use crate::wire::{Ack, ConnectionRole, EpochGap, Kind, Resize, StreamRole};
use crate::{GatewayGeneration, Limits, WireError};
use everssh::association::AssociationId;
use std::fmt;

#[derive(Debug)]
pub enum ClientError {
    Queue(QueueError),
    Wire(WireError),
    Handshake(HandshakeError),
    AssociationMismatch,
    GenerationMismatch,
    RoleMismatch,
    InputEpochMismatch,
    OutputEpochMismatch,
    OutputBehindAcknowledgement,
    ObserverInput,
    InputClosed,
    SignalDenied(u8),
    GapMismatch,
    OutputAlreadyStaged,
    OutputNotStaged,
    OutputProgressInvalid,
}

impl fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Queue(error) => write!(formatter, "{error}"),
            Self::Wire(error) => write!(formatter, "{error}"),
            Self::Handshake(error) => write!(formatter, "{error}"),
            Self::AssociationMismatch => formatter.write_str("everudp association changed"),
            Self::GenerationMismatch => formatter.write_str("everudp gateway generation changed"),
            Self::RoleMismatch => formatter.write_str("everudp connection role changed"),
            Self::InputEpochMismatch => formatter.write_str("everudp input epoch changed"),
            Self::OutputEpochMismatch => {
                formatter.write_str("everudp output epoch changed without GAP")
            }
            Self::OutputBehindAcknowledgement => {
                formatter.write_str("everudp server output position is behind its acknowledgement")
            }
            Self::ObserverInput => formatter.write_str("everudp observer cannot send input"),
            Self::InputClosed => formatter.write_str("everudp input is already closed"),
            Self::SignalDenied(_) => formatter.write_str("everudp signal is not allow-listed"),
            Self::GapMismatch => formatter.write_str("everudp GAP epochs are inconsistent"),
            Self::OutputAlreadyStaged => {
                formatter.write_str("an everudp output operation is already staged")
            }
            Self::OutputNotStaged => formatter.write_str("no everudp output operation is staged"),
            Self::OutputProgressInvalid => {
                formatter.write_str("invalid everudp stdout acceptance progress")
            }
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Queue(error) => Some(error),
            Self::Wire(error) => Some(error),
            Self::Handshake(error) => Some(error),
            _ => None,
        }
    }
}

impl From<QueueError> for ClientError {
    fn from(value: QueueError) -> Self {
        Self::Queue(value)
    }
}

impl From<WireError> for ClientError {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}

impl From<HandshakeError> for ClientError {
    fn from(value: HandshakeError) -> Self {
        Self::Handshake(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputOperation<'a> {
    Bytes(&'a [u8]),
    Ownership(u8),
    Exit(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputDisposition<'a> {
    Deliver(OutputOperation<'a>),
    Duplicate { acknowledgement: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputStage {
    Staged { kind: Kind, sequence: u64 },
    Duplicate { sequence: u64, acknowledgement: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingOutputView<'a> {
    pub kind: Kind,
    pub sequence: u64,
    pub operation: OutputOperation<'a>,
}

#[derive(Debug, Clone, Copy)]
struct PendingOutput {
    kind: Kind,
    sequence: u64,
    length: usize,
    stdout_offset: usize,
}

/// Persistent client-side state kept across sequential QUIC connections.
pub struct ClientAssociation {
    association_id: AssociationId,
    generation: GatewayGeneration,
    role: ConnectionRole,
    input_epoch: u64,
    input: ReplayRing,
    output: DeliveryGate,
    server_control: DeliveryGate,
    control: ReplayRing,
    input_closed: bool,
    last_gap: Option<EpochGap>,
    gap_notice_pending: bool,
    output_staging: Box<[u8]>,
    pending_output: Option<PendingOutput>,
    limits: Limits,
    #[cfg(feature = "path-diagnostics")]
    path_trace: Option<crate::path_trace::FileTrace>,
}

impl ClientAssociation {
    pub fn new(
        association_id: AssociationId,
        generation: GatewayGeneration,
        role: ConnectionRole,
        limits: Limits,
    ) -> Result<Self, ClientError> {
        limits.validate().map_err(WireError::from)?;
        let mut output_staging = Vec::new();
        output_staging
            .try_reserve_exact(limits.terminal_frame_max)
            .map_err(|_| QueueError::Allocation)?;
        output_staging.resize(limits.terminal_frame_max, 0);
        Ok(Self {
            association_id,
            generation,
            role,
            input_epoch: 0,
            input: ReplayRing::new(StreamRole::Input, &limits)?,
            output: DeliveryGate::new(0, 0),
            server_control: DeliveryGate::new(0, 0),
            control: ReplayRing::control_after_hello(&limits)?,
            input_closed: false,
            last_gap: None,
            gap_notice_pending: false,
            output_staging: output_staging.into_boxed_slice(),
            pending_output: None,
            limits,
            #[cfg(feature = "path-diagnostics")]
            path_trace: None,
        })
    }

    pub fn role(&self) -> ConnectionRole {
        self.role
    }

    #[cfg(feature = "path-diagnostics")]
    pub fn enable_path_trace(&mut self, path: &std::path::Path) -> std::io::Result<()> {
        if self.path_trace.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "trace already enabled",
            ));
        }
        self.path_trace = Some(crate::path_trace::FileTrace::create(path)?);
        Ok(())
    }

    #[cfg(feature = "path-diagnostics")]
    pub(crate) fn trace_input_written(&mut self, sequence: u64) {
        if let Some(trace) = self.path_trace.as_mut() {
            trace.record(
                crate::path_trace::Stage::ClientInputWritten,
                self.input_epoch,
                sequence,
            );
        }
    }

    #[cfg(any(feature = "datagram-spike", feature = "path-packet-diagnostics"))]
    pub(crate) fn input_epoch(&self) -> u64 {
        self.input_epoch
    }

    #[cfg(feature = "datagram-spike")]
    pub(crate) fn output_position(&self) -> (u64, u64) {
        (self.output.epoch(), self.output.acknowledgement())
    }

    pub fn association_id(&self) -> AssociationId {
        self.association_id
    }

    pub fn generation(&self) -> GatewayGeneration {
        self.generation
    }

    pub(crate) fn begin_server_control(
        &mut self,
        sequence: u64,
    ) -> Result<DeliveryDecision, ClientError> {
        self.server_control
            .begin(self.server_control.epoch(), sequence)
            .map_err(Into::into)
    }

    pub(crate) fn commit_server_control(&mut self, sequence: u64) -> Result<(), ClientError> {
        self.server_control
            .commit(self.server_control.epoch(), sequence)
            .map_err(Into::into)
    }

    pub(crate) fn abort_server_control(&mut self, sequence: u64) -> Result<(), ClientError> {
        self.server_control
            .abort(self.server_control.epoch(), sequence)
            .map_err(Into::into)
    }

    pub fn position(&self) -> ResumePosition {
        let delivered_output = self.output.acknowledgement();
        ResumePosition {
            input_epoch: self.input_epoch,
            next_input: self.input.next_sequence(),
            output_epoch: self.output.epoch(),
            next_output: delivered_output,
            delivered_output_ack: delivered_output,
        }
    }

    pub fn resume_hello(&self) -> Result<ClientHello, ClientError> {
        ClientHello::resume(
            self.association_id,
            self.generation,
            self.role,
            self.position(),
        )
        .map_err(Into::into)
    }

    /// Reconstructs link-local control state after CLIENT_HELLO has carried
    /// the durable cumulative output acknowledgement. Input and output
    /// sequence spaces remain association-lifetime state.
    pub(crate) fn start_link(&mut self) {
        self.server_control = DeliveryGate::new(0, 0);
        self.control.restart_control_after_hello();
    }

    pub fn apply_server_hello(&mut self, hello: ServerHello) -> Result<(), ClientError> {
        if hello.association_id() != self.association_id {
            return Err(ClientError::AssociationMismatch);
        }
        if hello.generation() != self.generation {
            return Err(ClientError::GenerationMismatch);
        }
        if hello.role() != self.role {
            return Err(ClientError::RoleMismatch);
        }
        if hello.input_epoch != self.input_epoch {
            return Err(ClientError::InputEpochMismatch);
        }
        if hello.accepted_input_ack > self.input.next_sequence() {
            return Err(QueueError::AckAhead.into());
        }
        let committed_input = self
            .input
            .first_unacknowledged_sequence()
            .unwrap_or_else(|| self.input.next_sequence());
        if hello.accepted_input_ack < committed_input {
            return Err(QueueError::AckBehind.into());
        }
        if let Some((abandoned, replacement)) = hello.pending_gap {
            if hello.output_epoch != replacement {
                return Err(ClientError::GapMismatch);
            }
            let gap = EpochGap::new(abandoned, replacement)?;
            if self.last_gap != Some(gap) && abandoned != self.output.epoch() {
                return Err(ClientError::GapMismatch);
            }
        } else if hello.output_epoch != self.output.epoch() {
            return Err(ClientError::OutputEpochMismatch);
        }
        let acknowledged_output = if hello.pending_gap.is_some()
            && self.last_gap
                != hello.pending_gap.map(|(abandoned, replacement)| EpochGap {
                    abandoned_epoch: abandoned,
                    replacement_epoch: replacement,
                }) {
            0
        } else {
            self.output.acknowledgement()
        };
        if hello.next_output < acknowledged_output {
            return Err(ClientError::OutputBehindAcknowledgement);
        }
        self.input.acknowledge(hello.accepted_input_ack)?;
        if let Some((abandoned, replacement)) = hello.pending_gap {
            self.apply_gap(EpochGap::new(abandoned, replacement)?)?;
        }
        Ok(())
    }

    pub fn stdin_read_capacity(&self) -> usize {
        if self.role != ConnectionRole::Writer
            || self.input_closed
            || self.input.remaining_operations() == 0
        {
            return 0;
        }
        self.input
            .remaining_wire_bytes()
            .saturating_sub(crate::wire::HEADER_LEN)
            .min(self.limits.copy_buffer_bytes)
            .min(self.limits.terminal_frame_max)
    }

    pub fn queue_input(&mut self, bytes: &[u8]) -> Result<u64, ClientError> {
        self.require_open_writer()?;
        let sequence = self.input.push(Kind::Input, bytes)?;
        #[cfg(feature = "path-diagnostics")]
        if let Some(trace) = self.path_trace.as_mut() {
            trace.record(
                crate::path_trace::Stage::ClientInputQueued,
                self.input_epoch,
                sequence,
            );
        }
        Ok(sequence)
    }

    pub fn queue_resize(&mut self, resize: Resize) -> Result<u64, ClientError> {
        self.require_open_writer()?;
        self.input
            .push(Kind::Resize, &resize.encode())
            .map_err(Into::into)
    }

    pub fn queue_signal(&mut self, signal: u8) -> Result<u64, ClientError> {
        self.require_open_writer()?;
        if !matches!(signal, 1 | 2 | 3 | 15 | 18 | 20) {
            return Err(ClientError::SignalDenied(signal));
        }
        self.input.push(Kind::Signal, &[signal]).map_err(Into::into)
    }

    pub fn queue_input_close(&mut self) -> Result<u64, ClientError> {
        self.require_open_writer()?;
        let sequence = self.input.push(Kind::InputClose, &[])?;
        self.input_closed = true;
        Ok(sequence)
    }

    /// Explicitly retires this PTY-lifetime association. This differs from a
    /// transport close, which remains resumable after network loss.
    pub fn queue_detach(&mut self) -> Result<u64, ClientError> {
        self.control.push(Kind::Detach, &[]).map_err(Into::into)
    }

    pub fn copy_input(&self, sequence: u64, output: &mut [u8]) -> Result<FrameCopy, ClientError> {
        self.input
            .copy_sequence(sequence, output)
            .map_err(Into::into)
    }

    pub fn first_unacknowledged_input(&self) -> Option<u64> {
        self.input.first_unacknowledged_sequence()
    }

    pub fn next_input_sequence(&self) -> u64 {
        self.input.next_sequence()
    }

    pub fn ambiguous_input_operations(&self) -> usize {
        self.input.unacknowledged_operations()
    }

    pub fn accept_input_ack(&mut self, acknowledgement: Ack) -> Result<(), ClientError> {
        if acknowledgement.epoch != self.input_epoch {
            return Err(ClientError::InputEpochMismatch);
        }
        self.input.acknowledge(acknowledgement.next_expected)?;
        Ok(())
    }

    pub fn begin_output<'a>(
        &mut self,
        kind: Kind,
        sequence: u64,
        payload: &'a [u8],
    ) -> Result<OutputDisposition<'a>, ClientError> {
        let operation = decode_output_operation(kind, payload, &self.limits)?;
        match self.output.begin(self.output.epoch(), sequence)? {
            DeliveryDecision::Deliver => Ok(OutputDisposition::Deliver(operation)),
            DeliveryDecision::Duplicate => Ok(OutputDisposition::Duplicate {
                acknowledgement: self.output.acknowledgement(),
            }),
        }
    }

    /// Copies one complete decoded output operation into persistent fixed
    /// staging. Local stdout progress can then survive a QUIC reconnect
    /// without replaying a prefix that stdout already accepted.
    pub fn stage_output(
        &mut self,
        kind: Kind,
        sequence: u64,
        payload: &[u8],
    ) -> Result<OutputStage, ClientError> {
        if self.pending_output.is_some() {
            return Err(ClientError::OutputAlreadyStaged);
        }
        match self.begin_output(kind, sequence, payload)? {
            OutputDisposition::Duplicate { acknowledgement } => Ok(OutputStage::Duplicate {
                sequence,
                acknowledgement,
            }),
            OutputDisposition::Deliver(_) => {
                if payload.len() > self.output_staging.len() {
                    self.abort_output(sequence)?;
                    return Err(WireError::OutputTooSmall {
                        needed: payload.len(),
                        available: self.output_staging.len(),
                    }
                    .into());
                }
                self.output_staging[..payload.len()].copy_from_slice(payload);
                self.pending_output = Some(PendingOutput {
                    kind,
                    sequence,
                    length: payload.len(),
                    stdout_offset: 0,
                });
                #[cfg(feature = "path-diagnostics")]
                if kind == Kind::Output {
                    if let Some(trace) = self.path_trace.as_mut() {
                        trace.record(
                            crate::path_trace::Stage::ClientOutputStaged,
                            self.output.epoch(),
                            sequence,
                        );
                    }
                }
                Ok(OutputStage::Staged { kind, sequence })
            }
        }
    }

    pub fn pending_output(&self) -> Result<PendingOutputView<'_>, ClientError> {
        let pending = self.pending_output.ok_or(ClientError::OutputNotStaged)?;
        let payload = &self.output_staging[..pending.length];
        let operation = match decode_output_operation(pending.kind, payload, &self.limits)? {
            OutputOperation::Bytes(_) => {
                OutputOperation::Bytes(&payload[pending.stdout_offset..pending.length])
            }
            operation => operation,
        };
        Ok(PendingOutputView {
            kind: pending.kind,
            sequence: pending.sequence,
            operation,
        })
    }

    pub fn has_pending_output(&self) -> bool {
        self.pending_output.is_some()
    }

    pub fn advance_stdout(&mut self, accepted: usize) -> Result<bool, ClientError> {
        let pending = self
            .pending_output
            .as_mut()
            .ok_or(ClientError::OutputNotStaged)?;
        if pending.kind != Kind::Output
            || accepted == 0
            || accepted > pending.length.saturating_sub(pending.stdout_offset)
        {
            return Err(ClientError::OutputProgressInvalid);
        }
        pending.stdout_offset += accepted;
        Ok(pending.stdout_offset == pending.length)
    }

    pub fn finish_staged_output(&mut self) -> Result<Ack, ClientError> {
        let pending = self.pending_output.ok_or(ClientError::OutputNotStaged)?;
        if pending.kind == Kind::Output && pending.stdout_offset != pending.length {
            return Err(ClientError::OutputProgressInvalid);
        }
        let acknowledgement = self.commit_output(pending.sequence)?;
        #[cfg(feature = "path-diagnostics")]
        if pending.kind == Kind::Output {
            if let Some(trace) = self.path_trace.as_mut() {
                trace.record(
                    crate::path_trace::Stage::ClientOutputAccepted,
                    self.output.epoch(),
                    pending.sequence,
                );
            }
        }
        self.output_staging[..pending.length].fill(0);
        self.pending_output = None;
        Ok(acknowledgement)
    }

    pub fn repeat_staged_duplicate(&mut self, acknowledgement: u64) -> Result<Ack, ClientError> {
        self.repeat_output_ack(acknowledgement)
    }

    pub fn can_queue_output_ack(&self) -> bool {
        self.control.can_accept(Kind::AckOutput, Ack::WIRE_LEN)
    }

    pub fn commit_output(&mut self, sequence: u64) -> Result<Ack, ClientError> {
        if !self.can_queue_output_ack() {
            return Err(QueueError::Full.into());
        }
        let epoch = self.output.epoch();
        self.output.commit(epoch, sequence)?;
        self.queue_output_ack(self.output.acknowledgement())
    }

    pub fn abort_output(&mut self, sequence: u64) -> Result<(), ClientError> {
        self.output
            .abort(self.output.epoch(), sequence)
            .map_err(Into::into)
    }

    pub fn repeat_output_ack(&mut self, next_expected: u64) -> Result<Ack, ClientError> {
        self.queue_output_ack(next_expected)
    }

    pub fn apply_gap(&mut self, gap: EpochGap) -> Result<bool, ClientError> {
        if self.last_gap == Some(gap) {
            return Ok(false);
        }
        if gap.abandoned_epoch != self.output.epoch() {
            return Err(ClientError::GapMismatch);
        }
        // A GAP abandons the whole old output epoch, including a suffix
        // staged across a partial local stdout write.  The accepted prefix
        // cannot be recalled, but the stale suffix must never block the new
        // epoch or be replayed after it.  Abort the delivery gate before
        // resetting it and scrub the retained payload.
        if let Some(pending) = self.pending_output.take() {
            self.output.abort(gap.abandoned_epoch, pending.sequence)?;
            self.output_staging[..pending.length].fill(0);
        }
        self.output.reset_epoch(gap.replacement_epoch, 0)?;
        self.last_gap = Some(gap);
        self.gap_notice_pending = true;
        Ok(true)
    }

    pub fn take_gap_notice(&mut self) -> Option<EpochGap> {
        if !self.gap_notice_pending {
            return None;
        }
        self.gap_notice_pending = false;
        self.last_gap
    }

    pub fn control(&self) -> &ReplayRing {
        &self.control
    }

    pub fn copy_control(&self, output: &mut [u8]) -> Result<FrameCopy, ClientError> {
        self.control.copy_unacked(0, output).map_err(Into::into)
    }

    pub fn acknowledge_control_sent(&mut self, next_expected: u64) -> Result<(), ClientError> {
        self.control.acknowledge(next_expected).map_err(Into::into)
    }

    fn require_open_writer(&self) -> Result<(), ClientError> {
        if self.role != ConnectionRole::Writer {
            return Err(ClientError::ObserverInput);
        }
        if self.input_closed {
            return Err(ClientError::InputClosed);
        }
        Ok(())
    }

    fn queue_output_ack(&mut self, next_expected: u64) -> Result<Ack, ClientError> {
        let acknowledgement = Ack {
            epoch: self.output.epoch(),
            next_expected,
        };
        self.control
            .push(Kind::AckOutput, &acknowledgement.encode())?;
        Ok(acknowledgement)
    }
}

impl fmt::Debug for ClientAssociation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientAssociation")
            .field("association_id", &self.association_id)
            .field("generation", &self.generation)
            .field("role", &self.role)
            .field("position", &self.position())
            .field(
                "ambiguous_input_operations",
                &self.ambiguous_input_operations(),
            )
            .field("input_closed", &self.input_closed)
            .field("last_gap", &self.last_gap)
            .field(
                "pending_output",
                &self.pending_output.map(|pending| {
                    (
                        pending.kind,
                        pending.sequence,
                        pending.length,
                        pending.stdout_offset,
                    )
                }),
            )
            .field("payload", &"<REDACTED>")
            .finish()
    }
}

impl Drop for ClientAssociation {
    fn drop(&mut self) {
        self.output_staging.fill(0);
    }
}

fn decode_output_operation<'a>(
    kind: Kind,
    payload: &'a [u8],
    limits: &Limits,
) -> Result<OutputOperation<'a>, ClientError> {
    if kind.stream() != StreamRole::Output {
        return Err(WireError::KindNotAllowed {
            kind,
            stream: StreamRole::Output,
        }
        .into());
    }
    let (minimum, maximum) = kind.payload_bounds(limits);
    if payload.len() < minimum {
        return Err(WireError::LengthInvalid {
            kind,
            length: payload.len(),
        }
        .into());
    }
    if payload.len() > maximum {
        return Err(WireError::PayloadTooLarge {
            kind,
            length: payload.len(),
            maximum,
        }
        .into());
    }
    match kind {
        Kind::Output => Ok(OutputOperation::Bytes(payload)),
        Kind::Ownership => Ok(OutputOperation::Ownership(payload[0])),
        Kind::Exit => Ok(OutputOperation::Exit(i32::from_be_bytes(
            payload.try_into().map_err(|_| WireError::LengthInvalid {
                kind,
                length: payload.len(),
            })?,
        ))),
        _ => Err(WireError::KindNotAllowed {
            kind,
            stream: StreamRole::Output,
        }
        .into()),
    }
}
