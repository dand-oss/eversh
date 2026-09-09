//! Gateway-side association reducer over authenticated connections and replay slabs.

use crate::gateway::{GatewayAction, GatewayError, GatewayLifecycle};
use crate::handshake::{ClientHello, HandshakeError, ServerHello};
use crate::queues::{DeliveryDecision, DeliveryGate, GatewayReplaySlabs, QueueError, ReplayRing};
use crate::transport::AdmittedConnection;
use crate::wire::{Ack, ConnectionRole, Kind, Resize, StreamRole};
use crate::{GatewayGeneration, WireError};
use everssh::association::AssociationId;
use everssh::bootstrap::ct_eq;
use std::fmt;

#[derive(Debug)]
pub enum AssociationError {
    Admission(crate::AdmissionError),
    Gateway(GatewayError),
    Queue(QueueError),
    Wire(WireError),
    Handshake(HandshakeError),
    InitialRequired,
    ResumeRequired,
    ResumePosition,
    ObserverInput,
    SignalDenied(u8),
}

impl fmt::Display for AssociationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admission(error) => write!(formatter, "{error}"),
            Self::Gateway(error) => write!(formatter, "{error}"),
            Self::Queue(error) => write!(formatter, "{error}"),
            Self::Wire(error) => write!(formatter, "{error}"),
            Self::Handshake(error) => write!(formatter, "{error}"),
            Self::InitialRequired => {
                formatter.write_str("initial everudp association hello required")
            }
            Self::ResumeRequired => formatter.write_str("resume everudp hello required"),
            Self::ResumePosition => formatter.write_str("everudp resume position was rejected"),
            Self::ObserverInput => formatter.write_str("everudp observer sent input"),
            Self::SignalDenied(_) => formatter.write_str("everudp signal is not allow-listed"),
        }
    }
}

impl std::error::Error for AssociationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Admission(error) => Some(error),
            Self::Gateway(error) => Some(error),
            Self::Queue(error) => Some(error),
            Self::Wire(error) => Some(error),
            Self::Handshake(error) => Some(error),
            _ => None,
        }
    }
}

impl From<GatewayError> for AssociationError {
    fn from(value: GatewayError) -> Self {
        Self::Gateway(value)
    }
}

impl From<crate::AdmissionError> for AssociationError {
    fn from(value: crate::AdmissionError) -> Self {
        Self::Admission(value)
    }
}

impl From<QueueError> for AssociationError {
    fn from(value: QueueError) -> Self {
        Self::Queue(value)
    }
}

impl From<WireError> for AssociationError {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}

impl From<HandshakeError> for AssociationError {
    fn from(value: HandshakeError) -> Self {
        Self::Handshake(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputOperation<'a> {
    Bytes(&'a [u8]),
    Resize(Resize),
    Signal(u8),
    Close,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputDisposition<'a> {
    Deliver(InputOperation<'a>),
    Duplicate { acknowledgement: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlDisposition {
    Applied,
    Duplicate,
}

/// Immutable identity established by the one-use bootstrap and required on
/// every later QUIC connection for this PTY-lifetime association.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AssociationAuthorization {
    association_id: AssociationId,
    generation: GatewayGeneration,
    role: ConnectionRole,
    client_spki_sha256: [u8; 32],
}

impl AssociationAuthorization {
    pub fn authorize(
        &self,
        hello: &ClientHello,
        client_spki_sha256: [u8; 32],
    ) -> Result<(), crate::AdmissionError> {
        if !matches!(hello, ClientHello::Resume { .. })
            || hello.association_id() != self.association_id
            || hello.generation() != self.generation
            || hello.role() != self.role
            || !ct_eq(&self.client_spki_sha256, &client_spki_sha256)
        {
            return Err(crate::AdmissionError::BindingMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for AssociationAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AssociationAuthorization")
            .field("association_id", &self.association_id)
            .field("generation", &self.generation)
            .field("role", &self.role)
            .field("client_spki_sha256", &"<REDACTED>")
            .finish()
    }
}

#[derive(Debug)]
pub struct GatewayAssociation {
    association_id: AssociationId,
    generation: GatewayGeneration,
    role: ConnectionRole,
    client_spki_sha256: [u8; 32],
    input_delivery: DeliveryGate,
    control_delivery: DeliveryGate,
    input_closed: bool,
    resume_gap: Option<(u64, u64)>,
}

impl GatewayAssociation {
    pub fn establish(
        admitted: &AdmittedConnection,
        lifecycle: &mut GatewayLifecycle,
        slabs: &mut GatewayReplaySlabs,
    ) -> Result<(Self, GatewayAction), AssociationError> {
        if !matches!(admitted.hello(), ClientHello::Initial { .. }) {
            return Err(AssociationError::InitialRequired);
        }
        let association_id = admitted.hello().association_id();
        let role = admitted.hello().role();
        let action = lifecycle.admit(admitted, admitted.take_over())?;
        if role == ConnectionRole::Observer {
            if let Err(error) = slabs.add_observer(association_id) {
                let _ = lifecycle.release(association_id);
                return Err(error.into());
            }
        }
        let mut association = Self::new_authenticated(
            association_id,
            admitted.hello().generation(),
            role,
            admitted.client_spki_sha256(),
        );
        if let Err(error) = association.queue_server_hello(slabs) {
            association.rollback_initial(lifecycle, slabs)?;
            return Err(error);
        }
        Ok((association, action))
    }

    /// Restores the pre-admission state when an initial connection cannot
    /// carry its SERVER_HELLO. No terminal operation is accepted before this
    /// point, so releasing this one association is unambiguous.
    pub(crate) fn rollback_initial(
        &self,
        lifecycle: &mut GatewayLifecycle,
        slabs: &mut GatewayReplaySlabs,
    ) -> Result<(), AssociationError> {
        let _ = lifecycle.release(self.association_id);
        match self.role {
            ConnectionRole::Writer => slabs.restart_writer_control(),
            ConnectionRole::Observer => slabs.remove_observer(self.association_id)?,
        }
        Ok(())
    }

    pub fn association_id(&self) -> AssociationId {
        self.association_id
    }

    pub fn generation(&self) -> GatewayGeneration {
        self.generation
    }

    pub fn role(&self) -> ConnectionRole {
        self.role
    }

    #[cfg(any(feature = "datagram-spike", feature = "path-diagnostics"))]
    pub(crate) fn input_position(&self) -> (u64, u64) {
        (
            self.input_delivery.epoch(),
            self.input_delivery.acknowledgement(),
        )
    }

    pub fn input_closed(&self) -> bool {
        self.input_closed
    }

    pub fn mark_input_closed(&mut self) {
        self.input_closed = true;
    }

    pub fn client_spki_sha256(&self) -> [u8; 32] {
        self.client_spki_sha256
    }

    pub fn authorization(&self) -> AssociationAuthorization {
        AssociationAuthorization {
            association_id: self.association_id,
            generation: self.generation,
            role: self.role,
            client_spki_sha256: self.client_spki_sha256,
        }
    }

    pub fn resume(
        &mut self,
        admitted: &AdmittedConnection,
        lifecycle: &mut GatewayLifecycle,
        slabs: &mut GatewayReplaySlabs,
    ) -> Result<GatewayAction, AssociationError> {
        if !matches!(admitted.hello(), ClientHello::Resume { .. }) {
            return Err(AssociationError::ResumeRequired);
        }
        self.authorization()
            .authorize(admitted.hello(), admitted.client_spki_sha256())?;
        let position = admitted.hello().position();
        if position.input_epoch != self.input_delivery.epoch()
            || position.next_input < self.input_delivery.acknowledgement()
            || position.next_output != position.delivered_output_ack
        {
            return Err(AssociationError::ResumePosition);
        }

        // Ownership is checked before any replay state changes. A stale
        // writer generation must not acknowledge output owned by its
        // replacement.
        let action = lifecycle.admit(admitted, false)?;

        let resume_gap = match self.role {
            ConnectionRole::Writer => slabs
                .reconcile_writer_resume(position.output_epoch, position.delivered_output_ack)?,
            ConnectionRole::Observer => slabs.reconcile_observer_resume(
                self.association_id,
                position.output_epoch,
                position.delivered_output_ack,
            )?,
        };

        self.control_delivery = DeliveryGate::new(0, 1);
        match self.role {
            ConnectionRole::Writer => slabs.restart_writer_control(),
            ConnectionRole::Observer => slabs.restart_observer_control(self.association_id)?,
        }
        self.resume_gap = resume_gap;
        self.queue_server_hello(slabs)?;
        self.complete_resume_for(slabs, resume_gap)?;
        self.resume_gap = None;
        Ok(action)
    }

    pub fn server_hello(
        &self,
        slabs: &GatewayReplaySlabs,
    ) -> Result<ServerHello, AssociationError> {
        let output = match self.role {
            ConnectionRole::Writer => slabs.writer_output(),
            ConnectionRole::Observer => slabs
                .observer_output(self.association_id)
                .ok_or(QueueError::UnknownObserver)?,
        };
        ServerHello::new(
            self.association_id,
            self.generation,
            self.role,
            self.input_delivery.epoch(),
            self.input_delivery.acknowledgement(),
            output.epoch(),
            output.next_sequence(),
            self.resume_gap.or(output.pending_gap()),
        )
        .map_err(AssociationError::from)
    }

    pub fn queue_server_hello(
        &mut self,
        slabs: &mut GatewayReplaySlabs,
    ) -> Result<u64, AssociationError> {
        let hello = self.server_hello(slabs)?;
        let mut payload = [0_u8; ServerHello::ENCODED_LEN];
        hello.encode_into(&mut payload)?;
        self.control_mut(slabs)?
            .push(Kind::ServerHello, &payload)
            .map_err(AssociationError::from)
    }

    pub fn begin_input<'a>(
        &mut self,
        kind: Kind,
        sequence: u64,
        payload: &'a [u8],
    ) -> Result<InputDisposition<'a>, AssociationError> {
        if self.role != ConnectionRole::Writer {
            return Err(AssociationError::ObserverInput);
        }
        let operation = decode_input_operation(kind, payload)?;
        match self
            .input_delivery
            .begin(self.input_delivery.epoch(), sequence)?
        {
            DeliveryDecision::Deliver => Ok(InputDisposition::Deliver(operation)),
            DeliveryDecision::Duplicate => Ok(InputDisposition::Duplicate {
                acknowledgement: self.input_delivery.acknowledgement(),
            }),
        }
    }

    pub fn commit_input(
        &mut self,
        sequence: u64,
        slabs: &mut GatewayReplaySlabs,
    ) -> Result<Ack, AssociationError> {
        let epoch = self.input_delivery.epoch();
        let next_expected = self
            .input_delivery
            .acknowledgement()
            .checked_add(1)
            .ok_or(QueueError::SequenceOverflow)?;
        let acknowledgement = Ack {
            epoch,
            next_expected,
        };
        let payload = acknowledgement.encode();
        if !self
            .control(slabs)?
            .can_accept(Kind::AckInput, payload.len())
        {
            return Err(QueueError::Full.into());
        }
        self.input_delivery.commit(epoch, sequence)?;
        self.control_mut(slabs)?.push(Kind::AckInput, &payload)?;
        Ok(acknowledgement)
    }

    pub fn can_queue_input_ack(&self, slabs: &GatewayReplaySlabs) -> bool {
        self.control(slabs)
            .is_ok_and(|control| control.can_accept(Kind::AckInput, Ack::WIRE_LEN))
    }

    pub fn repeat_input_ack(
        &self,
        next_expected: u64,
        slabs: &mut GatewayReplaySlabs,
    ) -> Result<Ack, AssociationError> {
        let acknowledgement = Ack {
            epoch: self.input_delivery.epoch(),
            next_expected,
        };
        self.control_mut(slabs)?
            .push(Kind::AckInput, &acknowledgement.encode())?;
        Ok(acknowledgement)
    }

    pub fn abort_input(&mut self, sequence: u64) -> Result<(), AssociationError> {
        self.input_delivery
            .abort(self.input_delivery.epoch(), sequence)
            .map_err(AssociationError::from)
    }

    pub fn accept_output_ack(
        &mut self,
        control_sequence: u64,
        acknowledgement: Ack,
        slabs: &mut GatewayReplaySlabs,
    ) -> Result<ControlDisposition, AssociationError> {
        let control_epoch = self.control_delivery.epoch();
        match self
            .control_delivery
            .begin(control_epoch, control_sequence)?
        {
            DeliveryDecision::Duplicate => return Ok(ControlDisposition::Duplicate),
            DeliveryDecision::Deliver => {}
        }
        let applied = match self.role {
            ConnectionRole::Writer => {
                slabs.acknowledge_writer_epoch(acknowledgement.epoch, acknowledgement.next_expected)
            }
            ConnectionRole::Observer => slabs.acknowledge_observer_epoch(
                self.association_id,
                acknowledgement.epoch,
                acknowledgement.next_expected,
            ),
        };
        if let Err(error) = applied {
            self.control_delivery
                .abort(control_epoch, control_sequence)?;
            return Err(error.into());
        }
        self.control_delivery
            .commit(control_epoch, control_sequence)?;
        Ok(ControlDisposition::Applied)
    }

    pub fn accept_detach(
        &mut self,
        control_sequence: u64,
    ) -> Result<ControlDisposition, AssociationError> {
        let epoch = self.control_delivery.epoch();
        match self.control_delivery.begin(epoch, control_sequence)? {
            DeliveryDecision::Duplicate => Ok(ControlDisposition::Duplicate),
            DeliveryDecision::Deliver => {
                self.control_delivery.commit(epoch, control_sequence)?;
                Ok(ControlDisposition::Applied)
            }
        }
    }

    pub fn complete_resume(
        &mut self,
        slabs: &mut GatewayReplaySlabs,
    ) -> Result<Option<(u64, u64)>, AssociationError> {
        self.complete_resume_for(slabs, None)
    }

    fn complete_resume_for(
        &mut self,
        slabs: &mut GatewayReplaySlabs,
        client_gap: Option<(u64, u64)>,
    ) -> Result<Option<(u64, u64)>, AssociationError> {
        match self.role {
            ConnectionRole::Writer => slabs
                .complete_writer_resume_for(client_gap)
                .map_err(Into::into),
            ConnectionRole::Observer => slabs
                .complete_observer_resume_for(self.association_id, client_gap)
                .map_err(Into::into),
        }
    }

    pub fn control<'a>(
        &self,
        slabs: &'a GatewayReplaySlabs,
    ) -> Result<&'a ReplayRing, AssociationError> {
        match self.role {
            ConnectionRole::Writer => Ok(slabs.writer_control()),
            ConnectionRole::Observer => slabs
                .observer_control(self.association_id)
                .map_err(AssociationError::from),
        }
    }

    pub fn output<'a>(
        &self,
        slabs: &'a GatewayReplaySlabs,
    ) -> Result<&'a crate::queues::OutputReplay, AssociationError> {
        match self.role {
            ConnectionRole::Writer => Ok(slabs.writer_output()),
            ConnectionRole::Observer => slabs
                .observer_output(self.association_id)
                .ok_or(QueueError::UnknownObserver.into()),
        }
    }

    pub fn acknowledge_control_sent(
        &self,
        next_expected: u64,
        slabs: &mut GatewayReplaySlabs,
    ) -> Result<(), AssociationError> {
        self.control_mut(slabs)?
            .acknowledge(next_expected)
            .map_err(Into::into)
    }

    fn new_authenticated(
        association_id: AssociationId,
        generation: GatewayGeneration,
        role: ConnectionRole,
        client_spki_sha256: [u8; 32],
    ) -> Self {
        Self {
            association_id,
            generation,
            role,
            client_spki_sha256,
            input_delivery: DeliveryGate::new(0, 0),
            // CLIENT_HELLO is record zero on the client-to-gateway control stream.
            control_delivery: DeliveryGate::new(0, 1),
            input_closed: false,
            resume_gap: None,
        }
    }

    fn control_mut<'a>(
        &self,
        slabs: &'a mut GatewayReplaySlabs,
    ) -> Result<&'a mut ReplayRing, AssociationError> {
        match self.role {
            ConnectionRole::Writer => Ok(slabs.writer_control_mut()),
            ConnectionRole::Observer => slabs
                .observer_control_mut(self.association_id)
                .map_err(AssociationError::from),
        }
    }
}

fn decode_input_operation(
    kind: Kind,
    payload: &[u8],
) -> Result<InputOperation<'_>, AssociationError> {
    if kind.stream() != StreamRole::Input {
        return Err(WireError::KindNotAllowed {
            kind,
            stream: StreamRole::Input,
        }
        .into());
    }
    let limits = crate::Limits::default();
    let (minimum, maximum) = kind.payload_bounds(&limits);
    if payload.len() > maximum {
        return Err(WireError::PayloadTooLarge {
            kind,
            length: payload.len(),
            maximum,
        }
        .into());
    }
    if payload.len() < minimum {
        return Err(WireError::LengthInvalid {
            kind,
            length: payload.len(),
        }
        .into());
    }
    match kind {
        Kind::Input => Ok(InputOperation::Bytes(payload)),
        Kind::Resize => Resize::decode_exact(payload)
            .map(InputOperation::Resize)
            .map_err(AssociationError::from),
        Kind::Signal => {
            let signal = payload[0];
            if matches!(signal, 1 | 2 | 3 | 15 | 18 | 20) {
                Ok(InputOperation::Signal(signal))
            } else {
                Err(AssociationError::SignalDenied(signal))
            }
        }
        Kind::InputClose => Ok(InputOperation::Close),
        _ => Err(WireError::KindNotAllowed {
            kind,
            stream: StreamRole::Input,
        }
        .into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{decode_record, EpochGap};
    use crate::{Limits, OutputPush};

    fn association(byte: u8) -> AssociationId {
        AssociationId::from_bytes([byte; 16]).expect("association")
    }

    fn generation() -> GatewayGeneration {
        GatewayGeneration::from_bytes([2; 16]).expect("generation")
    }

    #[test]
    fn input_ack_is_queued_only_after_sink_commit() {
        let limits = Limits::default();
        let mut slabs = GatewayReplaySlabs::new(&limits).expect("slabs");
        let mut association = GatewayAssociation::new_authenticated(
            association(1),
            generation(),
            ConnectionRole::Writer,
            [3; 32],
        );
        association.queue_server_hello(&mut slabs).expect("hello");
        assert!(matches!(
            association
                .begin_input(Kind::Input, 0, b"abc")
                .expect("begin"),
            InputDisposition::Deliver(InputOperation::Bytes(b"abc"))
        ));
        assert_eq!(
            association
                .control(&slabs)
                .expect("control")
                .next_sequence(),
            1
        );
        association.abort_input(0).expect("failed sink");
        assert!(matches!(
            association
                .begin_input(Kind::Input, 0, b"abc")
                .expect("retry"),
            InputDisposition::Deliver(_)
        ));
        let ack = association.commit_input(0, &mut slabs).expect("commit");
        assert_eq!(ack.next_expected, 1);
        assert_eq!(
            association
                .control(&slabs)
                .expect("control")
                .next_sequence(),
            2
        );
        assert_eq!(
            association
                .begin_input(Kind::Input, 0, b"abc")
                .expect("duplicate"),
            InputDisposition::Duplicate { acknowledgement: 1 }
        );
    }

    #[test]
    fn output_ack_is_idempotent_and_gap_is_replay_queued_before_buffering() {
        let limits = Limits::default();
        let mut slabs = GatewayReplaySlabs::new(&limits).expect("slabs");
        let mut association = GatewayAssociation::new_authenticated(
            association(1),
            generation(),
            ConnectionRole::Writer,
            [3; 32],
        );
        association.queue_server_hello(&mut slabs).expect("hello");
        assert!(matches!(
            slabs
                .push_output(Kind::Output, b"x")
                .expect("output")
                .writer,
            OutputPush::Buffered { sequence: 0, .. }
        ));
        let ack = Ack {
            epoch: 0,
            next_expected: 1,
        };
        assert_eq!(
            association
                .accept_output_ack(1, ack, &mut slabs)
                .expect("ack"),
            ControlDisposition::Applied
        );
        assert_eq!(
            association
                .accept_output_ack(1, ack, &mut slabs)
                .expect("duplicate"),
            ControlDisposition::Duplicate
        );

        for _ in 0..=limits.queue_operations_per_direction {
            slabs.push_output(Kind::Output, b"y").expect("fill");
        }
        assert!(slabs.writer_output().is_discarding());
        assert_eq!(
            association.complete_resume(&mut slabs).expect("resume"),
            Some((0, 1))
        );
        assert!(!slabs.writer_output().is_discarding());
        let control = association.control(&slabs).expect("control");
        let mut wire = vec![0_u8; limits.control_frame_max + crate::wire::HEADER_LEN];
        let gap_record = control
            .copy_unacked(control.unacknowledged_operations() - 1, &mut wire)
            .expect("gap");
        let (record, _) = decode_record(StreamRole::Control, &wire[..gap_record.wire_len], &limits)
            .expect("decode gap");
        assert_eq!(record.header.kind, Kind::Gap);
        assert_eq!(
            EpochGap::decode_exact(record.payload).expect("gap payload"),
            EpochGap::new(0, 1).expect("expected gap")
        );
    }

    #[test]
    fn observers_cannot_enter_the_input_reducer() {
        let mut observer = GatewayAssociation::new_authenticated(
            association(1),
            generation(),
            ConnectionRole::Observer,
            [3; 32],
        );
        assert!(matches!(
            observer.begin_input(Kind::Input, 0, b"x"),
            Err(AssociationError::ObserverInput)
        ));
    }
}
