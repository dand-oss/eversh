//! Allocation-stable replay rings, delivery gates, output epochs, and fanout.

use crate::limits::Limits;
use crate::wire::{FrameHeader, Kind, StreamRole, HEADER_LEN};
use crate::WireError;
use everssh::association::AssociationId;
use std::fmt;
use std::mem::size_of;

const CONTROL_QUEUE_BYTES: usize = 64 * 1024;
const OBSERVER_SLOTS: usize = 8;
const GATEWAY_RING_COUNT: usize = 3 + OBSERVER_SLOTS * 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueError {
    Allocation,
    Full,
    AckAhead,
    AckBehind,
    SequenceGap,
    SequenceOverflow,
    EpochMismatch,
    DeliveryPending,
    DeliveryNotPending,
    BufferTooSmall,
    ObserverCapacity,
    UnknownObserver,
    Wire(WireError),
}

impl fmt::Display for QueueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allocation => formatter.write_str("everudp replay slab allocation failed"),
            Self::Full => formatter.write_str("everudp replay queue is full"),
            Self::AckAhead => formatter.write_str("everudp acknowledgement is ahead of sequence"),
            Self::AckBehind => {
                formatter.write_str("everudp acknowledgement regressed behind committed sequence")
            }
            Self::SequenceGap => formatter.write_str("everudp sequence has a gap"),
            Self::SequenceOverflow => formatter.write_str("everudp sequence overflowed"),
            Self::EpochMismatch => formatter.write_str("everudp replay epoch does not match"),
            Self::DeliveryPending => {
                formatter.write_str("an everudp sink delivery is already pending")
            }
            Self::DeliveryNotPending => {
                formatter.write_str("the everudp sink delivery is not pending")
            }
            Self::BufferTooSmall => {
                formatter.write_str("everudp replay output buffer is too small")
            }
            Self::ObserverCapacity => {
                formatter.write_str("everudp observer replay capacity is exhausted")
            }
            Self::UnknownObserver => formatter.write_str("unknown everudp observer association"),
            Self::Wire(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for QueueError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Wire(error) => Some(error),
            _ => None,
        }
    }
}

impl From<WireError> for QueueError {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueSnapshot {
    pub next_sequence: u64,
    pub first_unacknowledged: Option<u64>,
    pub operations: usize,
    pub wire_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameCopy {
    pub kind: Kind,
    pub sequence: u64,
    pub wire_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingAllocationSignature {
    bytes: usize,
    slots: usize,
    byte_capacity: usize,
    operation_capacity: usize,
}

#[derive(Debug, Clone, Copy)]
struct Slot {
    kind: Kind,
    sequence: u64,
    start: usize,
    wire_len: usize,
}

pub struct ReplayRing {
    stream: StreamRole,
    bytes: Box<[u8]>,
    slots: Box<[Option<Slot>]>,
    byte_head: usize,
    byte_tail: usize,
    bytes_used: usize,
    slot_head: usize,
    slot_count: usize,
    next_sequence: u64,
}

impl ReplayRing {
    pub fn new(stream: StreamRole, limits: &Limits) -> Result<Self, QueueError> {
        limits.validate().map_err(WireError::from)?;
        Self::with_capacities(
            stream,
            limits.queue_bytes_per_direction,
            limits.queue_operations_per_direction,
        )
    }

    pub(crate) fn control(limits: &Limits) -> Result<Self, QueueError> {
        Self::with_capacities(
            StreamRole::Control,
            CONTROL_QUEUE_BYTES.min(limits.queue_bytes_per_direction),
            limits.queue_operations_per_direction,
        )
    }

    pub(crate) fn control_after_hello(limits: &Limits) -> Result<Self, QueueError> {
        let mut control = Self::control(limits)?;
        control.next_sequence = 1;
        Ok(control)
    }

    fn with_capacities(
        stream: StreamRole,
        byte_capacity: usize,
        operation_capacity: usize,
    ) -> Result<Self, QueueError> {
        if byte_capacity < HEADER_LEN || operation_capacity == 0 {
            return Err(QueueError::Allocation);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(byte_capacity)
            .map_err(|_| QueueError::Allocation)?;
        bytes.resize(byte_capacity, 0);
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(operation_capacity)
            .map_err(|_| QueueError::Allocation)?;
        slots.resize(operation_capacity, None);
        Ok(Self {
            stream,
            bytes: bytes.into_boxed_slice(),
            slots: slots.into_boxed_slice(),
            byte_head: 0,
            byte_tail: 0,
            bytes_used: 0,
            slot_head: 0,
            slot_count: 0,
            next_sequence: 0,
        })
    }

    pub fn push(&mut self, kind: Kind, payload: &[u8]) -> Result<u64, QueueError> {
        self.validate_shape(kind, payload.len())?;
        let wire_len = HEADER_LEN
            .checked_add(payload.len())
            .ok_or(QueueError::Full)?;
        if self.slot_count == self.slots.len()
            || wire_len > self.bytes.len().saturating_sub(self.bytes_used)
        {
            return Err(QueueError::Full);
        }
        if self.next_sequence == u64::MAX {
            return Err(QueueError::SequenceOverflow);
        }
        let sequence = self.next_sequence;
        let payload_len = u32::try_from(payload.len()).map_err(|_| QueueError::Full)?;
        let header = FrameHeader::new(kind, sequence, payload_len).encode();
        let start = self.byte_tail;
        self.write_circular(&header);
        self.write_circular(payload);
        let slot = (self.slot_head + self.slot_count) % self.slots.len();
        self.slots[slot] = Some(Slot {
            kind,
            sequence,
            start,
            wire_len,
        });
        self.slot_count += 1;
        self.bytes_used += wire_len;
        self.next_sequence += 1;
        Ok(sequence)
    }

    pub fn acknowledge(&mut self, next_expected: u64) -> Result<(), QueueError> {
        if next_expected > self.next_sequence {
            return Err(QueueError::AckAhead);
        }
        let committed = self
            .first_unacknowledged_sequence()
            .unwrap_or(self.next_sequence);
        if next_expected < committed {
            return Err(QueueError::AckBehind);
        }
        while self.slot_count > 0 {
            let Some(slot) = self.slots[self.slot_head] else {
                return Err(QueueError::SequenceGap);
            };
            if slot.sequence >= next_expected {
                break;
            }
            self.zero_circular(slot.start, slot.wire_len);
            self.byte_head = (slot.start + slot.wire_len) % self.bytes.len();
            self.bytes_used -= slot.wire_len;
            self.slots[self.slot_head] = None;
            self.slot_head = (self.slot_head + 1) % self.slots.len();
            self.slot_count -= 1;
        }
        if self.slot_count == 0 {
            self.byte_head = self.byte_tail;
        }
        Ok(())
    }

    pub fn copy_unacked(
        &self,
        unacknowledged_index: usize,
        output: &mut [u8],
    ) -> Result<FrameCopy, QueueError> {
        if unacknowledged_index >= self.slot_count {
            return Err(QueueError::SequenceGap);
        }
        let index = (self.slot_head + unacknowledged_index) % self.slots.len();
        let slot = self.slots[index].ok_or(QueueError::SequenceGap)?;
        if output.len() < slot.wire_len {
            return Err(QueueError::BufferTooSmall);
        }
        self.read_circular(slot.start, slot.wire_len, output);
        Ok(FrameCopy {
            kind: slot.kind,
            sequence: slot.sequence,
            wire_len: slot.wire_len,
        })
    }

    /// Copies one retained record by its absolute sequence number.
    ///
    /// Send cursors use absolute sequence numbers so cumulative ACKs may
    /// retire records without shifting a live cursor onto the wrong slot.
    pub fn copy_sequence(&self, sequence: u64, output: &mut [u8]) -> Result<FrameCopy, QueueError> {
        let first = self
            .first_unacknowledged_sequence()
            .ok_or(QueueError::SequenceGap)?;
        let offset = sequence.checked_sub(first).ok_or(QueueError::SequenceGap)?;
        let index = usize::try_from(offset).map_err(|_| QueueError::SequenceGap)?;
        self.copy_unacked(index, output)
    }

    pub fn unacknowledged_operations(&self) -> usize {
        self.slot_count
    }

    pub fn unacknowledged_wire_bytes(&self) -> usize {
        self.bytes_used
    }

    pub fn first_unacknowledged_sequence(&self) -> Option<u64> {
        (self.slot_count > 0)
            .then(|| self.slots[self.slot_head].map(|slot| slot.sequence))
            .flatten()
    }

    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    pub fn can_poll_source(&self) -> bool {
        self.slot_count < self.slots.len()
            && self.bytes.len().saturating_sub(self.bytes_used) > HEADER_LEN
    }

    pub fn can_accept(&self, kind: Kind, payload_len: usize) -> bool {
        if self.validate_shape(kind, payload_len).is_err() || self.next_sequence == u64::MAX {
            return false;
        }
        let Some(wire_len) = HEADER_LEN.checked_add(payload_len) else {
            return false;
        };
        self.slot_count < self.slots.len()
            && wire_len <= self.bytes.len().saturating_sub(self.bytes_used)
    }

    pub fn remaining_wire_bytes(&self) -> usize {
        self.bytes.len().saturating_sub(self.bytes_used)
    }

    pub fn remaining_operations(&self) -> usize {
        self.slots.len().saturating_sub(self.slot_count)
    }

    pub fn snapshot(&self) -> QueueSnapshot {
        QueueSnapshot {
            next_sequence: self.next_sequence,
            first_unacknowledged: self.first_unacknowledged_sequence(),
            operations: self.slot_count,
            wire_bytes: self.bytes_used,
        }
    }

    pub fn allocated_bytes(&self) -> usize {
        self.bytes.len() + self.slots.len() * size_of::<Option<Slot>>()
    }

    pub fn allocation_signature(&self) -> RingAllocationSignature {
        RingAllocationSignature {
            bytes: self.bytes.as_ptr() as usize,
            slots: self.slots.as_ptr() as usize,
            byte_capacity: self.bytes.len(),
            operation_capacity: self.slots.len(),
        }
    }

    fn validate_shape(&self, kind: Kind, length: usize) -> Result<(), QueueError> {
        if kind.stream() != self.stream {
            return Err(QueueError::Wire(WireError::KindNotAllowed {
                kind,
                stream: self.stream,
            }));
        }
        let limits = Limits::default();
        let (minimum, maximum) = kind.payload_bounds(&limits);
        if length > maximum {
            return Err(QueueError::Wire(WireError::PayloadTooLarge {
                kind,
                length,
                maximum,
            }));
        }
        if length < minimum {
            return Err(QueueError::Wire(WireError::LengthInvalid { kind, length }));
        }
        Ok(())
    }

    fn write_circular(&mut self, input: &[u8]) {
        let first = input.len().min(self.bytes.len() - self.byte_tail);
        self.bytes[self.byte_tail..self.byte_tail + first].copy_from_slice(&input[..first]);
        if first < input.len() {
            self.bytes[..input.len() - first].copy_from_slice(&input[first..]);
        }
        self.byte_tail = (self.byte_tail + input.len()) % self.bytes.len();
    }

    fn read_circular(&self, start: usize, length: usize, output: &mut [u8]) {
        let first = length.min(self.bytes.len() - start);
        output[..first].copy_from_slice(&self.bytes[start..start + first]);
        if first < length {
            output[first..length].copy_from_slice(&self.bytes[..length - first]);
        }
    }

    fn zero_circular(&mut self, start: usize, length: usize) {
        let first = length.min(self.bytes.len() - start);
        self.bytes[start..start + first].fill(0);
        if first < length {
            self.bytes[..length - first].fill(0);
        }
    }

    fn clear_and_restart_sequence(&mut self) {
        for offset in 0..self.slot_count {
            let index = (self.slot_head + offset) % self.slots.len();
            self.slots[index] = None;
        }
        self.bytes.fill(0);
        self.byte_head = 0;
        self.byte_tail = 0;
        self.bytes_used = 0;
        self.slot_head = 0;
        self.slot_count = 0;
        self.next_sequence = 0;
    }

    pub(crate) fn restart_control_after_hello(&mut self) {
        debug_assert_eq!(self.stream, StreamRole::Control);
        self.clear_and_restart_sequence();
        self.next_sequence = 1;
    }
}

impl fmt::Debug for ReplayRing {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayRing")
            .field("stream", &self.stream)
            .field("payload", &"<REDACTED>")
            .field("snapshot", &self.snapshot())
            .finish()
    }
}

impl Drop for ReplayRing {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryDecision {
    Deliver,
    Duplicate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryGate {
    epoch: u64,
    next_expected: u64,
    pending: Option<(u64, u64)>,
}

impl DeliveryGate {
    pub const fn new(epoch: u64, next_expected: u64) -> Self {
        Self {
            epoch,
            next_expected,
            pending: None,
        }
    }

    pub fn begin(&mut self, epoch: u64, sequence: u64) -> Result<DeliveryDecision, QueueError> {
        if epoch != self.epoch {
            return Err(QueueError::EpochMismatch);
        }
        if self.pending.is_some() {
            return Err(QueueError::DeliveryPending);
        }
        if sequence < self.next_expected {
            return Ok(DeliveryDecision::Duplicate);
        }
        if sequence > self.next_expected {
            return Err(QueueError::SequenceGap);
        }
        self.pending = Some((epoch, sequence));
        Ok(DeliveryDecision::Deliver)
    }

    pub fn commit(&mut self, epoch: u64, sequence: u64) -> Result<(), QueueError> {
        if self.pending != Some((epoch, sequence)) {
            return Err(QueueError::DeliveryNotPending);
        }
        self.next_expected = self
            .next_expected
            .checked_add(1)
            .ok_or(QueueError::SequenceOverflow)?;
        self.pending = None;
        Ok(())
    }

    pub fn abort(&mut self, epoch: u64, sequence: u64) -> Result<(), QueueError> {
        if self.pending != Some((epoch, sequence)) {
            return Err(QueueError::DeliveryNotPending);
        }
        self.pending = None;
        Ok(())
    }

    pub fn reset_epoch(&mut self, epoch: u64, next_expected: u64) -> Result<(), QueueError> {
        if self.pending.is_some() {
            return Err(QueueError::DeliveryPending);
        }
        self.epoch = epoch;
        self.next_expected = next_expected;
        Ok(())
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn acknowledgement(&self) -> u64 {
        self.next_expected
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputPush {
    Buffered {
        epoch: u64,
        sequence: u64,
    },
    Overrun {
        abandoned_epoch: u64,
        replacement_epoch: u64,
    },
    Discarded {
        epoch: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputMode {
    Buffering,
    DiscardingUntilResume,
}

pub struct OutputReplay {
    epoch: u64,
    ring: ReplayRing,
    mode: OutputMode,
    pending_gap: Option<(u64, u64)>,
    gap_announced: bool,
}

impl OutputReplay {
    pub fn new(limits: &Limits) -> Result<Self, QueueError> {
        Ok(Self {
            epoch: 0,
            ring: ReplayRing::new(StreamRole::Output, limits)?,
            mode: OutputMode::Buffering,
            pending_gap: None,
            gap_announced: false,
        })
    }

    pub fn push(&mut self, kind: Kind, payload: &[u8]) -> Result<OutputPush, QueueError> {
        if self.mode == OutputMode::DiscardingUntilResume {
            self.ring.validate_shape(kind, payload.len())?;
            return Ok(OutputPush::Discarded { epoch: self.epoch });
        }
        match self.ring.push(kind, payload) {
            Ok(sequence) => Ok(OutputPush::Buffered {
                epoch: self.epoch,
                sequence,
            }),
            Err(QueueError::Full) => {
                let abandoned_epoch = self.epoch;
                self.epoch = self
                    .epoch
                    .checked_add(1)
                    .ok_or(QueueError::SequenceOverflow)?;
                self.ring.clear_and_restart_sequence();
                self.mode = OutputMode::DiscardingUntilResume;
                let earliest_abandoned = self
                    .pending_gap
                    .map_or(abandoned_epoch, |(earliest, _)| earliest);
                self.pending_gap = Some((earliest_abandoned, self.epoch));
                self.gap_announced = false;
                Ok(OutputPush::Overrun {
                    abandoned_epoch,
                    replacement_epoch: self.epoch,
                })
            }
            Err(error) => Err(error),
        }
    }

    pub fn acknowledge(&mut self, epoch: u64, next_expected: u64) -> Result<(), QueueError> {
        if epoch != self.epoch {
            return Err(QueueError::EpochMismatch);
        }
        self.ring.acknowledge(next_expected)
    }

    pub fn complete_resume(&mut self) -> Option<(u64, u64)> {
        if self.mode != OutputMode::DiscardingUntilResume {
            return None;
        }
        self.mode = OutputMode::Buffering;
        self.gap_announced = true;
        self.pending_gap
    }

    fn replace_generation(&mut self) -> Result<(u64, u64), QueueError> {
        let abandoned = self.epoch;
        self.epoch = self
            .epoch
            .checked_add(1)
            .ok_or(QueueError::SequenceOverflow)?;
        self.ring.clear_and_restart_sequence();
        self.mode = OutputMode::Buffering;
        let earliest = self.pending_gap.map_or(abandoned, |(earliest, _)| earliest);
        self.pending_gap = Some((earliest, self.epoch));
        self.gap_announced = true;
        Ok((earliest, self.epoch))
    }

    /// Reconciles a client's durable output position. An unconfirmed gap is
    /// tailored from the epoch that client actually knows; reporting the
    /// replacement epoch confirms the gap and permits cumulative ACKs again.
    pub fn reconcile_resume(
        &mut self,
        client_epoch: u64,
        delivered_ack: u64,
    ) -> Result<Option<(u64, u64)>, QueueError> {
        if let Some((earliest, replacement)) = self.pending_gap {
            if client_epoch == replacement {
                if self.mode == OutputMode::DiscardingUntilResume || !self.gap_announced {
                    return Err(QueueError::EpochMismatch);
                }
                self.acknowledge(client_epoch, delivered_ack)?;
                self.pending_gap = None;
                self.gap_announced = false;
                return Ok(None);
            }
            if client_epoch < earliest || client_epoch >= replacement {
                return Err(QueueError::EpochMismatch);
            }
            return Ok(Some((client_epoch, replacement)));
        }
        self.acknowledge(client_epoch, delivered_ack)?;
        Ok(None)
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn is_discarding(&self) -> bool {
        self.mode == OutputMode::DiscardingUntilResume
    }

    pub fn unacknowledged_operations(&self) -> usize {
        self.ring.unacknowledged_operations()
    }

    pub fn next_sequence(&self) -> u64 {
        self.ring.next_sequence()
    }

    pub fn first_unacknowledged_sequence(&self) -> Option<u64> {
        self.ring.first_unacknowledged_sequence()
    }

    pub fn pending_gap(&self) -> Option<(u64, u64)> {
        self.pending_gap
    }

    pub fn copy_unacked(&self, index: usize, output: &mut [u8]) -> Result<FrameCopy, QueueError> {
        self.ring.copy_unacked(index, output)
    }

    pub fn copy_sequence(&self, sequence: u64, output: &mut [u8]) -> Result<FrameCopy, QueueError> {
        self.ring.copy_sequence(sequence, output)
    }

    fn allocated_bytes(&self) -> usize {
        self.ring.allocated_bytes()
    }

    fn allocation_signature(&self) -> RingAllocationSignature {
        self.ring.allocation_signature()
    }
}

impl fmt::Debug for OutputReplay {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutputReplay")
            .field("epoch", &self.epoch)
            .field("mode", &self.mode)
            .field("pending_gap", &self.pending_gap)
            .field("gap_announced", &self.gap_announced)
            .field("payload", &"<REDACTED>")
            .finish()
    }
}

struct ObserverReplay {
    association_id: Option<AssociationId>,
    output: OutputReplay,
    control: ReplayRing,
}

impl ObserverReplay {
    fn new(limits: &Limits) -> Result<Self, QueueError> {
        Ok(Self {
            association_id: None,
            output: OutputReplay::new(limits)?,
            control: ReplayRing::control(limits)?,
        })
    }

    fn allocated_bytes(&self) -> usize {
        self.output.allocated_bytes() + self.control.allocated_bytes()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FanoutReport {
    pub writer: OutputPush,
    observer_overruns: [Option<AssociationId>; OBSERVER_SLOTS],
}

impl FanoutReport {
    pub fn observer_overran(&self, association_id: AssociationId) -> bool {
        self.observer_overruns
            .iter()
            .flatten()
            .any(|candidate| *candidate == association_id)
    }

    pub fn observer_overrun_count(&self) -> usize {
        self.observer_overruns.iter().flatten().count()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayAllocationSignature {
    data: [usize; GATEWAY_RING_COUNT],
    slots: [usize; GATEWAY_RING_COUNT],
}

pub struct GatewayReplaySlabs {
    input: ReplayRing,
    writer_output: OutputReplay,
    writer_control: ReplayRing,
    observers: Box<[ObserverReplay]>,
    global_cap: usize,
    #[cfg(feature = "path-diagnostics")]
    path_trace: Option<crate::path_trace::FileTrace>,
}

impl GatewayReplaySlabs {
    pub fn new(limits: &Limits) -> Result<Self, QueueError> {
        limits.validate().map_err(WireError::from)?;
        let mut observers = Vec::new();
        observers
            .try_reserve_exact(OBSERVER_SLOTS)
            .map_err(|_| QueueError::Allocation)?;
        for _ in 0..OBSERVER_SLOTS {
            observers.push(ObserverReplay::new(limits)?);
        }
        let slabs = Self {
            input: ReplayRing::new(StreamRole::Input, limits)?,
            writer_output: OutputReplay::new(limits)?,
            writer_control: ReplayRing::control(limits)?,
            observers: observers.into_boxed_slice(),
            global_cap: limits.global_queue_bytes,
            #[cfg(feature = "path-diagnostics")]
            path_trace: None,
        };
        if slabs.allocated_bytes() > slabs.global_cap {
            return Err(QueueError::Allocation);
        }
        Ok(slabs)
    }

    /// This diagnostic currently correlates one writer generation only.
    #[cfg(feature = "path-diagnostics")]
    pub fn enable_path_trace(&mut self, path: &std::path::Path) -> std::io::Result<()> {
        if self.path_trace.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "trace already enabled",
            ));
        }
        self.path_trace = Some(crate::path_trace::FileTrace::create(path)?);
        if self
            .observers
            .iter()
            .any(|observer| observer.association_id.is_some())
        {
            self.invalidate_path_trace();
        }
        Ok(())
    }

    #[cfg(feature = "path-diagnostics")]
    pub(crate) fn trace_boundary(
        &mut self,
        stage: crate::path_trace::Stage,
        epoch: u64,
        sequence: u64,
    ) {
        if let Some(trace) = self.path_trace.as_mut() {
            trace.record(stage, epoch, sequence);
        }
    }

    #[cfg(feature = "path-diagnostics")]
    fn invalidate_path_trace(&mut self) {
        if let Some(trace) = self.path_trace.as_mut() {
            trace.invalidate();
        }
    }

    /// An authenticated writer detach ends the measured writer lifetime even
    /// though the persistent gateway and PTY may continue running.
    #[cfg(feature = "path-diagnostics")]
    pub(crate) fn finish_path_trace(&mut self) {
        drop(self.path_trace.take());
    }

    pub fn add_observer(&mut self, association_id: AssociationId) -> Result<(), QueueError> {
        #[cfg(feature = "path-diagnostics")]
        self.invalidate_path_trace();
        if self
            .observers
            .iter()
            .any(|observer| observer.association_id == Some(association_id))
        {
            return Ok(());
        }
        let observer = self
            .observers
            .iter_mut()
            .find(|observer| observer.association_id.is_none())
            .ok_or(QueueError::ObserverCapacity)?;
        observer.association_id = Some(association_id);
        Ok(())
    }

    pub fn remove_observer(&mut self, association_id: AssociationId) -> Result<(), QueueError> {
        let observer = self.observer_mut(association_id)?;
        observer.output.ring.clear_and_restart_sequence();
        observer.output.epoch = 0;
        observer.output.mode = OutputMode::Buffering;
        observer.output.pending_gap = None;
        observer.output.gap_announced = false;
        observer.control.clear_and_restart_sequence();
        observer.association_id = None;
        Ok(())
    }

    pub fn push_output(&mut self, kind: Kind, payload: &[u8]) -> Result<FanoutReport, QueueError> {
        let writer = self.writer_output.push(kind, payload)?;
        #[cfg(feature = "path-diagnostics")]
        if kind == Kind::Output {
            if let OutputPush::Buffered { epoch, sequence } = writer {
                self.trace_boundary(
                    crate::path_trace::Stage::GatewayOutputQueued,
                    epoch,
                    sequence,
                );
            }
        }
        let mut observer_overruns = [None; OBSERVER_SLOTS];
        let mut overrun_index = 0usize;
        for observer in self
            .observers
            .iter_mut()
            .filter(|observer| observer.association_id.is_some())
        {
            if matches!(
                observer.output.push(kind, payload)?,
                OutputPush::Overrun { .. }
            ) {
                observer_overruns[overrun_index] = observer.association_id;
                overrun_index += 1;
            }
        }
        Ok(FanoutReport {
            writer,
            observer_overruns,
        })
    }

    pub fn push_writer_output(
        &mut self,
        kind: Kind,
        payload: &[u8],
    ) -> Result<OutputPush, QueueError> {
        self.writer_output.push(kind, payload)
    }

    pub fn acknowledge_writer(&mut self, next_expected: u64) -> Result<(), QueueError> {
        self.writer_output
            .acknowledge(self.writer_output.epoch(), next_expected)
    }

    pub fn acknowledge_writer_epoch(
        &mut self,
        epoch: u64,
        next_expected: u64,
    ) -> Result<(), QueueError> {
        self.writer_output.acknowledge(epoch, next_expected)
    }

    pub fn acknowledge_observer(
        &mut self,
        association_id: AssociationId,
        next_expected: u64,
    ) -> Result<(), QueueError> {
        let observer = self.observer_mut(association_id)?;
        observer
            .output
            .acknowledge(observer.output.epoch(), next_expected)
    }

    pub fn acknowledge_observer_epoch(
        &mut self,
        association_id: AssociationId,
        epoch: u64,
        next_expected: u64,
    ) -> Result<(), QueueError> {
        self.observer_mut(association_id)?
            .output
            .acknowledge(epoch, next_expected)
    }

    pub fn writer_output(&self) -> &OutputReplay {
        &self.writer_output
    }

    pub fn observer_output(&self, association_id: AssociationId) -> Option<&OutputReplay> {
        self.observers
            .iter()
            .find(|observer| observer.association_id == Some(association_id))
            .map(|observer| &observer.output)
    }

    pub fn input(&self) -> &ReplayRing {
        &self.input
    }

    pub fn input_mut(&mut self) -> &mut ReplayRing {
        &mut self.input
    }

    pub fn writer_control_mut(&mut self) -> &mut ReplayRing {
        &mut self.writer_control
    }

    pub fn writer_control(&self) -> &ReplayRing {
        &self.writer_control
    }

    /// Starts a future-only writer generation after an explicit takeover or
    /// replacement of a disconnected client. Old unacknowledged output is
    /// never shown to the new actor; its first SERVER_HELLO carries one GAP.
    pub fn replace_writer_generation(&mut self) -> Result<(u64, u64), QueueError> {
        #[cfg(feature = "path-diagnostics")]
        self.invalidate_path_trace();
        self.input.clear_and_restart_sequence();
        self.writer_control.clear_and_restart_sequence();
        self.writer_output.replace_generation()
    }

    pub(crate) fn restart_writer_control(&mut self) {
        self.writer_control.clear_and_restart_sequence();
    }

    pub fn observer_control(
        &self,
        association_id: AssociationId,
    ) -> Result<&ReplayRing, QueueError> {
        self.observers
            .iter()
            .find(|observer| observer.association_id == Some(association_id))
            .map(|observer| &observer.control)
            .ok_or(QueueError::UnknownObserver)
    }

    pub fn observer_control_mut(
        &mut self,
        association_id: AssociationId,
    ) -> Result<&mut ReplayRing, QueueError> {
        self.observer_mut(association_id)
            .map(|observer| &mut observer.control)
    }

    pub(crate) fn restart_observer_control(
        &mut self,
        association_id: AssociationId,
    ) -> Result<(), QueueError> {
        self.observer_mut(association_id)?
            .control
            .clear_and_restart_sequence();
        Ok(())
    }

    pub fn complete_writer_resume(&mut self) -> Result<Option<(u64, u64)>, QueueError> {
        self.complete_writer_resume_for(None)
    }

    pub(crate) fn complete_writer_resume_for(
        &mut self,
        client_gap: Option<(u64, u64)>,
    ) -> Result<Option<(u64, u64)>, QueueError> {
        let Some(stored) = self.writer_output.complete_resume() else {
            return Ok(None);
        };
        let (abandoned, replacement) = client_gap.unwrap_or(stored);
        let payload = crate::wire::EpochGap::new(abandoned, replacement)?.encode();
        self.writer_control.push(Kind::Gap, &payload)?;
        Ok(Some((abandoned, replacement)))
    }

    pub fn complete_observer_resume(
        &mut self,
        association_id: AssociationId,
    ) -> Result<Option<(u64, u64)>, QueueError> {
        self.complete_observer_resume_for(association_id, None)
    }

    pub(crate) fn complete_observer_resume_for(
        &mut self,
        association_id: AssociationId,
        client_gap: Option<(u64, u64)>,
    ) -> Result<Option<(u64, u64)>, QueueError> {
        let observer = self.observer_mut(association_id)?;
        let Some(stored) = observer.output.complete_resume() else {
            return Ok(None);
        };
        let (abandoned, replacement) = client_gap.unwrap_or(stored);
        let payload = crate::wire::EpochGap::new(abandoned, replacement)?.encode();
        observer.control.push(Kind::Gap, &payload)?;
        Ok(Some((abandoned, replacement)))
    }

    pub(crate) fn reconcile_writer_resume(
        &mut self,
        client_epoch: u64,
        delivered_ack: u64,
    ) -> Result<Option<(u64, u64)>, QueueError> {
        self.writer_output
            .reconcile_resume(client_epoch, delivered_ack)
    }

    pub(crate) fn reconcile_observer_resume(
        &mut self,
        association_id: AssociationId,
        client_epoch: u64,
        delivered_ack: u64,
    ) -> Result<Option<(u64, u64)>, QueueError> {
        self.observer_mut(association_id)?
            .output
            .reconcile_resume(client_epoch, delivered_ack)
    }

    pub fn allocated_bytes(&self) -> usize {
        self.input.allocated_bytes()
            + self.writer_output.allocated_bytes()
            + self.writer_control.allocated_bytes()
            + self
                .observers
                .iter()
                .map(ObserverReplay::allocated_bytes)
                .sum::<usize>()
    }

    pub fn allocation_signature(&self) -> GatewayAllocationSignature {
        let mut data = [0usize; GATEWAY_RING_COUNT];
        let mut slots = [0usize; GATEWAY_RING_COUNT];
        let mut index = 0usize;
        for signature in [
            self.input.allocation_signature(),
            self.writer_output.allocation_signature(),
            self.writer_control.allocation_signature(),
        ] {
            data[index] = signature.bytes;
            slots[index] = signature.slots;
            index += 1;
        }
        for observer in &self.observers {
            for signature in [
                observer.output.allocation_signature(),
                observer.control.allocation_signature(),
            ] {
                data[index] = signature.bytes;
                slots[index] = signature.slots;
                index += 1;
            }
        }
        GatewayAllocationSignature { data, slots }
    }

    fn observer_mut(
        &mut self,
        association_id: AssociationId,
    ) -> Result<&mut ObserverReplay, QueueError> {
        self.observers
            .iter_mut()
            .find(|observer| observer.association_id == Some(association_id))
            .ok_or(QueueError::UnknownObserver)
    }
}

impl fmt::Debug for GatewayReplaySlabs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayReplaySlabs")
            .field("allocated_bytes", &self.allocated_bytes())
            .field("global_cap", &self.global_cap)
            .field("payload", &"<REDACTED>")
            .finish()
    }
}
