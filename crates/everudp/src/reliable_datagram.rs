//! Pure wire and receive-window state for the v4 reliable-DATAGRAM spike.
//!
//! Nothing in this module performs I/O or advances delivery on receipt. The
//! caller must commit a staged record only after its complete sink operation
//! succeeds.

use crate::limits::Limits;
use crate::wire::Kind;
use std::fmt;

pub const VERSION: u8 = 4;
pub const ALPN: &[u8] = b"everudp-rdgram/1";
pub const HEADER_LEN: usize = 46;
pub const MAX_WIRE_LEN: usize = 1_200;
pub const MAX_PAYLOAD_LEN: usize = 1_024;
pub const REORDER_SLOTS: usize = 64;
pub const MAX_TRANSMITS_PER_WAKE: usize = 8;
pub const DELAYED_ACK_MICROS: u64 = 1_000;
pub const MIN_RTO_MICROS: u64 = 2_000;
pub const PRE_SAMPLE_RTT_MICROS: u64 = 100_000;
pub const MAX_BACKOFF_MICROS: u64 = 60_000_000;

const FLAG_ACK_ONLY: u8 = 0x01;
const KNOWN_FLAGS: u8 = FLAG_ACK_ONLY;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Direction {
    ClientToGateway = 1,
    GatewayToClient = 2,
}

impl Direction {
    fn decode(value: u8) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::ClientToGateway),
            2 => Ok(Self::GatewayToClient),
            other => Err(Error::Direction(other)),
        }
    }

    fn accepts(self, kind: Kind) -> bool {
        match self {
            Self::ClientToGateway => {
                matches!(
                    kind,
                    Kind::Input | Kind::Resize | Kind::Signal | Kind::InputClose
                )
            }
            Self::GatewayToClient => {
                matches!(kind, Kind::Output | Kind::Ownership | Kind::Exit)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckState {
    pub epoch: u64,
    pub base: u64,
    pub bits: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Data<'a> {
    pub direction: Direction,
    pub kind: Kind,
    pub epoch: u64,
    pub sequence: u64,
    pub acknowledgement: AckState,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame<'a> {
    Data(Data<'a>),
    AckOnly {
        direction: Direction,
        acknowledgement: AckState,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offer {
    Ready,
    FutureStored,
    Duplicate,
    StaleEpoch,
    FutureEpoch,
    OutsideWindow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckApply {
    Applied { retired: usize },
    StaleCumulative,
    StaleEpoch,
    FutureEpoch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadyRecord<'a> {
    pub kind: Kind,
    pub sequence: u64,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Slot {
    sequence: u64,
    kind: Kind,
    length: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Incomplete { needed: usize, available: usize },
    Version(u8),
    Direction(u8),
    Kind(u8),
    KindForDirection { direction: Direction, kind: Kind },
    Flags(u8),
    Length { declared: usize, actual: usize },
    PayloadBounds { kind: Kind, length: usize },
    OutputTooSmall { needed: usize, available: usize },
    SequenceOverflow,
    ConflictingDuplicate(u64),
    NoReadyRecord,
    CommitSequence { expected: u64, actual: u64 },
    QueueFull,
    Sequence { expected: u64, actual: u64 },
    AckAhead { next_sequence: u64, actual: u64 },
    SelectiveAckAhead(u64),
    UnknownSequence(u64),
    Allocation,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete { needed, available } => {
                write!(
                    formatter,
                    "incomplete datagram: need {needed}, have {available}"
                )
            }
            Self::Version(version) => write!(formatter, "unsupported datagram version {version}"),
            Self::Direction(direction) => {
                write!(formatter, "invalid datagram direction {direction}")
            }
            Self::Kind(kind) => write!(formatter, "invalid datagram kind {kind}"),
            Self::KindForDirection { direction, kind } => {
                write!(formatter, "kind {kind:?} is invalid for {direction:?}")
            }
            Self::Flags(flags) => write!(formatter, "invalid datagram flags {flags:#04x}"),
            Self::Length { declared, actual } => {
                write!(
                    formatter,
                    "datagram length {actual} does not match {declared}"
                )
            }
            Self::PayloadBounds { kind, length } => {
                write!(formatter, "payload length {length} is invalid for {kind:?}")
            }
            Self::OutputTooSmall { needed, available } => {
                write!(formatter, "output needs {needed} bytes, has {available}")
            }
            Self::SequenceOverflow => formatter.write_str("sequence window overflow"),
            Self::ConflictingDuplicate(sequence) => {
                write!(formatter, "conflicting duplicate sequence {sequence}")
            }
            Self::NoReadyRecord => formatter.write_str("no next record is staged"),
            Self::CommitSequence { expected, actual } => {
                write!(
                    formatter,
                    "commit sequence {actual} does not match {expected}"
                )
            }
            Self::QueueFull => formatter.write_str("bounded transmit metadata queue is full"),
            Self::Sequence { expected, actual } => {
                write!(
                    formatter,
                    "transmit sequence {actual} does not match next sequence {expected}"
                )
            }
            Self::AckAhead {
                next_sequence,
                actual,
            } => {
                write!(
                    formatter,
                    "cumulative acknowledgement {actual} exceeds next sequence {next_sequence}"
                )
            }
            Self::SelectiveAckAhead(sequence) => {
                write!(
                    formatter,
                    "selective acknowledgement names unsent sequence {sequence}"
                )
            }
            Self::UnknownSequence(sequence) => {
                write!(formatter, "unknown transmit sequence {sequence}")
            }
            Self::Allocation => formatter.write_str("bounded datagram allocation failed"),
        }
    }
}

impl std::error::Error for Error {}

pub fn encode_data(data: Data<'_>, output: &mut [u8]) -> Result<usize, Error> {
    validate_payload(data.direction, data.kind, data.payload, &Limits::default())?;
    encode(
        data.direction,
        data.kind as u8,
        0,
        data.epoch,
        data.sequence,
        data.acknowledgement,
        data.payload,
        output,
    )
}

pub fn encode_ack_only(
    direction: Direction,
    acknowledgement: AckState,
    output: &mut [u8],
) -> Result<usize, Error> {
    encode(
        direction,
        0,
        FLAG_ACK_ONLY,
        0,
        0,
        acknowledgement,
        &[],
        output,
    )
}

#[allow(clippy::too_many_arguments)]
fn encode(
    direction: Direction,
    kind: u8,
    flags: u8,
    epoch: u64,
    sequence: u64,
    acknowledgement: AckState,
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize, Error> {
    let total = HEADER_LEN
        .checked_add(payload.len())
        .ok_or(Error::SequenceOverflow)?;
    if total > MAX_WIRE_LEN || payload.len() > MAX_PAYLOAD_LEN {
        return Err(Error::Length {
            declared: MAX_WIRE_LEN,
            actual: total,
        });
    }
    if output.len() < total {
        return Err(Error::OutputTooSmall {
            needed: total,
            available: output.len(),
        });
    }
    let payload_len = u16::try_from(payload.len()).map_err(|_| Error::SequenceOverflow)?;
    output[0] = VERSION;
    output[1] = direction as u8;
    output[2] = kind;
    output[3] = flags;
    output[4..12].copy_from_slice(&epoch.to_be_bytes());
    output[12..20].copy_from_slice(&sequence.to_be_bytes());
    output[20..28].copy_from_slice(&acknowledgement.epoch.to_be_bytes());
    output[28..36].copy_from_slice(&acknowledgement.base.to_be_bytes());
    output[36..44].copy_from_slice(&acknowledgement.bits.to_be_bytes());
    output[44..46].copy_from_slice(&payload_len.to_be_bytes());
    output[HEADER_LEN..total].copy_from_slice(payload);
    Ok(total)
}

pub fn decode<'a>(
    expected_direction: Direction,
    input: &'a [u8],
    limits: &Limits,
) -> Result<Frame<'a>, Error> {
    if input.len() < HEADER_LEN {
        return Err(Error::Incomplete {
            needed: HEADER_LEN,
            available: input.len(),
        });
    }
    if input.len() > MAX_WIRE_LEN {
        return Err(Error::Length {
            declared: MAX_WIRE_LEN,
            actual: input.len(),
        });
    }
    if input[0] != VERSION {
        return Err(Error::Version(input[0]));
    }
    let direction = Direction::decode(input[1])?;
    if direction != expected_direction {
        return Err(Error::Direction(input[1]));
    }
    let flags = input[3];
    if flags & !KNOWN_FLAGS != 0 {
        return Err(Error::Flags(flags));
    }
    let epoch = read_u64(&input[4..12]);
    let sequence = read_u64(&input[12..20]);
    let acknowledgement = AckState {
        epoch: read_u64(&input[20..28]),
        base: read_u64(&input[28..36]),
        bits: read_u64(&input[36..44]),
    };
    let payload_len = usize::from(u16::from_be_bytes([input[44], input[45]]));
    let declared = HEADER_LEN
        .checked_add(payload_len)
        .ok_or(Error::SequenceOverflow)?;
    if declared != input.len() {
        return Err(Error::Length {
            declared,
            actual: input.len(),
        });
    }

    if flags == FLAG_ACK_ONLY {
        if input[2] != 0 || epoch != 0 || sequence != 0 || payload_len != 0 {
            return Err(Error::Flags(flags));
        }
        return Ok(Frame::AckOnly {
            direction,
            acknowledgement,
        });
    }
    if flags != 0 {
        return Err(Error::Flags(flags));
    }
    let kind = decode_kind(input[2])?;
    let payload = &input[HEADER_LEN..];
    validate_payload(direction, kind, payload, limits)?;
    Ok(Frame::Data(Data {
        direction,
        kind,
        epoch,
        sequence,
        acknowledgement,
        payload,
    }))
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes.try_into().expect("caller provides eight bytes"))
}

fn decode_kind(value: u8) -> Result<Kind, Error> {
    match value {
        0x20 => Ok(Kind::Input),
        0x21 => Ok(Kind::Resize),
        0x22 => Ok(Kind::Signal),
        0x23 => Ok(Kind::InputClose),
        0x40 => Ok(Kind::Output),
        0x41 => Ok(Kind::Ownership),
        0x42 => Ok(Kind::Exit),
        other => Err(Error::Kind(other)),
    }
}

fn validate_payload(
    direction: Direction,
    kind: Kind,
    payload: &[u8],
    limits: &Limits,
) -> Result<(), Error> {
    if !direction.accepts(kind) {
        return Err(Error::KindForDirection { direction, kind });
    }
    let (minimum, maximum) = kind.payload_bounds(limits);
    let maximum = maximum.min(MAX_PAYLOAD_LEN);
    if payload.len() < minimum || payload.len() > maximum {
        return Err(Error::PayloadBounds {
            kind,
            length: payload.len(),
        });
    }
    Ok(())
}

/// Fixed-memory reorder state. Receipt never implies delivery; only
/// `commit_ready` advances the cumulative acknowledgement.
pub struct ReceiveWindow {
    epoch: u64,
    next_expected: u64,
    slots: Box<[Option<Slot>]>,
    payloads: Box<[u8]>,
}

impl ReceiveWindow {
    pub fn new(epoch: u64, next_expected: u64) -> Result<Self, Error> {
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(REORDER_SLOTS)
            .map_err(|_| Error::Allocation)?;
        slots.resize(REORDER_SLOTS, None);
        let payload_bytes = REORDER_SLOTS
            .checked_mul(MAX_PAYLOAD_LEN)
            .ok_or(Error::Allocation)?;
        let mut payloads = Vec::new();
        payloads
            .try_reserve_exact(payload_bytes)
            .map_err(|_| Error::Allocation)?;
        payloads.resize(payload_bytes, 0);
        Ok(Self {
            epoch,
            next_expected,
            slots: slots.into_boxed_slice(),
            payloads: payloads.into_boxed_slice(),
        })
    }

    pub fn acknowledgement(&self) -> AckState {
        let mut bits = 0_u64;
        for offset in 0..REORDER_SLOTS {
            let Some(sequence) = self.next_expected.checked_add(offset as u64) else {
                break;
            };
            let index = slot_index(sequence);
            if self.slots[index].is_some_and(|slot| slot.sequence == sequence) {
                bits |= 1_u64 << offset;
            }
        }
        AckState {
            epoch: self.epoch,
            base: self.next_expected,
            bits,
        }
    }

    pub fn offer(&mut self, data: Data<'_>) -> Result<Offer, Error> {
        if data.epoch < self.epoch {
            return Ok(Offer::StaleEpoch);
        }
        if data.epoch > self.epoch {
            return Ok(Offer::FutureEpoch);
        }
        if data.sequence < self.next_expected {
            return Ok(Offer::Duplicate);
        }
        let end = self
            .next_expected
            .checked_add(REORDER_SLOTS as u64)
            .ok_or(Error::SequenceOverflow)?;
        if data.sequence >= end {
            return Ok(Offer::OutsideWindow);
        }
        if data.payload.len() > MAX_PAYLOAD_LEN {
            return Err(Error::PayloadBounds {
                kind: data.kind,
                length: data.payload.len(),
            });
        }
        let index = slot_index(data.sequence);
        if let Some(slot) = self.slots[index] {
            let stored = self.payload(index, slot.length);
            return if slot.sequence == data.sequence
                && slot.kind == data.kind
                && stored == data.payload
            {
                Ok(Offer::Duplicate)
            } else {
                Err(Error::ConflictingDuplicate(data.sequence))
            };
        }
        let range = payload_range(index, data.payload.len());
        self.payloads[range].copy_from_slice(data.payload);
        self.slots[index] = Some(Slot {
            sequence: data.sequence,
            kind: data.kind,
            length: data.payload.len(),
        });
        Ok(if data.sequence == self.next_expected {
            Offer::Ready
        } else {
            Offer::FutureStored
        })
    }

    pub fn ready(&self) -> Option<ReadyRecord<'_>> {
        let index = slot_index(self.next_expected);
        let slot = self.slots[index]?;
        (slot.sequence == self.next_expected).then(|| ReadyRecord {
            kind: slot.kind,
            sequence: slot.sequence,
            payload: self.payload(index, slot.length),
        })
    }

    pub fn commit_ready(&mut self, sequence: u64) -> Result<AckState, Error> {
        let index = slot_index(self.next_expected);
        let slot = self.slots[index].ok_or(Error::NoReadyRecord)?;
        if slot.sequence != self.next_expected || sequence != self.next_expected {
            return Err(Error::CommitSequence {
                expected: self.next_expected,
                actual: sequence,
            });
        }
        let range = payload_range(index, slot.length);
        self.payloads[range].fill(0);
        self.slots[index] = None;
        self.next_expected = self
            .next_expected
            .checked_add(1)
            .ok_or(Error::SequenceOverflow)?;
        Ok(self.acknowledgement())
    }

    pub fn reset(&mut self, epoch: u64, next_expected: u64) {
        self.payloads.fill(0);
        self.slots.fill(None);
        self.epoch = epoch;
        self.next_expected = next_expected;
    }

    fn payload(&self, index: usize, length: usize) -> &[u8] {
        &self.payloads[payload_range(index, length)]
    }
}

impl fmt::Debug for ReceiveWindow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReceiveWindow")
            .field("epoch", &self.epoch)
            .field("next_expected", &self.next_expected)
            .field(
                "occupied",
                &self.slots.iter().filter(|slot| slot.is_some()).count(),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TransmitSlot {
    sequence: u64,
    sent_at_micros: Option<u64>,
    attempts: u16,
}

/// Fixed-memory delivery metadata for records retained by the replay ring.
///
/// Payload bytes stay in the existing replay ring. This tracker controls only
/// initial offers, retry timing, and cumulative retirement. Selective ACK bits
/// may suppress retries on the current link, but never remove a slot.
pub struct TransmitWindow {
    epoch: u64,
    first_unacknowledged: u64,
    next_sequence: u64,
    slots: Box<[Option<TransmitSlot>]>,
    selective_base: u64,
    selective_bits: u64,
    selective_observed_at_micros: Option<u64>,
    scan_offset: usize,
    jitter_seed: u64,
}

impl TransmitWindow {
    pub fn new(
        epoch: u64,
        first_sequence: u64,
        capacity: usize,
        jitter_seed: u64,
    ) -> Result<Self, Error> {
        if capacity == 0 {
            return Err(Error::Allocation);
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(capacity)
            .map_err(|_| Error::Allocation)?;
        slots.resize(capacity, None);
        Ok(Self {
            epoch,
            first_unacknowledged: first_sequence,
            next_sequence: first_sequence,
            slots: slots.into_boxed_slice(),
            selective_base: first_sequence,
            selective_bits: 0,
            selective_observed_at_micros: None,
            scan_offset: 0,
            jitter_seed,
        })
    }

    pub fn track(&mut self, sequence: u64) -> Result<(), Error> {
        if sequence != self.next_sequence {
            return Err(Error::Sequence {
                expected: self.next_sequence,
                actual: sequence,
            });
        }
        if sequence == u64::MAX || self.len() == self.slots.len() {
            return Err(if sequence == u64::MAX {
                Error::SequenceOverflow
            } else {
                Error::QueueFull
            });
        }
        let index = transmit_slot_index(sequence, self.slots.len());
        if self.slots[index].is_some() {
            return Err(Error::QueueFull);
        }
        self.slots[index] = Some(TransmitSlot {
            sequence,
            sent_at_micros: None,
            attempts: 0,
        });
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(Error::SequenceOverflow)?;
        Ok(())
    }

    pub fn due(&mut self, now_micros: u64, path_rtt_micros: u64) -> DueBatch {
        let count = self.len();
        if count == 0 {
            return DueBatch::default();
        }
        let mut batch = DueBatch::default();
        let start = self.scan_offset.min(count - 1);
        for visited in 0..count {
            let offset = (start + visited) % count;
            let Some(sequence) = self.first_unacknowledged.checked_add(offset as u64) else {
                break;
            };
            if self.is_selectively_received(sequence, now_micros, path_rtt_micros) {
                continue;
            }
            let index = transmit_slot_index(sequence, self.slots.len());
            let Some(slot) = self.slots[index] else {
                continue;
            };
            if slot.sequence != sequence
                || !slot.is_due(now_micros, path_rtt_micros, self.jitter_seed)
            {
                continue;
            }
            batch.push(sequence);
            if batch.len == MAX_TRANSMITS_PER_WAKE {
                self.scan_offset = (offset + 1) % count;
                return batch;
            }
        }
        self.scan_offset = start;
        batch
    }

    /// Records a DATAGRAM accepted by noQ's send API. Socket flush is not a
    /// delivery event and does not affect cumulative retirement.
    pub fn mark_sent(&mut self, sequence: u64, now_micros: u64) -> Result<(), Error> {
        if sequence < self.first_unacknowledged || sequence >= self.next_sequence {
            return Err(Error::UnknownSequence(sequence));
        }
        let index = transmit_slot_index(sequence, self.slots.len());
        let slot = self.slots[index]
            .as_mut()
            .filter(|slot| slot.sequence == sequence)
            .ok_or(Error::UnknownSequence(sequence))?;
        slot.sent_at_micros = Some(now_micros);
        slot.attempts = slot.attempts.saturating_add(1);
        Ok(())
    }

    pub fn apply_acknowledgement(
        &mut self,
        ack: AckState,
        now_micros: u64,
    ) -> Result<AckApply, Error> {
        if ack.epoch < self.epoch {
            return Ok(AckApply::StaleEpoch);
        }
        if ack.epoch > self.epoch {
            return Ok(AckApply::FutureEpoch);
        }
        if ack.base < self.first_unacknowledged {
            return Ok(AckApply::StaleCumulative);
        }
        if ack.base > self.next_sequence {
            return Err(Error::AckAhead {
                next_sequence: self.next_sequence,
                actual: ack.base,
            });
        }
        validate_selective_ack(ack.base, ack.bits, self.next_sequence)?;

        let retired_u64 = ack.base - self.first_unacknowledged;
        let retired = usize::try_from(retired_u64).map_err(|_| Error::SequenceOverflow)?;
        for offset in 0..retired {
            let sequence = self
                .first_unacknowledged
                .checked_add(offset as u64)
                .ok_or(Error::SequenceOverflow)?;
            let index = transmit_slot_index(sequence, self.slots.len());
            let slot = self.slots[index].ok_or(Error::UnknownSequence(sequence))?;
            if slot.sequence != sequence {
                return Err(Error::UnknownSequence(sequence));
            }
            self.slots[index] = None;
        }
        let old_selective_base = self.selective_base;
        self.first_unacknowledged = ack.base;
        let same_cumulative_generation = ack.base == old_selective_base;
        self.selective_bits = if same_cumulative_generation {
            self.selective_bits | ack.bits
        } else {
            ack.bits
        };
        self.selective_base = ack.base;
        self.selective_observed_at_micros = if self.selective_bits == 0 {
            None
        } else if same_cumulative_generation {
            self.selective_observed_at_micros.or(Some(now_micros))
        } else {
            Some(now_micros)
        };
        self.scan_offset = self.scan_offset.min(self.len().saturating_sub(1));
        Ok(AckApply::Applied { retired })
    }

    /// Starts a new QUIC connection for the same association. Durable
    /// cumulative state remains, while same-link SACK and retry timing do not.
    pub fn restart_link(&mut self) {
        self.selective_base = self.first_unacknowledged;
        self.selective_bits = 0;
        self.selective_observed_at_micros = None;
        self.scan_offset = 0;
        for slot in self.slots.iter_mut().flatten() {
            slot.sent_at_micros = None;
            slot.attempts = 0;
        }
    }

    pub fn reset_epoch(&mut self, epoch: u64, first_sequence: u64) {
        self.slots.fill(None);
        self.epoch = epoch;
        self.first_unacknowledged = first_sequence;
        self.next_sequence = first_sequence;
        self.selective_base = first_sequence;
        self.selective_bits = 0;
        self.selective_observed_at_micros = None;
        self.scan_offset = 0;
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn first_unacknowledged(&self) -> u64 {
        self.first_unacknowledged
    }

    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    pub fn len(&self) -> usize {
        usize::try_from(self.next_sequence - self.first_unacknowledged)
            .expect("bounded transmit window length fits usize")
    }

    pub fn is_empty(&self) -> bool {
        self.first_unacknowledged == self.next_sequence
    }

    fn is_selectively_received(
        &self,
        sequence: u64,
        now_micros: u64,
        path_rtt_micros: u64,
    ) -> bool {
        let Some(offset) = sequence.checked_sub(self.selective_base) else {
            return false;
        };
        if offset >= 64 || self.selective_bits & (1_u64 << offset) == 0 {
            return false;
        }
        let Some(observed_at) = self.selective_observed_at_micros else {
            return false;
        };
        let suppression =
            retransmission_delay_micros(path_rtt_micros, 1, self.jitter_seed, sequence);
        now_micros.saturating_sub(observed_at) < suppression
    }
}

impl fmt::Debug for TransmitWindow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransmitWindow")
            .field("epoch", &self.epoch)
            .field("first_unacknowledged", &self.first_unacknowledged)
            .field("next_sequence", &self.next_sequence)
            .field("selective_base", &self.selective_base)
            .field("selective_bits", &self.selective_bits)
            .finish_non_exhaustive()
    }
}

impl TransmitSlot {
    fn is_due(self, now_micros: u64, path_rtt_micros: u64, jitter_seed: u64) -> bool {
        let Some(sent_at_micros) = self.sent_at_micros else {
            return true;
        };
        let delay =
            retransmission_delay_micros(path_rtt_micros, self.attempts, jitter_seed, self.sequence);
        now_micros.saturating_sub(sent_at_micros) >= delay
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DueBatch {
    sequences: [u64; MAX_TRANSMITS_PER_WAKE],
    len: usize,
}

impl DueBatch {
    pub fn as_slice(&self) -> &[u64] {
        &self.sequences[..self.len]
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn push(&mut self, sequence: u64) {
        self.sequences[self.len] = sequence;
        self.len += 1;
    }
}

impl Default for DueBatch {
    fn default() -> Self {
        Self {
            sequences: [0; MAX_TRANSMITS_PER_WAKE],
            len: 0,
        }
    }
}

/// Computes the delay after at least one completed send attempt. The base is
/// twice the current path RTT and never below RTT plus the delayed-ACK bound.
/// Before an RTT sample exists, callers pass zero and use the locked 100 ms
/// initial estimate. Subsequent attempts back off exponentially to 60 s with
/// deterministic +/-10% association jitter.
pub fn retransmission_delay_micros(
    path_rtt_micros: u64,
    completed_attempts: u16,
    jitter_seed: u64,
    sequence: u64,
) -> u64 {
    let path_rtt_micros = if path_rtt_micros == 0 {
        PRE_SAMPLE_RTT_MICROS
    } else {
        path_rtt_micros
    };
    let base = path_rtt_micros
        .saturating_mul(2)
        .max(path_rtt_micros.saturating_add(DELAYED_ACK_MICROS))
        .clamp(MIN_RTO_MICROS, MAX_BACKOFF_MICROS);
    let shift = u32::from(completed_attempts.saturating_sub(1)).min(10);
    let backed_off = base.saturating_mul(1_u64 << shift).min(MAX_BACKOFF_MICROS);
    let span = backed_off / 10;
    let width = span.saturating_mul(2).saturating_add(1);
    let sample = mix64(jitter_seed ^ sequence ^ u64::from(completed_attempts));
    let adjustment = sample % width;
    backed_off
        .saturating_sub(span)
        .saturating_add(adjustment)
        .clamp(MIN_RTO_MICROS, MAX_BACKOFF_MICROS)
}

fn mix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn validate_selective_ack(base: u64, bits: u64, next_sequence: u64) -> Result<(), Error> {
    if bits == 0 {
        return Ok(());
    }
    let highest_offset = u64::from(63 - bits.leading_zeros());
    let highest = base
        .checked_add(highest_offset)
        .ok_or(Error::SequenceOverflow)?;
    if highest >= next_sequence {
        return Err(Error::SelectiveAckAhead(highest));
    }
    Ok(())
}

fn transmit_slot_index(sequence: u64, capacity: usize) -> usize {
    (sequence % capacity as u64) as usize
}

/// Coalesces sink-commit/reorder ACK changes and schedules best-effort
/// ACK-only frames without creating ACK feedback loops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckScheduler {
    current: AckState,
    last_advertised: AckState,
    deadline_micros: Option<u64>,
}

impl AckScheduler {
    pub fn new(initial: AckState) -> Self {
        Self {
            current: initial,
            last_advertised: initial,
            deadline_micros: None,
        }
    }

    pub fn update(&mut self, current: AckState, now_micros: u64) {
        if current == self.current {
            return;
        }
        self.current = current;
        let delayed = now_micros.saturating_add(DELAYED_ACK_MICROS);
        self.deadline_micros = Some(
            self.deadline_micros
                .map_or(delayed, |existing| existing.min(delayed)),
        );
    }

    pub fn repeat_after_duplicate(&mut self, now_micros: u64) {
        self.deadline_micros = Some(
            self.deadline_micros
                .map_or(now_micros, |existing| existing.min(now_micros)),
        );
    }

    pub fn flush(&mut self, now_micros: u64) {
        self.repeat_after_duplicate(now_micros);
    }

    pub fn due(&self, now_micros: u64) -> Option<AckState> {
        self.deadline_micros
            .filter(|deadline| now_micros >= *deadline)
            .map(|_| self.current)
    }

    pub fn advertised(&mut self, acknowledgement: AckState) {
        self.last_advertised = acknowledgement;
        if acknowledgement == self.current {
            self.deadline_micros = None;
        }
    }

    pub fn piggyback(&mut self) -> AckState {
        let current = self.current;
        self.advertised(current);
        current
    }

    pub fn current(&self) -> AckState {
        self.current
    }

    pub fn deadline_micros(&self) -> Option<u64> {
        self.deadline_micros
    }

    pub fn last_advertised(&self) -> AckState {
        self.last_advertised
    }
}

fn slot_index(sequence: u64) -> usize {
    (sequence % REORDER_SLOTS as u64) as usize
}

fn payload_range(index: usize, length: usize) -> std::ops::Range<usize> {
    let start = index * MAX_PAYLOAD_LEN;
    start..start + length
}

#[cfg(test)]
mod tests {
    use super::{
        decode, encode_ack_only, encode_data, retransmission_delay_micros, AckApply, AckScheduler,
        AckState, Data, Direction, Error, Frame, Offer, ReceiveWindow, TransmitWindow, HEADER_LEN,
        MAX_BACKOFF_MICROS, MAX_PAYLOAD_LEN, MAX_TRANSMITS_PER_WAKE, MAX_WIRE_LEN, MIN_RTO_MICROS,
        REORDER_SLOTS,
    };
    use crate::wire::{Kind, Resize};
    use crate::Limits;

    const ACK: AckState = AckState {
        epoch: 7,
        base: 11,
        bits: 0x55aa,
    };

    fn payload(kind: Kind) -> Vec<u8> {
        match kind {
            Kind::Input | Kind::Output => b"terminal".to_vec(),
            Kind::Resize => Resize {
                rows: 24,
                columns: 80,
                pixel_width: 640,
                pixel_height: 480,
            }
            .encode()
            .to_vec(),
            Kind::Signal => vec![2],
            Kind::InputClose => Vec::new(),
            Kind::Ownership => vec![1],
            Kind::Exit => 43_i32.to_be_bytes().to_vec(),
            _ => unreachable!("test covers only datagram data kinds"),
        }
    }

    #[test]
    fn every_data_kind_has_one_canonical_round_trip() {
        let cases = [
            (Direction::ClientToGateway, Kind::Input),
            (Direction::ClientToGateway, Kind::Resize),
            (Direction::ClientToGateway, Kind::Signal),
            (Direction::ClientToGateway, Kind::InputClose),
            (Direction::GatewayToClient, Kind::Output),
            (Direction::GatewayToClient, Kind::Ownership),
            (Direction::GatewayToClient, Kind::Exit),
        ];
        for (direction, kind) in cases {
            let payload = payload(kind);
            let data = Data {
                direction,
                kind,
                epoch: 3,
                sequence: 9,
                acknowledgement: ACK,
                payload: &payload,
            };
            let mut wire = [0_u8; MAX_WIRE_LEN];
            let used = encode_data(data, &mut wire).expect("valid data frame encodes");
            assert_eq!(
                decode(direction, &wire[..used], &Limits::default()),
                Ok(Frame::Data(data))
            );
        }
    }

    #[test]
    fn ack_only_and_every_truncation_are_canonical() {
        let mut wire = [0_u8; MAX_WIRE_LEN];
        let used = encode_ack_only(Direction::ClientToGateway, ACK, &mut wire)
            .expect("valid acknowledgement frame encodes");
        assert_eq!(used, HEADER_LEN);
        assert_eq!(
            decode(
                Direction::ClientToGateway,
                &wire[..used],
                &Limits::default()
            ),
            Ok(Frame::AckOnly {
                direction: Direction::ClientToGateway,
                acknowledgement: ACK,
            })
        );
        for end in 0..HEADER_LEN {
            assert!(matches!(
                decode(Direction::ClientToGateway, &wire[..end], &Limits::default()),
                Err(Error::Incomplete { .. })
            ));
        }
        wire[HEADER_LEN] = 1;
        assert!(matches!(
            decode(
                Direction::ClientToGateway,
                &wire[..HEADER_LEN + 1],
                &Limits::default()
            ),
            Err(Error::Length { .. })
        ));
    }

    #[test]
    fn malformed_flags_direction_kind_and_lengths_fail_closed() {
        let mut wire = [0_u8; MAX_WIRE_LEN];
        let used = encode_data(
            Data {
                direction: Direction::ClientToGateway,
                kind: Kind::Input,
                epoch: 1,
                sequence: 2,
                acknowledgement: ACK,
                payload: b"x",
            },
            &mut wire,
        )
        .expect("valid input frame encodes");
        assert!(matches!(
            decode(
                Direction::GatewayToClient,
                &wire[..used],
                &Limits::default()
            ),
            Err(Error::Direction(1))
        ));
        wire[3] = 0x80;
        assert!(matches!(
            decode(
                Direction::ClientToGateway,
                &wire[..used],
                &Limits::default()
            ),
            Err(Error::Flags(0x80))
        ));
        wire[3] = 0;
        wire[2] = Kind::Output as u8;
        assert!(matches!(
            decode(
                Direction::ClientToGateway,
                &wire[..used],
                &Limits::default()
            ),
            Err(Error::KindForDirection { .. })
        ));
        wire[2] = Kind::Input as u8;
        wire[45] = 2;
        assert!(matches!(
            decode(
                Direction::ClientToGateway,
                &wire[..used],
                &Limits::default()
            ),
            Err(Error::Length { .. })
        ));
        assert!(matches!(
            encode_data(
                Data {
                    direction: Direction::ClientToGateway,
                    kind: Kind::Input,
                    epoch: 0,
                    sequence: 0,
                    acknowledgement: ACK,
                    payload: &[0; MAX_PAYLOAD_LEN + 1],
                },
                &mut wire,
            ),
            Err(Error::PayloadBounds { .. })
        ));
    }

    #[test]
    fn reorder_window_commits_only_contiguous_sink_acceptance() {
        let mut window = ReceiveWindow::new(4, 10).expect("bounded receive window allocates");
        for sequence in [12, 11, 10] {
            let byte = [sequence as u8];
            let offered = window
                .offer(Data {
                    direction: Direction::ClientToGateway,
                    kind: Kind::Input,
                    epoch: 4,
                    sequence,
                    acknowledgement: ACK,
                    payload: &byte,
                })
                .expect("valid record enters receive window");
            assert_eq!(
                offered,
                if sequence == 10 {
                    Offer::Ready
                } else {
                    Offer::FutureStored
                }
            );
        }
        assert_eq!(window.acknowledgement().base, 10);
        assert_eq!(window.acknowledgement().bits & 0b111, 0b111);
        for sequence in 10..13 {
            let ready = window.ready().expect("contiguous record ready");
            assert_eq!(ready.sequence, sequence);
            assert_eq!(ready.payload, &[sequence as u8]);
            let acknowledgement = window
                .commit_ready(sequence)
                .expect("ready sink commit advances acknowledgement");
            assert_eq!(acknowledgement.base, sequence + 1);
        }
        assert!(window.ready().is_none());
    }

    #[test]
    fn duplicate_epoch_and_window_edges_are_nonmutating() {
        let mut window = ReceiveWindow::new(5, 20).expect("bounded receive window allocates");
        let offer = |epoch, sequence, byte: &'static [u8]| Data {
            direction: Direction::GatewayToClient,
            kind: Kind::Output,
            epoch,
            sequence,
            acknowledgement: ACK,
            payload: byte,
        };
        assert_eq!(
            window
                .offer(offer(4, 20, b"a"))
                .expect("stale epoch is a classified no-op"),
            Offer::StaleEpoch
        );
        assert_eq!(
            window
                .offer(offer(6, 20, b"a"))
                .expect("future epoch is a classified no-op"),
            Offer::FutureEpoch
        );
        assert_eq!(
            window
                .offer(offer(5, 19, b"a"))
                .expect("old sequence is a classified duplicate"),
            Offer::Duplicate
        );
        assert_eq!(
            window
                .offer(offer(5, 20 + REORDER_SLOTS as u64, b"a"))
                .expect("outside-window sequence is a classified no-op"),
            Offer::OutsideWindow
        );
        assert_eq!(window.acknowledgement().bits, 0);

        assert_eq!(
            window
                .offer(offer(5, 20, b"a"))
                .expect("next sequence becomes ready"),
            Offer::Ready
        );
        assert_eq!(
            window
                .offer(offer(5, 20, b"a"))
                .expect("identical sequence is a duplicate"),
            Offer::Duplicate
        );
        assert!(matches!(
            window.offer(offer(5, 20, b"b")),
            Err(Error::ConflictingDuplicate(20))
        ));
        assert!(matches!(
            window.commit_ready(21),
            Err(Error::CommitSequence { .. })
        ));
        assert_eq!(
            window
                .ready()
                .expect("failed commit preserves record")
                .payload,
            b"a"
        );
    }

    #[test]
    fn reset_discards_selective_state_and_changes_epoch() {
        let mut window = ReceiveWindow::new(1, 0).expect("bounded receive window allocates");
        window
            .offer(Data {
                direction: Direction::GatewayToClient,
                kind: Kind::Output,
                epoch: 1,
                sequence: 2,
                acknowledgement: ACK,
                payload: b"secret",
            })
            .expect("valid future record enters receive window");
        assert_ne!(window.acknowledgement().bits, 0);
        window.reset(2, 7);
        assert_eq!(
            window.acknowledgement(),
            AckState {
                epoch: 2,
                base: 7,
                bits: 0
            }
        );
        assert!(window.ready().is_none());
    }

    #[test]
    fn acknowledgement_at_sequence_limit_never_overflows() {
        let mut window = ReceiveWindow::new(9, u64::MAX).expect("bounded receive window allocates");
        assert_eq!(
            window.acknowledgement(),
            AckState {
                epoch: 9,
                base: u64::MAX,
                bits: 0,
            }
        );
        assert!(matches!(
            window.offer(Data {
                direction: Direction::GatewayToClient,
                kind: Kind::Output,
                epoch: 9,
                sequence: u64::MAX,
                acknowledgement: ACK,
                payload: b"x",
            }),
            Err(Error::SequenceOverflow)
        ));
    }

    #[test]
    fn cumulative_ack_retires_while_selective_ack_only_suppresses() {
        let mut sender =
            TransmitWindow::new(3, 10, 16, 0x1234).expect("bounded transmit window allocates");
        for sequence in 10..13 {
            sender.track(sequence).expect("contiguous record tracks");
        }
        assert_eq!(sender.due(0, 100).as_slice(), &[10, 11, 12]);
        for sequence in 10..13 {
            sender
                .mark_sent(sequence, 0)
                .expect("tracked record records send time");
        }

        assert_eq!(
            sender
                .apply_acknowledgement(
                    AckState {
                        epoch: 3,
                        base: 10,
                        bits: 0b010,
                    },
                    1_999_000
                )
                .expect("valid selective acknowledgement applies"),
            AckApply::Applied { retired: 0 }
        );
        assert_eq!(sender.first_unacknowledged(), 10);
        assert_eq!(sender.len(), 3);
        assert_eq!(sender.due(2_000_000, 100).as_slice(), &[10, 12]);

        assert_eq!(
            sender
                .apply_acknowledgement(
                    AckState {
                        epoch: 3,
                        base: 12,
                        bits: 0,
                    },
                    2_000_000
                )
                .expect("cumulative acknowledgement retires prefix"),
            AckApply::Applied { retired: 2 }
        );
        assert_eq!(sender.first_unacknowledged(), 12);
        assert_eq!(sender.len(), 1);
    }

    #[test]
    fn reordered_and_impossible_acknowledgements_fail_safely() {
        let mut sender =
            TransmitWindow::new(7, 40, 8, 9).expect("bounded transmit window allocates");
        sender.track(40).expect("first record tracks");
        sender.track(41).expect("second record tracks");
        assert_eq!(
            sender
                .apply_acknowledgement(
                    AckState {
                        epoch: 6,
                        base: 99,
                        bits: u64::MAX,
                    },
                    0
                )
                .expect("stale epoch is ignored before peer-controlled positions"),
            AckApply::StaleEpoch
        );
        assert_eq!(
            sender
                .apply_acknowledgement(
                    AckState {
                        epoch: 8,
                        base: 0,
                        bits: 0,
                    },
                    0
                )
                .expect("future epoch is classified"),
            AckApply::FutureEpoch
        );
        sender
            .apply_acknowledgement(
                AckState {
                    epoch: 7,
                    base: 41,
                    bits: 0,
                },
                0,
            )
            .expect("valid cumulative acknowledgement applies");
        assert_eq!(
            sender
                .apply_acknowledgement(
                    AckState {
                        epoch: 7,
                        base: 40,
                        bits: 0,
                    },
                    0
                )
                .expect("reordered older acknowledgement is ignored"),
            AckApply::StaleCumulative
        );
        assert!(matches!(
            sender.apply_acknowledgement(
                AckState {
                    epoch: 7,
                    base: 43,
                    bits: 0,
                },
                0
            ),
            Err(Error::AckAhead { .. })
        ));
        assert!(matches!(
            sender.apply_acknowledgement(
                AckState {
                    epoch: 7,
                    base: 41,
                    bits: 0b10,
                },
                0
            ),
            Err(Error::SelectiveAckAhead(42))
        ));
        assert_eq!(sender.first_unacknowledged(), 41);
        assert_eq!(sender.len(), 1);
    }

    #[test]
    fn retry_work_is_bounded_and_reconnect_forgets_same_link_sack() {
        let mut sender =
            TransmitWindow::new(2, 0, 24, 88).expect("bounded transmit window allocates");
        for sequence in 0..20 {
            sender.track(sequence).expect("contiguous record tracks");
        }
        let first = sender.due(0, 100);
        assert_eq!(first.as_slice(), &[0, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(first.as_slice().len(), MAX_TRANSMITS_PER_WAKE);
        for &sequence in first.as_slice() {
            sender
                .mark_sent(sequence, 0)
                .expect("offered record records send time");
        }
        let second = sender.due(0, 100);
        assert_eq!(second.as_slice(), &[8, 9, 10, 11, 12, 13, 14, 15]);

        sender
            .apply_acknowledgement(
                AckState {
                    epoch: 2,
                    base: 0,
                    bits: 1,
                },
                0,
            )
            .expect("same-link selective acknowledgement applies");
        sender.restart_link();
        assert!(sender.due(0, 100).as_slice().contains(&0));
    }

    #[test]
    fn retransmission_backoff_is_deterministic_and_bounded() {
        let first = retransmission_delay_micros(1, 1, 55, 9);
        assert!((MIN_RTO_MICROS..=2_200).contains(&first));
        assert_eq!(first, retransmission_delay_micros(1, 1, 55, 9));
        let saturated = retransmission_delay_micros(u64::MAX, u16::MAX, 55, 9);
        assert!((900_000..=MAX_BACKOFF_MICROS).contains(&saturated));
    }

    #[test]
    fn delayed_ack_coalesces_piggybacks_and_repeats_after_duplicate() {
        let initial = AckState {
            epoch: 1,
            base: 0,
            bits: 0,
        };
        let committed = AckState {
            epoch: 1,
            base: 1,
            bits: 0,
        };
        let mut scheduler = AckScheduler::new(initial);
        scheduler.update(committed, 10_000);
        assert_eq!(scheduler.due(10_999), None);
        assert_eq!(scheduler.due(11_000), Some(committed));
        assert_eq!(scheduler.piggyback(), committed);
        assert_eq!(scheduler.due(20_000), None);
        assert_eq!(scheduler.last_advertised(), committed);

        scheduler.repeat_after_duplicate(20_000);
        assert_eq!(scheduler.due(20_000), Some(committed));
        scheduler.advertised(committed);
        assert_eq!(scheduler.deadline_micros(), None);
    }

    #[test]
    fn lost_final_ack_after_sack_cannot_permanently_suppress_reprobe() {
        let mut sender =
            TransmitWindow::new(1, 0, 4, 17).expect("bounded transmit window allocates");
        let mut receiver = ReceiveWindow::new(1, 0).expect("bounded receive window allocates");
        sender.track(0).expect("first record tracks");
        sender
            .mark_sent(0, 0)
            .expect("initial offer records send time");

        let data = Data {
            direction: Direction::ClientToGateway,
            kind: Kind::Input,
            epoch: 1,
            sequence: 0,
            acknowledgement: ACK,
            payload: b"x",
        };
        assert_eq!(
            receiver.offer(data).expect("record enters receive window"),
            Offer::Ready
        );
        let selective = receiver.acknowledgement();
        assert_eq!(selective.base, 0);
        assert_eq!(selective.bits, 1);
        sender
            .apply_acknowledgement(selective, 0)
            .expect("selective acknowledgement applies");
        receiver
            .commit_ready(0)
            .expect("sink commit advances cumulative acknowledgement");
        // The base=1 ACK is intentionally lost. Repeated copies of the old
        // base=0 SACK cannot renew its one-RTO suppression lease.
        sender
            .apply_acknowledgement(selective, 1_000)
            .expect("same-base selective acknowledgement is harmless");

        let first_reprobe = sender.due(10_000, 100);
        assert_eq!(first_reprobe.as_slice(), &[0]);
        sender
            .mark_sent(0, 10_000)
            .expect("first reprobe records send time");
        assert_eq!(sender.due(2_000_000, 100).as_slice(), &[0]);

        assert_eq!(
            receiver.offer(data).expect("reprobe is a duplicate"),
            Offer::Duplicate
        );
        assert_eq!(
            sender
                .apply_acknowledgement(receiver.acknowledgement(), 2_000_000)
                .expect("repeated cumulative acknowledgement applies"),
            AckApply::Applied { retired: 1 }
        );
        assert!(sender.is_empty());
    }

    #[test]
    fn finite_data_and_ack_loss_converges_exactly_once() {
        const RECORDS: u64 = 12;
        let mut sender =
            TransmitWindow::new(1, 0, 16, 0xfeed).expect("bounded transmit window allocates");
        let mut receiver = ReceiveWindow::new(1, 0).expect("bounded receive window allocates");
        for sequence in 0..RECORDS {
            sender.track(sequence).expect("contiguous record tracks");
        }

        let mut now_micros = 0;
        let mut first_data_drop = [false; RECORDS as usize];
        let mut acknowledgements_to_drop = 5;
        let mut delivered = Vec::new();

        for _round in 0..32 {
            let due = sender.due(now_micros, 100);
            let mut sent = Vec::new();
            for &sequence in due.as_slice() {
                sender
                    .mark_sent(sequence, now_micros)
                    .expect("due record records send time");
                sent.push(sequence);
            }

            let mut acknowledgements = Vec::new();
            for sequence in sent {
                let should_drop =
                    matches!(sequence, 1 | 4 | 7) && !first_data_drop[sequence as usize];
                if should_drop {
                    first_data_drop[sequence as usize] = true;
                    continue;
                }
                let payload = [sequence as u8];
                let offer = receiver
                    .offer(Data {
                        direction: Direction::ClientToGateway,
                        kind: Kind::Input,
                        epoch: 1,
                        sequence,
                        acknowledgement: AckState {
                            epoch: 0,
                            base: 0,
                            bits: 0,
                        },
                        payload: &payload,
                    })
                    .expect("model record is valid");
                if offer == Offer::Duplicate {
                    acknowledgements.push(receiver.acknowledgement());
                    continue;
                }
                while let Some(ready) = receiver.ready() {
                    delivered.push(ready.sequence);
                    receiver
                        .commit_ready(ready.sequence)
                        .expect("model sink commit advances once");
                }
                acknowledgements.push(receiver.acknowledgement());
            }

            for acknowledgement in acknowledgements {
                if acknowledgements_to_drop > 0 {
                    acknowledgements_to_drop -= 1;
                    continue;
                }
                sender
                    .apply_acknowledgement(acknowledgement, now_micros)
                    .expect("receiver-generated acknowledgement is valid");
            }
            if sender.is_empty() {
                break;
            }
            now_micros = now_micros.saturating_add(MAX_BACKOFF_MICROS);
        }

        assert!(
            sender.is_empty(),
            "finite loss must eventually drain replay"
        );
        assert_eq!(delivered, (0..RECORDS).collect::<Vec<_>>());
    }
}
