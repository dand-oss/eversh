//! Bounded association state for reconnecting an opaque SSH byte stream.
//!
//! StableSSH-style resume needs more than a retry loop: each direction retains
//! frames until the peer acknowledges delivery, then replays them on a fresh
//! transport association. This module owns that boundary without terminal
//! interpretation or an unbounded packet-count queue.

use crate::error::Error;
use std::collections::VecDeque;
use std::io::Write;
use zeroize::Zeroizing;

pub const RESUME_VERSION: u8 = 1;
pub const RESUME_HEADER_LEN: usize = 14;
pub const RESUME_MAX_DATA_LEN: usize = u32::MAX as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameKind {
    Data = 1,
    Fin = 2,
    Ack = 3,
}

impl FrameKind {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Data),
            2 => Some(Self::Fin),
            3 => Some(Self::Ack),
            _ => None,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum ResumeOperation {
    Data(Zeroizing<Vec<u8>>),
    Fin,
    Ack,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ResumeFrame {
    sequence: u64,
    operation: ResumeOperation,
}

impl ResumeFrame {
    pub fn data(sequence: u64, bytes: Vec<u8>) -> Result<Self, Error> {
        if sequence == 0 || bytes.is_empty() || bytes.len() > RESUME_MAX_DATA_LEN {
            return Err(Error::ResumeFrameMalformed);
        }
        Ok(Self {
            sequence,
            operation: ResumeOperation::Data(Zeroizing::new(bytes)),
        })
    }

    pub fn fin(sequence: u64) -> Result<Self, Error> {
        if sequence == 0 {
            return Err(Error::ResumeFrameMalformed);
        }
        Ok(Self {
            sequence,
            operation: ResumeOperation::Fin,
        })
    }

    pub fn ack(sequence: u64) -> Result<Self, Error> {
        Ok(Self {
            sequence,
            operation: ResumeOperation::Ack,
        })
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn wire_len(&self) -> usize {
        RESUME_HEADER_LEN + self.data_len()
    }

    pub fn data_len(&self) -> usize {
        match &self.operation {
            ResumeOperation::Data(bytes) => bytes.len(),
            ResumeOperation::Fin | ResumeOperation::Ack => 0,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut wire = Vec::with_capacity(self.wire_len());
        let _ = self.encode_into(&mut wire);
        wire
    }

    pub fn encode_into<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        let payload_len = u32::try_from(self.data_len()).unwrap_or(u32::MAX);
        let kind = match self.operation {
            ResumeOperation::Data(_) => FrameKind::Data,
            ResumeOperation::Fin => FrameKind::Fin,
            ResumeOperation::Ack => FrameKind::Ack,
        };
        let mut header = [0; RESUME_HEADER_LEN];
        header[0] = RESUME_VERSION;
        header[1] = kind as u8;
        header[2..10].copy_from_slice(&self.sequence.to_be_bytes());
        header[10..].copy_from_slice(&payload_len.to_be_bytes());
        writer.write_all(&header)?;
        if let ResumeOperation::Data(bytes) = &self.operation {
            writer.write_all(bytes)?;
        }
        Ok(())
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < RESUME_HEADER_LEN || bytes[0] != RESUME_VERSION {
            return Err(Error::ResumeFrameMalformed);
        }
        let kind = FrameKind::from_u8(bytes[1]).ok_or(Error::ResumeFrameMalformed)?;
        let sequence = u64::from_be_bytes(
            bytes[2..10]
                .try_into()
                .map_err(|_| Error::ResumeFrameMalformed)?,
        );
        let payload_len = u32::from_be_bytes(
            bytes[10..14]
                .try_into()
                .map_err(|_| Error::ResumeFrameMalformed)?,
        ) as usize;
        let payload = &bytes[RESUME_HEADER_LEN..];
        if payload.len() != payload_len {
            return Err(Error::ResumeFrameMalformed);
        }
        match kind {
            FrameKind::Data => Self::data(sequence, payload.to_vec()),
            FrameKind::Fin if payload.is_empty() => Self::fin(sequence),
            FrameKind::Ack if payload.is_empty() => Self::ack(sequence),
            _ => Err(Error::ResumeFrameMalformed),
        }
    }
}

impl std::fmt::Debug for ResumeFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let operation = match &self.operation {
            ResumeOperation::Data(bytes) => format!("Data({} bytes, <REDACTED>)", bytes.len()),
            ResumeOperation::Fin => "Fin".to_owned(),
            ResumeOperation::Ack => "Ack".to_owned(),
        };
        f.debug_struct("ResumeFrame")
            .field("sequence", &self.sequence)
            .field("operation", &operation)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResumeQueueLimits {
    max_wire_bytes: usize,
    max_pending_frames: usize,
}

impl ResumeQueueLimits {
    pub fn new(max_wire_bytes: usize, max_pending_frames: usize) -> Result<Self, Error> {
        if max_wire_bytes < RESUME_HEADER_LEN || max_pending_frames == 0 {
            return Err(Error::ResumeLimitInvalid);
        }
        Ok(Self {
            max_wire_bytes,
            max_pending_frames,
        })
    }

    pub fn max_wire_bytes(&self) -> usize {
        self.max_wire_bytes
    }

    pub fn max_pending_frames(&self) -> usize {
        self.max_pending_frames
    }
}

#[derive(Debug)]
pub struct ReplayQueue {
    limits: ResumeQueueLimits,
    frames: VecDeque<ResumeFrame>,
    queued_wire_bytes: usize,
    last_assigned: u64,
    last_acked: u64,
}

impl ReplayQueue {
    pub fn new(limits: ResumeQueueLimits) -> Self {
        Self {
            limits,
            frames: VecDeque::new(),
            queued_wire_bytes: 0,
            last_assigned: 0,
            last_acked: 0,
        }
    }

    pub fn push_data(&mut self, bytes: Vec<u8>) -> Result<u64, Error> {
        let frame = self.make_frame(ResumeOperation::Data(Zeroizing::new(bytes)))?;
        let sequence = frame.sequence();
        self.insert(frame);
        Ok(sequence)
    }

    pub fn push_fin(&mut self) -> Result<u64, Error> {
        let frame = self.make_frame(ResumeOperation::Fin)?;
        let sequence = frame.sequence();
        self.insert(frame);
        Ok(sequence)
    }

    pub fn queued_wire_bytes(&self) -> usize {
        self.queued_wire_bytes
    }

    pub fn front_sequence(&self) -> Option<u64> {
        self.frames.front().map(ResumeFrame::sequence)
    }

    pub fn pending_frames(&self) -> usize {
        self.frames.len()
    }

    pub fn encode_pending<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut count = 0;
        for frame in &self.frames {
            frame.encode_into(writer)?;
            count += 1;
        }
        Ok(count)
    }

    pub fn ack_through(&mut self, sequence: u64) -> Result<(), Error> {
        if sequence == 0 {
            return Ok(());
        }
        if sequence < self.last_acked {
            return Err(Error::ResumeSequenceInvalid);
        }
        if sequence == self.last_acked {
            return Ok(());
        }
        if sequence > self.last_assigned
            || (!self.frames.is_empty()
                && !self.frames.iter().any(|frame| frame.sequence() == sequence))
        {
            return Err(Error::ResumeSequenceInvalid);
        }

        while self
            .front_sequence()
            .is_some_and(|pending| pending <= sequence)
        {
            let Some(frame) = self.frames.pop_front() else {
                break;
            };
            self.queued_wire_bytes = self.queued_wire_bytes.saturating_sub(frame.wire_len());
            self.last_acked = frame.sequence();
        }
        if self.frames.is_empty() {
            self.last_acked = self.last_assigned;
        }
        Ok(())
    }

    fn make_frame(&self, operation: ResumeOperation) -> Result<ResumeFrame, Error> {
        let sequence = self
            .last_assigned
            .checked_add(1)
            .ok_or(Error::ResumeSequenceOverflow)?;
        let frame = ResumeFrame {
            sequence,
            operation,
        };
        if frame.wire_len() > self.limits.max_wire_bytes
            || self.frames.len() >= self.limits.max_pending_frames
            || self.queued_wire_bytes > self.limits.max_wire_bytes - frame.wire_len()
        {
            return Err(Error::ResumeQueueFull);
        }
        Ok(frame)
    }

    fn insert(&mut self, frame: ResumeFrame) {
        self.queued_wire_bytes += frame.wire_len();
        self.last_assigned = frame.sequence();
        self.frames.push_back(frame);
    }
}

#[derive(Debug, Default)]
pub struct ResumeReceiver {
    last_delivered: u64,
    fin_sequence: Option<u64>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ResumeDelivery {
    Data(Zeroizing<Vec<u8>>),
    Fin,
    Duplicate,
}

impl ResumeReceiver {
    pub fn accept(&mut self, frame: ResumeFrame) -> Result<ResumeDelivery, Error> {
        if frame.sequence() == 0 {
            return Err(Error::ResumeFrameMalformed);
        }
        if let Some(fin) = self.fin_sequence {
            if frame.sequence() > fin {
                return Err(Error::ResumeOperationInvalid);
            }
            return Ok(ResumeDelivery::Duplicate);
        }
        if matches!(frame.operation, ResumeOperation::Ack) {
            return Err(Error::ResumeOperationInvalid);
        }
        if frame.sequence() <= self.last_delivered {
            return Ok(ResumeDelivery::Duplicate);
        }
        let next = self
            .last_delivered
            .checked_add(1)
            .ok_or(Error::ResumeSequenceOverflow)?;
        if frame.sequence() != next {
            return Err(Error::ResumeSequenceInvalid);
        }

        let sequence = frame.sequence();
        match frame.operation {
            ResumeOperation::Data(bytes) => {
                if bytes.is_empty() {
                    return Err(Error::ResumeFrameMalformed);
                }
                self.last_delivered = sequence;
                Ok(ResumeDelivery::Data(bytes))
            }
            ResumeOperation::Fin => {
                self.last_delivered = frame.sequence();
                self.fin_sequence = Some(frame.sequence());
                Ok(ResumeDelivery::Fin)
            }
            ResumeOperation::Ack => Err(Error::ResumeOperationInvalid),
        }
    }

    pub fn acknowledgement(&self) -> Result<ResumeFrame, Error> {
        ResumeFrame::ack(self.last_delivered)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io;

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("resume writer failure"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn decode_stream(bytes: &[u8]) -> Vec<ResumeFrame> {
        let mut frames = Vec::new();
        let mut offset = 0;
        while offset < bytes.len() {
            let header = &bytes[offset..offset + RESUME_HEADER_LEN];
            let payload_len = u32::from_be_bytes(header[10..14].try_into().unwrap()) as usize;
            let end = offset + RESUME_HEADER_LEN + payload_len;
            frames.push(ResumeFrame::decode_exact(&bytes[offset..end]).unwrap());
            offset = end;
        }
        frames
    }

    #[test]
    fn frames_are_exact_and_reject_noncanonical_shapes() {
        let data = ResumeFrame::data(7, b"opaque-ssh-bytes".to_vec()).unwrap();
        let wire = data.encode();
        assert_eq!(wire.len(), data.wire_len());
        assert_eq!(ResumeFrame::decode_exact(&wire).unwrap(), data);
        assert!(!format!("{data:?}").contains("opaque-ssh-bytes"));

        let fin = ResumeFrame::fin(8).unwrap();
        let ack = ResumeFrame::ack(9).unwrap();
        assert_eq!(ResumeFrame::decode_exact(&fin.encode()).unwrap(), fin);
        assert_eq!(ResumeFrame::decode_exact(&ack.encode()).unwrap(), ack);

        for cut in 0..wire.len() {
            assert!(ResumeFrame::decode_exact(&wire[..cut]).is_err());
        }
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(ResumeFrame::decode_exact(&trailing).is_err());
        let mut bad_version = wire.clone();
        bad_version[0] ^= 1;
        assert!(ResumeFrame::decode_exact(&bad_version).is_err());
        let mut bad_kind = wire.clone();
        bad_kind[1] = 0;
        assert!(ResumeFrame::decode_exact(&bad_kind).is_err());
        assert!(ResumeFrame::data(0, b"data".to_vec()).is_err());
        assert!(ResumeFrame::data(1, Vec::new()).is_err());
    }

    #[test]
    fn queue_bounds_are_byte_and_frame_based() {
        let limits = ResumeQueueLimits::new(RESUME_HEADER_LEN * 2 + 5, 16).unwrap();
        let mut queue = ReplayQueue::new(limits);
        assert_eq!(queue.push_data(b"abc".to_vec()).unwrap(), 1);
        assert_eq!(queue.push_data(b"de".to_vec()).unwrap(), 2);
        assert_eq!(queue.queued_wire_bytes(), RESUME_HEADER_LEN * 2 + 5);
        assert!(queue.push_data(vec![0]).is_err());
        assert_eq!(queue.front_sequence(), Some(1));
        assert_eq!(queue.pending_frames(), 2);

        assert!(ResumeQueueLimits::new(RESUME_HEADER_LEN - 1, 1).is_err());
        assert!(ResumeQueueLimits::new(RESUME_HEADER_LEN, 0).is_err());

        let mut frame_limited = ReplayQueue::new(ResumeQueueLimits::new(1024, 1).unwrap());
        frame_limited.push_data(b"a".to_vec()).unwrap();
        assert!(frame_limited.push_data(vec![b'b']).is_err());
    }

    #[test]
    fn zero_ack_is_an_initial_noop_and_encode_failures_propagate() {
        let mut queue = ReplayQueue::new(ResumeQueueLimits::new(1024, 16).unwrap());
        assert!(queue.ack_through(0).is_ok());
        assert_eq!(
            ResumeReceiver::default()
                .acknowledgement()
                .unwrap()
                .sequence(),
            0
        );

        queue.push_data(b"pending".to_vec()).unwrap();
        let mut writer = FailingWriter;
        assert!(queue.encode_pending(&mut writer).is_err());
        let frame = ResumeFrame::data(1, b"pending".to_vec()).unwrap();
        assert!(frame.encode_into(&mut FailingWriter).is_err());
    }

    #[test]
    fn cumulative_acks_trim_only_complete_frames() {
        let mut queue = ReplayQueue::new(ResumeQueueLimits::new(1024, 16).unwrap());
        queue.push_data(b"one".to_vec()).unwrap();
        queue.push_data(b"two".to_vec()).unwrap();
        queue.push_fin().unwrap();

        queue.ack_through(1).unwrap();
        assert_eq!(queue.front_sequence(), Some(2));
        assert!(queue.ack_through(2).is_ok());
        assert_eq!(queue.front_sequence(), Some(3));
        assert!(queue.ack_through(4).is_err());
        queue.ack_through(3).unwrap();
        assert_eq!(queue.front_sequence(), None);
        assert_eq!(queue.queued_wire_bytes(), 0);
        assert!(queue.ack_through(3).is_ok());
    }

    #[test]
    fn reconnect_replays_unacknowledged_bytes_and_suppresses_duplicates() {
        let mut sender = ReplayQueue::new(ResumeQueueLimits::new(1024, 16).unwrap());
        let mut receiver = ResumeReceiver::default();
        sender.push_data(b"one".to_vec()).unwrap();
        sender.push_data(b"two".to_vec()).unwrap();
        sender.push_data(b"three".to_vec()).unwrap();
        sender.push_fin().unwrap();

        let mut first_connection = Vec::new();
        assert_eq!(sender.encode_pending(&mut first_connection).unwrap(), 4);
        let frames = decode_stream(&first_connection);
        assert_eq!(frames.len(), 4);
        assert_eq!(
            receiver.accept(frames[0].clone()).unwrap(),
            ResumeDelivery::Data(Zeroizing::new(b"one".to_vec()))
        );
        assert_eq!(receiver.acknowledgement().unwrap().sequence(), 1);

        let mut second_connection = Vec::new();
        assert_eq!(sender.encode_pending(&mut second_connection).unwrap(), 4);
        let replay = decode_stream(&second_connection);
        assert_eq!(
            receiver.accept(replay[0].clone()).unwrap(),
            ResumeDelivery::Duplicate
        );
        assert_eq!(
            receiver.accept(replay[1].clone()).unwrap(),
            ResumeDelivery::Data(Zeroizing::new(b"two".to_vec()))
        );
        assert_eq!(
            receiver.accept(replay[2].clone()).unwrap(),
            ResumeDelivery::Data(Zeroizing::new(b"three".to_vec()))
        );
        assert_eq!(
            receiver.accept(replay[3].clone()).unwrap(),
            ResumeDelivery::Fin
        );
        sender
            .ack_through(receiver.acknowledgement().unwrap().sequence())
            .unwrap();
        assert_eq!(sender.front_sequence(), None);
    }

    #[test]
    fn receiver_accepts_only_the_next_sequence_and_one_fin() {
        let mut receiver = ResumeReceiver::default();
        let ahead = ResumeFrame::data(2, b"ahead".to_vec()).unwrap();
        assert!(receiver.accept(ahead).is_err());

        let first = ResumeFrame::data(1, b"first".to_vec()).unwrap();
        assert!(receiver.accept(first.clone()).is_ok());
        assert_eq!(receiver.accept(first).unwrap(), ResumeDelivery::Duplicate);
        assert!(receiver.accept(ResumeFrame::ack(2).unwrap()).is_err());

        let fin = ResumeFrame::fin(2).unwrap();
        assert_eq!(receiver.accept(fin.clone()).unwrap(), ResumeDelivery::Fin);
        assert_eq!(receiver.accept(fin).unwrap(), ResumeDelivery::Duplicate);
        let after_fin = ResumeFrame::data(3, b"late".to_vec()).unwrap();
        assert!(receiver.accept(after_fin).is_err());
    }
}
