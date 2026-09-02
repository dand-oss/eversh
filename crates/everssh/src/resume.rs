//! Bounded association state for reconnecting an opaque SSH byte stream.
//!
//! StableSSH-style resume needs more than a retry loop: each direction retains
//! frames until the peer acknowledges delivery, then replays them on a fresh
//! transport association. This module owns that boundary without terminal
//! interpretation or an unbounded packet-count queue.

use crate::error::Error;
use std::collections::VecDeque;
use std::io::Write as StdWrite;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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

    pub fn is_ack(&self) -> bool {
        matches!(self.operation, ResumeOperation::Ack)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut wire = Vec::with_capacity(self.wire_len());
        let _ = self.encode_into(&mut wire);
        wire
    }

    pub fn encode_into<W: StdWrite>(&self, writer: &mut W) -> Result<(), Error> {
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

    pub async fn encode_into_async<W: AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
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
        writer.write_all(&header).await?;
        if let ResumeOperation::Data(bytes) = &self.operation {
            writer.write_all(bytes).await?;
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

    pub fn last_sequence(&self) -> Option<u64> {
        self.frames.back().map(ResumeFrame::sequence)
    }

    pub fn pending_frames(&self) -> usize {
        self.frames.len()
    }

    pub fn frames(&self) -> impl Iterator<Item = &ResumeFrame> {
        self.frames.iter()
    }

    pub fn can_accept(&self, data_len: usize) -> bool {
        let Some(frame_len) = RESUME_HEADER_LEN.checked_add(data_len) else {
            return false;
        };
        self.frames.len() < self.limits.max_pending_frames
            && frame_len <= self.limits.max_wire_bytes
            && self.queued_wire_bytes <= self.limits.max_wire_bytes - frame_len
    }

    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    pub fn encode_pending<W: StdWrite>(&self, writer: &mut W) -> Result<usize, Error> {
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

/// Incremental decoder for a bounded stream of resume frames.
#[derive(Debug)]
pub struct ResumeFrameDecoder {
    max_data_len: usize,
    header: [u8; RESUME_HEADER_LEN],
    header_filled: usize,
    body: Zeroizing<Vec<u8>>,
    body_filled: usize,
}

impl ResumeFrameDecoder {
    pub fn new(max_data_len: usize) -> Result<Self, Error> {
        if max_data_len == 0 || max_data_len > RESUME_MAX_DATA_LEN {
            return Err(Error::ResumeLimitInvalid);
        }
        Ok(Self {
            max_data_len,
            header: [0; RESUME_HEADER_LEN],
            header_filled: 0,
            body: Zeroizing::new(Vec::new()),
            body_filled: 0,
        })
    }

    pub fn decode_chunk(&mut self, input: &[u8]) -> Result<Vec<ResumeFrame>, Error> {
        let mut decoded = Vec::new();
        let mut offset = 0;
        while offset < input.len() {
            if self.header_filled < RESUME_HEADER_LEN {
                let count = (input.len() - offset).min(RESUME_HEADER_LEN - self.header_filled);
                self.header[self.header_filled..self.header_filled + count]
                    .copy_from_slice(&input[offset..offset + count]);
                self.header_filled += count;
                offset += count;
                if self.header_filled < RESUME_HEADER_LEN {
                    break;
                }
                self.start_body()?;
            }

            let needed = self.body.len() - self.body_filled;
            if needed == 0 {
                decoded.push(self.take_frame()?);
                continue;
            }

            let count = (input.len() - offset).min(needed);
            let destination = &mut self.body[self.body_filled..self.body_filled + count];
            destination.copy_from_slice(&input[offset..offset + count]);
            self.body_filled += count;
            offset += count;
            if self.body_filled == self.body.len() {
                decoded.push(self.take_frame()?);
            }
        }
        Ok(decoded)
    }

    fn start_body(&mut self) -> Result<(), Error> {
        if self.header[0] != RESUME_VERSION {
            return Err(Error::ResumeFrameMalformed);
        }
        let payload_len = u32::from_be_bytes(
            self.header[10..]
                .try_into()
                .map_err(|_| Error::ResumeFrameMalformed)?,
        ) as usize;
        if payload_len > self.max_data_len {
            return Err(Error::ResumeFrameMalformed);
        }
        let mut body = Vec::new();
        body.try_reserve_exact(payload_len)
            .map_err(|_| Error::BridgeAllocation)?;
        body.resize(payload_len, 0);
        self.body = Zeroizing::new(body);
        self.body_filled = 0;
        Ok(())
    }

    fn take_frame(&mut self) -> Result<ResumeFrame, Error> {
        let mut header = [0; RESUME_HEADER_LEN];
        header.copy_from_slice(&self.header);
        let body = std::mem::take(&mut self.body);
        self.header = [0; RESUME_HEADER_LEN];
        self.header_filled = 0;
        self.body_filled = 0;

        let mut wire = Zeroizing::new(Vec::with_capacity(RESUME_HEADER_LEN + body.len()));
        wire.extend_from_slice(&header);
        wire.extend_from_slice(body.as_slice());
        ResumeFrame::decode_exact(wire.as_slice())
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

    pub fn delivered_ack(&self) -> u64 {
        self.last_delivered
    }
}

pub const DEFAULT_RESUME_MAX_WIRE_BYTES: usize = 4 * 1024 * 1024;
pub const DEFAULT_RESUME_MAX_PENDING_FRAMES: usize = 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResumeAssociationConfig {
    max_wire_bytes: usize,
    max_pending_frames: usize,
    copy_buf: usize,
}

impl ResumeAssociationConfig {
    pub fn new(
        max_wire_bytes: usize,
        max_pending_frames: usize,
        copy_buf: usize,
    ) -> Result<Self, Error> {
        ResumeQueueLimits::new(max_wire_bytes, max_pending_frames)?;
        if copy_buf == 0 || copy_buf > RESUME_MAX_DATA_LEN || copy_buf > max_wire_bytes {
            return Err(Error::ResumeLimitInvalid);
        }
        Ok(Self {
            max_wire_bytes,
            max_pending_frames,
            copy_buf,
        })
    }
}

impl Default for ResumeAssociationConfig {
    fn default() -> Self {
        Self {
            max_wire_bytes: DEFAULT_RESUME_MAX_WIRE_BYTES,
            max_pending_frames: DEFAULT_RESUME_MAX_PENDING_FRAMES,
            copy_buf: 16 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssociationBoundary {
    Local,
    Remote,
    Protocol,
}

#[derive(Debug)]
pub struct AssociationRunError {
    pub boundary: AssociationBoundary,
    pub source: Error,
}

impl AssociationRunError {
    fn io(boundary: AssociationBoundary, source: std::io::Error) -> Self {
        Self {
            boundary,
            source: Error::Io(source),
        }
    }

    fn protocol(source: Error) -> Self {
        Self {
            boundary: AssociationBoundary::Protocol,
            source,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssociationCompletion {
    Clean,
}

/// Transport-independent replay state shared by the client and server actors.
pub struct AssociationCore {
    outbound: ReplayQueue,
    inbound: ResumeReceiver,
    config: ResumeAssociationConfig,
    local_eof: bool,
    remote_eof: bool,
}

impl AssociationCore {
    pub fn new(config: ResumeAssociationConfig) -> Result<Self, Error> {
        let limits = ResumeQueueLimits::new(config.max_wire_bytes, config.max_pending_frames)?;
        Ok(Self {
            outbound: ReplayQueue::new(limits),
            inbound: ResumeReceiver::default(),
            config,
            local_eof: false,
            remote_eof: false,
        })
    }

    pub fn apply_peer_ack(&mut self, sequence: u64) -> Result<(), Error> {
        self.outbound.ack_through(sequence)
    }

    pub fn outbound_is_empty(&self) -> bool {
        self.outbound.is_empty()
    }

    pub fn delivered_ack(&self) -> u64 {
        self.inbound.delivered_ack()
    }

    pub fn outbound_last_assigned(&self) -> u64 {
        self.outbound.last_assigned
    }

    pub async fn run_connection<LR, LW, RR, RW>(
        &mut self,
        local_read: &mut LR,
        local_write: &mut LW,
        remote_read: &mut RR,
        remote_write: &mut RW,
    ) -> Result<AssociationCompletion, AssociationRunError>
    where
        LR: AsyncRead + Unpin,
        LW: AsyncWrite + Unpin,
        RR: AsyncRead + Unpin,
        RW: AsyncWrite + Unpin,
    {
        let mut decoder =
            ResumeFrameDecoder::new(self.config.copy_buf).map_err(AssociationRunError::protocol)?;
        self.replay(remote_write).await?;

        let mut local_buffer = Vec::new();
        local_buffer
            .try_reserve_exact(self.config.copy_buf)
            .map_err(|_| AssociationRunError::protocol(Error::BridgeAllocation))?;
        local_buffer.resize(self.config.copy_buf, 0);
        let mut remote_buffer = [0_u8; 1024];

        loop {
            if self.clean() {
                return Ok(AssociationCompletion::Clean);
            }
            let accept_local = !self.local_eof && self.outbound.can_accept(self.config.copy_buf);
            tokio::select! {
                biased;
                result = local_read.read(&mut local_buffer), if accept_local => {
                    let count = match result {
                        Ok(0) => {
                            let fin = self
                                .outbound
                                .push_fin()
                                .map_err(AssociationRunError::protocol)?;
                            debug_assert_eq!(Some(fin), self.outbound.last_sequence());
                            self.local_eof = true;
                            self.write_outbound_tail(remote_write).await?;
                            continue;
                        }
                        Ok(count) => count,
                        Err(source) => {
                            return Err(AssociationRunError::io(
                                AssociationBoundary::Local,
                                source,
                            ));
                        }
                    };
                    self.outbound
                        .push_data(local_buffer[..count].to_vec())
                        .map_err(AssociationRunError::protocol)?;
                    self.write_outbound_tail(remote_write).await?;
                }
                result = remote_read.read(&mut remote_buffer) => {
                    let count = match result {
                        Ok(0) => {
                            if self.clean() {
                                return Ok(AssociationCompletion::Clean);
                            }
                            return Err(AssociationRunError::io(
                                AssociationBoundary::Remote,
                                std::io::Error::new(
                                    std::io::ErrorKind::UnexpectedEof,
                                    "remote stream ended before association FIN",
                                ),
                            ));
                        }
                        Ok(count) => count,
                        Err(source) => {
                            return Err(AssociationRunError::io(
                                AssociationBoundary::Remote,
                                source,
                            ));
                        }
                    };
                    let frames = decoder
                        .decode_chunk(&remote_buffer[..count])
                        .map_err(AssociationRunError::protocol)?;
                    for frame in frames {
                        self.accept_remote_frame(frame, local_write, remote_write)
                            .await?;
                    }
                }
            }
        }
    }

    async fn replay<RW: AsyncWrite + Unpin>(
        &mut self,
        remote_write: &mut RW,
    ) -> Result<(), AssociationRunError> {
        let frames: Vec<ResumeFrame> = self.outbound.frames().cloned().collect();
        for frame in frames {
            frame
                .encode_into_async(remote_write)
                .await
                .map_err(|source| AssociationRunError::io(AssociationBoundary::Remote, source))?;
        }
        remote_write
            .flush()
            .await
            .map_err(|source| AssociationRunError::io(AssociationBoundary::Remote, source))
    }

    async fn write_outbound_tail<RW: AsyncWrite + Unpin>(
        &mut self,
        remote_write: &mut RW,
    ) -> Result<(), AssociationRunError> {
        let Some(frame) = self.outbound.frames().last().cloned() else {
            return Ok(());
        };
        frame
            .encode_into_async(remote_write)
            .await
            .map_err(|source| AssociationRunError::io(AssociationBoundary::Remote, source))?;
        remote_write
            .flush()
            .await
            .map_err(|source| AssociationRunError::io(AssociationBoundary::Remote, source))
    }

    async fn accept_remote_frame<LW: AsyncWrite + Unpin, RW: AsyncWrite + Unpin>(
        &mut self,
        frame: ResumeFrame,
        local_write: &mut LW,
        remote_write: &mut RW,
    ) -> Result<(), AssociationRunError> {
        if frame.is_ack() {
            let acknowledgement = frame.sequence();
            return self
                .apply_peer_ack(acknowledgement)
                .map_err(AssociationRunError::protocol);
        }
        match self
            .inbound
            .accept(frame)
            .map_err(AssociationRunError::protocol)?
        {
            ResumeDelivery::Data(bytes) => {
                local_write
                    .write_all(bytes.as_slice())
                    .await
                    .map_err(|source| {
                        AssociationRunError::io(AssociationBoundary::Local, source)
                    })?;
                local_write.flush().await.map_err(|source| {
                    AssociationRunError::io(AssociationBoundary::Local, source)
                })?;
            }
            ResumeDelivery::Fin => {
                local_write.flush().await.map_err(|source| {
                    AssociationRunError::io(AssociationBoundary::Local, source)
                })?;
                local_write.shutdown().await.map_err(|source| {
                    AssociationRunError::io(AssociationBoundary::Local, source)
                })?;
                self.remote_eof = true;
            }
            ResumeDelivery::Duplicate => {}
        }

        let acknowledgement = self
            .inbound
            .acknowledgement()
            .map_err(AssociationRunError::protocol)?;
        acknowledgement
            .encode_into_async(remote_write)
            .await
            .map_err(|source| AssociationRunError::io(AssociationBoundary::Remote, source))?;
        remote_write
            .flush()
            .await
            .map_err(|source| AssociationRunError::io(AssociationBoundary::Remote, source))?;

        Ok(())
    }

    fn clean(&self) -> bool {
        self.local_eof && self.remote_eof && self.outbound.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io;

    struct FailingWriter;

    impl StdWrite for FailingWriter {
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

    #[tokio::test]
    async fn association_core_transfers_both_directions_and_finishes_cleanly() {
        let config = ResumeAssociationConfig::new(256, 16, 64).unwrap();
        let mut client = AssociationCore::new(config).unwrap();
        let mut server = AssociationCore::new(config).unwrap();

        let (client_local, mut client_peer) = tokio::io::duplex(128);
        let (server_target, mut target_peer) = tokio::io::duplex(128);
        let (client_network, server_network) = tokio::io::duplex(128);
        let (mut client_local_read, mut client_local_write) = tokio::io::split(client_local);
        let (mut client_remote_read, mut client_remote_write) = tokio::io::split(client_network);
        let (mut server_target_read, mut server_target_write) = tokio::io::split(server_target);
        let (mut server_remote_read, mut server_remote_write) = tokio::io::split(server_network);

        client_peer.write_all(b"hello").await.unwrap();
        target_peer.write_all(b"world").await.unwrap();
        shutdown_split(&mut client_peer).await;
        shutdown_split(&mut target_peer).await;

        let client_connection = client.run_connection(
            &mut client_local_read,
            &mut client_local_write,
            &mut client_remote_read,
            &mut client_remote_write,
        );
        let server_connection = server.run_connection(
            &mut server_target_read,
            &mut server_target_write,
            &mut server_remote_read,
            &mut server_remote_write,
        );
        let (client_result, server_result) = tokio::join!(client_connection, server_connection);
        assert_eq!(client_result.unwrap(), AssociationCompletion::Clean);
        assert_eq!(server_result.unwrap(), AssociationCompletion::Clean);
        assert!(client.outbound_is_empty());
        assert!(server.outbound_is_empty());

        let mut client_seen = Vec::new();
        client_peer.read_to_end(&mut client_seen).await.unwrap();
        assert_eq!(client_seen, b"world");
        let mut server_seen = Vec::new();
        target_peer.read_to_end(&mut server_seen).await.unwrap();
        assert_eq!(server_seen, b"hello");
    }

    async fn shutdown_split<W: AsyncWrite + Unpin>(writer: &mut W) {
        writer.shutdown().await.unwrap();
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
    fn streaming_decoder_reassembles_multiple_frames_at_every_split() {
        let first = ResumeFrame::data(1, b"first".to_vec()).unwrap();
        let second = ResumeFrame::data(2, b"second!".to_vec()).unwrap();
        let fin = ResumeFrame::fin(3).unwrap();
        let mut wire = Vec::new();
        for frame in [first.clone(), second.clone(), fin.clone()] {
            frame.encode_into(&mut wire).unwrap();
        }

        let mut decoder = ResumeFrameDecoder::new(16).unwrap();
        for split in 0..=wire.len() {
            let mut found = Vec::new();
            for chunk in [&wire[..split], &wire[split..]] {
                found.extend(decoder.decode_chunk(chunk).unwrap());
            }
            assert_eq!(found, vec![first.clone(), second.clone(), fin.clone()]);
        }

        let mut oversize = ResumeFrame::data(1, vec![0_u8; 17]).unwrap().encode();
        oversize.extend_from_slice(&[0]);
        let mut rejected = ResumeFrameDecoder::new(16).unwrap();
        assert!(rejected.decode_chunk(&oversize).is_err());

        let mut bad_version = first.encode();
        bad_version[0] ^= 1;
        let mut version_rejected = ResumeFrameDecoder::new(16).unwrap();
        assert!(version_rejected.decode_chunk(&bad_version).is_err());
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
