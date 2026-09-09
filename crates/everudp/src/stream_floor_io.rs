//! Bounded record I/O shared by the disposable reliable-stream floor.
//!
//! This module deliberately stops at the application/stream boundary.  It does
//! not own admission, event scheduling, replay, or terminal state.  Both the
//! ordinary noQ adapter and the native protocol adapter use the same fixed
//! record buffers and commit semantics here.

use crate::error::{LimitViolation, WireError};
use crate::transport::TransportError;
use crate::wire::{decode_record, encode_record, Kind, Record, StreamRole, HEADER_LEN};
use crate::Limits;
use std::pin::Pin;
use std::task::{Context, Poll};
use zeroize::Zeroize;

/// Maximum application operation handed to either stream adapter per turn.
pub const MAX_APPLICATION_CHUNK: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadProgress {
    /// Input was accepted but the record is not complete yet.
    Consumed(usize),
    /// A complete record is available through [`RecordReader::record`].
    Record(usize),
    /// The stream ended cleanly between records.
    CleanEof,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteProgress {
    pub accepted: usize,
    pub complete: bool,
    pub blocked: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum StreamIoError {
    Limits(LimitViolation),
    Wire(WireError),
    TruncatedRecord,
    InvalidCommit { accepted: usize, available: usize },
    Stream,
}

impl std::fmt::Display for StreamIoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Limits(error) => error.fmt(f),
            Self::Wire(error) => error.fmt(f),
            Self::TruncatedRecord => f.write_str("everudp stream ended within a record"),
            Self::InvalidCommit {
                accepted,
                available,
            } => {
                write!(
                    f,
                    "stream commit {accepted} exceeds {available} pending bytes"
                )
            }
            Self::Stream => f.write_str("everudp stream I/O failed"),
        }
    }
}

impl std::error::Error for StreamIoError {}

impl From<WireError> for StreamIoError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

impl From<LimitViolation> for StreamIoError {
    fn from(error: LimitViolation) -> Self {
        Self::Limits(error)
    }
}

impl From<StreamIoError> for TransportError {
    fn from(error: StreamIoError) -> Self {
        match error {
            StreamIoError::Limits(error) => Self::InvalidLimits(error),
            StreamIoError::Wire(error) => Self::Protocol(error),
            StreamIoError::TruncatedRecord
            | StreamIoError::InvalidCommit { .. }
            | StreamIoError::Stream => Self::Stream,
        }
    }
}

/// A single bounded wire record whose suffix remains owned until committed.
pub struct RecordWriter {
    stream: StreamRole,
    limits: Limits,
    bytes: Box<[u8]>,
    length: usize,
    sent: usize,
    terminal: bool,
}

impl RecordWriter {
    /// Allocate the maximum record buffer once.  Call [`load`](Self::load) for
    /// each subsequent record; adapters must reuse this value across turns.
    pub fn new(stream: StreamRole, limits: Limits) -> Result<Self, StreamIoError> {
        limits.validate()?;
        let capacity = record_capacity(stream, &limits)?;
        Ok(Self {
            stream,
            limits,
            bytes: vec![0_u8; capacity].into_boxed_slice(),
            length: 0,
            sent: 0,
            terminal: false,
        })
    }

    /// Encode one record into the preallocated buffer.  Loading while a
    /// previous record is pending is rejected so unsent bytes cannot be lost.
    pub fn load(&mut self, kind: Kind, sequence: u64, payload: &[u8]) -> Result<(), StreamIoError> {
        if self.terminal || !self.is_complete() {
            return Err(StreamIoError::Stream);
        }
        let length = encode_record(
            self.stream,
            kind,
            sequence,
            payload,
            &self.limits,
            &mut self.bytes,
        )?;
        self.length = length;
        self.sent = 0;
        Ok(())
    }

    pub fn pending(&self) -> &[u8] {
        let end = (self.sent + MAX_APPLICATION_CHUNK).min(self.length);
        &self.bytes[self.sent..end]
    }

    pub const fn is_complete(&self) -> bool {
        self.sent == self.length
    }

    pub fn commit(&mut self, accepted: usize) -> Result<WriteProgress, StreamIoError> {
        if self.terminal {
            return Err(StreamIoError::Stream);
        }
        let available = self.length - self.sent;
        if accepted > available {
            self.terminal = true;
            self.bytes.zeroize();
            return Err(StreamIoError::InvalidCommit {
                accepted,
                available,
            });
        }
        if accepted > self.pending().len() {
            self.terminal = true;
            self.bytes.zeroize();
            return Err(StreamIoError::InvalidCommit {
                accepted,
                available: self.pending().len(),
            });
        }
        self.bytes[self.sent..self.sent + accepted].zeroize();
        self.sent += accepted;
        Ok(WriteProgress {
            accepted,
            complete: self.is_complete(),
            blocked: accepted == 0 && !self.is_complete(),
        })
    }

    /// One ordinary-driver write with the same offered slice as the native path.
    pub fn poll_write_ordinary(
        &mut self,
        stream: &mut noq::SendStream,
        cx: &mut Context<'_>,
    ) -> Poll<Result<WriteProgress, StreamIoError>> {
        if self.terminal {
            return Poll::Ready(Err(StreamIoError::Stream));
        }
        if self.is_complete() {
            return Poll::Ready(self.commit(0));
        }
        match Pin::new(stream).poll_write(cx, self.pending()) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(count)) => Poll::Ready(self.commit(count)),
            Poll::Ready(Err(_)) => {
                self.terminal = true;
                self.bytes.zeroize();
                Poll::Ready(Err(StreamIoError::Stream))
            }
        }
    }

    /// Perform one bounded native noQ write.  A blocked write retains the exact
    /// suffix and is retried only after the owning event loop receives Writable.
    #[cfg(feature = "stream-floor")]
    pub fn write_native(
        &mut self,
        connection: &mut noq_proto::Connection,
        stream: noq_proto::StreamId,
    ) -> Result<WriteProgress, StreamIoError> {
        if self.terminal {
            return Err(StreamIoError::Stream);
        }
        if self.is_complete() {
            return Ok(WriteProgress {
                accepted: 0,
                complete: true,
                blocked: false,
            });
        }
        match connection.send_stream(stream).write(self.pending()) {
            Ok(accepted) => self.commit(accepted),
            Err(noq_proto::WriteError::Blocked) => Ok(WriteProgress {
                accepted: 0,
                complete: false,
                blocked: true,
            }),
            Err(_) => {
                self.terminal = true;
                self.bytes.zeroize();
                Err(StreamIoError::Stream)
            }
        }
    }
}

impl Drop for RecordWriter {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Fixed-storage ordered reader.  It never consumes beyond the current header
/// or payload boundary, so the next record remains in the stream for the next
/// call. Inspect [`record`](Self::record) after `ReadProgress::Record`, then call
/// [`consume_record`](Self::consume_record) only after sink acceptance.
pub struct RecordReader {
    stream: StreamRole,
    limits: Limits,
    bytes: Box<[u8]>,
    filled: usize,
    target: usize,
    record: Option<(Kind, u64, usize)>,
    terminal: bool,
}

impl RecordReader {
    pub fn new(stream: StreamRole, limits: Limits) -> Result<Self, StreamIoError> {
        limits.validate()?;
        let capacity = record_capacity(stream, &limits)?;
        Ok(Self {
            stream,
            limits,
            bytes: vec![0_u8; capacity].into_boxed_slice(),
            filled: 0,
            target: HEADER_LEN,
            record: None,
            terminal: false,
        })
    }

    pub const fn remaining(&self) -> usize {
        self.target - self.filled
    }

    pub const fn is_terminal(&self) -> bool {
        self.terminal
    }

    pub fn record(&self) -> Option<Record<'_>> {
        let (_, _, used) = self.record?;
        decode_record(self.stream, &self.bytes[..used], &self.limits)
            .ok()
            .map(|(record, _)| record)
    }

    /// Release the current record only after the application sink has accepted
    /// every payload byte.  No payload copy or allocation is performed.
    pub fn consume_record(&mut self) -> bool {
        let Some((_, _, used)) = self.record.take() else {
            return false;
        };
        self.bytes[..used].zeroize();
        self.filled = 0;
        self.target = HEADER_LEN;
        true
    }

    /// Feed at most the bytes needed for this record.  The returned consumed
    /// count is always bounded by `input.len()` and `remaining()`.
    pub fn feed(&mut self, input: &[u8]) -> Result<ReadProgress, StreamIoError> {
        if self.terminal || self.record.is_some() {
            return Err(StreamIoError::Stream);
        }
        let count = input.len().min(self.remaining()).min(MAX_APPLICATION_CHUNK);
        if count == 0 {
            return Ok(ReadProgress::Consumed(0));
        }
        self.bytes[self.filled..self.filled + count].copy_from_slice(&input[..count]);
        self.accept_read(count)
    }

    fn accept_read(&mut self, count: usize) -> Result<ReadProgress, StreamIoError> {
        self.filled += count;
        if self.filled < self.target {
            return Ok(ReadProgress::Consumed(count));
        }
        if self.target == HEADER_LEN {
            let header = match crate::wire::FrameHeader::decode(
                &self.bytes[..HEADER_LEN],
                self.stream,
                &self.limits,
            ) {
                Ok(header) => header,
                Err(error) => return self.fail(error.into()),
            };
            self.target = HEADER_LEN + header.payload_len as usize;
            if self.filled < self.target {
                return Ok(ReadProgress::Consumed(count));
            }
        }
        let (record, used) =
            match decode_record(self.stream, &self.bytes[..self.target], &self.limits) {
                Ok(record) => record,
                Err(error) => return self.fail(error.into()),
            };
        self.record = Some((record.header.kind, record.header.sequence, used));
        Ok(ReadProgress::Record(count))
    }

    /// Read directly into the shared record buffer, without an additional
    /// ordinary-only copy or a write-all/read-all batching loop.
    pub fn poll_read_ordinary(
        &mut self,
        stream: &mut noq::RecvStream,
        cx: &mut Context<'_>,
    ) -> Poll<Result<ReadProgress, StreamIoError>> {
        if self.terminal || self.record.is_some() {
            return Poll::Ready(Err(StreamIoError::Stream));
        }
        let end = self.filled + self.remaining().min(MAX_APPLICATION_CHUNK);
        match stream.poll_read(cx, &mut self.bytes[self.filled..end]) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(0)) => Poll::Ready(self.clean_eof()),
            Poll::Ready(Ok(count)) => Poll::Ready(self.accept_read(count)),
            Poll::Ready(Err(_)) => Poll::Ready(self.fail(StreamIoError::Stream)),
        }
    }

    pub fn clean_eof(&mut self) -> Result<ReadProgress, StreamIoError> {
        if self.terminal {
            return Err(StreamIoError::Stream);
        }
        self.terminal = true;
        if self.filled == 0 && self.record.is_none() {
            Ok(ReadProgress::CleanEof)
        } else {
            self.bytes.zeroize();
            Err(StreamIoError::TruncatedRecord)
        }
    }

    fn fail<T>(&mut self, error: StreamIoError) -> Result<T, StreamIoError> {
        self.terminal = true;
        self.bytes.zeroize();
        Err(error)
    }

    /// Read one bounded chunk from a native noQ stream.  `Chunks` is finalized
    /// on every path, including blocked, reset, EOF, and parse failure.
    #[cfg(feature = "stream-floor")]
    pub fn read_native(
        &mut self,
        connection: &mut noq_proto::Connection,
        stream: noq_proto::StreamId,
    ) -> NativeRead {
        if self.terminal || self.record.is_some() {
            return NativeRead {
                result: Err(StreamIoError::Stream),
                should_transmit: false,
            };
        }
        let mut recv = connection.recv_stream(stream);
        let mut chunks = match recv.read(true) {
            Ok(chunks) => chunks,
            Err(_) => {
                self.terminal = true;
                self.bytes.zeroize();
                return NativeRead {
                    result: Err(StreamIoError::Stream),
                    should_transmit: false,
                };
            }
        };
        let chunk = chunks.next(self.remaining().min(MAX_APPLICATION_CHUNK));
        let should_transmit = chunks.finalize().should_transmit();
        match chunk {
            Ok(Some(chunk)) if !chunk.bytes.is_empty() => {
                let result = self.feed(&chunk.bytes);
                NativeRead {
                    result,
                    should_transmit,
                }
            }
            Ok(Some(_)) => {
                self.terminal = true;
                self.bytes.zeroize();
                NativeRead {
                    result: Err(StreamIoError::Stream),
                    should_transmit,
                }
            }
            Ok(None) => NativeRead {
                result: self.clean_eof(),
                should_transmit,
            },
            Err(noq_proto::ReadError::Blocked) => NativeRead {
                result: Ok(ReadProgress::Consumed(0)),
                should_transmit,
            },
            Err(noq_proto::ReadError::Reset(_)) => {
                self.terminal = true;
                self.bytes.zeroize();
                NativeRead {
                    result: Err(StreamIoError::Stream),
                    should_transmit,
                }
            }
        }
    }
}

#[cfg(feature = "stream-floor")]
#[derive(Debug, PartialEq, Eq)]
pub struct NativeRead {
    pub result: Result<ReadProgress, StreamIoError>,
    pub should_transmit: bool,
}

fn record_capacity(stream: StreamRole, limits: &Limits) -> Result<usize, StreamIoError> {
    let payload = match stream {
        StreamRole::Control => limits.control_frame_max,
        StreamRole::Input | StreamRole::Output => limits.terminal_frame_max,
    };
    HEADER_LEN
        .checked_add(payload)
        .ok_or(StreamIoError::Wire(WireError::LengthOverflow))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits::default()
    }

    fn feed_all(reader: &mut RecordReader, mut input: &[u8]) {
        while !input.is_empty() {
            let count = match reader.feed(input).expect("valid prefix") {
                ReadProgress::Consumed(count) | ReadProgress::Record(count) => count,
                ReadProgress::CleanEof => panic!("feed cannot return EOF"),
            };
            assert!(count > 0);
            input = &input[count..];
        }
    }

    #[test]
    fn every_split_and_truncation_preserves_record_and_failure_state() {
        let limits = limits();
        let mut wire = [0; 64];
        let size = encode_record(
            StreamRole::Output,
            Kind::Output,
            7,
            b"payload",
            &limits,
            &mut wire,
        )
        .expect("wire");
        let mut reader = RecordReader::new(StreamRole::Output, limits).expect("reader");
        let pointer = reader.bytes.as_ptr();
        for split in 0..=size {
            feed_all(&mut reader, &wire[..split]);
            feed_all(&mut reader, &wire[split..size]);
            assert_eq!(reader.record().expect("complete").payload, b"payload");
            assert_eq!(reader.bytes.as_ptr(), pointer);
            assert!(
                reader.feed(b"next").is_err(),
                "sink must release record first"
            );
            assert_eq!(reader.record().expect("retained").payload, b"payload");
            assert!(reader.consume_record());
        }
        assert_eq!(reader.clean_eof(), Ok(ReadProgress::CleanEof));
        assert!(reader.feed(&wire[..size]).is_err());
        for end in 1..size {
            let mut reader = RecordReader::new(StreamRole::Output, limits).expect("reader");
            feed_all(&mut reader, &wire[..end]);
            assert_eq!(reader.clean_eof(), Err(StreamIoError::TruncatedRecord));
            assert!(reader.clean_eof().is_err());
            assert!(reader.feed(&wire[..size]).is_err());
            assert!(reader.bytes.iter().all(|byte| *byte == 0));
        }
    }

    #[test]
    fn writer_rejects_overcommit_and_cannot_replace_pending_record() {
        let mut writer = RecordWriter::new(StreamRole::Output, limits()).expect("writer");
        let payload = [1; MAX_APPLICATION_CHUNK + 1];
        writer.load(Kind::Output, 1, &payload).expect("load");
        let prefix = writer.pending().to_vec();
        assert!(writer.load(Kind::Output, 2, b"replacement").is_err());
        assert_eq!(writer.pending(), prefix);
        assert!(matches!(
            writer.commit(MAX_APPLICATION_CHUNK + 1),
            Err(StreamIoError::InvalidCommit { .. })
        ));
        assert!(writer.commit(0).is_err());
        assert!(writer.load(Kind::Output, 2, b"replacement").is_err());
        assert!(writer.bytes.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn writer_retains_suffix_across_zero_and_partial_writes() {
        let payload = b"bounded stream payload";
        let mut writer = RecordWriter::new(StreamRole::Output, limits()).expect("writer");
        writer.load(Kind::Output, 7, payload).expect("load");
        let total = writer.pending().len();
        assert!(writer.commit(0).expect("blocked").blocked);
        let first = writer.commit(3).expect("partial");
        assert_eq!(first.accepted, 3);
        assert_eq!(writer.pending().len(), total - 3);
        let rest = writer.pending().len();
        assert!(writer.commit(rest).expect("finish").complete);
        assert!(writer.pending().is_empty());
    }

    #[test]
    fn reader_never_consumes_next_record_and_reports_truncation() {
        let limits = limits();
        let mut first = [0; 128];
        let first_len = encode_record(
            StreamRole::Output,
            Kind::Output,
            1,
            b"one",
            &limits,
            &mut first,
        )
        .expect("first");
        let mut second = [0; 128];
        let second_len = encode_record(
            StreamRole::Output,
            Kind::Output,
            2,
            b"two",
            &limits,
            &mut second,
        )
        .expect("second");
        let mut reader = RecordReader::new(StreamRole::Output, limits).expect("reader");
        let mut input = Vec::from(&first[..first_len]);
        input.extend_from_slice(&second[..second_len]);
        let header_progress = reader.feed(&input).expect("first header feed");
        assert_eq!(header_progress, ReadProgress::Consumed(HEADER_LEN));
        let progress = reader
            .feed(&input[HEADER_LEN..])
            .expect("first payload feed");
        assert_eq!(progress, ReadProgress::Record(first_len - HEADER_LEN));
        assert_eq!(reader.record().expect("record").header.sequence, 1);
        assert_eq!(reader.record().expect("record").payload, b"one");
        assert!(reader.consume_record());
        assert_eq!(
            reader.feed(&input[first_len..]).expect("second header"),
            ReadProgress::Consumed(HEADER_LEN)
        );
        assert_eq!(
            reader
                .feed(&input[first_len + HEADER_LEN..])
                .expect("second payload"),
            ReadProgress::Record(second_len - HEADER_LEN)
        );
        assert_eq!(reader.record().expect("second").header.sequence, 2);
        assert!(reader.consume_record());

        let mut truncated = RecordReader::new(StreamRole::Output, limits).expect("reader");
        truncated.feed(&first[..first_len - 1]).expect("partial");
        assert_eq!(truncated.clean_eof(), Err(StreamIoError::TruncatedRecord));
        assert_eq!(truncated.clean_eof(), Err(StreamIoError::Stream));
    }

    #[test]
    fn writer_reuses_storage_and_caps_each_application_write() {
        let limits = limits();
        let payload = vec![9_u8; MAX_APPLICATION_CHUNK + 257];
        let mut writer = RecordWriter::new(StreamRole::Output, limits).expect("writer");
        writer.load(Kind::Output, 1, &payload).expect("load");
        let pointer = writer.pending().as_ptr();
        assert_eq!(writer.pending().len(), MAX_APPLICATION_CHUNK);
        let mut left = writer.pending().len();
        while !writer.is_complete() {
            writer.commit(left.min(997)).expect("partial");
            left = writer.pending().len();
        }
        writer.load(Kind::Output, 2, b"reuse").expect("reload");
        assert_eq!(writer.pending().as_ptr(), pointer);
    }

    #[test]
    fn reader_caps_large_payload_chunks() {
        let limits = limits();
        let payload = vec![4_u8; MAX_APPLICATION_CHUNK + 11];
        let mut wire = vec![0_u8; HEADER_LEN + payload.len()];
        let used = encode_record(
            StreamRole::Output,
            Kind::Output,
            4,
            &payload,
            &limits,
            &mut wire,
        )
        .expect("encode");
        let mut reader = RecordReader::new(StreamRole::Output, limits).expect("reader");
        assert_eq!(
            reader.feed(&wire).expect("header"),
            ReadProgress::Consumed(HEADER_LEN)
        );
        assert_eq!(
            reader
                .feed(&wire[HEADER_LEN..])
                .expect("first payload chunk"),
            ReadProgress::Consumed(MAX_APPLICATION_CHUNK)
        );
        assert_eq!(
            reader
                .feed(&wire[HEADER_LEN + MAX_APPLICATION_CHUNK..used])
                .expect("final payload chunk"),
            ReadProgress::Record(11)
        );
        assert!(reader.consume_record());
    }

    #[test]
    fn malformed_record_latches_error_and_cannot_be_reused() {
        let limits = limits();
        let mut reader = RecordReader::new(StreamRole::Output, limits).expect("reader");
        let mut malformed = [0_u8; HEADER_LEN];
        malformed[0] = crate::wire::WIRE_VERSION;
        malformed[1] = Kind::Input as u8;
        malformed[10..14].copy_from_slice(&1_u32.to_be_bytes());
        assert!(matches!(
            reader.feed(&malformed),
            Err(StreamIoError::Wire(WireError::KindNotAllowed { .. }))
        ));
        assert_eq!(reader.feed(&malformed), Err(StreamIoError::Stream));
        assert_eq!(reader.clean_eof(), Err(StreamIoError::Stream));
    }
}
