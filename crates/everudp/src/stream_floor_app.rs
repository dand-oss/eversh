//! Shared opaque echo transitions for both disposable stream runtimes.
//!
//! Construct only after admission. These states own no sockets or tasks: the
//! adapters service control independently and close the association on errors.
//! Sequences are absolute payload byte offsets, starting at zero. Nothing here
//! implements PTY replay, terminal parsing, or a reconnect association.

use crate::stream_floor_io::{RecordReader, RecordWriter, MAX_APPLICATION_CHUNK};
use crate::transport::TransportError;
use crate::wire::{Kind, StreamRole};
use crate::Limits;

/// Shared client input boundary: at most one framed record is outstanding.
/// Local reads stop while that record is pending, in either runtime mode.
pub struct InputSource {
    buffer: Box<[u8; MAX_APPLICATION_CHUNK]>,
    writer: RecordWriter,
    next: u64,
    eof: bool,
    failed: bool,
}

impl InputSource {
    pub fn new(limits: Limits) -> Result<Self, TransportError> {
        Ok(Self {
            buffer: Box::new([0; MAX_APPLICATION_CHUNK]),
            writer: RecordWriter::new(StreamRole::Input, limits)?,
            next: 0,
            eof: false,
            failed: false,
        })
    }

    pub fn buffer(&mut self) -> Option<&mut [u8]> {
        (!self.failed && !self.eof && self.writer.is_complete()).then_some(&mut self.buffer[..])
    }

    /// Commit the actual local read count. WouldBlock/Interrupted must not be
    /// committed as zero: zero means real EOF and permanently closes input.
    pub fn commit_read(&mut self, count: usize) -> Result<(), TransportError> {
        if self.failed || self.eof || !self.writer.is_complete() || count > self.buffer.len() {
            self.failed = true;
            return Err(TransportError::Rejected);
        }
        if count == 0 {
            self.eof = true;
            return Ok(());
        }
        let Some(end) = self.next.checked_add(count as u64) else {
            self.failed = true;
            return Err(TransportError::Rejected);
        };
        if let Err(error) = self
            .writer
            .load(Kind::Input, self.next, &self.buffer[..count])
        {
            self.failed = true;
            return Err(error.into());
        }
        self.next = end;
        Ok(())
    }

    pub fn writer(&mut self) -> Option<&mut RecordWriter> {
        (!self.failed).then_some(&mut self.writer)
    }

    pub fn finish_ready(&self) -> bool {
        !self.failed && self.eof && self.writer.is_complete()
    }

    pub fn bytes_read(&self) -> u64 {
        self.next
    }
}

impl Drop for InputSource {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.buffer.zeroize();
    }
}

/// One outstanding echo record. A blocked output cannot accumulate input.
pub struct EchoRelay {
    input: RecordReader,
    output: RecordWriter,
    next: u64,
    pending_end: Option<u64>,
    failed: bool,
    input_kind: Kind,
    output_kind: Kind,
}

impl EchoRelay {
    pub fn new(limits: Limits) -> Result<Self, TransportError> {
        Self::with_streams(
            limits,
            StreamRole::Input,
            StreamRole::Output,
            Kind::Input,
            Kind::Output,
        )
    }

    /// Opaque diagnostic control echoes progress independently of data. Their
    /// sequences also count payload bytes; handshake records are not counted.
    pub fn control(limits: Limits) -> Result<Self, TransportError> {
        Self::with_streams(
            limits,
            StreamRole::Control,
            StreamRole::Control,
            Kind::LinkStatus,
            Kind::LinkStatus,
        )
    }

    fn with_streams(
        limits: Limits,
        input: StreamRole,
        output: StreamRole,
        input_kind: Kind,
        output_kind: Kind,
    ) -> Result<Self, TransportError> {
        Ok(Self {
            input: RecordReader::new(input, limits)?,
            output: RecordWriter::new(output, limits)?,
            next: 0,
            pending_end: None,
            failed: false,
            input_kind,
            output_kind,
        })
    }

    /// No input polling while the previous echo is awaiting stream acceptance.
    pub fn input(&mut self) -> Option<&mut RecordReader> {
        (!self.failed && self.pending_end.is_none()).then_some(&mut self.input)
    }

    /// Stage a complete input record once. Returns false while input is partial
    /// or the previous echo is still pending, without changing either buffer.
    pub fn stage(&mut self) -> Result<bool, TransportError> {
        if self.failed {
            return Err(TransportError::Rejected);
        }
        if self.pending_end.is_some() {
            return Ok(false);
        }
        let Some(record) = self.input.record() else {
            return Ok(false);
        };
        if record.header.kind != self.input_kind || record.header.sequence != self.next {
            self.failed = true;
            return Err(TransportError::Rejected);
        }
        let Some(end) = self.next.checked_add(record.payload.len() as u64) else {
            self.failed = true;
            return Err(TransportError::Rejected);
        };
        if let Err(error) = self
            .output
            .load(self.output_kind, self.next, record.payload)
        {
            self.failed = true;
            return Err(error.into());
        }
        self.pending_end = Some(end);
        Ok(true)
    }

    pub fn output(&mut self) -> Option<&mut RecordWriter> {
        (!self.failed && self.pending_end.is_some()).then_some(&mut self.output)
    }

    /// Advance only when all framed output bytes have been accepted. Partial
    /// and zero-byte writes retain the current input and its exact output suffix.
    pub fn complete_output(&mut self) -> Result<bool, TransportError> {
        if self.failed {
            return Err(TransportError::Rejected);
        }
        let Some(end) = self.pending_end else {
            return Ok(false);
        };
        if !self.output.is_complete() {
            return Ok(false);
        }
        if !self.input.consume_record() {
            self.failed = true;
            return Err(TransportError::Rejected);
        }
        self.next = end;
        self.pending_end = None;
        Ok(true)
    }
}

/// The client retains output until the local sink accepts every payload byte.
pub struct OutputSink {
    reader: RecordReader,
    next: u64,
    accepted: usize,
    pending_end: Option<u64>,
    failed: bool,
}

impl OutputSink {
    pub fn new(limits: Limits) -> Result<Self, TransportError> {
        Ok(Self {
            reader: RecordReader::new(StreamRole::Output, limits)?,
            next: 0,
            accepted: 0,
            pending_end: None,
            failed: false,
        })
    }

    pub fn reader(&mut self) -> Option<&mut RecordReader> {
        (!self.failed && self.pending_end.is_none()).then_some(&mut self.reader)
    }

    /// Fully accepted payload bytes, excluding any partially accepted record.
    pub fn bytes_delivered(&self) -> u64 {
        self.next
    }

    pub fn stage(&mut self) -> Result<bool, TransportError> {
        if self.failed {
            return Err(TransportError::Rejected);
        }
        if self.pending_end.is_some() {
            return Ok(false);
        }
        let Some(record) = self.reader.record() else {
            return Ok(false);
        };
        if record.header.kind != Kind::Output || record.header.sequence != self.next {
            self.failed = true;
            return Err(TransportError::Rejected);
        }
        let Some(end) = self.next.checked_add(record.payload.len() as u64) else {
            self.failed = true;
            return Err(TransportError::Rejected);
        };
        self.pending_end = Some(end);
        Ok(true)
    }

    pub fn pending(&self) -> Option<&[u8]> {
        if self.failed || self.pending_end.is_none() {
            return None;
        }
        let payload = self.reader.record()?.payload;
        Some(&payload[self.accepted..payload.len().min(self.accepted + MAX_APPLICATION_CHUNK)])
    }

    pub fn commit(&mut self, accepted: usize) -> Result<bool, TransportError> {
        let Some(pending) = self.pending() else {
            self.failed = true;
            return Err(TransportError::Rejected);
        };
        if accepted > pending.len() {
            self.failed = true;
            return Err(TransportError::Rejected);
        }
        self.accepted += accepted;
        let length = self
            .reader
            .record()
            .ok_or(TransportError::Rejected)?
            .payload
            .len();
        if self.accepted != length {
            return Ok(false);
        }
        self.next = self.pending_end.take().ok_or(TransportError::Rejected)?;
        self.reader.consume_record();
        self.accepted = 0;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::encode_record;

    #[test]
    fn client_source_frames_offsets_and_backpressures_until_complete() {
        let limits = Limits::default();
        let mut source = InputSource::new(limits).expect("source");
        let original_buffer = source.buffer().expect("buffer").as_ptr();
        for (offset, payload) in [(0, &b"abc"[..]), (3, &b"defgh"[..])] {
            source.buffer().expect("buffer")[..payload.len()].copy_from_slice(payload);
            source.commit_read(payload.len()).expect("local read");
            assert!(source.buffer().is_none());
            let writer = source.writer().expect("writer");
            let mut reader = RecordReader::new(StreamRole::Input, limits).expect("reader");
            while !writer.is_complete() {
                writer.commit(0).expect("blocked write");
                let count = writer.pending().len().min(reader.remaining()).min(2);
                reader
                    .feed(&writer.pending()[..count])
                    .expect("framed input");
                writer.commit(count).expect("partial stream write");
            }
            let record = reader.record().expect("input record");
            assert_eq!(record.header.sequence, offset);
            assert_eq!(record.payload, payload);
            assert_eq!(
                source.buffer().expect("reused buffer").as_ptr(),
                original_buffer
            );
        }
        source.commit_read(0).expect("real EOF");
        assert!(source.buffer().is_none() && source.finish_ready());
        assert_eq!(source.bytes_read(), 8);
    }

    #[test]
    fn client_source_rejects_overread_overflow_and_overwriting_pending_input() {
        for case in 0..3 {
            let mut source = InputSource::new(Limits::default()).expect("source");
            let count = match case {
                0 => MAX_APPLICATION_CHUNK + 1,
                1 => {
                    source.next = u64::MAX;
                    1
                }
                _ => {
                    source.commit_read(1).expect("first record");
                    1
                }
            };
            assert!(source.commit_read(count).is_err());
            assert!(source.buffer().is_none() && source.writer().is_none());
            assert!(!source.finish_ready());
            assert!(source.commit_read(0).is_err());
        }
    }

    fn feed(reader: &mut RecordReader, role: StreamRole, kind: Kind, seq: u64, payload: &[u8]) {
        let mut encoded = vec![0; payload.len() + crate::wire::HEADER_LEN];
        let used = encode_record(role, kind, seq, payload, &Limits::default(), &mut encoded)
            .expect("encode");
        let mut offset = 0;
        while offset < used {
            let count = reader
                .remaining()
                .min(MAX_APPLICATION_CHUNK)
                .min(used - offset);
            reader.feed(&encoded[offset..offset + count]).expect("feed");
            offset += count;
        }
    }

    #[test]
    fn relay_and_sink_hold_records_across_partial_and_zero_acceptance() {
        let mut relay = EchoRelay::new(Limits::default()).expect("relay");
        let mut sink = OutputSink::new(Limits::default()).expect("sink");
        let payload = vec![0x5a; 65536];
        for offset in [0, 65536] {
            feed(
                relay.input().expect("input"),
                StreamRole::Input,
                Kind::Input,
                offset,
                &payload,
            );
            assert!(relay.stage().expect("stage"));
            assert!(!relay.stage().expect("idempotent pending"));
            assert!(relay.input().is_none());
            assert!(!relay.complete_output().expect("not accepted"));
            while !relay.output().expect("output").is_complete() {
                let output = relay.output().expect("output");
                assert_eq!(output.commit(0).expect("pending").accepted, 0);
                let reader = sink.reader().expect("reader");
                let count = output.pending().len().min(reader.remaining()).min(7);
                reader
                    .feed(&output.pending()[..count])
                    .expect("partial feed");
                output.commit(count).expect("partial write");
            }
            assert!(relay.complete_output().expect("complete"));
            assert!(sink.stage().expect("sink stage"));
            assert!(sink.reader().is_none());
            assert!(!sink.commit(0).expect("sink pending"));
            let mut accepted = 0;
            while let Some(pending) = sink.pending() {
                assert!(pending.len() <= MAX_APPLICATION_CHUNK);
                assert_eq!(pending, &payload[accepted..accepted + pending.len()]);
                let count = pending.len().min(13);
                accepted += count;
                sink.commit(count).expect("sink commit");
            }
            assert_eq!(accepted, payload.len());
            assert!(sink.reader().is_some());
        }
    }

    #[test]
    fn sequence_kind_and_sink_overcommit_fail_closed() {
        for (kind, seq, bytes) in [(Kind::Input, 1, &b"x"[..]), (Kind::InputClose, 0, &b""[..])] {
            let mut relay = EchoRelay::new(Limits::default()).expect("relay");
            feed(
                relay.input().expect("input"),
                StreamRole::Input,
                kind,
                seq,
                bytes,
            );
            assert!(relay.stage().is_err());
            assert!(relay.stage().is_err());
            assert!(relay.input().is_none() && relay.output().is_none());
        }
        let mut sink = OutputSink::new(Limits::default()).expect("sink");
        feed(
            sink.reader().expect("reader"),
            StreamRole::Output,
            Kind::Output,
            0,
            b"x",
        );
        assert!(sink.stage().expect("stage"));
        assert!(sink.commit(2).is_err());
        assert!(sink.pending().is_none() && sink.reader().is_none());
        assert!(sink.commit(0).is_err());
    }
}
