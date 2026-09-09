//! Fixed-storage initial control-record assembly for the disposable floor.
use crate::handshake::{ClientHello, HandshakeError};
use crate::transport::TransportError;
use crate::wire::{FrameHeader, Kind, StreamRole, HEADER_LEN};
use crate::Limits;
use zeroize::Zeroize;

/// Assembles one hello without consuming following capability bytes. Completion
/// is decoding only: TLS-bound invitation admission is a separate required step.
pub struct HelloReader {
    bytes: [u8; HEADER_LEN + ClientHello::MAX_ENCODED_LEN],
    filled: usize,
    target: usize,
    terminal: bool,
    limits: Limits,
}

pub struct HelloRead {
    pub hello: Option<ClientHello>,
    /// A chunk was consumed; another bounded read may make immediate progress.
    pub progressed: bool,
    /// noQ queued flow-control work which the reactor should transmit.
    pub should_transmit: bool,
}

impl HelloReader {
    pub fn new(limits: Limits) -> Result<Self, TransportError> {
        limits.validate()?;
        Ok(Self {
            bytes: [0; HEADER_LEN + ClientHello::MAX_ENCODED_LEN],
            filled: 0,
            target: HEADER_LEN,
            terminal: false,
            limits,
        })
    }

    /// Maximum bytes needed for the current header/payload stage.
    pub fn remaining(&self) -> usize {
        if self.terminal {
            0
        } else {
            self.target - self.filled
        }
    }

    /// Read one ordered chunk, never beyond the current hello stage. Always
    /// finalizes noQ's read transaction, including reset, FIN and parse errors.
    pub fn read_stream(
        &mut self,
        connection: &mut noq_proto::Connection,
        stream: noq_proto::StreamId,
    ) -> Result<HelloRead, TransportError> {
        if self.terminal {
            return Err(TransportError::Stream);
        }
        if stream != noq_proto::StreamId::new(noq_proto::Side::Client, noq_proto::Dir::Bi, 0) {
            return Err(self.incomplete_eof());
        }
        let mut recv = connection.recv_stream(stream);
        let mut chunks = match recv.read(true) {
            Ok(chunks) => chunks,
            Err(_) => return Err(self.incomplete_eof()),
        };
        let chunk = chunks.next(self.remaining());
        let should_transmit = chunks.finalize().should_transmit();
        match chunk {
            Ok(Some(chunk)) => {
                if chunk.bytes.is_empty() {
                    return Err(self.incomplete_eof());
                }
                let (consumed, hello) = self.push(&chunk.bytes)?;
                if consumed != chunk.bytes.len() {
                    return Err(self.incomplete_eof());
                }
                Ok(HelloRead {
                    hello,
                    progressed: true,
                    should_transmit,
                })
            }
            Err(noq_proto::ReadError::Blocked) => Ok(HelloRead {
                hello: None,
                progressed: false,
                should_transmit,
            }),
            Ok(None) | Err(noq_proto::ReadError::Reset(_)) => Err(self.incomplete_eof()),
        }
    }

    pub fn push(&mut self, input: &[u8]) -> Result<(usize, Option<ClientHello>), TransportError> {
        let result = self.push_inner(input);
        if result.is_err() || matches!(&result, Ok((_, Some(_)))) {
            self.terminal = true;
            self.bytes.zeroize();
        }
        result
    }

    fn push_inner(&mut self, input: &[u8]) -> Result<(usize, Option<ClientHello>), TransportError> {
        if self.terminal {
            return Err(TransportError::Stream);
        }
        let mut consumed = 0;
        loop {
            let count = (self.target - self.filled).min(input.len() - consumed);
            self.bytes[self.filled..self.filled + count]
                .copy_from_slice(&input[consumed..consumed + count]);
            self.filled += count;
            consumed += count;
            if self.filled < self.target {
                return Ok((consumed, None));
            }
            if self.target == HEADER_LEN {
                let header = FrameHeader::decode(
                    &self.bytes[..HEADER_LEN],
                    StreamRole::Control,
                    &self.limits,
                )?;
                if header.kind != Kind::ClientHello
                    || header.sequence != 0
                    || !matches!(
                        header.payload_len as usize,
                        ClientHello::INITIAL_ENCODED_LEN | ClientHello::RESUME_ENCODED_LEN
                    )
                {
                    return Err(TransportError::Handshake(HandshakeError::InvalidLength));
                }
                self.target = HEADER_LEN + header.payload_len as usize;
            } else {
                return Ok((
                    consumed,
                    Some(ClientHello::decode_exact(
                        &self.bytes[HEADER_LEN..self.target],
                    )?),
                ));
            }
        }
    }

    /// A stream FIN before successful decoding is a terminal truncation.
    pub fn incomplete_eof(&mut self) -> TransportError {
        self.terminal = true;
        self.bytes.zeroize();
        TransportError::Stream
    }
}

impl Drop for HelloReader {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{encode_record, ConnectionRole};
    use crate::{GatewayGeneration, ResumePosition};
    use everssh::{association::AssociationId, bootstrap::SecretToken};

    fn fixture() -> (ClientHello, Vec<u8>) {
        let hello = ClientHello::initial(
            AssociationId::from_bytes([1; 16]).expect("association"),
            GatewayGeneration::from_bytes([2; 16]).expect("generation"),
            ConnectionRole::Writer,
            ResumePosition {
                input_epoch: 0,
                next_input: 0,
                output_epoch: 0,
                next_output: 0,
                delivered_output_ack: 0,
            },
            SecretToken::from_bytes([3; 32]),
        )
        .expect("hello");
        let mut payload = [0; ClientHello::MAX_ENCODED_LEN];
        let length = hello.encode_into(&mut payload).expect("encode hello");
        let mut wire = vec![0; HEADER_LEN + length];
        encode_record(
            StreamRole::Control,
            Kind::ClientHello,
            0,
            &payload[..length],
            &Limits::default(),
            &mut wire,
        )
        .expect("record");
        (hello, wire)
    }

    #[test]
    fn every_split_preserves_following_bytes_and_scrubs_storage() {
        let (hello, wire) = fixture();
        for split in 0..wire.len() {
            let mut reader = HelloReader::new(Limits::default()).expect("reader");
            assert_eq!(reader.push(&wire[..split]).expect("prefix"), (split, None));
            let mut tail = wire[split..].to_vec();
            tail.extend_from_slice(b"capability");
            assert_eq!(
                reader.push(&tail).expect("complete"),
                (wire.len() - split, Some(hello.clone()))
            );
            assert!(reader.bytes.iter().all(|byte| *byte == 0));
            assert_eq!(reader.remaining(), 0);
            assert!(reader.push(&[]).is_err());
        }
    }

    #[test]
    fn malformed_headers_fail_before_payload_and_latch() {
        let (_, wire) = fixture();
        for (offset, byte) in [(0, 9), (1, 0xff), (9, 1), (10, 0xff), (13, 0)] {
            let mut header = wire[..HEADER_LEN].to_vec();
            header[offset] = byte;
            let mut reader = HelloReader::new(Limits::default()).expect("reader");
            assert!(reader.push(&header).is_err());
            assert!(reader.push(&wire).is_err());
            assert!(reader.bytes.iter().all(|byte| *byte == 0));
        }
    }

    #[test]
    fn every_truncation_is_terminal_and_scrubbed() {
        let (_, wire) = fixture();
        for end in 0..wire.len() {
            let mut reader = HelloReader::new(Limits::default()).expect("reader");
            reader.push(&wire[..end]).expect("prefix");
            assert!(matches!(reader.incomplete_eof(), TransportError::Stream));
            assert!(reader.push(&wire[end..]).is_err());
            assert!(reader.bytes.iter().all(|byte| *byte == 0));
        }
    }
}
