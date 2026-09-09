//! Bounded pending control bytes for the disposable synchronous floor.
use crate::handshake::ClientHello;
use crate::transport::TransportError;
use crate::wire::{encode_record, Kind, StreamRole, HEADER_LEN};
use crate::Limits;
use zeroize::{Zeroize, Zeroizing};

const CAPACITY: usize = HEADER_LEN + ClientHello::MAX_ENCODED_LEN;

pub struct ControlWriter {
    bytes: [u8; CAPACITY],
    length: usize,
    sent: usize,
    failed: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ControlWrite {
    pub accepted: usize,
    pub complete: bool,
    pub blocked: bool,
}

impl ControlWriter {
    pub fn from_bytes(input: &[u8]) -> Result<Self, TransportError> {
        if input.len() > CAPACITY {
            return Err(TransportError::Stream);
        }
        let mut writer = Self {
            bytes: [0; CAPACITY],
            length: input.len(),
            sent: 0,
            failed: false,
        };
        writer.bytes[..input.len()].copy_from_slice(input);
        Ok(writer)
    }

    pub fn hello(hello: &ClientHello, limits: &Limits) -> Result<Self, TransportError> {
        let mut payload = Zeroizing::new([0; ClientHello::MAX_ENCODED_LEN]);
        let used = hello.encode_into(&mut payload[..])?;
        let mut writer = Self::from_bytes(&[])?;
        writer.length = encode_record(
            StreamRole::Control,
            Kind::ClientHello,
            0,
            &payload[..used],
            limits,
            &mut writer.bytes,
        )?;
        Ok(writer)
    }

    /// One nonblocking write attempt. Accepted bytes are owned by noQ; only the
    /// unsent suffix remains here. No stream FIN is sent by this writer.
    pub fn write_stream(
        &mut self,
        connection: &mut noq_proto::Connection,
        stream: noq_proto::StreamId,
    ) -> Result<ControlWrite, TransportError> {
        if stream != noq_proto::StreamId::new(noq_proto::Side::Client, noq_proto::Dir::Bi, 0) {
            self.failed = true;
            self.bytes.zeroize();
            return Err(TransportError::Stream);
        }
        self.write_with(|bytes| connection.send_stream(stream).write(bytes))
    }

    fn write_with(
        &mut self,
        send: impl FnOnce(&[u8]) -> Result<usize, noq_proto::WriteError>,
    ) -> Result<ControlWrite, TransportError> {
        if self.failed {
            return Err(TransportError::Stream);
        }
        if self.sent == self.length {
            return Ok(ControlWrite {
                accepted: 0,
                complete: true,
                blocked: false,
            });
        }
        match send(&self.bytes[self.sent..self.length]) {
            Ok(count) if count <= self.length - self.sent => {
                self.bytes[self.sent..self.sent + count].zeroize();
                self.sent += count;
                Ok(ControlWrite {
                    accepted: count,
                    complete: self.sent == self.length,
                    blocked: count == 0,
                })
            }
            Err(noq_proto::WriteError::Blocked) => Ok(ControlWrite {
                accepted: 0,
                complete: false,
                blocked: true,
            }),
            Ok(_) | Err(_) => {
                self.failed = true;
                self.bytes.zeroize();
                Err(TransportError::Stream)
            }
        }
    }
}

impl Drop for ControlWriter {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_partial_write_retains_exact_suffix_across_backpressure() {
        let input = [42; CAPACITY];
        for first in 0..CAPACITY {
            let mut writer = ControlWriter::from_bytes(&input).expect("writer");
            let result = writer
                .write_with(|bytes| {
                    assert_eq!(bytes, input);
                    Ok(first)
                })
                .expect("partial");
            assert_eq!(result.accepted, first);
            assert!(!result.complete);
            assert!(writer.bytes[..first].iter().all(|byte| *byte == 0));
            let result = writer
                .write_with(|bytes| {
                    assert_eq!(bytes, &input[first..]);
                    Err(noq_proto::WriteError::Blocked)
                })
                .expect("blocked");
            assert!(result.blocked);
            let result = writer
                .write_with(|bytes| {
                    assert_eq!(bytes, &input[first..]);
                    Ok(bytes.len())
                })
                .expect("remaining");
            assert!(result.complete);
            assert!(writer.bytes.iter().all(|byte| *byte == 0));
            assert!(
                writer
                    .write_with(|_| panic!("duplicate write"))
                    .expect("already complete")
                    .complete
            );
        }
    }

    #[test]
    fn failure_and_invalid_count_scrub_and_latch() {
        for outcome in [Ok(CAPACITY + 1), Err(noq_proto::WriteError::ClosedStream)] {
            let mut writer = ControlWriter::from_bytes(&[42; CAPACITY]).expect("writer");
            assert!(writer.write_with(|_| outcome).is_err());
            assert!(writer.bytes.iter().all(|byte| *byte == 0));
            assert!(writer
                .write_with(|_| panic!("retry after terminal error"))
                .is_err());
        }
        assert!(ControlWriter::from_bytes(&[0; CAPACITY + 1]).is_err());
    }
}
