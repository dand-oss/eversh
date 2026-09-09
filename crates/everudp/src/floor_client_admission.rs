//! Client half of the disposable floor's bounded capability negotiation.
use crate::floor_admission::{AdmissionPoll, CLIENT_CAPABILITY, SERVER_CAPABILITY};
use crate::floor_control_writer::ControlWriter;
use crate::transport::TransportError;
use crate::wire::ConnectionRole;
use crate::{ClientHello, Limits};
use noq_proto::{Connection, Dir, StreamId, VarInt};
use std::time::Instant;

pub struct ClientAdmission {
    hello: Option<ControlWriter>,
    capability: Option<ControlWriter>,
    stream: Option<StreamId>,
    reply: [u8; 8],
    received: usize,
    ready: bool,
    failed: bool,
    deadline: Instant,
}

impl ClientAdmission {
    pub fn new(
        hello: &ClientHello,
        limits: &Limits,
        deadline: Instant,
    ) -> Result<Self, TransportError> {
        if !matches!(hello, ClientHello::Initial { .. }) || hello.role() != ConnectionRole::Writer {
            return Err(TransportError::Rejected);
        }
        Ok(Self {
            hello: Some(ControlWriter::hello(hello, limits)?),
            capability: Some(ControlWriter::from_bytes(&CLIENT_CAPABILITY)?),
            stream: None,
            reply: [0; 8],
            received: 0,
            ready: false,
            failed: false,
            deadline,
        })
    }

    /// One bounded operation per call. Ready requires receipt of the complete
    /// exact server capability; queued client writes alone do not grant it.
    pub fn poll(
        &mut self,
        connection: &mut Connection,
        now: Instant,
    ) -> Result<AdmissionPoll, TransportError> {
        if self.failed {
            return Err(TransportError::Rejected);
        }
        let result = if connection.is_closed() {
            Err(TransportError::Connection)
        } else if !self.ready && now >= self.deadline {
            Err(TransportError::Timeout)
        } else {
            self.poll_inner(connection)
        };
        if result.is_err() {
            self.failed = true;
            self.ready = false;
            self.hello = None;
            self.capability = None;
            connection.close(
                now,
                VarInt::from_u32(0x4555),
                bytes::Bytes::from_static(b"everudp admission rejected"),
            );
        }
        result
    }

    fn poll_inner(&mut self, connection: &mut Connection) -> Result<AdmissionPoll, TransportError> {
        if connection.crypto_session().is_handshaking() {
            return Ok(AdmissionPoll::Pending { progressed: false });
        }
        let stream = match self.stream {
            Some(stream) => stream,
            None => match connection.streams().open(Dir::Bi) {
                Some(stream) => {
                    self.stream = Some(stream);
                    stream
                }
                None => return Ok(AdmissionPoll::Pending { progressed: false }),
            },
        };
        if self.ready {
            return Ok(AdmissionPoll::Ready { stream });
        }
        if let Some(writer) = self.hello.as_mut() {
            let written = writer.write_stream(connection, stream)?;
            if written.complete {
                self.hello = None;
            }
            return Ok(AdmissionPoll::Pending {
                progressed: written.accepted != 0,
            });
        }
        if let Some(writer) = self.capability.as_mut() {
            let written = writer.write_stream(connection, stream)?;
            if written.complete {
                self.capability = None;
            }
            return Ok(AdmissionPoll::Pending {
                progressed: written.accepted != 0,
            });
        }
        let mut recv = connection.recv_stream(stream);
        let mut chunks = recv.read(true).map_err(|_| TransportError::Stream)?;
        let chunk = chunks.next(self.reply.len() - self.received);
        let _ = chunks.finalize(); // Caller drives protocol after each poll.
        match chunk {
            Ok(Some(chunk)) if !chunk.bytes.is_empty() => {
                let end = self.received + chunk.bytes.len();
                self.reply[self.received..end].copy_from_slice(&chunk.bytes);
                self.received = end;
            }
            Err(noq_proto::ReadError::Blocked) => {
                return Ok(AdmissionPoll::Pending { progressed: false })
            }
            _ => return Err(TransportError::Stream),
        }
        if self.received == self.reply.len() {
            if self.reply != SERVER_CAPABILITY {
                return Err(TransportError::Rejected);
            }
            self.ready = true;
            Ok(AdmissionPoll::Ready { stream })
        } else {
            Ok(AdmissionPoll::Pending { progressed: true })
        }
    }
}
