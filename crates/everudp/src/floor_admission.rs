//! Bounded server admission for the disposable single-owner floor.
use crate::floor_control::HelloReader;
use crate::floor_control_writer::ControlWriter;
use crate::transport::{floor_authorize_initial, TransportError};
use crate::wire::ConnectionRole;
use crate::{ClientHello, InvitationStore, Limits};
use noq_proto::{Connection, Dir, StreamId, VarInt};
use std::time::Instant;

// Frozen v4 floor capability bytes, identical to everudp-floor's safe control.
pub const CLIENT_CAPABILITY: [u8; 8] = [
    b'E',
    b'U',
    crate::reliable_datagram::VERSION,
    1,
    4,
    0,
    4,
    0xb0,
];
pub const SERVER_CAPABILITY: [u8; 8] = [
    b'E',
    b'U',
    crate::reliable_datagram::VERSION,
    2,
    4,
    0,
    4,
    0xb0,
];

#[derive(Debug, PartialEq, Eq)]
pub enum AdmissionPoll {
    Pending { progressed: bool },
    Ready { stream: StreamId },
}

pub struct ServerAdmission {
    reader: HelloReader,
    stream: Option<StreamId>,
    hello: Option<ClientHello>,
    capability: [u8; 8],
    received: usize,
    reply: Option<ControlWriter>,
    ready: bool,
    failed: bool,
    deadline: Instant,
}

impl ServerAdmission {
    pub fn new(limits: Limits, deadline: Instant) -> Result<Self, TransportError> {
        Ok(Self {
            reader: HelloReader::new(limits)?,
            stream: None,
            hello: None,
            capability: [0; 8],
            received: 0,
            reply: None,
            ready: false,
            failed: false,
            deadline,
        })
    }

    /// Returns the admitted identity only after capability reply acceptance.
    pub fn admitted_hello(&self) -> Option<&ClientHello> {
        if self.ready {
            self.hello.as_ref()
        } else {
            None
        }
    }

    /// One bounded stream operation per call. The caller must not handle
    /// application datagrams before Ready, and must drive protocol transmits
    /// after each turn (including error/flow-control transitions).
    pub fn poll(
        &mut self,
        connection: &mut Connection,
        invitations: &mut InvitationStore,
        now: Instant,
        now_ms: u64,
    ) -> Result<AdmissionPoll, TransportError> {
        if self.failed {
            return Err(TransportError::Rejected);
        }
        let result = if connection.is_closed() {
            Err(TransportError::Connection)
        } else if !self.ready && now >= self.deadline {
            Err(TransportError::Timeout)
        } else {
            self.poll_inner(connection, invitations, now_ms)
        };
        if result.is_err() {
            self.failed = true;
            self.ready = false;
            self.hello = None;
            self.reply = None;
            self.reader.incomplete_eof();
            connection.close(
                now,
                VarInt::from_u32(0x4555),
                bytes::Bytes::from_static(b"everudp admission rejected"),
            );
        }
        result
    }

    fn poll_inner(
        &mut self,
        connection: &mut Connection,
        invitations: &mut InvitationStore,
        now_ms: u64,
    ) -> Result<AdmissionPoll, TransportError> {
        if connection.crypto_session().is_handshaking() {
            return Ok(AdmissionPoll::Pending { progressed: false });
        }
        let stream = match self.stream {
            Some(stream) => stream,
            None => match connection.streams().accept(Dir::Bi) {
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
        if self.hello.is_none() {
            let read = self.reader.read_stream(connection, stream)?;
            if let Some(hello) = read.hello {
                if hello.role() != ConnectionRole::Writer {
                    return Err(TransportError::Rejected);
                }
                floor_authorize_initial(connection, &hello, invitations, now_ms)?;
                self.hello = Some(hello);
            }
            return Ok(AdmissionPoll::Pending {
                progressed: read.progressed,
            });
        }
        if self.received < self.capability.len() {
            let mut recv = connection.recv_stream(stream);
            let mut chunks = recv.read(true).map_err(|_| TransportError::Stream)?;
            let chunk = chunks.next(self.capability.len() - self.received);
            let _ = chunks.finalize(); // Caller drives protocol after every poll.
            match chunk {
                Ok(Some(chunk)) if !chunk.bytes.is_empty() => {
                    let end = self.received + chunk.bytes.len();
                    self.capability[self.received..end].copy_from_slice(&chunk.bytes);
                    self.received = end;
                }
                Err(noq_proto::ReadError::Blocked) => {
                    return Ok(AdmissionPoll::Pending { progressed: false })
                }
                _ => return Err(TransportError::Stream),
            }
            if self.received == self.capability.len() {
                if self.capability != CLIENT_CAPABILITY {
                    return Err(TransportError::Rejected);
                }
                self.reply = Some(ControlWriter::from_bytes(&SERVER_CAPABILITY)?);
            }
            return Ok(AdmissionPoll::Pending { progressed: true });
        }
        let written = self
            .reply
            .as_mut()
            .ok_or(TransportError::Rejected)?
            .write_stream(connection, stream)?;
        if written.complete {
            self.ready = true;
            self.reply = None;
            Ok(AdmissionPoll::Ready { stream })
        } else {
            Ok(AdmissionPoll::Pending {
                progressed: written.accepted != 0,
            })
        }
    }
}
