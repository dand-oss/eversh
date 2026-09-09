//! Native `noq-proto` reliable-stream admission for the stream-floor experiment.
//!
//! This adapter deliberately performs one bounded stream operation per call.
//! The owner must call the client/server `poll` method after a corresponding
//! `Readable`/`Writable` event, on deadline expiry, and again after reported
//! progress (subject to the owner's fairness budget). Drive protocol transmission
//! after every result, including Ready and errors: both may leave frames pending.

use crate::stream_floor_handshake::{ClientHandshake, ServerHandshake};
use crate::stream_floor_io::{ReadProgress, RecordReader};
use crate::stream_floor_protocol::{stream_role, validate_negotiated_profile};
use crate::transport::{floor_authorize_initial, TransportError, CONTROL_STREAM_PRIORITY};
use crate::wire::StreamRole;
use crate::{ClientHello, InvitationStore, Limits};
use noq_proto::{Connection, Dir, Side, StreamId};
use std::time::Instant;

const CLOSE_CODE: noq_proto::VarInt = noq_proto::VarInt::from_u32(0x4555);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeHandshakePoll {
    Pending {
        progressed: bool,
        should_transmit: bool,
    },
    Ready {
        stream: StreamId,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeControl {
    pub stream: StreamId,
}

pub struct NativeClientHandshake {
    handshake: ClientHandshake,
    reader: RecordReader,
    stream: Option<StreamId>,
    deadline: Instant,
    failed: bool,
}

impl NativeClientHandshake {
    pub fn new(
        hello: ClientHello,
        limits: Limits,
        deadline: Instant,
    ) -> Result<Self, TransportError> {
        Ok(Self {
            handshake: ClientHandshake::new(hello, limits)?,
            reader: RecordReader::new(StreamRole::Control, limits)?,
            stream: None,
            deadline,
            failed: false,
        })
    }

    pub fn ready(&self) -> bool {
        !self.failed && self.handshake.ready()
    }
    pub fn control(&self) -> Option<NativeControl> {
        self.ready()
            .then(|| self.stream.map(|stream| NativeControl { stream }))
            .flatten()
    }

    pub fn poll(
        &mut self,
        connection: &mut Connection,
        now: Instant,
    ) -> Result<NativeHandshakePoll, TransportError> {
        let result = self.poll_inner(connection, now);
        match result {
            Ok(result) => Ok(result),
            Err(error) => self.fail(connection, now, error),
        }
    }

    fn poll_inner(
        &mut self,
        connection: &mut Connection,
        now: Instant,
    ) -> Result<NativeHandshakePoll, TransportError> {
        if self.failed {
            return Err(TransportError::Rejected);
        }
        if !self.ready() && now >= self.deadline {
            return Err(TransportError::Timeout);
        }
        if connection.is_closed() {
            return Err(TransportError::Connection);
        }
        if connection.crypto_session().is_handshaking() {
            return Ok(NativeHandshakePoll::Pending {
                progressed: false,
                should_transmit: false,
            });
        }
        let stream = match self.stream {
            Some(stream) => stream,
            None => {
                validate_negotiated_profile(
                    connection.crypto_session().handshake_data(),
                    connection.datagrams().max_size(),
                )?;
                let Some(stream) = connection.streams().open(Dir::Bi) else {
                    return Ok(NativeHandshakePoll::Pending {
                        progressed: false,
                        should_transmit: false,
                    });
                };
                require_client_control(stream)?;
                connection
                    .send_stream(stream)
                    .set_priority(CONTROL_STREAM_PRIORITY)
                    .map_err(|_| TransportError::Stream)?;
                self.stream = Some(stream);
                stream
            }
        };
        if !self.handshake.ready() && !self.handshake.outgoing()?.is_complete() {
            let progress = self
                .handshake
                .outgoing()?
                .write_native(connection, stream)
                .map_err(TransportError::from)?;
            return Ok(NativeHandshakePoll::Pending {
                progressed: progress.accepted != 0,
                should_transmit: false,
            });
        }
        if self.handshake.ready() {
            return Ok(NativeHandshakePoll::Ready { stream });
        }
        let read = self.reader.read_native(connection, stream);
        match read.result {
            Ok(ReadProgress::Record(_)) => {
                let record = self.reader.record().ok_or(TransportError::Rejected)?;
                self.handshake.receive_reply(record)?;
                self.reader.consume_record();
                if self.handshake.ready() {
                    Ok(NativeHandshakePoll::Ready { stream })
                } else {
                    Err(TransportError::Rejected)
                }
            }
            Ok(ReadProgress::Consumed(_)) => Ok(NativeHandshakePoll::Pending {
                progressed: !matches!(read.result, Ok(ReadProgress::Consumed(0))),
                should_transmit: read.should_transmit,
            }),
            Ok(ReadProgress::CleanEof) => Err(TransportError::Stream),
            Err(error) => Err(error.into()),
        }
    }

    fn fail<T>(
        &mut self,
        connection: &mut Connection,
        now: Instant,
        error: TransportError,
    ) -> Result<T, TransportError> {
        self.failed = true;
        connection.close(
            now,
            CLOSE_CODE,
            bytes::Bytes::from_static(b"everudp stream-floor handshake failed"),
        );
        Err(error)
    }
}

pub struct NativeServerHandshake {
    handshake: ServerHandshake,
    reader: RecordReader,
    stream: Option<StreamId>,
    deadline: Instant,
    failed: bool,
}

impl NativeServerHandshake {
    pub fn new(limits: Limits, deadline: Instant) -> Result<Self, TransportError> {
        Ok(Self {
            handshake: ServerHandshake::new(limits)?,
            reader: RecordReader::new(StreamRole::Control, limits)?,
            stream: None,
            deadline,
            failed: false,
        })
    }

    pub fn ready(&self) -> bool {
        !self.failed && self.handshake.ready()
    }
    pub fn control(&self) -> Option<NativeControl> {
        self.ready()
            .then(|| self.stream.map(|stream| NativeControl { stream }))
            .flatten()
    }

    pub fn poll(
        &mut self,
        connection: &mut Connection,
        invitations: &mut InvitationStore,
        now: Instant,
        now_ms: u64,
    ) -> Result<NativeHandshakePoll, TransportError> {
        let result = self.poll_inner(connection, invitations, now, now_ms);
        match result {
            Ok(result) => Ok(result),
            Err(error) => self.fail(connection, now, error),
        }
    }

    fn poll_inner(
        &mut self,
        connection: &mut Connection,
        invitations: &mut InvitationStore,
        now: Instant,
        now_ms: u64,
    ) -> Result<NativeHandshakePoll, TransportError> {
        if self.failed {
            return Err(TransportError::Rejected);
        }
        if !self.ready() && now >= self.deadline {
            return Err(TransportError::Timeout);
        }
        if connection.is_closed() {
            return Err(TransportError::Connection);
        }
        if connection.crypto_session().is_handshaking() {
            return Ok(NativeHandshakePoll::Pending {
                progressed: false,
                should_transmit: false,
            });
        }
        let stream = match self.stream {
            Some(stream) => stream,
            None => {
                validate_negotiated_profile(
                    connection.crypto_session().handshake_data(),
                    connection.datagrams().max_size(),
                )?;
                let Some(stream) = connection.streams().accept(Dir::Bi) else {
                    return Ok(NativeHandshakePoll::Pending {
                        progressed: false,
                        should_transmit: false,
                    });
                };
                require_client_control(stream)?;
                connection
                    .send_stream(stream)
                    .set_priority(CONTROL_STREAM_PRIORITY)
                    .map_err(|_| TransportError::Stream)?;
                self.stream = Some(stream);
                stream
            }
        };
        if !self.handshake.ready() && self.handshake.outgoing().is_err() {
            let read = self.reader.read_native(connection, stream);
            match read.result {
                Ok(ReadProgress::Record(_)) => {
                    let record = self.reader.record().ok_or(TransportError::Rejected)?;
                    self.handshake.receive_hello(record, |hello| {
                        let takeover =
                            floor_authorize_initial(connection, hello, invitations, now_ms)?;
                        if takeover {
                            return Err(TransportError::Rejected);
                        }
                        Ok(false)
                    })?;
                    self.reader.consume_record();
                    return Ok(NativeHandshakePoll::Pending {
                        progressed: true,
                        should_transmit: read.should_transmit,
                    });
                }
                Ok(ReadProgress::Consumed(_)) => {
                    return Ok(NativeHandshakePoll::Pending {
                        progressed: !matches!(read.result, Ok(ReadProgress::Consumed(0))),
                        should_transmit: read.should_transmit,
                    })
                }
                Ok(ReadProgress::CleanEof) => return Err(TransportError::Stream),
                Err(error) => return Err(error.into()),
            }
        }
        if !self.handshake.ready() {
            let progress = self
                .handshake
                .outgoing()?
                .write_native(connection, stream)
                .map_err(TransportError::from)?;
            if progress.complete {
                self.handshake.finish_reply()?;
            }
            return if self.handshake.ready() {
                Ok(NativeHandshakePoll::Ready { stream })
            } else {
                Ok(NativeHandshakePoll::Pending {
                    progressed: progress.accepted != 0,
                    should_transmit: false,
                })
            };
        }
        Ok(NativeHandshakePoll::Ready { stream })
    }

    fn fail<T>(
        &mut self,
        connection: &mut Connection,
        now: Instant,
        error: TransportError,
    ) -> Result<T, TransportError> {
        self.failed = true;
        connection.close(
            now,
            CLOSE_CODE,
            bytes::Bytes::from_static(b"everudp stream-floor handshake failed"),
        );
        Err(error)
    }
}

fn require_client_control(stream: StreamId) -> Result<(), TransportError> {
    if stream_role(stream)? != StreamRole::Control
        || stream.initiator() != Side::Client
        || stream.dir() != Dir::Bi
    {
        return Err(TransportError::Rejected);
    }
    Ok(())
}
