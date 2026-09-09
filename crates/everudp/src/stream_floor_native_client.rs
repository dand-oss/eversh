//! Native client scheduler for the disposable stream comparison. Local Read
//! and Write adapters MUST be nonblocking. Drain native events before polling,
//! drive protocol after every result (including errors), and reschedule positive
//! progress within a fairness budget. Local readiness is explicitly rearmed.

use crate::stream_floor_app::{InputSource, OutputSink};
use crate::stream_floor_io::{ReadProgress, RecordReader};
use crate::stream_floor_protocol::{stream_role, StreamLayout};
use crate::transport::{TransportError, INPUT_STREAM_PRIORITY};
use crate::wire::StreamRole;
use crate::Limits;
use noq_proto::{Connection, Dir, Event, StreamEvent, StreamId};
use std::io::{ErrorKind, Read, Write};
use std::time::Instant;

#[derive(Debug, PartialEq, Eq)]
pub enum ClientPoll {
    Pending {
        progressed: bool,
        should_transmit: bool,
    },
    Complete {
        bytes: u64,
    },
}

pub struct NativeClient {
    layout: StreamLayout,
    control_id: StreamId,
    input_id: Option<StreamId>,
    output_id: Option<StreamId>,
    control: RecordReader,
    source: InputSource,
    sink: OutputSink,
    control_readable: bool,
    input_writable: bool,
    output_readable: bool,
    local_readable: bool,
    local_writable: bool,
    input_fin: bool,
    input_acked: bool,
    output_eof: bool,
    failed: bool,
}

impl NativeClient {
    /// Requires completed authenticated admission on control_id.
    pub fn new(control_id: StreamId, limits: Limits) -> Result<Self, TransportError> {
        let mut layout = StreamLayout::default();
        if layout.register(control_id)? != StreamRole::Control {
            return Err(TransportError::Rejected);
        }
        Ok(Self {
            layout,
            control_id,
            input_id: None,
            output_id: None,
            control: RecordReader::new(StreamRole::Control, limits)?,
            source: InputSource::new(limits)?,
            sink: OutputSink::new(limits)?,
            control_readable: true,
            input_writable: true,
            output_readable: true,
            local_readable: true,
            local_writable: true,
            input_fin: false,
            input_acked: false,
            output_eof: false,
            failed: false,
        })
    }

    pub fn local_input_ready(&mut self) {
        self.local_readable = true;
    }
    pub fn local_output_ready(&mut self) {
        self.local_writable = true;
    }

    /// Poll local descriptors only when a blocked operation can be retried.
    /// Watching writable stdout while no output is pending would busy-spin.
    pub fn local_interests(&mut self) -> (bool, bool) {
        (
            !self.failed && !self.local_readable && self.source.buffer().is_some(),
            !self.failed && !self.local_writable && self.sink.pending().is_some(),
        )
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
            noq_proto::VarInt::from_u32(0x4555),
            bytes::Bytes::from_static(b"everudp stream-floor client failed"),
        );
        Err(error)
    }

    pub fn event(
        &mut self,
        connection: &mut Connection,
        event: &Event,
        now: Instant,
    ) -> Result<(), TransportError> {
        let result = self.event_inner(event);
        match result {
            Ok(()) => Ok(()),
            Err(error) => self.fail(connection, now, error),
        }
    }

    fn event_inner(&mut self, event: &Event) -> Result<(), TransportError> {
        if self.failed {
            return Err(TransportError::Rejected);
        }
        match event {
            Event::Stream(StreamEvent::Opened { .. } | StreamEvent::Available { .. }) => {}
            Event::Stream(StreamEvent::Readable { id }) => {
                if *id == self.control_id {
                    self.control_readable = true;
                } else if stream_role(*id)? == StreamRole::Output {
                    self.output_readable = true;
                } else {
                    return Err(TransportError::Stream);
                }
            }
            Event::Stream(StreamEvent::Writable { id }) => {
                if Some(*id) == self.input_id {
                    self.input_writable = true;
                } else if *id != self.control_id {
                    return Err(TransportError::Stream);
                }
            }
            Event::Stream(StreamEvent::Finished { id })
                if Some(*id) == self.input_id && self.input_fin =>
            {
                self.input_acked = true
            }
            Event::HandshakeDataReady | Event::Connected | Event::HandshakeConfirmed => {}
            _ => return Err(TransportError::Stream),
        }
        Ok(())
    }

    pub fn poll<R: Read, W: Write>(
        &mut self,
        connection: &mut Connection,
        now: Instant,
        local_input: &mut R,
        local_output: &mut W,
    ) -> Result<ClientPoll, TransportError> {
        if self.failed {
            return Err(TransportError::Rejected);
        }
        let result = self.poll_inner(connection, local_input, local_output);
        match result {
            Ok(result) => Ok(result),
            Err(error) => self.fail(connection, now, error),
        }
    }

    fn poll_inner<R: Read, W: Write>(
        &mut self,
        connection: &mut Connection,
        local_input: &mut R,
        local_output: &mut W,
    ) -> Result<ClientPoll, TransportError> {
        if connection.is_closed() {
            return Err(TransportError::Connection);
        }
        if connection.streams().accept(Dir::Bi).is_some() {
            return Err(TransportError::Rejected);
        }
        if self.input_id.is_none() {
            if let Some(id) = connection.streams().open(Dir::Uni) {
                if self.layout.register(id)? != StreamRole::Input {
                    return Err(TransportError::Rejected);
                }
                connection
                    .send_stream(id)
                    .set_priority(INPUT_STREAM_PRIORITY)
                    .map_err(|_| TransportError::Stream)?;
                self.input_id = Some(id);
            }
        }
        if self.output_id.is_none() {
            if let Some(id) = connection.streams().accept(Dir::Uni) {
                if self.layout.register(id)? != StreamRole::Output {
                    return Err(TransportError::Rejected);
                }
                self.output_id = Some(id);
            }
        }
        if self.output_id.is_some() && connection.streams().accept(Dir::Uni).is_some() {
            return Err(TransportError::Rejected);
        }
        let mut progressed = false;
        let mut should_transmit = false;
        if self.control_readable {
            let read = self.control.read_native(connection, self.control_id);
            should_transmit |= read.should_transmit;
            match read.result? {
                ReadProgress::Consumed(0) => self.control_readable = false,
                _ => return Err(TransportError::Stream), // no unsolicited control response
            }
        }
        if self.local_readable {
            if let Some(buffer) = self.source.buffer() {
                match local_input.read(buffer) {
                    Ok(count) => {
                        self.source.commit_read(count)?;
                        progressed = true;
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        self.local_readable = false
                    }
                    Err(error) if error.kind() == ErrorKind::Interrupted => progressed = true,
                    Err(error) => return Err(TransportError::Io(error)),
                }
            }
        }
        if let Some(input) = self.input_id {
            if self.input_writable {
                let write = self
                    .source
                    .writer()
                    .ok_or(TransportError::Rejected)?
                    .write_native(connection, input)?;
                progressed |= write.accepted != 0;
                if write.blocked {
                    self.input_writable = false;
                }
            }
            if self.source.finish_ready() && !self.input_fin {
                connection
                    .send_stream(input)
                    .finish()
                    .map_err(|_| TransportError::Stream)?;
                self.input_fin = true;
                progressed = true;
                should_transmit = true;
            }
        }
        if let Some(output) = self
            .output_id
            .filter(|_| self.output_readable && !self.output_eof)
        {
            if let Some(reader) = self.sink.reader() {
                let read = reader.read_native(connection, output);
                should_transmit |= read.should_transmit;
                match read.result? {
                    ReadProgress::Consumed(count) => {
                        progressed |= count != 0;
                        if count == 0 {
                            self.output_readable = false;
                        }
                    }
                    ReadProgress::Record(_) => progressed |= self.sink.stage()?,
                    ReadProgress::CleanEof => self.output_eof = true,
                }
            }
        }
        if self.local_writable {
            if let Some(bytes) = self.sink.pending() {
                match local_output.write(bytes) {
                    Ok(0) => return Err(TransportError::Io(ErrorKind::WriteZero.into())),
                    Ok(count) => {
                        self.sink.commit(count)?;
                        progressed = true;
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        self.local_writable = false
                    }
                    Err(error) if error.kind() == ErrorKind::Interrupted => progressed = true,
                    Err(error) => return Err(TransportError::Io(error)),
                }
            }
        }
        if self.output_eof {
            if !self.input_fin || self.sink.bytes_delivered() != self.source.bytes_read() {
                return Err(TransportError::Rejected);
            }
            if self.input_acked && self.layout.complete() {
                return Ok(ClientPoll::Complete {
                    bytes: self.sink.bytes_delivered(),
                });
            }
        }
        Ok(ClientPoll::Pending {
            progressed,
            should_transmit,
        })
    }
}
