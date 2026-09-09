//! Native `noq-proto` three-stream echo scheduler for the bounded floor.
//!
//! The server owns the application scheduler. Its caller drains every native
//! event in FIFO order, passes each event to [`NativeServerEcho::event`], and
//! calls [`NativeServerEcho::poll`] after protocol work. Reads and writes are
//! bounded by the shared record adapter; blocked readiness is retained until a
//! corresponding Writable/Readable event arrives. Drain all retained events
//! before testing completion. Drive protocol transmission after every poll,
//! including errors, and reschedule positive progress within a fairness budget.

use crate::stream_floor_app::EchoRelay;
use crate::stream_floor_io::ReadProgress;
use crate::stream_floor_protocol::{stream_role, StreamLayout};
use crate::transport::{TransportError, OUTPUT_STREAM_PRIORITY};
use crate::wire::StreamRole;
use crate::Limits;
use noq_proto::{Connection, Dir, Event, StreamEvent, StreamId};
use std::time::Instant;

const CLOSE_CODE: noq_proto::VarInt = noq_proto::VarInt::from_u32(0x4555);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeEchoPoll {
    Pending {
        progressed: bool,
        should_transmit: bool,
    },
    Complete,
}

pub struct NativeServerEcho {
    layout: StreamLayout,
    control: EchoRelay,
    data: EchoRelay,
    control_id: StreamId,
    input_id: Option<StreamId>,
    output_id: Option<StreamId>,
    control_readable: bool,
    control_writable: bool,
    input_readable: bool,
    output_writable: bool,
    input_eof: bool,
    output_finished: bool,
    output_acked: bool,
    failed: bool,
}

fn register(
    layout: &mut StreamLayout,
    id: StreamId,
    expected: StreamRole,
) -> Result<(), TransportError> {
    if layout.register(id)? != expected {
        return Err(TransportError::Stream);
    }
    Ok(())
}

impl NativeServerEcho {
    pub fn new(control_id: StreamId, limits: Limits) -> Result<Self, TransportError> {
        if stream_role(control_id)? != StreamRole::Control {
            return Err(TransportError::Stream);
        }
        let mut layout = StreamLayout::default();
        register(&mut layout, control_id, StreamRole::Control)?;
        Ok(Self {
            layout,
            control: EchoRelay::control(limits)?,
            data: EchoRelay::new(limits)?,
            control_id,
            input_id: None,
            output_id: None,
            control_readable: true,
            control_writable: true,
            input_readable: true,
            output_writable: true,
            input_eof: false,
            output_finished: false,
            output_acked: false,
            failed: false,
        })
    }

    /// Process one event in FIFO order. All terminal events latch failure.
    pub fn event(
        &mut self,
        connection: &mut Connection,
        event: &Event,
        now: Instant,
    ) -> Result<(), TransportError> {
        let result = self.event_inner(event);
        if result.is_err() {
            self.failed = true;
            connection.close(
                now,
                CLOSE_CODE,
                bytes::Bytes::from_static(b"everudp stream-floor echo failed"),
            );
        }
        result
    }

    fn event_inner(&mut self, event: &Event) -> Result<(), TransportError> {
        if self.failed {
            return Err(TransportError::Rejected);
        }
        match event {
            Event::Stream(StreamEvent::Opened { .. })
            | Event::Stream(StreamEvent::Available { .. }) => Ok(()),
            Event::Stream(StreamEvent::Readable { id }) => {
                if *id == self.control_id {
                    self.control_readable = true;
                } else if Some(*id) == self.input_id || stream_role(*id)? == StreamRole::Input {
                    self.input_readable = true;
                } else {
                    return Err(TransportError::Stream);
                }
                Ok(())
            }
            Event::Stream(StreamEvent::Writable { id }) => {
                if *id == self.control_id {
                    self.control_writable = true;
                } else if Some(*id) == self.output_id || stream_role(*id)? == StreamRole::Output {
                    self.output_writable = true;
                } else {
                    return Err(TransportError::Stream);
                }
                Ok(())
            }
            Event::Stream(StreamEvent::Finished { id }) => {
                if Some(*id) == self.output_id && self.output_finished {
                    self.output_acked = true;
                    Ok(())
                } else {
                    Err(TransportError::Stream)
                }
            }
            Event::Stream(StreamEvent::Stopped { .. })
            | Event::ConnectionLost { .. }
            | Event::DatagramReceived
            | Event::DatagramsUnblocked
            | Event::Path(_)
            | Event::NatTraversal(_) => Err(TransportError::Stream),
            Event::HandshakeDataReady | Event::Connected | Event::HandshakeConfirmed => Ok(()),
        }
    }

    fn ensure_streams(&mut self, connection: &mut Connection) -> Result<(), TransportError> {
        if connection.streams().accept(Dir::Bi).is_some() {
            return Err(TransportError::Stream);
        }
        if self.input_id.is_none() {
            if let Some(id) = connection.streams().accept(Dir::Uni) {
                register(&mut self.layout, id, StreamRole::Input)?;
                self.input_id = Some(id);
            }
        }
        if self.input_id.is_some() && connection.streams().accept(Dir::Uni).is_some() {
            return Err(TransportError::Stream);
        }
        if self.output_id.is_none() {
            if let Some(id) = connection.streams().open(Dir::Uni) {
                register(&mut self.layout, id, StreamRole::Output)?;
                connection
                    .send_stream(id)
                    .set_priority(OUTPUT_STREAM_PRIORITY)
                    .map_err(|_| TransportError::Stream)?;
                self.output_id = Some(id);
            }
        }
        Ok(())
    }

    /// Drive at most one bounded read and write per active stream.
    pub fn poll(
        &mut self,
        connection: &mut Connection,
        now: Instant,
    ) -> Result<NativeEchoPoll, TransportError> {
        if self.failed {
            return Err(TransportError::Rejected);
        }
        if connection.is_closed() {
            self.failed = true;
            return Err(TransportError::Connection);
        }
        let result = self.poll_inner(connection);
        if result.is_err() {
            self.failed = true;
            connection.close(
                now,
                CLOSE_CODE,
                bytes::Bytes::from_static(b"everudp stream-floor echo failed"),
            );
        }
        result
    }

    fn poll_inner(
        &mut self,
        connection: &mut Connection,
    ) -> Result<NativeEchoPoll, TransportError> {
        self.ensure_streams(connection)?;
        let mut progressed = false;
        let mut should_transmit = false;
        if self.control_readable {
            if let Some(reader) = self.control.input() {
                let read = reader.read_native(connection, self.control_id);
                should_transmit |= read.should_transmit;
                match read.result.map_err(TransportError::from)? {
                    ReadProgress::Consumed(n) => {
                        progressed |= n != 0;
                        if n == 0 {
                            self.control_readable = false;
                        }
                    }
                    ReadProgress::Record(_) => progressed |= self.control.stage()?,
                    ReadProgress::CleanEof => return Err(TransportError::Stream),
                }
            }
        }
        if self.control_writable {
            if let Some(writer) = self.control.output() {
                let write = writer
                    .write_native(connection, self.control_id)
                    .map_err(TransportError::from)?;
                progressed |= write.accepted != 0;
                if write.blocked {
                    self.control_writable = false;
                }
            }
        }
        progressed |= self.control.complete_output()?;
        let (Some(input), Some(output)) = (self.input_id, self.output_id) else {
            return Ok(NativeEchoPoll::Pending {
                progressed,
                should_transmit,
            });
        };
        if !self.input_eof && self.input_readable {
            if let Some(reader) = self.data.input() {
                let read = reader.read_native(connection, input);
                should_transmit |= read.should_transmit;
                match read.result.map_err(TransportError::from)? {
                    ReadProgress::Consumed(n) => {
                        progressed |= n != 0;
                        if n == 0 {
                            self.input_readable = false;
                        }
                    }
                    ReadProgress::Record(_) => progressed |= self.data.stage()?,
                    ReadProgress::CleanEof => self.input_eof = true,
                }
            }
        }
        if self.output_writable {
            if let Some(writer) = self.data.output() {
                let write = writer
                    .write_native(connection, output)
                    .map_err(TransportError::from)?;
                progressed |= write.accepted != 0;
                if write.blocked {
                    self.output_writable = false;
                }
            }
        }
        progressed |= self.data.complete_output()?;
        if self.input_eof && self.data.output().is_none() && !self.output_finished {
            connection
                .send_stream(output)
                .finish()
                .map_err(|_| TransportError::Stream)?;
            self.output_finished = true;
            progressed = true;
            should_transmit = true;
        }
        if self.input_eof && self.output_finished && self.output_acked {
            return Ok(NativeEchoPoll::Complete);
        }
        Ok(NativeEchoPoll::Pending {
            progressed,
            should_transmit,
        })
    }

    pub fn complete(&self) -> bool {
        self.input_eof && self.output_finished && self.output_acked && !self.failed
    }
    /// True only after the native stream writer reports Blocked and before a
    /// Writable event. Exposed for the experiment's flow-control evidence.
    pub fn output_blocked(&self) -> bool {
        !self.output_writable
    }
    pub fn layout_complete(&self) -> bool {
        self.layout.complete()
    }
}
