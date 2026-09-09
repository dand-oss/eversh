//! Shared admission ordering for both disposable stream drivers.
use crate::handshake::{ClientHello, ServerHello};
use crate::stream_floor_io::RecordWriter;
use crate::stream_floor_protocol::{validate_client_hello, validate_server_hello};
use crate::transport::TransportError;
use crate::wire::{ConnectionRole, Kind, Record, StreamRole};
use crate::Limits;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    AwaitHello,
    SendingReply,
    Ready,
    Failed,
}

pub struct ServerHandshake {
    phase: Phase,
    outgoing: RecordWriter,
}

impl ServerHandshake {
    pub fn new(limits: Limits) -> Result<Self, TransportError> {
        Ok(Self {
            phase: Phase::AwaitHello,
            outgoing: RecordWriter::new(StreamRole::Control, limits)?,
        })
    }

    /// The callback must call the appropriate TLS-bound invitation helper for
    /// the actual connection. No reply is staged if validation or admission fails.
    pub fn receive_hello(
        &mut self,
        record: Record<'_>,
        authorize: impl FnOnce(&ClientHello) -> Result<bool, TransportError>,
    ) -> Result<(), TransportError> {
        let result = self.receive_inner(record, authorize);
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        result
    }

    fn receive_inner(
        &mut self,
        record: Record<'_>,
        authorize: impl FnOnce(&ClientHello) -> Result<bool, TransportError>,
    ) -> Result<(), TransportError> {
        if self.phase != Phase::AwaitHello
            || record.header.kind != Kind::ClientHello
            || record.header.sequence != 0
        {
            return Err(TransportError::Rejected);
        }
        let hello = ClientHello::decode_exact(record.payload)?;
        validate_client_hello(&hello)?;
        authorize(&hello)?;
        let reply = ServerHello::new(
            hello.association_id(),
            hello.generation(),
            ConnectionRole::Writer,
            0,
            0,
            0,
            0,
            None,
        )?;
        let mut payload = [0; ServerHello::ENCODED_LEN];
        let used = reply.encode_into(&mut payload)?;
        self.outgoing.load(Kind::ServerHello, 0, &payload[..used])?;
        self.phase = Phase::SendingReply;
        Ok(())
    }

    pub fn outgoing(&mut self) -> Result<&mut RecordWriter, TransportError> {
        if self.phase != Phase::SendingReply {
            return Err(TransportError::Rejected);
        }
        Ok(&mut self.outgoing)
    }

    /// Call only after the last reply byte has been accepted by the stream.
    pub fn finish_reply(&mut self) -> Result<(), TransportError> {
        if self.phase != Phase::SendingReply || !self.outgoing.is_complete() {
            self.phase = Phase::Failed;
            return Err(TransportError::Rejected);
        }
        self.phase = Phase::Ready;
        Ok(())
    }

    pub fn ready(&self) -> bool {
        self.phase == Phase::Ready
    }
}

pub struct ClientHandshake {
    expected: ClientHello,
    outgoing: RecordWriter,
    phase: Phase,
}

impl ClientHandshake {
    pub fn new(hello: ClientHello, limits: Limits) -> Result<Self, TransportError> {
        validate_client_hello(&hello)?;
        let mut payload = zeroize::Zeroizing::new([0; ClientHello::MAX_ENCODED_LEN]);
        let used = hello.encode_into(&mut payload[..])?;
        let mut outgoing = RecordWriter::new(StreamRole::Control, limits)?;
        outgoing.load(Kind::ClientHello, 0, &payload[..used])?;
        Ok(Self {
            expected: hello,
            outgoing,
            phase: Phase::AwaitHello,
        })
    }

    pub fn outgoing(&mut self) -> Result<&mut RecordWriter, TransportError> {
        if self.phase != Phase::AwaitHello {
            return Err(TransportError::Rejected);
        }
        Ok(&mut self.outgoing)
    }

    pub fn receive_reply(&mut self, record: Record<'_>) -> Result<(), TransportError> {
        let result = self.receive_inner(record);
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        result
    }

    fn receive_inner(&mut self, record: Record<'_>) -> Result<(), TransportError> {
        if self.phase != Phase::AwaitHello
            || !self.outgoing.is_complete()
            || record.header.kind != Kind::ServerHello
            || record.header.sequence != 0
        {
            return Err(TransportError::Rejected);
        }
        validate_server_hello(&self.expected, &ServerHello::decode_exact(record.payload)?)?;
        self.phase = Phase::Ready;
        Ok(())
    }

    pub fn ready(&self) -> bool {
        self.phase == Phase::Ready
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::decode_record;
    use crate::{GatewayGeneration, ResumePosition};
    use everssh::{association::AssociationId, bootstrap::SecretToken};

    fn client() -> ClientHandshake {
        let hello = ClientHello::initial(
            AssociationId::from_bytes([1; 16]).expect("id"),
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
        ClientHandshake::new(hello, Limits::default()).expect("client")
    }

    #[test]
    fn neither_side_is_ready_before_full_authenticated_reply() {
        let mut client = client();
        let mut server = ServerHandshake::new(Limits::default()).expect("server");
        let request = client.outgoing().expect("request").pending().to_vec();
        let (record, _) =
            decode_record(StreamRole::Control, &request, &Limits::default()).expect("record");
        let mut called = false;
        server
            .receive_hello(record, |_| {
                called = true;
                Ok(false)
            })
            .expect("authorize");
        assert!(called && !server.ready() && !client.ready());
        let reply = server.outgoing().expect("reply").pending().to_vec();
        server
            .outgoing()
            .expect("reply")
            .commit(reply.len() - 1)
            .expect("partial");
        assert!(!server.ready());
        server
            .outgoing()
            .expect("reply")
            .commit(1)
            .expect("last byte");
        server.finish_reply().expect("reply accepted");
        assert!(server.ready() && !client.ready());
        client
            .outgoing()
            .expect("request")
            .commit(request.len())
            .expect("request sent");
        let (record, _) =
            decode_record(StreamRole::Control, &reply, &Limits::default()).expect("reply record");
        client.receive_reply(record).expect("validated reply");
        assert!(client.ready());
        assert!(client.receive_reply(record).is_err());
        assert!(!client.ready());
    }

    #[test]
    fn rejected_admission_never_stages_reply_or_allows_retry() {
        let mut client = client();
        let request = client.outgoing().expect("request").pending().to_vec();
        let (record, _) =
            decode_record(StreamRole::Control, &request, &Limits::default()).expect("record");
        let mut server = ServerHandshake::new(Limits::default()).expect("server");
        assert!(server
            .receive_hello(record, |_| Err(TransportError::Rejected))
            .is_err());
        assert!(!server.ready());
        assert!(server.outgoing().is_err());
        assert!(server
            .receive_hello(record, |_| panic!("failed state retried authorization"))
            .is_err());
    }

    #[test]
    fn invalid_header_and_premature_completion_fail_closed() {
        let mut client = client();
        let request = client.outgoing().expect("request").pending().to_vec();
        let (record, _) =
            decode_record(StreamRole::Control, &request, &Limits::default()).expect("record");
        let mut bad_record = record;
        bad_record.header.sequence = 1;
        let mut server = ServerHandshake::new(Limits::default()).expect("server");
        assert!(server
            .receive_hello(bad_record, |_| panic!(
                "invalid header reached authorization"
            ))
            .is_err());
        assert!(!server.ready());
        let mut server = ServerHandshake::new(Limits::default()).expect("server");
        server
            .receive_hello(record, |_| Ok(false))
            .expect("authorize");
        let reply = server.outgoing().expect("reply").pending().to_vec();
        assert!(
            server.finish_reply().is_err(),
            "pending reply cannot enable traffic"
        );
        assert!(server.outgoing().is_err());
        assert!(!server.ready());
        let (reply, _) =
            decode_record(StreamRole::Control, &reply, &Limits::default()).expect("reply");
        assert!(
            client.receive_reply(reply).is_err(),
            "unsent hello cannot complete"
        );
        assert!(!client.ready());
        assert!(client.outgoing().is_err());
    }
}
