//! Shared stream-floor wire checks. These do not replace TLS/token admission.

use crate::handshake::{ClientHello, ServerHello};
use crate::transport::TransportError;
use crate::wire::{ConnectionRole, StreamRole};
use noq_proto::{Dir, Side, StreamId};

/// Check observed TLS/QUIC properties before opening or accepting app streams.
/// This is not a receipt for private transport windows or ACK settings.
pub fn validate_negotiated_profile(
    handshake: Option<Box<dyn std::any::Any>>,
    max_datagram_size: Option<usize>,
) -> Result<(), TransportError> {
    let handshake = handshake
        .and_then(|data| {
            data.downcast::<noq_proto::crypto::rustls::HandshakeData>()
                .ok()
        })
        .ok_or(TransportError::Rejected)?;
    if handshake.protocol.as_deref() != Some(crate::transport::STREAM_FLOOR_ALPN)
        || max_datagram_size.is_some()
    {
        return Err(TransportError::Rejected);
    }
    Ok(())
}

/// Register each stream exactly once when opened or accepted. Readable and
/// writable notifications are not registrations. A rejected layout is terminal.
#[derive(Default)]
pub struct StreamLayout {
    registered: u8,
    failed: bool,
}

impl StreamLayout {
    pub fn register(&mut self, id: StreamId) -> Result<StreamRole, TransportError> {
        if self.failed {
            return Err(TransportError::Stream);
        }
        let role = match stream_role(id) {
            Ok(role) => role,
            Err(error) => {
                self.failed = true;
                return Err(error);
            }
        };
        let bit = match role {
            StreamRole::Control => 1,
            StreamRole::Input => 2,
            StreamRole::Output => 4,
        };
        if self.registered & bit != 0 {
            self.failed = true;
            return Err(TransportError::Stream);
        }
        self.registered |= bit;
        Ok(role)
    }

    pub fn complete(&self) -> bool {
        !self.failed && self.registered == 7
    }
}

pub fn stream_role(id: StreamId) -> Result<StreamRole, TransportError> {
    if id.index() != 0 {
        return Err(TransportError::Stream);
    }
    match (id.initiator(), id.dir()) {
        (Side::Client, Dir::Bi) => Ok(StreamRole::Control),
        (Side::Client, Dir::Uni) => Ok(StreamRole::Input),
        (Side::Server, Dir::Uni) => Ok(StreamRole::Output),
        _ => Err(TransportError::Stream),
    }
}

/// The experiment permits only a fresh writer. The runtime must subsequently
/// validate the invitation against the TLS identity before sending ServerHello.
pub fn validate_client_hello(hello: &ClientHello) -> Result<(), TransportError> {
    let position = hello.position();
    if !matches!(hello, ClientHello::Initial { .. })
        || hello.role() != ConnectionRole::Writer
        || position.input_epoch != 0
        || position.next_input != 0
        || position.output_epoch != 0
        || position.next_output != 0
        || position.delivered_output_ack != 0
    {
        return Err(TransportError::Rejected);
    }
    Ok(())
}

pub fn validate_server_hello(
    expected: &ClientHello,
    reply: &ServerHello,
) -> Result<(), TransportError> {
    validate_client_hello(expected)?;
    if reply.association_id() != expected.association_id()
        || reply.generation() != expected.generation()
        || reply.role() != ConnectionRole::Writer
        || reply.input_epoch != 0
        || reply.accepted_input_ack != 0
        || reply.output_epoch != 0
        || reply.next_output != 0
        || reply.pending_gap.is_some()
    {
        return Err(TransportError::Rejected);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GatewayGeneration, ResumePosition};
    use everssh::{association::AssociationId, bootstrap::SecretToken};

    fn hello(role: ConnectionRole) -> ClientHello {
        ClientHello::initial(
            AssociationId::from_bytes([1; 16]).expect("id"),
            GatewayGeneration::from_bytes([2; 16]).expect("generation"),
            role,
            ResumePosition {
                input_epoch: 0,
                next_input: 0,
                output_epoch: 0,
                next_output: 0,
                delivered_output_ack: 0,
            },
            SecretToken::from_bytes([3; 32]),
        )
        .expect("hello")
    }

    #[test]
    fn layout_rejects_extra_duplicate_and_wrong_initiator_streams() {
        let ids = [
            StreamId::new(Side::Client, Dir::Bi, 0),
            StreamId::new(Side::Client, Dir::Uni, 0),
            StreamId::new(Side::Server, Dir::Uni, 0),
        ];
        let mut layout = StreamLayout::default();
        for id in ids {
            layout.register(id).expect("valid stream");
        }
        assert!(layout.complete());
        assert!(layout.register(ids[0]).is_err());
        assert!(!layout.complete());
        for invalid in [
            StreamId::new(Side::Server, Dir::Bi, 0),
            StreamId::new(Side::Client, Dir::Bi, 1),
            StreamId::new(Side::Client, Dir::Uni, 1),
            StreamId::new(Side::Server, Dir::Uni, 1),
        ] {
            let mut layout = StreamLayout::default();
            assert!(layout.register(invalid).is_err());
            assert!(layout.register(ids[0]).is_err(), "error must latch");
        }
    }

    #[test]
    fn server_hello_must_match_fresh_writer_and_zero_state() {
        let request = hello(ConnectionRole::Writer);
        let valid = ServerHello::new(
            request.association_id(),
            request.generation(),
            ConnectionRole::Writer,
            0,
            0,
            0,
            0,
            None,
        )
        .expect("reply");
        validate_server_hello(&request, &valid).expect("matching reply");
        assert!(validate_client_hello(&hello(ConnectionRole::Observer)).is_err());
        for field in 0..3 {
            let reply = ServerHello::new(
                if field == 0 {
                    AssociationId::from_bytes([9; 16]).expect("other id")
                } else {
                    request.association_id()
                },
                if field == 1 {
                    GatewayGeneration::from_bytes([9; 16]).expect("other generation")
                } else {
                    request.generation()
                },
                if field == 2 {
                    ConnectionRole::Observer
                } else {
                    ConnectionRole::Writer
                },
                0,
                0,
                0,
                0,
                None,
            )
            .expect("reply");
            assert!(validate_server_hello(&request, &reply).is_err());
        }
        let resume = ClientHello::resume(
            request.association_id(),
            request.generation(),
            ConnectionRole::Writer,
            request.position(),
        )
        .expect("resume hello");
        assert!(validate_client_hello(&resume).is_err());
        for field in 0..5 {
            let mut reply = valid;
            match field {
                0 => reply.input_epoch = 1,
                1 => reply.accepted_input_ack = 1,
                2 => reply.output_epoch = 1,
                3 => reply.next_output = 1,
                _ => reply.pending_gap = Some((0, 1)),
            }
            assert!(validate_server_hello(&request, &reply).is_err());
        }
    }
}
