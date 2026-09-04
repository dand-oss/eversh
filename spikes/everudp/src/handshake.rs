//! Authenticated one-association UDP bootstrap for the hardened spike path.

use crate::aead::{
    derive_session_roots, SessionRoots, ASSOCIATION_ID_LEN, BOOTSTRAP_SECRET_LEN,
    HANDSHAKE_RANDOM_LEN,
};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};

pub const CLIENT_HELLO_LEN: usize = 4 + ASSOCIATION_ID_LEN + HANDSHAKE_RANDOM_LEN + 32;
pub const SERVER_HELLO_LEN: usize = 4 + ASSOCIATION_ID_LEN + HANDSHAKE_RANDOM_LEN + 32;
const CLIENT_MAGIC: [u8; 4] = *b"EUC1";
const SERVER_MAGIC: [u8; 4] = *b"EUS1";
const CLIENT_LABEL: &[u8] = b"everudp client hello v1";
const SERVER_LABEL: &[u8] = b"everudp server hello v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeError {
    Randomness,
    Malformed,
    Authentication,
    AssociationMismatch,
}

pub struct ClientHandshake {
    wire: [u8; CLIENT_HELLO_LEN],
    association_id: [u8; ASSOCIATION_ID_LEN],
    client_random: [u8; HANDSHAKE_RANDOM_LEN],
}

impl ClientHandshake {
    pub fn begin(secret: &[u8; BOOTSTRAP_SECRET_LEN]) -> Result<Self, HandshakeError> {
        let random = SystemRandom::new();
        let mut association_id = [0u8; ASSOCIATION_ID_LEN];
        let mut client_random = [0u8; HANDSHAKE_RANDOM_LEN];
        random
            .fill(&mut association_id)
            .map_err(|_| HandshakeError::Randomness)?;
        random
            .fill(&mut client_random)
            .map_err(|_| HandshakeError::Randomness)?;
        if association_id == [0u8; ASSOCIATION_ID_LEN] {
            return Err(HandshakeError::Randomness);
        }
        Ok(Self::with_values(secret, association_id, client_random))
    }

    fn with_values(
        secret: &[u8; BOOTSTRAP_SECRET_LEN],
        association_id: [u8; ASSOCIATION_ID_LEN],
        client_random: [u8; HANDSHAKE_RANDOM_LEN],
    ) -> Self {
        let mut wire = [0u8; CLIENT_HELLO_LEN];
        wire[..4].copy_from_slice(&CLIENT_MAGIC);
        wire[4..4 + ASSOCIATION_ID_LEN].copy_from_slice(&association_id);
        wire[4 + ASSOCIATION_ID_LEN..4 + ASSOCIATION_ID_LEN + HANDSHAKE_RANDOM_LEN]
            .copy_from_slice(&client_random);
        let tag = client_tag(secret, &association_id, &client_random);
        wire[CLIENT_HELLO_LEN - tag.len()..].copy_from_slice(&tag);
        Self {
            wire,
            association_id,
            client_random,
        }
    }

    pub fn wire(&self) -> &[u8; CLIENT_HELLO_LEN] {
        &self.wire
    }

    pub fn association_id(&self) -> [u8; ASSOCIATION_ID_LEN] {
        self.association_id
    }

    pub fn finish(
        &self,
        secret: &[u8; BOOTSTRAP_SECRET_LEN],
        reply: &[u8],
    ) -> Result<SessionRoots, HandshakeError> {
        if reply.len() != SERVER_HELLO_LEN || reply[..4] != SERVER_MAGIC {
            return Err(HandshakeError::Malformed);
        }
        let association_id: [u8; ASSOCIATION_ID_LEN] = reply[4..4 + ASSOCIATION_ID_LEN]
            .try_into()
            .map_err(|_| HandshakeError::Malformed)?;
        if association_id != self.association_id {
            return Err(HandshakeError::AssociationMismatch);
        }
        let server_random: [u8; HANDSHAKE_RANDOM_LEN] = reply
            [4 + ASSOCIATION_ID_LEN..4 + ASSOCIATION_ID_LEN + HANDSHAKE_RANDOM_LEN]
            .try_into()
            .map_err(|_| HandshakeError::Malformed)?;
        let signed = server_mac_input(&association_id, &self.client_random, &server_random);
        hmac::verify(
            &hmac::Key::new(hmac::HMAC_SHA256, secret),
            &signed,
            &reply[SERVER_HELLO_LEN - 32..],
        )
        .map_err(|_| HandshakeError::Authentication)?;
        Ok(derive_session_roots(
            secret,
            &association_id,
            &self.client_random,
            &server_random,
        ))
    }
}

pub struct ServerHandshake {
    client_wire: [u8; CLIENT_HELLO_LEN],
    reply: [u8; SERVER_HELLO_LEN],
    association_id: [u8; ASSOCIATION_ID_LEN],
    roots: SessionRoots,
}

impl ServerHandshake {
    pub fn accept(
        secret: &[u8; BOOTSTRAP_SECRET_LEN],
        packet: &[u8],
    ) -> Result<Self, HandshakeError> {
        let random = SystemRandom::new();
        let mut server_random = [0u8; HANDSHAKE_RANDOM_LEN];
        random
            .fill(&mut server_random)
            .map_err(|_| HandshakeError::Randomness)?;
        Self::with_server_random(secret, packet, server_random)
    }

    fn with_server_random(
        secret: &[u8; BOOTSTRAP_SECRET_LEN],
        packet: &[u8],
        server_random: [u8; HANDSHAKE_RANDOM_LEN],
    ) -> Result<Self, HandshakeError> {
        if packet.len() != CLIENT_HELLO_LEN || packet[..4] != CLIENT_MAGIC {
            return Err(HandshakeError::Malformed);
        }
        let client_wire: [u8; CLIENT_HELLO_LEN] =
            packet.try_into().map_err(|_| HandshakeError::Malformed)?;
        let association_id: [u8; ASSOCIATION_ID_LEN] = packet[4..4 + ASSOCIATION_ID_LEN]
            .try_into()
            .map_err(|_| HandshakeError::Malformed)?;
        if association_id == [0u8; ASSOCIATION_ID_LEN] {
            return Err(HandshakeError::Malformed);
        }
        let client_random: [u8; HANDSHAKE_RANDOM_LEN] = packet
            [4 + ASSOCIATION_ID_LEN..4 + ASSOCIATION_ID_LEN + HANDSHAKE_RANDOM_LEN]
            .try_into()
            .map_err(|_| HandshakeError::Malformed)?;
        let signed = client_mac_input(&association_id, &client_random);
        hmac::verify(
            &hmac::Key::new(hmac::HMAC_SHA256, secret),
            &signed,
            &packet[CLIENT_HELLO_LEN - 32..],
        )
        .map_err(|_| HandshakeError::Authentication)?;

        let mut reply = [0u8; SERVER_HELLO_LEN];
        reply[..4].copy_from_slice(&SERVER_MAGIC);
        reply[4..4 + ASSOCIATION_ID_LEN].copy_from_slice(&association_id);
        reply[4 + ASSOCIATION_ID_LEN..4 + ASSOCIATION_ID_LEN + HANDSHAKE_RANDOM_LEN]
            .copy_from_slice(&server_random);
        let tag = server_tag(secret, &association_id, &client_random, &server_random);
        reply[SERVER_HELLO_LEN - tag.len()..].copy_from_slice(&tag);
        let roots = derive_session_roots(secret, &association_id, &client_random, &server_random);
        Ok(Self {
            client_wire,
            reply,
            association_id,
            roots,
        })
    }

    pub fn reply(&self) -> &[u8; SERVER_HELLO_LEN] {
        &self.reply
    }

    pub fn roots(&self) -> SessionRoots {
        self.roots
    }

    pub fn association_id(&self) -> [u8; ASSOCIATION_ID_LEN] {
        self.association_id
    }

    pub fn is_client_retransmit(&self, packet: &[u8]) -> bool {
        packet == self.client_wire
    }
}

pub struct AmplificationBudget {
    available: usize,
    ceiling: usize,
}

impl AmplificationBudget {
    pub fn new(ceiling: usize) -> Self {
        Self {
            available: 0,
            ceiling,
        }
    }

    pub fn credit_receive(&mut self, bytes: usize) {
        self.available = self.available.saturating_add(bytes).min(self.ceiling);
    }

    pub fn debit_send(&mut self, bytes: usize) -> bool {
        if bytes > self.available {
            return false;
        }
        self.available -= bytes;
        true
    }

    pub fn available(&self) -> usize {
        self.available
    }
}

fn client_mac_input(
    association_id: &[u8; ASSOCIATION_ID_LEN],
    client_random: &[u8; HANDSHAKE_RANDOM_LEN],
) -> Vec<u8> {
    [CLIENT_LABEL, association_id, client_random].concat()
}

fn server_mac_input(
    association_id: &[u8; ASSOCIATION_ID_LEN],
    client_random: &[u8; HANDSHAKE_RANDOM_LEN],
    server_random: &[u8; HANDSHAKE_RANDOM_LEN],
) -> Vec<u8> {
    [SERVER_LABEL, association_id, client_random, server_random].concat()
}

fn client_tag(
    secret: &[u8; BOOTSTRAP_SECRET_LEN],
    association_id: &[u8; ASSOCIATION_ID_LEN],
    client_random: &[u8; HANDSHAKE_RANDOM_LEN],
) -> [u8; 32] {
    let input = client_mac_input(association_id, client_random);
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, secret), &input)
        .as_ref()
        .try_into()
        .expect("HMAC-SHA256 tag length")
}

fn server_tag(
    secret: &[u8; BOOTSTRAP_SECRET_LEN],
    association_id: &[u8; ASSOCIATION_ID_LEN],
    client_random: &[u8; HANDSHAKE_RANDOM_LEN],
    server_random: &[u8; HANDSHAKE_RANDOM_LEN],
) -> [u8; 32] {
    let input = server_mac_input(association_id, client_random, server_random);
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, secret), &input)
        .as_ref()
        .try_into()
        .expect("HMAC-SHA256 tag length")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::Role;

    const SECRET: [u8; BOOTSTRAP_SECRET_LEN] = [0x51; BOOTSTRAP_SECRET_LEN];
    const OTHER_SECRET: [u8; BOOTSTRAP_SECRET_LEN] = [0x52; BOOTSTRAP_SECRET_LEN];
    const ASSOCIATION: [u8; ASSOCIATION_ID_LEN] = [0x61; ASSOCIATION_ID_LEN];
    const CLIENT_RANDOM: [u8; HANDSHAKE_RANDOM_LEN] = [0x71; HANDSHAKE_RANDOM_LEN];
    const SERVER_RANDOM: [u8; HANDSHAKE_RANDOM_LEN] = [0x81; HANDSHAKE_RANDOM_LEN];

    fn pair() -> (ClientHandshake, ServerHandshake) {
        let client = ClientHandshake::with_values(&SECRET, ASSOCIATION, CLIENT_RANDOM);
        let server =
            ServerHandshake::with_server_random(&SECRET, client.wire(), SERVER_RANDOM).unwrap();
        (client, server)
    }

    #[test]
    fn authenticated_transcript_derives_compatible_directional_keys() {
        let (client_handshake, server_handshake) = pair();
        let client_roots = client_handshake
            .finish(&SECRET, server_handshake.reply())
            .unwrap();
        let mut client = client_roots.for_role(Role::Client);
        let mut server = server_handshake.roots().for_role(Role::Server);
        let packet = client.seal(b"bound", b"association");
        assert_eq!(server.open(&packet, b"association").unwrap(), b"bound");
        assert_eq!(server_handshake.association_id(), ASSOCIATION);
        assert!(server_handshake.is_client_retransmit(client_handshake.wire()));
    }

    #[test]
    fn forged_client_authentication_is_rejected() {
        let client = ClientHandshake::with_values(&OTHER_SECRET, ASSOCIATION, CLIENT_RANDOM);
        assert!(matches!(
            ServerHandshake::with_server_random(&SECRET, client.wire(), SERVER_RANDOM),
            Err(HandshakeError::Authentication)
        ));
    }

    #[test]
    fn forged_server_authentication_is_rejected() {
        let (client, server) = pair();
        let mut reply = *server.reply();
        *reply.last_mut().unwrap() ^= 1;
        assert!(matches!(
            client.finish(&SECRET, &reply),
            Err(HandshakeError::Authentication)
        ));
    }

    #[test]
    fn reply_for_another_association_is_rejected_before_use() {
        let (client, server) = pair();
        let mut reply = *server.reply();
        reply[4] ^= 1;
        assert!(matches!(
            client.finish(&SECRET, &reply),
            Err(HandshakeError::AssociationMismatch)
        ));
    }

    #[test]
    fn amplification_budget_never_sends_unearned_bytes() {
        let mut budget = AmplificationBudget::new(2400);
        assert!(!budget.debit_send(1));
        budget.credit_receive(84);
        assert!(budget.debit_send(84));
        assert_eq!(budget.available(), 0);
        budget.credit_receive(usize::MAX);
        assert_eq!(budget.available(), 2400);
        assert!(!budget.debit_send(2401));
    }
}
