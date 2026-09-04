//! Encrypted-UDP substrate: AES-256-GCM per-packet AEAD, 96-bit
//! monotonically non-repeating nonces, and a bounded anti-replay window.

use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use ring::hkdf;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const REPLAY_WINDOW: u64 = 64;
pub const TAG_LEN: usize = 16;
pub const BOOTSTRAP_SECRET_LEN: usize = 32;
pub const ASSOCIATION_ID_LEN: usize = 16;
pub const HANDSHAKE_RANDOM_LEN: usize = 32;
pub const KEY_ROTATION_INTERVAL: u64 = 1 << 20;

pub struct Substrate {
    cipher: Aes256Gcm,
    prefix: [u8; 4],
    counter: u64,
    highest_received: Option<u64>,
    received_bitmap: u64,
}

#[derive(Debug)]
pub struct SubstrateError;

impl Substrate {
    pub fn new(key: [u8; KEY_LEN], prefix: [u8; 4], counter: u64) -> Self {
        Self {
            cipher: Aes256Gcm::new_from_slice(&key).expect("AES-256 key"),
            prefix,
            counter,
            highest_received: None,
            received_bitmap: 0,
        }
    }

    pub fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let counter = self.counter;
        self.counter = self
            .counter
            .checked_add(1)
            .expect("nonce counter exhausted");
        let nonce = nonce(self.prefix, counter);
        let mut out = Vec::with_capacity(NONCE_LEN + plaintext.len() + TAG_LEN);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(
            &self
                .cipher
                .encrypt(
                    &nonce,
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .expect("seal"),
        );
        out
    }

    pub fn open(&mut self, packet: &[u8], aad: &[u8]) -> Result<Vec<u8>, SubstrateError> {
        if packet.len() < NONCE_LEN + TAG_LEN {
            return Err(SubstrateError);
        }
        let (nonce_bytes, ciphertext) = packet.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);
        let counter =
            u64::from_be_bytes(nonce_bytes[4..12].try_into().map_err(|_| SubstrateError)?);
        if nonce_bytes[..4] != self.prefix {
            return Err(SubstrateError);
        }
        if !self.counter_is_acceptable(counter) {
            return Err(SubstrateError);
        }
        let plaintext = self
            .cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| SubstrateError)?;
        // An unauthenticated nonce must never advance the replay window:
        // otherwise one forged high counter can evict all legitimate traffic.
        self.record_counter(counter);
        Ok(plaintext)
    }

    fn counter_is_acceptable(&self, counter: u64) -> bool {
        let Some(highest_received) = self.highest_received else {
            return true;
        };
        if counter > highest_received {
            return true;
        }
        let distance = highest_received.saturating_sub(counter);
        if distance >= REPLAY_WINDOW {
            return false;
        }
        let bit = 1u64.checked_shl(distance as u32).unwrap_or(0);
        self.received_bitmap & bit == 0
    }

    fn record_counter(&mut self, counter: u64) {
        let Some(highest_received) = self.highest_received else {
            self.highest_received = Some(counter);
            self.received_bitmap = 1;
            return;
        };
        if counter > highest_received {
            let shift = counter - highest_received;
            if shift >= REPLAY_WINDOW {
                self.received_bitmap = 1;
            } else {
                self.received_bitmap =
                    self.received_bitmap.checked_shl(shift as u32).unwrap_or(0) | 1;
            }
            self.highest_received = Some(counter);
            return;
        }
        let distance = highest_received.saturating_sub(counter);
        let bit = 1u64.checked_shl(distance as u32).unwrap_or(0);
        self.received_bitmap |= bit;
    }
}

fn nonce(prefix: [u8; 4], counter: u64) -> Nonce<U12> {
    let mut bytes = [0u8; NONCE_LEN];
    bytes[..4].copy_from_slice(&prefix);
    bytes[4..].copy_from_slice(&counter.to_be_bytes());
    *Nonce::from_slice(&bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

#[derive(Clone, Copy)]
pub struct SessionRoots {
    client_to_server: [u8; KEY_LEN],
    server_to_client: [u8; KEY_LEN],
}

impl SessionRoots {
    pub fn for_role(self, role: Role) -> SessionSubstrate {
        match role {
            Role::Client => SessionSubstrate::new(self.client_to_server, self.server_to_client, 0),
            Role::Server => SessionSubstrate::new(self.server_to_client, self.client_to_server, 0),
        }
    }
}

pub fn derive_session_roots(
    bootstrap_secret: &[u8; BOOTSTRAP_SECRET_LEN],
    association_id: &[u8; ASSOCIATION_ID_LEN],
    client_random: &[u8; HANDSHAKE_RANDOM_LEN],
    server_random: &[u8; HANDSHAKE_RANDOM_LEN],
) -> SessionRoots {
    let mut salt_bytes = [0u8; HANDSHAKE_RANDOM_LEN * 2];
    salt_bytes[..HANDSHAKE_RANDOM_LEN].copy_from_slice(client_random);
    salt_bytes[HANDSHAKE_RANDOM_LEN..].copy_from_slice(server_random);
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt_bytes);
    let prk = salt.extract(bootstrap_secret);
    let info = [b"everudp traffic roots v1".as_slice(), association_id];
    let mut output = [0u8; KEY_LEN * 2];
    prk.expand(&info, OutputLen(output.len()))
        .expect("fixed HKDF output length")
        .fill(&mut output)
        .expect("fixed HKDF output buffer");
    let mut client_to_server = [0u8; KEY_LEN];
    let mut server_to_client = [0u8; KEY_LEN];
    client_to_server.copy_from_slice(&output[..KEY_LEN]);
    server_to_client.copy_from_slice(&output[KEY_LEN..]);
    SessionRoots {
        client_to_server,
        server_to_client,
    }
}

struct OutputLen(usize);

impl hkdf::KeyType for OutputLen {
    fn len(&self) -> usize {
        self.0
    }
}

struct EpochCipher {
    epoch: u64,
    prefix: [u8; 4],
    cipher: Aes256Gcm,
}

impl EpochCipher {
    fn derive(root: &[u8; KEY_LEN], epoch: u64) -> Self {
        let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, root);
        let epoch_bytes = epoch.to_be_bytes();
        let info = [
            b"everudp packet epoch v1".as_slice(),
            epoch_bytes.as_slice(),
        ];
        let mut material = [0u8; KEY_LEN + 4];
        prk.expand(&info, OutputLen(material.len()))
            .expect("fixed HKDF output length")
            .fill(&mut material)
            .expect("fixed HKDF output buffer");
        let mut key = [0u8; KEY_LEN];
        let mut prefix = [0u8; 4];
        key.copy_from_slice(&material[..KEY_LEN]);
        prefix.copy_from_slice(&material[KEY_LEN..]);
        Self {
            epoch,
            prefix,
            cipher: Aes256Gcm::new_from_slice(&key).expect("AES-256 key"),
        }
    }

    fn open(
        &self,
        nonce: &Nonce<U12>,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, SubstrateError> {
        if nonce[..4] != self.prefix {
            return Err(SubstrateError);
        }
        self.cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| SubstrateError)
    }
}

struct SessionSender {
    root: [u8; KEY_LEN],
    counter: u64,
    current: EpochCipher,
}

impl SessionSender {
    fn new(root: [u8; KEY_LEN], counter: u64) -> Self {
        Self {
            root,
            counter,
            current: EpochCipher::derive(&root, counter / KEY_ROTATION_INTERVAL),
        }
    }

    fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let counter = self.counter;
        self.counter = self
            .counter
            .checked_add(1)
            .expect("nonce counter exhausted");
        let epoch = counter / KEY_ROTATION_INTERVAL;
        if self.current.epoch != epoch {
            self.current = EpochCipher::derive(&self.root, epoch);
        }
        let nonce = nonce(self.current.prefix, counter);
        let mut out = Vec::with_capacity(NONCE_LEN + plaintext.len() + TAG_LEN);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(
            &self
                .current
                .cipher
                .encrypt(
                    &nonce,
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .expect("seal"),
        );
        out
    }
}

struct SessionReceiver {
    root: [u8; KEY_LEN],
    current: EpochCipher,
    previous: Option<EpochCipher>,
    highest_received: Option<u64>,
    received_bitmap: u64,
}

impl SessionReceiver {
    fn new(root: [u8; KEY_LEN]) -> Self {
        Self {
            root,
            current: EpochCipher::derive(&root, 0),
            previous: None,
            highest_received: None,
            received_bitmap: 0,
        }
    }

    fn open(&mut self, packet: &[u8], aad: &[u8]) -> Result<Vec<u8>, SubstrateError> {
        if packet.len() < NONCE_LEN + TAG_LEN {
            return Err(SubstrateError);
        }
        let (nonce_bytes, ciphertext) = packet.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);
        let counter =
            u64::from_be_bytes(nonce_bytes[4..12].try_into().map_err(|_| SubstrateError)?);
        if !counter_is_acceptable(self.highest_received, self.received_bitmap, counter) {
            return Err(SubstrateError);
        }
        let epoch = counter / KEY_ROTATION_INTERVAL;
        let (plaintext, authenticated_new_epoch) = if epoch == self.current.epoch {
            (self.current.open(nonce, ciphertext, aad)?, None)
        } else if self.previous.as_ref().is_some_and(|key| key.epoch == epoch) {
            (
                self.previous
                    .as_ref()
                    .expect("checked previous epoch")
                    .open(nonce, ciphertext, aad)?,
                None,
            )
        } else if epoch == self.current.epoch.saturating_add(1) {
            let candidate = EpochCipher::derive(&self.root, epoch);
            let plaintext = candidate.open(nonce, ciphertext, aad)?;
            (plaintext, Some(candidate))
        } else {
            return Err(SubstrateError);
        };
        if let Some(next) = authenticated_new_epoch {
            let prior = std::mem::replace(&mut self.current, next);
            self.previous = Some(prior);
        }
        record_counter(
            &mut self.highest_received,
            &mut self.received_bitmap,
            counter,
        );
        Ok(plaintext)
    }
}

pub struct SessionSubstrate {
    sender: SessionSender,
    receiver: SessionReceiver,
}

impl SessionSubstrate {
    fn new(send_root: [u8; KEY_LEN], receive_root: [u8; KEY_LEN], counter: u64) -> Self {
        Self {
            sender: SessionSender::new(send_root, counter),
            receiver: SessionReceiver::new(receive_root),
        }
    }

    pub fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        self.sender.seal(plaintext, aad)
    }

    pub fn open(&mut self, packet: &[u8], aad: &[u8]) -> Result<Vec<u8>, SubstrateError> {
        self.receiver.open(packet, aad)
    }
}

fn counter_is_acceptable(highest: Option<u64>, bitmap: u64, counter: u64) -> bool {
    let Some(highest) = highest else {
        return true;
    };
    if counter > highest {
        return true;
    }
    let distance = highest.saturating_sub(counter);
    if distance >= REPLAY_WINDOW {
        return false;
    }
    bitmap & (1u64 << distance) == 0
}

fn record_counter(highest: &mut Option<u64>, bitmap: &mut u64, counter: u64) {
    let Some(current) = *highest else {
        *highest = Some(counter);
        *bitmap = 1;
        return;
    };
    if counter > current {
        let shift = counter - current;
        *bitmap = if shift >= REPLAY_WINDOW {
            1
        } else {
            bitmap.checked_shl(shift as u32).unwrap_or(0) | 1
        };
        *highest = Some(counter);
    } else {
        *bitmap |= 1u64 << (current - counter);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; KEY_LEN] = [0x5a; KEY_LEN];
    const PREFIX: [u8; 4] = [1, 2, 3, 4];

    #[test]
    fn authenticated_packet_is_accepted_only_once() {
        let mut sender = Substrate::new(KEY, PREFIX, 7);
        let mut receiver = Substrate::new(KEY, PREFIX, 100);
        let packet = sender.seal(b"hello", b"test");
        assert_eq!(receiver.open(&packet, b"test").unwrap(), b"hello");
        assert!(receiver.open(&packet, b"test").is_err());
    }

    #[test]
    fn forged_high_counter_does_not_advance_replay_window() {
        let mut sender = Substrate::new(KEY, PREFIX, 7);
        let mut receiver = Substrate::new(KEY, PREFIX, 100);
        let legitimate = sender.seal(b"hello", b"test");
        let mut forged = legitimate.clone();
        forged[4..12].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(receiver.open(&forged, b"test").is_err());
        assert_eq!(receiver.open(&legitimate, b"test").unwrap(), b"hello");
    }

    #[test]
    fn bad_tag_does_not_consume_legitimate_counter() {
        let mut sender = Substrate::new(KEY, PREFIX, 7);
        let mut receiver = Substrate::new(KEY, PREFIX, 100);
        let legitimate = sender.seal(b"hello", b"test");
        let mut forged = legitimate.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert!(receiver.open(&forged, b"test").is_err());
        assert_eq!(receiver.open(&legitimate, b"test").unwrap(), b"hello");
    }

    fn roots(marker: u8) -> SessionRoots {
        derive_session_roots(
            &[0x41; BOOTSTRAP_SECRET_LEN],
            &[0x22; ASSOCIATION_ID_LEN],
            &[marker; HANDSHAKE_RANDOM_LEN],
            &[0x33; HANDSHAKE_RANDOM_LEN],
        )
    }

    #[test]
    fn session_keys_are_directional_and_peer_compatible() {
        let roots = roots(0x11);
        let mut client = roots.for_role(Role::Client);
        let mut server = roots.for_role(Role::Server);
        let request = client.seal(b"request", b"session");
        assert!(client.open(&request, b"session").is_err());
        assert_eq!(server.open(&request, b"session").unwrap(), b"request");
        let response = server.seal(b"response", b"session");
        assert_eq!(client.open(&response, b"session").unwrap(), b"response");
    }

    #[test]
    fn fresh_handshake_randomness_changes_traffic_roots() {
        let first = roots(0x11);
        let second = roots(0x12);
        assert_ne!(first.client_to_server, second.client_to_server);
        assert_ne!(first.server_to_client, second.server_to_client);
        assert_ne!(first.client_to_server, first.server_to_client);
    }

    #[test]
    fn authenticated_rotation_preserves_boundary_and_reorder() {
        let roots = roots(0x11);
        let mut client = SessionSubstrate::new(
            roots.client_to_server,
            roots.server_to_client,
            KEY_ROTATION_INTERVAL - 1,
        );
        let mut server = roots.for_role(Role::Server);
        let before = client.seal(b"before", b"session");
        let after = client.seal(b"after", b"session");
        assert_eq!(server.open(&after, b"session").unwrap(), b"after");
        assert_eq!(server.open(&before, b"session").unwrap(), b"before");
    }

    #[test]
    fn forged_rotation_packet_does_not_install_epoch_or_consume_counter() {
        let roots = roots(0x11);
        let mut client = SessionSubstrate::new(
            roots.client_to_server,
            roots.server_to_client,
            KEY_ROTATION_INTERVAL,
        );
        let mut server = roots.for_role(Role::Server);
        let legitimate = client.seal(b"next epoch", b"session");
        let mut forged = legitimate.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert!(server.open(&forged, b"session").is_err());
        assert_eq!(server.open(&legitimate, b"session").unwrap(), b"next epoch");
    }
}
