//! Encrypted-UDP substrate: AES-256-GCM per-packet AEAD, 96-bit
//! monotonically non-repeating nonces, and a bounded anti-replay window.

use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const REPLAY_WINDOW: u64 = 64;
pub const TAG_LEN: usize = 16;

pub struct Substrate {
    cipher: Aes256Gcm,
    prefix: [u8; 4],
    counter: u64,
    highest_received: u64,
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
            highest_received: u64::MAX,
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
        if !self.accept_counter(counter) {
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

    fn accept_counter(&mut self, counter: u64) -> bool {
        if self.highest_received == u64::MAX {
            self.highest_received = counter;
            self.received_bitmap = 1;
            return true;
        }
        if counter > self.highest_received {
            let shift = counter - self.highest_received;
            if shift >= REPLAY_WINDOW {
                self.received_bitmap = 1;
            } else {
                self.received_bitmap =
                    self.received_bitmap.checked_shl(shift as u32).unwrap_or(0) | 1;
            }
            self.highest_received = counter;
            return true;
        }
        let distance = self.highest_received.saturating_sub(counter);
        if distance >= REPLAY_WINDOW {
            return false;
        }
        let bit = 1u64.checked_shl(distance as u32).unwrap_or(0);
        if self.received_bitmap & bit != 0 {
            return false;
        }
        self.received_bitmap |= bit;
        true
    }
}

fn nonce(prefix: [u8; 4], counter: u64) -> Nonce<U12> {
    let mut bytes = [0u8; NONCE_LEN];
    bytes[..4].copy_from_slice(&prefix);
    bytes[4..].copy_from_slice(&counter.to_be_bytes());
    *Nonce::from_slice(&bytes)
}
