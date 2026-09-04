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
}
