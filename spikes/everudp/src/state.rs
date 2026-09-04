//! Minimal bounded terminal-echo prediction state with explicit epochs,
//! sequence numbers, cumulative acknowledgement, deterministic
//! reconciliation, and a strict no-echo safety policy.

use std::collections::BTreeMap;

pub const EPOCH_LIMIT: usize = 64;
pub const PREDICTED_LIMIT: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EchoPolicy {
    /// Ordinary line input: printable bytes may render locally as predicted.
    Predict,
    /// Password/no-echo input: predictions are never displayed.
    #[default]
    NoEcho,
}

#[derive(Debug, Default)]
pub struct PredictionState {
    pub epoch: u32,
    pub next_seq: u64,
    pub acknowledged: u64,
    pub confirmed_bytes: Vec<u8>,
    pub predicted_echo_displays: u64,
    pub corrections: u64,
    predicted: BTreeMap<u64, Vec<u8>>,
    policy: EchoPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reconciliation {
    Confirmed { predicted: bool },
    Corrected,
}

impl PredictionState {
    pub fn new(epoch: u32, policy: EchoPolicy) -> Self {
        Self {
            epoch,
            policy,
            ..Self::default()
        }
    }

    pub fn send(&mut self, bytes: &[u8]) -> (u64, bool) {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        let displayed = self.policy == EchoPolicy::Predict && bytes.iter().all(is_echo_safe);
        if displayed {
            self.predicted_echo_displays = self.predicted_echo_displays.saturating_add(1);
        }
        if self.predicted.len() >= PREDICTED_LIMIT {
            self.predicted
                .remove(&self.predicted.keys().next().copied().unwrap_or(0));
        }
        self.predicted.insert(seq, bytes.to_vec());
        (seq, displayed)
    }

    pub fn reconcile(&mut self, ack: u64, bytes: &[u8]) -> Reconciliation {
        self.acknowledged = self.acknowledged.max(ack);
        while let Some(first) = self.predicted.keys().next().copied() {
            if first > self.acknowledged {
                break;
            }
            self.predicted.remove(&first);
        }
        let predicted = self
            .predicted
            .remove(&ack)
            .unwrap_or_else(|| bytes.to_vec());
        if predicted == bytes {
            self.confirmed_bytes.extend_from_slice(bytes);
            Reconciliation::Confirmed { predicted: true }
        } else {
            self.corrections += 1;
            self.confirmed_bytes.extend_from_slice(bytes);
            Reconciliation::Corrected
        }
    }

    pub fn reset(&mut self, epoch: u32) {
        if self.epoch.saturating_add(1) != epoch || self.epoch as usize >= EPOCH_LIMIT {
            panic!("everudp spike: unsafe epoch transition");
        }
        self.epoch = epoch;
        self.predicted.clear();
    }
}

fn is_echo_safe(byte: &u8) -> bool {
    matches!(byte, b' '..=b'~')
}
