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
    next_ack: u64,
    predicted: BTreeMap<u64, PendingPrediction>,
    received: BTreeMap<u64, Vec<u8>>,
    policy: EchoPolicy,
}

#[derive(Debug)]
struct PendingPrediction {
    bytes: Vec<u8>,
    displayed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reconciliation {
    Confirmed { predicted: bool },
    Corrected,
    Duplicate,
    Buffered,
    Unexpected,
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
        self.predicted.insert(
            seq,
            PendingPrediction {
                bytes: bytes.to_vec(),
                displayed,
            },
        );
        (seq, displayed)
    }

    pub fn reconcile(&mut self, ack: u64, bytes: &[u8]) -> Reconciliation {
        if ack < self.next_ack || self.received.contains_key(&ack) {
            return Reconciliation::Duplicate;
        }
        if ack >= self.next_seq || !self.predicted.contains_key(&ack) {
            return Reconciliation::Unexpected;
        }
        self.received.insert(ack, bytes.to_vec());
        if ack != self.next_ack {
            return Reconciliation::Buffered;
        }

        let mut first_result = None;
        while let Some(authoritative) = self.received.remove(&self.next_ack) {
            let prediction = self
                .predicted
                .remove(&self.next_ack)
                .expect("received acknowledgement has a pending input");
            let result = if prediction.bytes == authoritative {
                Reconciliation::Confirmed {
                    predicted: prediction.displayed,
                }
            } else {
                self.corrections = self.corrections.saturating_add(1);
                Reconciliation::Corrected
            };
            first_result.get_or_insert(result);
            self.confirmed_bytes.extend_from_slice(&authoritative);
            self.acknowledged = self.next_ack;
            self.next_ack = self.next_ack.saturating_add(1);
        }
        first_result.expect("current acknowledgement is ready")
    }

    pub fn reset(&mut self, epoch: u32) {
        if self.epoch.saturating_add(1) != epoch || self.epoch as usize >= EPOCH_LIMIT {
            panic!("everudp spike: unsafe epoch transition");
        }
        self.epoch = epoch;
        self.next_seq = 0;
        self.next_ack = 0;
        self.acknowledged = 0;
        self.confirmed_bytes.clear();
        self.predicted.clear();
        self.received.clear();
    }

    pub fn rendered_bytes(&self) -> Vec<u8> {
        let predicted_len = self
            .predicted
            .values()
            .filter(|prediction| prediction.displayed)
            .map(|prediction| prediction.bytes.len())
            .sum::<usize>();
        let mut rendered = Vec::with_capacity(self.confirmed_bytes.len() + predicted_len);
        rendered.extend_from_slice(&self.confirmed_bytes);
        for prediction in self.predicted.values() {
            if prediction.displayed {
                rendered.extend_from_slice(&prediction.bytes);
            }
        }
        rendered
    }
}

fn is_echo_safe(byte: &u8) -> bool {
    matches!(byte, b' '..=b'~')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirmed_prediction_does_not_append_twice() {
        let mut state = PredictionState::new(1, EchoPolicy::Predict);
        let (seq, displayed) = state.send(b"k");
        assert!(displayed);
        assert_eq!(
            state.reconcile(seq, b"k"),
            Reconciliation::Confirmed { predicted: true }
        );
        assert_eq!(state.reconcile(seq, b"k"), Reconciliation::Duplicate);
        assert_eq!(state.confirmed_bytes, b"k");
        assert_eq!(state.corrections, 0);
    }

    #[test]
    fn mismatch_is_corrected_not_silently_accepted() {
        let mut state = PredictionState::new(1, EchoPolicy::Predict);
        let (seq, _) = state.send(b"x");
        assert_eq!(state.reconcile(seq, b"y"), Reconciliation::Corrected);
        assert_eq!(state.confirmed_bytes, b"y");
        assert_eq!(state.corrections, 1);
    }

    #[test]
    fn no_echo_never_displays_predictions() {
        let mut state = PredictionState::new(1, EchoPolicy::NoEcho);
        let (seq, displayed) = state.send(b"secret");
        assert!(!displayed);
        assert_eq!(
            state.reconcile(seq, b"secret"),
            Reconciliation::Confirmed { predicted: false }
        );
        assert_eq!(state.predicted_echo_displays, 0);
    }

    #[test]
    fn epoch_reset_discards_old_generation_and_restarts_sequences() {
        let mut state = PredictionState::new(1, EchoPolicy::Predict);
        let (seq, _) = state.send(b"a");
        assert_eq!(
            state.reconcile(seq, b"a"),
            Reconciliation::Confirmed { predicted: true }
        );
        state.reset(2);
        assert!(state.predicted.is_empty());
        assert_eq!(state.epoch, 2);
        assert!(state.confirmed_bytes.is_empty());
        assert_eq!(state.send(b"b").0, 0);
    }

    #[test]
    fn out_of_order_ack_is_buffered_then_committed_in_sequence() {
        let mut state = PredictionState::new(1, EchoPolicy::Predict);
        let (first, _) = state.send(b"a");
        let (second, _) = state.send(b"b");

        assert_eq!(state.reconcile(second, b"b"), Reconciliation::Buffered);
        assert!(state.confirmed_bytes.is_empty());
        assert_eq!(
            state.reconcile(first, b"a"),
            Reconciliation::Confirmed { predicted: true }
        );
        assert_eq!(state.confirmed_bytes, b"ab");
        assert_eq!(state.reconcile(second, b"b"), Reconciliation::Duplicate);
    }

    #[test]
    fn acknowledgement_for_unsent_input_is_rejected_without_mutation() {
        let mut state = PredictionState::new(1, EchoPolicy::Predict);
        assert_eq!(state.reconcile(0, b"x"), Reconciliation::Unexpected);
        assert!(state.confirmed_bytes.is_empty());
        assert_eq!(state.corrections, 0);
    }
}
