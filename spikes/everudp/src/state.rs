//! Minimal bounded terminal-echo prediction state with explicit epochs,
//! sequence numbers, cumulative acknowledgement, deterministic
//! reconciliation, and a strict no-echo safety policy.

use std::{collections::BTreeMap, fmt};

pub const EPOCH_LIMIT: usize = 64;
pub const PREDICTED_LIMIT: usize = 1024;
pub const PENDING_BYTES_LIMIT: usize = 256 * 1024;
pub const REORDERED_LIMIT: usize = 64;
pub const REORDERED_BYTES_LIMIT: usize = 64 * 1024;
pub const CONFIRMED_BYTES_LIMIT: usize = 1024 * 1024;

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
    pending_bytes: usize,
    received: BTreeMap<u64, Vec<u8>>,
    received_bytes: usize,
    resync_required: bool,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateError {
    PendingEntriesFull,
    PendingBytesFull,
    ReorderEntriesFull,
    ReorderBytesFull,
    ConfirmedBytesFull,
    SequenceExhausted,
    ResyncRequired,
}

impl fmt::Display for StateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::PendingEntriesFull => "pending prediction entry limit reached",
            Self::PendingBytesFull => "pending prediction byte limit reached",
            Self::ReorderEntriesFull => "reordered acknowledgement entry limit reached",
            Self::ReorderBytesFull => "reordered acknowledgement byte limit reached",
            Self::ConfirmedBytesFull => "confirmed history byte limit reached; resync required",
            Self::SequenceExhausted => "prediction sequence exhausted; resync required",
            Self::ResyncRequired => "prediction state requires epoch resync",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for StateError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateUsage {
    pub pending_entries: usize,
    pub pending_bytes: usize,
    pub reordered_entries: usize,
    pub reordered_bytes: usize,
    pub confirmed_bytes: usize,
    pub resync_required: bool,
}

impl PredictionState {
    pub fn new(epoch: u32, policy: EchoPolicy) -> Self {
        Self {
            epoch,
            policy,
            ..Self::default()
        }
    }

    pub fn send(&mut self, bytes: &[u8]) -> Result<(u64, bool), StateError> {
        if self.resync_required {
            return Err(StateError::ResyncRequired);
        }
        if self.next_seq == u64::MAX {
            self.resync_required = true;
            return Err(StateError::SequenceExhausted);
        }
        if self.predicted.len() >= PREDICTED_LIMIT {
            return Err(StateError::PendingEntriesFull);
        }
        let Some(pending_bytes) = self.pending_bytes.checked_add(bytes.len()) else {
            return Err(StateError::PendingBytesFull);
        };
        if pending_bytes > PENDING_BYTES_LIMIT {
            return Err(StateError::PendingBytesFull);
        }

        let seq = self.next_seq;
        self.next_seq += 1;
        let displayed = self.policy == EchoPolicy::Predict && bytes.iter().all(is_echo_safe);
        if displayed {
            self.predicted_echo_displays = self.predicted_echo_displays.saturating_add(1);
        }
        self.pending_bytes = pending_bytes;
        self.predicted.insert(
            seq,
            PendingPrediction {
                bytes: bytes.to_vec(),
                displayed,
            },
        );
        Ok((seq, displayed))
    }

    pub fn reconcile(&mut self, ack: u64, bytes: &[u8]) -> Result<Reconciliation, StateError> {
        if self.resync_required {
            return Err(StateError::ResyncRequired);
        }
        if ack < self.next_ack || self.received.contains_key(&ack) {
            return Ok(Reconciliation::Duplicate);
        }
        if ack >= self.next_seq || !self.predicted.contains_key(&ack) {
            return Ok(Reconciliation::Unexpected);
        }
        if ack != self.next_ack {
            if self.received.len() >= REORDERED_LIMIT {
                return Err(StateError::ReorderEntriesFull);
            }
            let Some(received_bytes) = self.received_bytes.checked_add(bytes.len()) else {
                return Err(StateError::ReorderBytesFull);
            };
            if received_bytes > REORDERED_BYTES_LIMIT {
                return Err(StateError::ReorderBytesFull);
            }
            self.received.insert(ack, bytes.to_vec());
            self.received_bytes = received_bytes;
            return Ok(Reconciliation::Buffered);
        }

        let mut append_bytes = bytes.len();
        let mut following = ack + 1;
        while let Some(authoritative) = self.received.get(&following) {
            let Some(total) = append_bytes.checked_add(authoritative.len()) else {
                self.resync_required = true;
                return Err(StateError::ConfirmedBytesFull);
            };
            append_bytes = total;
            let Some(next) = following.checked_add(1) else {
                break;
            };
            following = next;
        }
        if self
            .confirmed_bytes
            .len()
            .checked_add(append_bytes)
            .is_none_or(|total| total > CONFIRMED_BYTES_LIMIT)
        {
            self.resync_required = true;
            return Err(StateError::ConfirmedBytesFull);
        }

        let first_result = self.commit(ack, bytes);
        while let Some(authoritative) = self.received.remove(&self.next_ack) {
            self.received_bytes -= authoritative.len();
            self.commit(self.next_ack, &authoritative);
        }
        Ok(first_result)
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
        self.pending_bytes = 0;
        self.received.clear();
        self.received_bytes = 0;
        self.resync_required = false;
    }

    pub fn usage(&self) -> StateUsage {
        StateUsage {
            pending_entries: self.predicted.len(),
            pending_bytes: self.pending_bytes,
            reordered_entries: self.received.len(),
            reordered_bytes: self.received_bytes,
            confirmed_bytes: self.confirmed_bytes.len(),
            resync_required: self.resync_required,
        }
    }

    pub fn resync_required(&self) -> bool {
        self.resync_required
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

    fn commit(&mut self, ack: u64, authoritative: &[u8]) -> Reconciliation {
        debug_assert_eq!(ack, self.next_ack);
        let prediction = self
            .predicted
            .remove(&ack)
            .expect("ready acknowledgement has a pending input");
        self.pending_bytes -= prediction.bytes.len();
        let result = if prediction.bytes == authoritative {
            Reconciliation::Confirmed {
                predicted: prediction.displayed,
            }
        } else {
            self.corrections = self.corrections.saturating_add(1);
            Reconciliation::Corrected
        };
        self.confirmed_bytes.extend_from_slice(authoritative);
        self.acknowledged = ack;
        self.next_ack = ack + 1;
        result
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
        let (seq, displayed) = state.send(b"k").unwrap();
        assert!(displayed);
        assert_eq!(
            state.reconcile(seq, b"k").unwrap(),
            Reconciliation::Confirmed { predicted: true }
        );
        assert_eq!(
            state.reconcile(seq, b"k").unwrap(),
            Reconciliation::Duplicate
        );
        assert_eq!(state.confirmed_bytes, b"k");
        assert_eq!(state.corrections, 0);
    }

    #[test]
    fn mismatch_is_corrected_not_silently_accepted() {
        let mut state = PredictionState::new(1, EchoPolicy::Predict);
        let (seq, _) = state.send(b"x").unwrap();
        assert_eq!(
            state.reconcile(seq, b"y").unwrap(),
            Reconciliation::Corrected
        );
        assert_eq!(state.confirmed_bytes, b"y");
        assert_eq!(state.corrections, 1);
    }

    #[test]
    fn no_echo_never_displays_predictions() {
        let mut state = PredictionState::new(1, EchoPolicy::NoEcho);
        let (seq, displayed) = state.send(b"secret").unwrap();
        assert!(!displayed);
        assert_eq!(
            state.reconcile(seq, b"secret").unwrap(),
            Reconciliation::Confirmed { predicted: false }
        );
        assert_eq!(state.predicted_echo_displays, 0);
    }

    #[test]
    fn epoch_reset_discards_old_generation_and_restarts_sequences() {
        let mut state = PredictionState::new(1, EchoPolicy::Predict);
        let (seq, _) = state.send(b"a").unwrap();
        assert_eq!(
            state.reconcile(seq, b"a").unwrap(),
            Reconciliation::Confirmed { predicted: true }
        );
        state.reset(2);
        assert!(state.predicted.is_empty());
        assert_eq!(state.epoch, 2);
        assert!(state.confirmed_bytes.is_empty());
        assert_eq!(state.send(b"b").unwrap().0, 0);
    }

    #[test]
    fn out_of_order_ack_is_buffered_then_committed_in_sequence() {
        let mut state = PredictionState::new(1, EchoPolicy::Predict);
        let (first, _) = state.send(b"a").unwrap();
        let (second, _) = state.send(b"b").unwrap();

        assert_eq!(
            state.reconcile(second, b"b").unwrap(),
            Reconciliation::Buffered
        );
        assert!(state.confirmed_bytes.is_empty());
        assert_eq!(
            state.reconcile(first, b"a").unwrap(),
            Reconciliation::Confirmed { predicted: true }
        );
        assert_eq!(state.confirmed_bytes, b"ab");
        assert_eq!(
            state.reconcile(second, b"b").unwrap(),
            Reconciliation::Duplicate
        );
    }

    #[test]
    fn acknowledgement_for_unsent_input_is_rejected_without_mutation() {
        let mut state = PredictionState::new(1, EchoPolicy::Predict);
        assert_eq!(
            state.reconcile(0, b"x").unwrap(),
            Reconciliation::Unexpected
        );
        assert!(state.confirmed_bytes.is_empty());
        assert_eq!(state.corrections, 0);
    }

    #[test]
    fn pending_entry_limit_backpressures_without_evicting_sequence_state() {
        let mut state = PredictionState::new(1, EchoPolicy::Predict);
        for expected in 0..PREDICTED_LIMIT as u64 {
            assert_eq!(state.send(b"x").unwrap().0, expected);
        }
        let before = state.usage();
        assert_eq!(state.send(b"overflow"), Err(StateError::PendingEntriesFull));
        assert_eq!(state.usage(), before);
        assert_eq!(state.next_seq, PREDICTED_LIMIT as u64);

        assert!(matches!(
            state.reconcile(0, b"x").unwrap(),
            Reconciliation::Confirmed { .. }
        ));
        assert_eq!(state.send(b"after-ack").unwrap().0, PREDICTED_LIMIT as u64);
    }

    #[test]
    fn pending_byte_limit_rejects_without_mutation() {
        let mut state = PredictionState::new(1, EchoPolicy::Predict);
        let at_limit = vec![b'x'; PENDING_BYTES_LIMIT];
        assert_eq!(state.send(&at_limit).unwrap().0, 0);
        let before = state.usage();
        assert_eq!(state.send(b"x"), Err(StateError::PendingBytesFull));
        assert_eq!(state.usage(), before);
        assert_eq!(state.next_seq, 1);
    }

    #[test]
    fn reorder_queue_limit_drops_future_ack_for_safe_retry() {
        let mut state = PredictionState::new(1, EchoPolicy::Predict);
        for _ in 0..=(REORDERED_LIMIT as u64 + 1) {
            state.send(b"x").unwrap();
        }
        for ack in 1..=REORDERED_LIMIT as u64 {
            assert_eq!(
                state.reconcile(ack, b"x").unwrap(),
                Reconciliation::Buffered
            );
        }
        let before = state.usage();
        assert_eq!(
            state.reconcile(REORDERED_LIMIT as u64 + 1, b"x"),
            Err(StateError::ReorderEntriesFull)
        );
        assert_eq!(state.usage(), before);
        assert!(!state.resync_required());

        state.reconcile(0, b"x").unwrap();
        assert_eq!(
            state.reconcile(REORDERED_LIMIT as u64 + 1, b"x").unwrap(),
            Reconciliation::Confirmed { predicted: true }
        );
    }

    #[test]
    fn confirmed_history_limit_requires_explicit_epoch_resync() {
        let mut state = PredictionState::new(1, EchoPolicy::Predict);
        let (first, _) = state.send(b"a").unwrap();
        let at_limit = vec![b'z'; CONFIRMED_BYTES_LIMIT];
        assert_eq!(
            state.reconcile(first, &at_limit).unwrap(),
            Reconciliation::Corrected
        );
        let (second, _) = state.send(b"b").unwrap();
        assert_eq!(
            state.reconcile(second, b"b"),
            Err(StateError::ConfirmedBytesFull)
        );
        assert!(state.resync_required());
        assert_eq!(state.confirmed_bytes.len(), CONFIRMED_BYTES_LIMIT);
        assert_eq!(state.send(b"c"), Err(StateError::ResyncRequired));

        state.reset(2);
        assert!(!state.resync_required());
        assert!(state.confirmed_bytes.is_empty());
        assert_eq!(state.send(b"c").unwrap().0, 0);
    }

    #[test]
    fn exhausted_sequence_requires_resync_without_wrapping() {
        let mut state = PredictionState::new(1, EchoPolicy::Predict);
        state.next_seq = u64::MAX;
        assert_eq!(state.send(b"x"), Err(StateError::SequenceExhausted));
        assert!(state.resync_required());
        assert_eq!(state.next_seq, u64::MAX);
    }
}
