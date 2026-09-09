//! Isolated client replay bookkeeping cost, not network or PTY qualification.
//!
//! Exercises the real input ring, output staging and 64 KiB control ring.
//! Report batch means only: this does not measure per-keystroke latency,
//! scheduler/QUIC costs, gateway fanout or allocation counts.

use everssh::association::AssociationId;
use everudp::wire::{Ack, ConnectionRole, Kind, HEADER_LEN};
use everudp::{ClientAssociation, GatewayGeneration, Limits, OutputStage};
use std::error::Error;
use std::hint::black_box;
use std::time::Instant;

const WARMUP: u64 = 10_000;
const ITERATIONS: u64 = 1_000_000;

fn association() -> Result<ClientAssociation, Box<dyn Error>> {
    Ok(ClientAssociation::new(
        AssociationId::from_bytes([1; 16])?,
        GatewayGeneration::from_bytes([2; 16])?,
        ConnectionRole::Writer,
        Limits::default(),
    )?)
}

fn cycle(client: &mut ClientAssociation, buffer: &mut [u8]) -> Result<(), Box<dyn Error>> {
    let payload = black_box([b'x']);
    let sequence = client.queue_input(&payload)?;
    let input = client.copy_input(sequence, buffer)?;
    assert_eq!(input.wire_len, HEADER_LEN + payload.len());
    assert_eq!(&buffer[HEADER_LEN..input.wire_len], &payload);
    client.accept_input_ack(Ack {
        epoch: 0,
        next_expected: sequence + 1,
    })?;
    assert_eq!(
        client.stage_output(Kind::Output, sequence, &payload)?,
        OutputStage::Staged {
            kind: Kind::Output,
            sequence,
        }
    );
    assert!(client.advance_stdout(payload.len())?);
    let ack = client.finish_staged_output()?;
    assert_eq!(ack.next_expected, sequence + 1);
    let control = client.copy_control(buffer)?;
    assert_eq!(control.kind, Kind::AckOutput);
    assert_eq!(control.wire_len, HEADER_LEN + Ack::WIRE_LEN);
    assert_eq!(&buffer[HEADER_LEN..control.wire_len], &ack.encode());
    client.acknowledge_control_sent(control.sequence + 1)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut client = association()?;
    let mut buffer = [0_u8; HEADER_LEN + Ack::WIRE_LEN];
    let control_allocation = client.control().allocation_signature();
    for _ in 0..WARMUP {
        cycle(&mut client, &mut buffer)?;
    }
    // Each measured batch traverses the entire input-ring byte capacity
    // more than twice and the actual control-ring capacity many times.
    assert!(
        ITERATIONS as usize * (HEADER_LEN + 1) > 2 * Limits::default().queue_bytes_per_direction
    );
    for sample in 0..6 {
        let started = Instant::now();
        for _ in 0..ITERATIONS {
            cycle(black_box(&mut client), black_box(&mut buffer))?;
        }
        let elapsed = started.elapsed();
        assert_eq!(client.ambiguous_input_operations(), 0);
        assert_eq!(client.control().unacknowledged_operations(), 0);
        assert!(!client.has_pending_output());
        assert_eq!(client.control().allocation_signature(), control_allocation);
        println!(
            "{{\"schema_version\":1,\"component\":\"client_replay_roundtrip\",\"qualification\":false,\"sample\":{sample},\"iterations\":{ITERATIONS},\"elapsed_ns\":{},\"mean_ns\":{}}}",
            elapsed.as_nanos(),
            elapsed.as_secs_f64() * 1e9 / ITERATIONS as f64,
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cycle_preserves_sequence_and_leaves_queues_empty() {
        let mut client = association().expect("association");
        let mut buffer = [0; HEADER_LEN + Ack::WIRE_LEN];
        for next in 1..=20 {
            cycle(&mut client, &mut buffer).expect("cycle");
            assert_eq!(client.next_input_sequence(), next);
            assert_eq!(client.ambiguous_input_operations(), 0);
            assert_eq!(client.control().unacknowledged_operations(), 0);
            assert!(!client.has_pending_output());
        }
    }
}
