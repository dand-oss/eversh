use everssh::association::AssociationId;
use everudp::wire::{decode_record, Kind, Resize, StreamRole, HEADER_LEN};
use everudp::{
    DeliveryDecision, DeliveryGate, GatewayReplaySlabs, Limits, OutputPush, OutputReplay,
    QueueError, ReplayRing,
};

fn association(byte: u8) -> AssociationId {
    AssociationId::from_bytes([byte; 16]).expect("association")
}

#[cfg(feature = "path-diagnostics")]
#[test]
fn gateway_trace_records_buffered_writer_output_not_discarded_output() {
    let path = std::env::temp_dir().join(format!(
        "everudp-gateway-path-overrun-{}.json",
        std::process::id()
    ));
    let limits = Limits::default();
    let mut slabs = GatewayReplaySlabs::new(&limits).expect("slabs");
    slabs.enable_path_trace(&path).expect("trace");
    for sequence in 0..limits.queue_operations_per_direction {
        assert!(
            matches!(slabs.push_output(Kind::Output, b"secret-output").expect("buffer"), everudp::FanoutReport { writer: OutputPush::Buffered { sequence: actual, .. }, .. } if actual == sequence as u64)
        );
    }
    assert!(matches!(
        slabs
            .push_output(Kind::Output, b"discarded-output")
            .expect("overrun")
            .writer,
        OutputPush::Overrun { .. }
    ));
    assert!(matches!(
        slabs
            .push_output(Kind::Output, b"discarded-output")
            .expect("discard")
            .writer,
        OutputPush::Discarded { .. }
    ));
    drop(slabs);
    let trace = std::fs::read_to_string(&path).expect("export");
    assert_eq!(
        trace.matches("gateway_output_queued").count(),
        limits.queue_operations_per_direction
    );
    assert!(!trace.contains("secret-output"));
    assert!(!trace.contains("discarded-output"));
    std::fs::remove_file(path).expect("remove test artifact");
}

#[cfg(feature = "path-diagnostics")]
#[test]
fn gateway_trace_rejects_multi_association_attribution() {
    for observer in [false, true] {
        let path = std::env::temp_dir().join(format!(
            "everudp-gateway-path-generation-{}-{observer}.json",
            std::process::id()
        ));
        let mut slabs = GatewayReplaySlabs::new(&Limits::default()).expect("slabs");
        slabs.enable_path_trace(&path).expect("trace");
        if observer {
            slabs.add_observer(association(3)).expect("observer");
        } else {
            slabs.replace_writer_generation().expect("replacement");
        }
        drop(slabs);
        let trace = std::fs::read_to_string(&path).expect("export");
        assert!(trace.contains("\"valid\":false"));
        std::fs::remove_file(path).expect("remove test artifact");
    }
}

#[test]
fn replay_ring_orders_mixed_input_operations_and_acks_complete_records() {
    let limits = Limits::default();
    let mut queue = ReplayRing::new(StreamRole::Input, &limits).expect("queue");
    let resize = Resize {
        rows: 24,
        columns: 80,
        pixel_width: 0,
        pixel_height: 0,
    }
    .encode();
    assert_eq!(queue.push(Kind::Input, b"abc").expect("input"), 0);
    assert_eq!(queue.push(Kind::Resize, &resize).expect("resize"), 1);
    assert_eq!(queue.push(Kind::Signal, &[15]).expect("signal"), 2);

    let allocation = queue.allocation_signature();
    let mut frame = vec![0_u8; limits.terminal_frame_max + HEADER_LEN];
    for (index, expected_kind) in [Kind::Input, Kind::Resize, Kind::Signal]
        .into_iter()
        .enumerate()
    {
        let copied = queue.copy_unacked(index, &mut frame).expect("copy");
        let (decoded, consumed) =
            decode_record(StreamRole::Input, &frame[..copied.wire_len], &limits).expect("decode");
        assert_eq!(consumed, copied.wire_len);
        assert_eq!(copied.sequence, index as u64);
        assert_eq!(decoded.header.kind, expected_kind);
    }

    queue.acknowledge(2).expect("ack two");
    assert_eq!(queue.unacknowledged_operations(), 1);
    assert_eq!(queue.first_unacknowledged_sequence(), Some(2));
    assert_eq!(queue.allocation_signature(), allocation);
    assert_eq!(queue.acknowledge(4), Err(QueueError::AckAhead));
    assert_eq!(queue.acknowledge(1), Err(QueueError::AckBehind));
}

#[test]
fn queue_saturation_is_nonmutating_and_ack_releases_capacity() {
    let limits = Limits::default();
    let mut queue = ReplayRing::new(StreamRole::Input, &limits).expect("queue");
    for _ in 0..limits.queue_operations_per_direction {
        queue.push(Kind::Input, &[0x5a]).expect("within cap");
    }
    let before = queue.snapshot();
    assert_eq!(queue.push(Kind::Input, &[0x6b]), Err(QueueError::Full));
    assert_eq!(queue.snapshot(), before);
    assert!(!queue.can_poll_source());
    queue.acknowledge(1).expect("release one");
    assert!(queue.can_poll_source());
    assert_eq!(queue.push(Kind::Input, &[0x6b]).expect("reused slot"), 1024);
}

#[test]
fn delivery_ack_advances_only_after_sink_commit_and_suppresses_duplicates() {
    let mut gate = DeliveryGate::new(7, 4);
    assert_eq!(gate.begin(7, 4).expect("begin"), DeliveryDecision::Deliver);
    assert_eq!(gate.acknowledgement(), 4, "sink has not committed");
    gate.abort(7, 4).expect("failed sink");
    assert_eq!(gate.begin(7, 4).expect("retry"), DeliveryDecision::Deliver);
    gate.commit(7, 4).expect("sink accepted");
    assert_eq!(gate.acknowledgement(), 5);
    assert_eq!(
        gate.begin(7, 4).expect("duplicate"),
        DeliveryDecision::Duplicate
    );
    assert_eq!(gate.begin(7, 6), Err(QueueError::SequenceGap));
    assert_eq!(gate.begin(8, 5), Err(QueueError::EpochMismatch));
}

#[test]
fn output_overrun_discards_until_resume_and_emits_one_gap_per_epoch() {
    let limits = Limits::default();
    let mut output = OutputReplay::new(&limits).expect("output");
    for _ in 0..limits.queue_operations_per_direction {
        assert!(matches!(
            output.push(Kind::Output, b"x").expect("buffer"),
            OutputPush::Buffered { epoch: 0, .. }
        ));
    }
    assert_eq!(
        output.push(Kind::Output, b"overrun").expect("overrun"),
        OutputPush::Overrun {
            abandoned_epoch: 0,
            replacement_epoch: 1,
        }
    );
    assert_eq!(output.unacknowledged_operations(), 0);
    assert_eq!(
        output.push(Kind::Output, b"stale").expect("discard"),
        OutputPush::Discarded { epoch: 1 }
    );
    assert_eq!(
        output.reconcile_resume(1, 0),
        Err(QueueError::EpochMismatch),
        "a client cannot claim an epoch the gateway has not announced"
    );
    assert_eq!(output.complete_resume(), Some((0, 1)));
    assert_eq!(output.pending_gap(), Some((0, 1)));
    assert_eq!(output.complete_resume(), None, "gap is emitted once");
    assert_eq!(
        output.reconcile_resume(0, 0).expect("retry old epoch"),
        Some((0, 1)),
        "the gap survives until a client confirms its replacement epoch"
    );
    assert_eq!(output.reconcile_resume(1, 0).expect("confirm gap"), None);
    assert_eq!(output.pending_gap(), None);
    assert_eq!(
        output.push(Kind::Output, b"future").expect("future"),
        OutputPush::Buffered {
            epoch: 1,
            sequence: 0,
        }
    );
}

#[test]
fn repeated_overrun_coalesces_unconfirmed_gap_for_each_client_epoch() {
    let limits = Limits::default();
    let mut output = OutputReplay::new(&limits).expect("output");
    for _ in 0..limits.queue_operations_per_direction {
        output.push(Kind::Output, b"a").expect("epoch zero");
    }
    assert!(matches!(
        output.push(Kind::Output, b"first overrun"),
        Ok(OutputPush::Overrun {
            abandoned_epoch: 0,
            replacement_epoch: 1,
        })
    ));
    assert_eq!(output.complete_resume(), Some((0, 1)));

    for _ in 0..limits.queue_operations_per_direction {
        output.push(Kind::Output, b"b").expect("epoch one");
    }
    assert!(matches!(
        output.push(Kind::Output, b"second overrun"),
        Ok(OutputPush::Overrun {
            abandoned_epoch: 1,
            replacement_epoch: 2,
        })
    ));
    assert_eq!(output.pending_gap(), Some((0, 2)));
    assert_eq!(output.complete_resume(), Some((0, 2)));
    assert_eq!(
        output.reconcile_resume(1, 0).expect("intermediate client"),
        Some((1, 2))
    );
    assert_eq!(output.reconcile_resume(2, 0).expect("confirm latest"), None);
}

#[test]
fn output_wire_byte_cap_overruns_before_the_operation_cap() {
    let limits = Limits::default();
    let mut output = OutputReplay::new(&limits).expect("output");
    let payload = vec![0x5a; limits.terminal_frame_max];
    let mut buffered = 0usize;
    loop {
        match output.push(Kind::Output, &payload).expect("output") {
            OutputPush::Buffered { .. } => buffered += 1,
            OutputPush::Overrun { .. } => break,
            OutputPush::Discarded { .. } => panic!("overrun transition was skipped"),
        }
    }
    assert!(buffered < limits.queue_operations_per_direction);
    assert!(output.is_discarding());
    assert_eq!(output.unacknowledged_operations(), 0);
}

#[test]
fn slow_observer_gaps_independently_and_global_slabs_stay_bounded() {
    let limits = Limits::default();
    let mut slabs = GatewayReplaySlabs::new(&limits).expect("slabs");
    slabs.add_observer(association(1)).expect("slow observer");
    slabs.add_observer(association(2)).expect("fast observer");
    let signature = slabs.allocation_signature();
    assert!(slabs.allocated_bytes() <= limits.global_queue_bytes);

    let mut saw_slow_gap = false;
    for sequence in 0..=limits.queue_operations_per_direction {
        let report = slabs.push_output(Kind::Output, b"x").expect("fanout");
        if report.observer_overran(association(1)) {
            saw_slow_gap = true;
        }
        slabs
            .acknowledge_writer((sequence + 1) as u64)
            .expect("writer ack");
        slabs
            .acknowledge_observer(association(2), (sequence + 1) as u64)
            .expect("fast ack");
    }
    assert!(saw_slow_gap);
    assert!(!slabs.writer_output().is_discarding());
    assert!(!slabs
        .observer_output(association(2))
        .expect("fast observer")
        .is_discarding());
    assert!(slabs
        .observer_output(association(1))
        .expect("slow observer")
        .is_discarding());
    assert_eq!(slabs.allocation_signature(), signature);
}

#[test]
fn ten_mib_survives_five_replay_boundaries_without_loss_or_duplication() {
    let limits = Limits::default();
    let mut queue = ReplayRing::new(StreamRole::Input, &limits).expect("queue");
    let mut receiver = DeliveryGate::new(0, 0);
    let mut frame = vec![0_u8; limits.terminal_frame_max + HEADER_LEN];
    let mut accepted = Vec::with_capacity(10 * 1024 * 1024);
    let mut generated = 0usize;
    let total = 10 * 1024 * 1024;
    let chunk = 16 * 1024;
    let reconnect_at = [2, 41, 129, 317, 511];

    while generated < total {
        let count = chunk.min(total - generated);
        let payload: Vec<u8> = (generated..generated + count)
            .map(|offset| (offset as u64).wrapping_mul(131).wrapping_add(17) as u8)
            .collect();
        let sequence = queue.push(Kind::Input, &payload).expect("queue input");
        deliver_front(&queue, &mut receiver, &mut frame, &mut accepted, &limits);
        if reconnect_at.contains(&(sequence as usize)) {
            deliver_front(&queue, &mut receiver, &mut frame, &mut accepted, &limits);
        }
        queue
            .acknowledge(receiver.acknowledgement())
            .expect("cumulative ack");
        generated += count;
    }

    let expected: Vec<u8> = (0..total)
        .map(|offset| (offset as u64).wrapping_mul(131).wrapping_add(17) as u8)
        .collect();
    assert_eq!(accepted, expected);
    assert_eq!(queue.unacknowledged_operations(), 0);
}

fn deliver_front(
    queue: &ReplayRing,
    receiver: &mut DeliveryGate,
    frame: &mut [u8],
    accepted: &mut Vec<u8>,
    limits: &Limits,
) {
    let copied = queue.copy_unacked(0, frame).expect("front");
    let (record, _) =
        decode_record(StreamRole::Input, &frame[..copied.wire_len], limits).expect("decode input");
    match receiver
        .begin(0, copied.sequence)
        .expect("ordered delivery")
    {
        DeliveryDecision::Deliver => {
            accepted.extend_from_slice(record.payload);
            receiver.commit(0, copied.sequence).expect("commit sink");
        }
        DeliveryDecision::Duplicate => {}
    }
}
