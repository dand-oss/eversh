use everssh::association::AssociationId;
use everudp::wire::{decode_record, Ack, ConnectionRole, EpochGap, Kind, Resize, StreamRole};
use everudp::{
    ClientAssociation, ClientError, ClientOutputDisposition, GatewayGeneration, Limits,
    OutputOperation, OutputStage, QueueError, ServerHello,
};

fn association() -> AssociationId {
    AssociationId::from_bytes([1; 16]).expect("association")
}

fn generation() -> GatewayGeneration {
    GatewayGeneration::from_bytes([2; 16]).expect("generation")
}

fn client(role: ConnectionRole) -> ClientAssociation {
    ClientAssociation::new(association(), generation(), role, Limits::default()).expect("client")
}

#[cfg(feature = "path-diagnostics")]
#[test]
fn client_path_trace_is_private_and_records_only_committed_output_once() {
    use std::os::unix::fs::PermissionsExt;
    let path =
        std::env::temp_dir().join(format!("everudp-client-path-{}.json", std::process::id()));
    let mut association = client(ConnectionRole::Writer);
    association
        .enable_path_trace(&path)
        .expect("exclusive trace");
    assert_eq!(
        std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(association.enable_path_trace(&path).is_err());
    let mut other = client(ConnectionRole::Writer);
    assert!(other.enable_path_trace(&path).is_err());
    association
        .queue_input(b"private-input-payload")
        .expect("input");
    association
        .stage_output(Kind::Output, 0, b"private-output-payload")
        .expect("output");
    assert!(association.finish_staged_output().is_err());
    assert!(std::fs::read(&path).expect("not exported yet").is_empty());
    association.advance_stdout(22).expect("sink progress");
    association.finish_staged_output().expect("accepted");
    assert!(matches!(
        association
            .stage_output(Kind::Output, 0, b"private-output-payload")
            .expect("duplicate"),
        OutputStage::Duplicate { .. }
    ));
    drop(association);
    let output = std::fs::read_to_string(&path).expect("trace");
    assert_eq!(output.matches("client_input_queued").count(), 1);
    assert_eq!(output.matches("client_output_staged").count(), 1);
    assert_eq!(output.matches("client_output_accepted").count(), 1);
    assert!(!output.contains("private-input-payload"));
    assert!(!output.contains("private-output-payload"));
    assert!(output.contains("\"valid\":true"));
    std::fs::remove_file(path).expect("remove test artifact");
}

fn hello(role: ConnectionRole) -> ServerHello {
    ServerHello::new(association(), generation(), role, 0, 0, 0, 0, None).expect("hello")
}

#[test]
fn input_bytes_resize_signal_and_close_share_one_ordered_replay_stream() {
    let limits = Limits::default();
    let mut client = client(ConnectionRole::Writer);
    client
        .apply_server_hello(hello(ConnectionRole::Writer))
        .expect("hello");
    assert_eq!(client.queue_input(b"a").expect("input"), 0);
    assert_eq!(
        client
            .queue_resize(Resize {
                rows: 24,
                columns: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("resize"),
        1
    );
    assert_eq!(client.queue_signal(2).expect("signal"), 2);
    assert_eq!(client.queue_input_close().expect("close"), 3);
    assert!(matches!(
        client.queue_input(b"late"),
        Err(ClientError::InputClosed)
    ));

    let mut wire = vec![0_u8; limits.terminal_frame_max + everudp::wire::HEADER_LEN];
    for (sequence, expected) in [
        (0, Kind::Input),
        (1, Kind::Resize),
        (2, Kind::Signal),
        (3, Kind::InputClose),
    ] {
        let copied = client.copy_input(sequence, &mut wire).expect("copy");
        let (record, consumed) =
            decode_record(StreamRole::Input, &wire[..copied.wire_len], &limits).expect("decode");
        assert_eq!(consumed, copied.wire_len);
        assert_eq!(
            (record.header.sequence, record.header.kind),
            (sequence, expected)
        );
    }
    client
        .accept_input_ack(Ack {
            epoch: 0,
            next_expected: 4,
        })
        .expect("ACK");
    assert_eq!(client.ambiguous_input_operations(), 0);
}

#[test]
fn output_ack_waits_for_sink_commit_and_duplicate_never_reaches_sink() {
    let limits = Limits::default();
    let mut client = client(ConnectionRole::Writer);
    client
        .apply_server_hello(hello(ConnectionRole::Writer))
        .expect("hello");
    assert_eq!(
        client
            .begin_output(Kind::Output, 0, b"opaque")
            .expect("begin"),
        ClientOutputDisposition::Deliver(OutputOperation::Bytes(b"opaque"))
    );
    client.abort_output(0).expect("sink rejected");
    assert_eq!(client.control().unacknowledged_operations(), 0);
    assert!(matches!(
        client
            .begin_output(Kind::Output, 0, b"opaque")
            .expect("retry"),
        ClientOutputDisposition::Deliver(_)
    ));
    let ack = client.commit_output(0).expect("sink accepted");
    assert_eq!(ack.next_expected, 1);
    assert_eq!(client.control().unacknowledged_operations(), 1);
    assert_eq!(
        client
            .begin_output(Kind::Output, 0, b"opaque")
            .expect("duplicate"),
        ClientOutputDisposition::Duplicate { acknowledgement: 1 }
    );
    client.repeat_output_ack(1).expect("repeat ACK");
    let mut wire = vec![0_u8; limits.control_frame_max + everudp::wire::HEADER_LEN];
    for (index, expected_sequence) in [(0, 1), (1, 2)] {
        let copied = client
            .control()
            .copy_unacked(index, &mut wire)
            .expect("copy ACK");
        let (record, _) =
            decode_record(StreamRole::Control, &wire[..copied.wire_len], &limits).expect("decode");
        assert_eq!(
            (record.header.kind, record.header.sequence),
            (Kind::AckOutput, expected_sequence)
        );
        assert_eq!(
            Ack::decode_exact(record.payload, record.header.kind).expect("ACK"),
            ack
        );
    }
}

#[test]
fn gap_resets_output_once_and_yields_one_notice() {
    let mut client = client(ConnectionRole::Writer);
    client
        .apply_server_hello(hello(ConnectionRole::Writer))
        .expect("hello");
    let gap = EpochGap::new(0, 1).expect("gap");
    assert!(client.apply_gap(gap).expect("first gap"));
    assert!(!client.apply_gap(gap).expect("duplicate gap"));
    assert_eq!(client.take_gap_notice(), Some(gap));
    assert_eq!(client.take_gap_notice(), None);
    assert!(matches!(
        client.begin_output(Kind::Output, 1, b"gap"),
        Err(ClientError::Queue(QueueError::SequenceGap))
    ));
    assert!(matches!(
        client
            .begin_output(Kind::Output, 0, b"future")
            .expect("future"),
        ClientOutputDisposition::Deliver(OutputOperation::Bytes(b"future"))
    ));
}

#[test]
fn full_input_queue_exposes_zero_stdin_capacity_without_losing_an_operation() {
    let limits = Limits::default();
    let mut client = client(ConnectionRole::Writer);
    for _ in 0..limits.queue_operations_per_direction {
        assert!(client.stdin_read_capacity() > 0);
        client.queue_input(b"x").expect("queue");
    }
    assert_eq!(client.stdin_read_capacity(), 0);
    assert!(matches!(
        client.queue_input(b"not-read"),
        Err(ClientError::Queue(QueueError::Full))
    ));
    assert_eq!(
        client.ambiguous_input_operations(),
        limits.queue_operations_per_direction
    );
}

#[test]
fn observer_has_no_input_surface() {
    let mut client = client(ConnectionRole::Observer);
    client
        .apply_server_hello(hello(ConnectionRole::Observer))
        .expect("hello");
    assert_eq!(client.stdin_read_capacity(), 0);
    assert!(matches!(
        client.queue_input(b"x"),
        Err(ClientError::ObserverInput)
    ));
}

#[test]
fn partial_stdout_progress_survives_until_the_complete_operation_is_acked() {
    let mut client = client(ConnectionRole::Writer);
    client
        .apply_server_hello(hello(ConnectionRole::Writer))
        .expect("hello");
    assert_eq!(
        client
            .stage_output(Kind::Output, 0, b"abcdef")
            .expect("stage"),
        OutputStage::Staged {
            kind: Kind::Output,
            sequence: 0,
        }
    );
    assert_eq!(
        client.pending_output().expect("pending").operation,
        OutputOperation::Bytes(b"abcdef")
    );
    assert!(!client.advance_stdout(2).expect("prefix"));
    assert_eq!(client.control().unacknowledged_operations(), 0);
    assert_eq!(
        client.pending_output().expect("resume pending").operation,
        OutputOperation::Bytes(b"cdef")
    );
    assert!(client.advance_stdout(4).expect("suffix"));
    assert_eq!(
        client.finish_staged_output().expect("finish").next_expected,
        1
    );
    assert_eq!(client.control().unacknowledged_operations(), 1);
    assert!(matches!(
        client.pending_output(),
        Err(ClientError::OutputNotStaged)
    ));
}

#[test]
fn gap_discards_a_partially_written_stale_suffix_and_accepts_future_output() {
    let mut client = client(ConnectionRole::Writer);
    client
        .apply_server_hello(hello(ConnectionRole::Writer))
        .expect("hello");
    client
        .stage_output(Kind::Output, 0, b"stale-prefix-and-suffix")
        .expect("stage old epoch");
    assert!(!client.advance_stdout(6).expect("accepted prefix"));

    let gap = EpochGap::new(0, 1).expect("gap");
    assert!(client.apply_gap(gap).expect("replace epoch"));
    assert!(matches!(
        client.pending_output(),
        Err(ClientError::OutputNotStaged)
    ));
    assert_eq!(client.take_gap_notice(), Some(gap));

    client
        .stage_output(Kind::Output, 0, b"future")
        .expect("future epoch output");
    assert_eq!(
        client.pending_output().expect("future pending").operation,
        OutputOperation::Bytes(b"future")
    );
    assert!(client.advance_stdout(6).expect("future accepted"));
    assert_eq!(
        client.finish_staged_output().expect("future ACK"),
        Ack {
            epoch: 1,
            next_expected: 1,
        }
    );
}
