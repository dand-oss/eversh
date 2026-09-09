use everudp::{parse_status_line, LinkState, StatusFile, StatusRecord, StatusTerminalCause};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

#[test]
fn private_status_journal_records_transitions_and_minute_heartbeats() {
    let root = std::env::temp_dir().join(format!(
        "everudp-status-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).expect("root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root mode");
    let path = root.join("status");
    let mut status = StatusFile::create_private(&path).expect("status");
    assert_eq!(fs::metadata(&path).expect("metadata").mode() & 0o777, 0o600);
    assert!(status
        .transition(LinkState::Connecting, 10)
        .expect("connecting"));
    assert!(!status
        .transition(LinkState::Connecting, 11)
        .expect("duplicate"));
    assert!(status
        .transition(LinkState::Connected, 20)
        .expect("connected"));
    assert!(status
        .transition(LinkState::Carrying, 30)
        .expect("carrying"));
    assert!(status
        .transition(LinkState::Disconnected { ambiguous_input: 3 }, 100,)
        .expect("disconnected"));
    assert!(status
        .transition(LinkState::Reconnecting { ambiguous_input: 3 }, 200)
        .expect("reconnecting"));
    assert!(status
        .transition(LinkState::RecoveringOverSsh { ambiguous_input: 3 }, 30_000,)
        .expect("recovering"));
    assert!(!status.heartbeat(60_099).expect("early heartbeat"));
    assert!(status.heartbeat(60_100).expect("heartbeat"));
    assert!(!status.heartbeat(60_101).expect("duplicate heartbeat"));
    status
        .terminal(StatusTerminalCause::LocalCancel, true, 3)
        .expect("terminal");
    drop(status);

    let lines = fs::read_to_string(&path).expect("read status");
    let parsed: Vec<_> = lines.lines().map(parse_status_line).collect();
    assert!(parsed.iter().all(Option::is_some));
    assert_eq!(
        parsed,
        [
            Some(StatusRecord::Transition(LinkState::Connecting)),
            Some(StatusRecord::Transition(LinkState::Connected)),
            Some(StatusRecord::Transition(LinkState::Carrying)),
            Some(StatusRecord::Transition(LinkState::Disconnected {
                ambiguous_input: 3,
            })),
            Some(StatusRecord::Transition(LinkState::Reconnecting {
                ambiguous_input: 3,
            })),
            Some(StatusRecord::Transition(LinkState::RecoveringOverSsh {
                ambiguous_input: 3,
            })),
            Some(StatusRecord::DisconnectedHeartbeat {
                elapsed_ms: 60_000,
                ambiguous_input: 3,
            }),
            Some(StatusRecord::Terminal {
                cause: StatusTerminalCause::LocalCancel,
                carried: true,
                ambiguous_input: 3,
            }),
        ]
    );
    assert!(!lines.contains("token"));
    assert!(!lines.contains("payload"));
    assert_eq!(fs::metadata(&path).expect("metadata").nlink(), 1);
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn malformed_or_cross_protocol_status_lines_are_rejected() {
    for line in [
        "everudp-status-v1",
        "everudp-status-v1 state disconnected",
        "everudp-status-v1 cause bogus carried=0 ambiguous-input=0",
        "everudp-status-v1 cause transport carried=2 ambiguous-input=0",
        "everssh-status-v1 reconnecting",
    ] {
        assert_eq!(parse_status_line(line), None, "{line}");
    }
}
