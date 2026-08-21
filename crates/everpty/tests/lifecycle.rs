//! Exhaustive transition tests for the broker lifecycle and writer
//! ownership state machines (design 5.1-5.3, 9).
#![allow(clippy::unwrap_used)]

use everpty::lifecycle::*;

#[test]
fn happy_path_start_to_exit() {
    let s = BrokerState::new();
    let s = s.ready().unwrap();
    let s = s.initial_writer(1).unwrap();
    assert_eq!(s.lifecycle, Lifecycle::Running);
    assert_eq!(s.ownership, Ownership::Writer(1));
    let s = s
        .terminal(
            TerminalCause::ChildExit {
                signal: false,
                value: 0,
            },
            true,
        )
        .unwrap();
    assert_eq!(s.lifecycle, Lifecycle::Exited);
    assert_eq!(s.ownership, Ownership::NoWriter);
    assert_eq!(
        s.terminal,
        Some(TerminalCause::ChildExit {
            signal: false,
            value: 0
        })
    );
}

#[test]
fn startup_deadline_is_terminal_failure_without_child() {
    let s = BrokerState::new()
        .ready()
        .unwrap()
        .startup_deadline()
        .unwrap();
    assert_eq!(s.lifecycle, Lifecycle::Failed);
    assert_eq!(s.terminal, Some(TerminalCause::StartupDeadline));
}

#[test]
fn second_writer_without_takeover_is_busy_and_changes_nothing() {
    let s = BrokerState::new()
        .ready()
        .unwrap()
        .initial_writer(7)
        .unwrap();
    let (s2, out) = s.writer_request(8, false).unwrap();
    assert_eq!(
        out,
        WriterRequestOutcome::Busy {
            current_writer_id: 7
        }
    );
    assert_eq!(s2, s, "Busy must not mutate state");
}

#[test]
fn takeover_is_atomic_revoked_then_granted() {
    let s = BrokerState::new()
        .ready()
        .unwrap()
        .initial_writer(7)
        .unwrap();
    let (s2, out) = s.writer_request(8, true).unwrap();
    assert_eq!(out, WriterRequestOutcome::TakeOver { old_writer_id: 7 });
    assert_eq!(
        s2.ownership,
        Ownership::Writer(8),
        "ownership changes atomically"
    );
}

#[test]
fn writer_can_be_granted_again_after_revocation() {
    let s = BrokerState::new()
        .ready()
        .unwrap()
        .initial_writer(7)
        .unwrap();
    let s = s.revoke_writer().unwrap();
    assert_eq!(s.ownership, Ownership::NoWriter);
    let (s, out) = s.writer_request(9, false).unwrap();
    assert_eq!(out, WriterRequestOutcome::Granted);
    assert_eq!(s.ownership, Ownership::Writer(9));
}

#[test]
fn invalid_transitions_rejected() {
    let fresh = BrokerState::new();
    assert!(fresh.initial_writer(1).is_err(), "writer before ready");
    assert!(
        fresh.writer_request(1, false).is_err(),
        "attach before Running"
    );
    let running = fresh.ready().unwrap().initial_writer(1).unwrap();
    assert!(running.ready().is_err(), "double ready");
    assert!(
        running.startup_deadline().is_err(),
        "deadline after Running"
    );
    let exited = running
        .terminal(
            TerminalCause::ChildExit {
                signal: true,
                value: 9,
            },
            true,
        )
        .unwrap();
    assert!(
        exited.writer_request(2, false).is_err(),
        "attach after exit"
    );
    assert!(exited.revoke_writer().is_err(), "revoke after exit");
}

#[test]
fn first_terminal_cause_wins_and_is_idempotent() {
    let running = BrokerState::new()
        .ready()
        .unwrap()
        .initial_writer(1)
        .unwrap();
    let a = running
        .terminal(TerminalCause::KillRequested, true)
        .unwrap();
    let b = a
        .terminal(
            TerminalCause::ChildExit {
                signal: false,
                value: 0,
            },
            true,
        )
        .unwrap();
    assert_eq!(a, b, "later causes are dropped");
}

#[test]
fn exhaustive_state_matrix_is_total() {
    // For every reachable (lifecycle, ownership) combination, every public
    // transition either applies or returns a typed error — never panics.
    let states = [
        BrokerState::new(),
        BrokerState::new().ready().unwrap(),
        BrokerState::new()
            .ready()
            .unwrap()
            .initial_writer(1)
            .unwrap(),
        BrokerState::new()
            .ready()
            .unwrap()
            .startup_deadline()
            .unwrap(),
        BrokerState::new()
            .ready()
            .unwrap()
            .initial_writer(1)
            .unwrap()
            .revoke_writer()
            .unwrap(),
        BrokerState::new()
            .ready()
            .unwrap()
            .initial_writer(1)
            .unwrap()
            .terminal(TerminalCause::KillRequested, true)
            .unwrap(),
    ];
    for s in states {
        let _ = s.ready();
        let _ = s.initial_writer(2);
        let _ = s.writer_request(2, false);
        let _ = s.writer_request(2, true);
        let _ = s.revoke_writer();
        let _ = s.startup_deadline();
        let _ = s.terminal(TerminalCause::InternalError, false);
    }
}
