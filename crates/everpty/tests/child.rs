//! Focused child-lifecycle integration tests (plans/m2-plan.md §4, §7;
//! commit 4).
//!
//! Every test operates only on the one child it freshly spawned through
//! `everpty::child::spawn`, which places that child in its own setsid
//! process group. Natural exits are OBSERVED non-consumingly through
//! `ChildProc::observe_exit`; signalling, group finalization, and the
//! one reap happen exclusively through `ChildProc::terminate`, which
//! re-proves the recorded PID/PGID/start-ticks identity before sending
//! anything; the panic cleanup guard goes through the same capability.
//! No raw kill of any form (libc, nix, shell, pkill, killall, negative
//! targets) appears anywhere in this file.
#![allow(clippy::unwrap_used)]

use std::ffi::OsString;
use std::io::Read;
use std::time::{Duration, Instant};

use everpty::child::{ChildProc, ExitOutcome, spawn, Spawned, SpawnSpec, SpawnStage};
use everpty::{Error, Limits};

fn os(s: &str) -> OsString {
    OsString::from(s)
}

fn sh_argv(script: &str) -> Vec<OsString> {
    vec![os("/bin/sh"), os("-c"), os(script)]
}

/// The captured environment every test child gets: a fixed PATH so
/// `sh` can find external tools (`sleep`, `stty`) without inheriting
/// anything from the test process.
fn test_env() -> Vec<OsString> {
    vec![os("PATH=/usr/bin:/bin")]
}

fn sh_spec<'a>(name: &'a str, argv: &'a [OsString], env: &'a [OsString]) -> SpawnSpec<'a> {
    SpawnSpec {
        session_name: name,
        argv,
        env,
        path_var: None,
        rows: 24,
        cols: 80,
        close_in_child: &[],
    }
}

fn spawn_sh(name: &str, argv: &[OsString], env: &[OsString]) -> Spawned {
    spawn(&sh_spec(name, argv, env), &Limits::default()).expect("spawn")
}

/// Ends a test child on panic through the identity-checked capability —
/// `terminate` re-proves PID/PGID/start ticks before any signal.
struct EndOnDrop(Option<ChildProc>);

impl EndOnDrop {
    fn child(&mut self) -> &mut ChildProc {
        self.0.as_mut().expect("child present")
    }
}

impl Drop for EndOnDrop {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.terminate(Duration::from_millis(500));
        }
    }
}

/// The mandatory pre-signal assertions: recorded PID and PGID are
/// positive, the child owns its setsid group, the live group identity
/// matches, and the `/proc` start ticks still match the record.
fn assert_recorded_identity(child: &ChildProc) {
    assert!(child.pid() > 0, "recorded pid must be positive");
    assert!(child.pgid() > 0, "recorded pgid must be positive");
    assert_eq!(child.pgid(), child.pid(), "child owns its setsid group");
    assert!(
        child.identity_matches().expect("identity check"),
        "group identity and start ticks must match"
    );
    let ticks = everpty::sys::proc_start_ticks(child.pid()).expect("proc ticks");
    assert_eq!(ticks, child.start_ticks());
}

/// Waits (bounded) until the leader's exit is OBSERVED without
/// reaping — the identity anchor stays valid afterwards; the caller
/// finalizes and reaps through `terminate`.
fn wait_exit_observed(child: &mut ChildProc, deadline: Duration) -> ExitOutcome {
    let end = Instant::now() + deadline;
    loop {
        if let Some(outcome) = child.observe_exit().expect("observe") {
            return outcome;
        }
        assert!(Instant::now() < end, "child did not exit in time");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Reads the nonblocking master until `needle` appears, EOF/EIO ends
/// the stream, or the deadline expires.
fn read_master_until(master: &mut std::fs::File, needle: &[u8], deadline: Duration) -> Vec<u8> {
    let end = Instant::now() + deadline;
    let mut got = Vec::new();
    let mut chunk = [0u8; 4096];
    while Instant::now() < end {
        match master.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                got.extend_from_slice(&chunk[..n]);
                if contains(&got, needle) {
                    return got;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) if e.raw_os_error() == Some(libc::EIO) => break,
            Err(e) => panic!("master read: {e}"),
        }
    }
    got
}

/// Reads the master until EOF or EIO — proof that no process holds
/// the slave side any more. Panics if the deadline passes first.
fn wait_master_closed(master: &mut std::fs::File, deadline: Duration) {
    let end = Instant::now() + deadline;
    let mut chunk = [0u8; 4096];
    while Instant::now() < end {
        match master.read(&mut chunk) {
            Ok(0) => return,
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) if e.raw_os_error() == Some(libc::EIO) => return,
            Err(e) => panic!("master read: {e}"),
        }
    }
    panic!("master never reached EOF/EIO; a slave holder survived");
}

#[test]
fn spawn_wires_ctty_foreground_group_winsize_and_session_env() {
    // The child proves — from /proc/self/stat — that it leads its own
    // process group (pgrp == $$), holds a real controlling terminal
    // (tty_nr != 0), and is that terminal's foreground group
    // (tpgid == pgrp); `stty size` proves the initial winsize reached
    // the PTY, and $EVERPTY_SESSION proves the environment injection.
    let script = "read _pid _comm _state _ppid pgrp _sess tty tpgid _rest < /proc/self/stat\n\
                  printf 'ID:%s:%s:%s:%s\\n' \"$$\" \"$pgrp\" \"$tty\" \"$tpgid\"\n\
                  stty size\n\
                  printf 'ENV:%s\\n' \"$EVERPTY_SESSION\"";
    let argv = sh_argv(script);
    let env = test_env();
    let spawned = spawn_sh("work", &argv, &env);
    let mut guard = EndOnDrop(Some(spawned.child));
    assert_recorded_identity(guard.child());
    let mut master = std::fs::File::from(spawned.master);
    let deadline = Duration::from_secs(5);
    let got = read_master_until(&mut master, b"ENV:work", deadline);
    assert!(contains(&got, b"ENV:work"), "missing session env; got {got:?}");
    assert!(contains(&got, b"24 80"), "missing initial winsize; got {got:?}");
    let pid = guard.child().pid().to_string();
    let text = String::from_utf8_lossy(&got);
    let id = text
        .lines()
        .map(|l| l.trim_end_matches('\r'))
        .find(|l| l.starts_with("ID:"))
        .expect("ID line");
    let fields: Vec<&str> = id.split(':').collect();
    assert_eq!(fields.len(), 5, "ID line shape: {id}");
    assert_eq!(fields[1], pid, "leader pid");
    assert_eq!(fields[2], pid, "own setsid process group");
    assert_ne!(fields[3], "0", "controlling terminal must be present");
    assert_eq!(fields[4], pid, "foreground group of the controlling tty");
    let observed = wait_exit_observed(guard.child(), Duration::from_secs(5));
    assert_eq!(observed, ExitOutcome::Exited(0));
    // The observation was non-consuming: the anchor still proves.
    assert!(guard.child().identity_matches().expect("identity"));
    let outcome = guard
        .child()
        .terminate(Duration::ZERO)
        .expect("finalize and reap");
    assert_eq!(outcome, ExitOutcome::Exited(0));
}

#[test]
fn bare_name_resolves_through_captured_path() {
    let argv = vec![os("sh"), os("-c"), os("exit 5")];
    let env = test_env();
    let mut spec = sh_spec("work", &argv, &env);
    let path_var = os("/usr/bin:/bin");
    spec.path_var = Some(&path_var);
    let spawned = spawn(&spec, &Limits::default()).expect("spawn via PATH");
    let mut guard = EndOnDrop(Some(spawned.child));
    assert_recorded_identity(guard.child());
    let observed = wait_exit_observed(guard.child(), Duration::from_secs(5));
    assert_eq!(observed, ExitOutcome::Exited(5));
    let outcome = guard
        .child()
        .terminate(Duration::ZERO)
        .expect("finalize and reap");
    assert_eq!(outcome, ExitOutcome::Exited(5));
}

#[test]
fn exec_failure_reports_stage_and_errno() {
    // Post-fork failure: the fixed record surfaces stage and errno,
    // and spawn reaps the failed child before returning.
    let argv = vec![os("/nonexistent-everpty/no-such-binary")];
    let env = test_env();
    let err = spawn(&sh_spec("work", &argv, &env), &Limits::default())
        .err()
        .expect("exec failure must surface");
    match err {
        Error::SpawnFailed { stage, errno } => {
            assert_eq!(stage, SpawnStage::Exec);
            assert_eq!(errno, libc::ENOENT);
        }
        other => panic!("unexpected error: {other}"),
    }

    // Pre-fork failure: a bare name that resolves nowhere never forks
    // or spawns anything.
    let bare = vec![os("definitely-not-a-real-tool-xyz")];
    let mut spec = sh_spec("work", &bare, &env);
    let path_var = os("/bin");
    spec.path_var = Some(&path_var);
    let err = spawn(&spec, &Limits::default()).err().expect("unresolvable name");
    assert!(
        matches!(err, Error::Io(ref e) if e.kind() == std::io::ErrorKind::NotFound),
        "unexpected error: {err}"
    );
}

#[test]
fn terminate_delivers_term_within_grace() {
    // `read` blocks forever on the quiet PTY; default TERM ends it.
    let argv = sh_argv("read _line");
    let env = test_env();
    let spawned = spawn_sh("work", &argv, &env);
    let mut guard = EndOnDrop(Some(spawned.child));
    assert_recorded_identity(guard.child());
    let outcome = guard
        .child()
        .terminate(Duration::from_secs(5))
        .expect("terminate");
    assert_eq!(outcome, ExitOutcome::Signaled(libc::SIGTERM as u32));
}

#[test]
fn terminate_escalates_to_kill_when_term_ignored() {
    // The spawn barrier releases the child into execve with every
    // signal at its default disposition; the shell's `trap '' TERM`
    // runs only AFTER exec. A TERM landing in that window would end
    // the leader without any escalation, so the shell must PROVE the
    // trap is installed (the marker reaches the master) before
    // terminate runs — after that, TERM is ignored at `read`, and
    // only the grace expiry's group SIGKILL can end it.
    let argv = sh_argv("trap '' TERM; printf 'TERM-IGNORED-READY\\n'; read _line");
    let env = test_env();
    let spawned = spawn_sh("work", &argv, &env);
    let mut guard = EndOnDrop(Some(spawned.child));
    let mut master = std::fs::File::from(spawned.master);
    let got = read_master_until(&mut master, b"TERM-IGNORED-READY", Duration::from_secs(5));
    assert!(
        contains(&got, b"TERM-IGNORED-READY"),
        "trap never installed; master: {got:?}"
    );
    assert_recorded_identity(guard.child());
    let outcome = guard
        .child()
        .terminate(Duration::from_millis(300))
        .expect("terminate");
    assert_eq!(outcome, ExitOutcome::Signaled(libc::SIGKILL as u32));
}

#[test]
fn terminate_kills_term_ignoring_descendant_in_group() {
    // The leader dies on TERM, but its backgrounded descendant ignores
    // TERM (the ignored disposition survives exec into `sleep`) and
    // holds the PTY slave. The descendant's marker proves its trap is
    // installed before terminate runs — otherwise a TERM landing in
    // the subshell's own startup window would end it at default
    // disposition and the test would prove nothing about group
    // escalation. Group finalization must still end the descendant by
    // escalation — far sooner than its finite 10-second self-exit
    // fallback, which keeps the test bounded even if escalation ever
    // failed.
    let argv = sh_argv(
        "(trap '' TERM; printf 'DESCENDANT-IGNORED-READY\\n'; sleep 10) & read _line",
    );
    let env = test_env();
    let spawned = spawn_sh("work", &argv, &env);
    let mut guard = EndOnDrop(Some(spawned.child));
    let mut master = std::fs::File::from(spawned.master);
    let got = read_master_until(
        &mut master,
        b"DESCENDANT-IGNORED-READY",
        Duration::from_secs(5),
    );
    assert!(
        contains(&got, b"DESCENDANT-IGNORED-READY"),
        "descendant trap never installed; master: {got:?}"
    );
    assert_recorded_identity(guard.child());
    let started = Instant::now();
    let outcome = guard
        .child()
        .terminate(Duration::from_secs(2))
        .expect("terminate");
    assert_eq!(outcome, ExitOutcome::Signaled(libc::SIGTERM as u32));
    // The descendant held the slave; only its death lets the master
    // reach EOF/EIO. Reaching it well under the 10 s fallback proves
    // the SIGKILL escalation — not the sleep — ended it.
    wait_master_closed(&mut master, Duration::from_secs(4));
    assert!(
        started.elapsed() < Duration::from_secs(6),
        "descendant outlived escalation"
    );
}

#[test]
fn observed_exit_keeps_anchor_until_terminate_finalizes() {
    let argv = sh_argv("exit 3");
    let env = test_env();
    let spawned = spawn_sh("work", &argv, &env);
    let mut guard = EndOnDrop(Some(spawned.child));
    // The exit is OBSERVED without reaping: the leader stays an
    // unreaped zombie, so the identity anchor still proves and no
    // finalized outcome exists yet.
    let observed = wait_exit_observed(guard.child(), Duration::from_secs(5));
    assert_eq!(observed, ExitOutcome::Exited(3));
    assert_eq!(guard.child().outcome(), None, "no finalized outcome yet");
    assert!(
        guard.child().identity_matches().expect("identity"),
        "the observation must not consume the identity anchor"
    );
    // Finalize and reap through the safe lifecycle path.
    let outcome = guard
        .child()
        .terminate(Duration::from_secs(1))
        .expect("finalize and reap");
    assert_eq!(outcome, ExitOutcome::Exited(3));
    assert_eq!(guard.child().outcome(), Some(ExitOutcome::Exited(3)));
    // Only now is the outcome cached; no signal is sent again.
    let again = guard
        .child()
        .terminate(Duration::from_secs(1))
        .expect("terminate after finalization");
    assert_eq!(again, ExitOutcome::Exited(3));
    // After the one reap the recorded identity can no longer be
    // proven.
    assert!(!guard.child().identity_matches().expect("identity"));
}

#[test]
fn master_read_ends_after_child_exit_proving_slave_closed() {
    // If the parent still held a slave descriptor, the master would
    // report WouldBlock forever instead of EOF/EIO after the child —
    // the only slave holder — exits.
    let argv = sh_argv("exit 0");
    let env = test_env();
    let spawned = spawn_sh("work", &argv, &env);
    let mut guard = EndOnDrop(Some(spawned.child));
    let observed = wait_exit_observed(guard.child(), Duration::from_secs(5));
    assert_eq!(observed, ExitOutcome::Exited(0));
    let mut master = std::fs::File::from(spawned.master);
    wait_master_closed(&mut master, Duration::from_secs(5));
    let outcome = guard
        .child()
        .terminate(Duration::ZERO)
        .expect("finalize and reap");
    assert_eq!(outcome, ExitOutcome::Exited(0));
}

#[test]
fn observe_exit_is_none_while_running() {
    let argv = sh_argv("sleep 1");
    let env = test_env();
    let spawned = spawn_sh("work", &argv, &env);
    let mut guard = EndOnDrop(Some(spawned.child));
    assert_eq!(guard.child().observe_exit().expect("observe"), None);
    assert_recorded_identity(guard.child());
    let outcome = guard
        .child()
        .terminate(Duration::from_secs(3))
        .expect("terminate");
    assert_eq!(outcome, ExitOutcome::Signaled(libc::SIGTERM as u32));
}
