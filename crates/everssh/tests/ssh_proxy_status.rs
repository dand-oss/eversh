//! Production-binary coverage of the `ssh-proxy` local link-status file
//! (design 3, 7): every PRE-BRIDGE failure classifies `clean-close` (an
//! ordinary failure: no probe, no reconnect), a graceful `SourceEof` only
//! classifies `clean-close` when Drain AND Finalize completed cleanly, and
//! the status path arrives exclusively as a `--status-file` ARGUMENT — an
//! ambient `EVERSH_LINK_STATUS_FILE` environment value is inert.
#![cfg(all(unix, feature = "cli"))]
#![allow(clippy::unwrap_used)]

use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, UdpSocket};
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const BIN: &str = env!("CARGO_BIN_EXE_everssh");

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("everssh-{label}-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write_fake_ssh(directory: &TempDir, body: &str) {
    let path = directory.0.join("ssh");
    fs::write(&path, body).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn fake_path(directory: &TempDir) -> std::ffi::OsString {
    let mut value = directory.0.as_os_str().to_os_string();
    value.push(":");
    value.push(std::env::var_os("PATH").unwrap_or_default());
    value
}

fn selected_non_loopback_v4() -> Ipv4Addr {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    socket.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).unwrap();
    match socket.local_addr().unwrap().ip() {
        std::net::IpAddr::V4(ip) if !ip.is_loopback() && !ip.is_unspecified() => ip,
        other => panic!("route did not select a usable non-loopback IPv4 address: {other}"),
    }
}

const CARRYING_LINE: &str = "everssh-status-v1 carrying\n";
const CLEAN_CLOSE_LINE: &str = "everssh-status-v1 cause clean-close carried=0\n";
const TRANSPORT_FAILURE_LINE: &str = "everssh-status-v1 cause transport-failure carried=0\n";

/// Run the real binary as `ssh-proxy` against a PATH-scoped fake `ssh` and
/// return (exit code, stderr, status-file bytes).
fn run_proxy(
    temp: &TempDir,
    ssh_body: &str,
    status_path: Option<&std::path::Path>,
    extra_env: &[(&str, &str)],
) -> (Option<i32>, Vec<u8>, Vec<u8>) {
    write_fake_ssh(temp, ssh_body);
    let mut command = Command::new(BIN);
    command
        .args(["ssh-proxy", "user@alias", "22"])
        .env("PATH", fake_path(temp))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(path) = status_path {
        command.arg("--status-file").arg(path);
    }
    for (key, value) in extra_env {
        command.env(key, value);
    }
    let child = command.spawn().unwrap();
    let output = child.wait_with_output().unwrap();
    let status = match status_path {
        Some(path) => fs::read(path).unwrap_or_default(),
        None => Vec::new(),
    };
    (output.status.code(), output.stderr, status)
}

/// A fake `ssh` that prints a canonical effective config for `-G` and then
/// fails every bootstrap attempt the way a rejected authentication does
/// (non-zero exit, diagnostics on stderr) — the pre-establishment auth
/// failure shape the real-OpenSSH gate exercises.
const AUTH_FAIL_SSH: &str = r#"#!/bin/sh
for arg in "$@"; do
  [ "$arg" = "-G" ] && { printf 'hostname fake\nproxycommand none\n'; exit 0; }
done
echo 'Permission denied (publickey,password).' >&2
exit 255
"#;

/// A fake `ssh` whose effective config carries an active proxy — rejected
/// by everssh's own recursive-proxy policy (`SshPolicyRejected`).
const POLICY_REJECT_SSH: &str = r#"#!/bin/sh
printf 'hostname fake\nproxycommand ssh -W %h:%p jump\n'
exit 0
"#;

/// A fake `ssh` that fails outright, including the `-G` policy query
/// itself (`SshProcessFailed` before any bootstrap is attempted).
const PROCESS_FAIL_SSH: &str = "#!/bin/sh\necho 'ssh: fake hard failure' >&2\nexit 255\n";

/// A fake `ssh` that answers `-G` cleanly but emits garbage instead of a
/// bootstrap record (`BootstrapMalformed`).
const MALFORMED_SSH: &str = r#"#!/bin/sh
for arg in "$@"; do
  [ "$arg" = "-G" ] && { printf 'hostname fake\nproxycommand none\n'; exit 0; }
done
printf 'this is not a bootstrap record\n'
exit 0
"#;

#[test]
fn pre_bridge_policy_rejection_classifies_clean_close() {
    let temp = TempDir::new("status-policy");
    let status = temp.0.join("status");
    fs::write(&status, b"").unwrap();
    let (code, stderr, file) = run_proxy(&temp, POLICY_REJECT_SSH, Some(&status), &[]);
    assert_eq!(code, Some(3), "stderr={}", String::from_utf8_lossy(&stderr));
    assert_eq!(file, CLEAN_CLOSE_LINE.as_bytes());
    assert!(!file.starts_with(CARRYING_LINE.as_bytes()));
}

#[test]
fn pre_bridge_config_query_failure_classifies_clean_close() {
    let temp = TempDir::new("status-gfail");
    let status = temp.0.join("status");
    fs::write(&status, b"").unwrap();
    let (code, stderr, file) = run_proxy(&temp, PROCESS_FAIL_SSH, Some(&status), &[]);
    assert_eq!(code, Some(3), "stderr={}", String::from_utf8_lossy(&stderr));
    assert_eq!(file, CLEAN_CLOSE_LINE.as_bytes());
}

#[test]
fn pre_bridge_authentication_failure_classifies_clean_close() {
    // The design 7 branch: an SSH-level authentication failure during the
    // bootstrap must surface as an ORDINARY failure (clean-close, nothing
    // carried) so the supervisor reports the 255 immediately with no probe
    // and no reconnect episode — never a retryable transport failure.
    let temp = TempDir::new("status-auth");
    let status = temp.0.join("status");
    fs::write(&status, b"").unwrap();
    let (code, stderr, file) = run_proxy(&temp, AUTH_FAIL_SSH, Some(&status), &[]);
    assert_eq!(code, Some(3), "stderr={}", String::from_utf8_lossy(&stderr));
    // Exactly the ordinary-failure record: no `carrying` line ever, since
    // nothing was carried.
    assert_eq!(file, CLEAN_CLOSE_LINE.as_bytes());
}

#[test]
fn pre_bridge_malformed_record_classifies_clean_close() {
    let temp = TempDir::new("status-malformed");
    let status = temp.0.join("status");
    fs::write(&status, b"").unwrap();
    let (code, stderr, file) = run_proxy(&temp, MALFORMED_SSH, Some(&status), &[]);
    assert_eq!(code, Some(3), "stderr={}", String::from_utf8_lossy(&stderr));
    assert_eq!(file, CLEAN_CLOSE_LINE.as_bytes());
}

#[test]
fn status_path_comes_only_from_the_argument_never_the_environment() {
    let temp = TempDir::new("status-argv");
    let ambient = temp.0.join("ambient");
    fs::write(&ambient, b"").unwrap();
    // No --status-file argument: nothing is instrumented, and an ambient
    // EVERSH_LINK_STATUS_FILE value cannot instrument it either (the env
    // handoff no longer exists at all).
    let (code, _stderr, _) = run_proxy(
        &temp,
        AUTH_FAIL_SSH,
        None,
        &[("EVERSH_LINK_STATUS_FILE", "set-but-must-be-ignored")],
    );
    assert_eq!(code, Some(3));
    assert_eq!(
        fs::read(&ambient).unwrap(),
        Vec::<u8>::new(),
        "ambient environment value must never receive status writes"
    );
    assert!(
        !temp.0.join("set-but-must-be-ignored").exists(),
        "a relative ambient path must not be created either"
    );
}

/// A graceful local EOF with an undeliverable opposite direction must NOT
/// classify clean-close: the exchange did not verifiably complete, so the
/// supervisor still gets a transport failure (review finding: a remote FIN
/// plus an incomplete drain is not proof of a completed exchange).
#[test]
fn source_eof_with_incomplete_drain_classifies_transport_failure() {
    let temp = TempDir::new("status-drain");
    let status = temp.0.join("status");
    fs::write(&status, b"").unwrap();

    // The working fake from the process suite: `-G` answers cleanly and the
    // bootstrap execs this binary's real bootstrap parent, which spawns the
    // real one-shot server bridging to our fake "sshd" target.
    write_fake_ssh(
        &temp,
        r#"#!/bin/sh
if IFS= read -r unexpected; then exit 90; fi
for arg in "$@"; do
  [ "$arg" = "-G" ] && { printf 'hostname fake\n'; exit 0; }
done
SSH_CONNECTION="$FAKE_CONN"
export SSH_CONNECTION
exec "$EVERSSH_BIN" __bootstrap-parent-v1
"#,
    );

    let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let target_port = target.local_addr().unwrap().port();
    let route_ip = selected_non_loopback_v4();
    let streamer = thread::spawn(move || {
        let (mut stream, _) = target.accept().unwrap();
        // Keep sending forever: the peer's QuicToPeer direction can never
        // drain, so the local EOF cannot complete the exchange.
        let chunk = vec![b'x'; 8192];
        loop {
            if stream.write_all(&chunk).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
    });

    let mut child = Command::new(BIN)
        .args(["ssh-proxy", "user@alias", &target_port.to_string()])
        .arg("--status-file")
        .arg(&status)
        .env("PATH", fake_path(&temp))
        .env("EVERSSH_BIN", BIN)
        .env(
            "FAKE_CONN",
            format!("{route_ip} 50000 {route_ip} {target_port}"),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Drain the proxy's stdout so the undraining direction keeps
    // delivering (a full pipe would stall instead — also a transport
    // failure, but not the one under test).
    let mut reader = child.stdout.take().unwrap();
    let drain = thread::spawn(move || {
        let mut chunk = [0u8; 8192];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    });
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(code) = child.try_wait().unwrap() {
            assert_eq!(code.code(), Some(3));
            break;
        }
        assert!(Instant::now() < deadline, "proxy never finished draining");
        thread::sleep(Duration::from_millis(20));
    }
    let _ = child.wait();
    let _ = drain.join();
    let _ = streamer.join();

    let file = fs::read_to_string(&status).unwrap();
    assert!(
        file.contains(CARRYING_LINE.trim_end_matches('\n')),
        "the streaming direction must have carried: {file:?}"
    );
    assert!(
        file.contains(TRANSPORT_FAILURE_LINE.trim_end_matches('\n')),
        "incomplete drain must classify transport-failure, not clean-close: {file:?}"
    );
    assert!(!file.contains("clean-close"), "{file:?}");
}
