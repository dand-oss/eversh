//! Slice 3 literal parsing and authoritative OpenSSH argv policy.
#![allow(clippy::unwrap_used)]

use everssh::role_protocol::{
    parse_ssh_connection, validate_release, ServerStartRecord, StartUdpPolicy, RELEASE_RECORD,
    SERVER_START_MAX, SSH_CONNECTION_MAX,
};
use everssh::ssh_policy::{validate_effective_config, SshPlan, REMOTE_BOOTSTRAP_COMMAND};
use everssh::Limits;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_path(label: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("everssh-{label}-{}-{nonce}", std::process::id()))
}

#[test]
fn ssh_connection_rejects_every_untrusted_shape() {
    let v4 = parse_ssh_connection("192.0.2.10 50000 192.0.2.20 2222").unwrap();
    assert_eq!(
        v4.authorized_target_addr(),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 2222))
    );
    let v6 = parse_ssh_connection("2001:db8::10 50000 2001:db8::20 2223").unwrap();
    assert_eq!(
        v6.authorized_target_addr(),
        SocketAddr::from((Ipv6Addr::LOCALHOST, 2223))
    );

    for value in [
        "",
        "host 1 192.0.2.1 22",
        "192.0.2.1 0 192.0.2.2 22",
        "192.0.2.1 1 192.0.2.2 0",
        "192.0.2.1 1 ::1 22",
        "192.0.2.1 1 192.0.2.2 22 extra",
        "192.0.2.1 1 192.0.2.2",
        "0.0.0.0 1 192.0.2.2 22",
        "224.0.0.1 1 192.0.2.2 22",
        "255.255.255.255 1 192.0.2.2 22",
        "fe80::1 1 fe80::2 22",
        "192.0.2.1 1 192.0.2.2 22\n",
        "192.0.2.1  1 192.0.2.2 22",
    ] {
        assert!(parse_ssh_connection(value).is_err(), "accepted {value:?}");
    }
}

#[test]
fn argv_is_destination_safe_allowlisted_and_fixed() {
    let plan = SshPlan::new(
        "alice@work-alias".into(),
        "2222".into(),
        vec![
            "-F/tmp/ssh-config".into(),
            "-i/tmp/key".into(),
            "-oCertificateFile=/tmp/key-cert.pub".into(),
            "-oStrictHostKeyChecking=yes".into(),
            "-oServerAliveInterval=5".into(),
        ],
    )
    .unwrap();
    let debug = format!("{plan:?}");
    assert!(!debug.contains("alice@work-alias"));
    assert!(!debug.contains("/tmp/key"));
    let args = plan.bootstrap_args();
    assert_eq!(&args[..2], ["-o", "ProxyCommand=none"]);
    assert_eq!(args[args.len() - 3], "--");
    assert_eq!(args[args.len() - 2], "alice@work-alias");
    assert_eq!(args.last().unwrap(), REMOTE_BOOTSTRAP_COMMAND);
    assert!(!args.iter().any(|arg| arg.contains("BatchMode")));
    let mandatory = args
        .iter()
        .position(|arg| arg == "ForkAfterAuthentication=no")
        .unwrap();
    let user = args
        .iter()
        .position(|arg| arg == "-F/tmp/ssh-config")
        .unwrap();
    assert!(mandatory < user);

    for bad in [
        "-oProxyCommand=none",
        "-oControlMaster=no",
        "-oForkAfterAuthentication=no",
        "-oRemoteCommand=none",
        "-oRequestTTY=no",
        "-oClearAllForwardings=yes",
        "-oBatchMode=yes",
        "-Jjump",
        "-L1:localhost:1",
        "-p22",
        "-S/tmp/control",
        "-F",
        "-oUser",
        "-oUnknown=yes",
    ] {
        assert!(SshPlan::new("alias".into(), "22".into(), vec![bad.into()]).is_err());
    }
}

#[test]
fn absolute_remote_binary_avoids_remote_path_lookup_without_command_injection() {
    let plan = SshPlan::new("alice@work-alias".into(), "2222".into(), vec![])
        .unwrap()
        .with_remote_binary("/home/alice/bin/everssh".into())
        .unwrap();
    assert_eq!(
        plan.bootstrap_args().last().unwrap(),
        "/home/alice/bin/everssh __bootstrap-parent-v1"
    );

    for rejected in [
        "everssh",
        "$HOME/bin/everssh",
        "/home/alice/bin/everssh --help",
        "/home/alice/bin/everssh$(false)",
        "/home/alice/bin/../everssh",
    ] {
        assert!(
            SshPlan::new("alias".into(), "22".into(), vec![])
                .unwrap()
                .with_remote_binary(rejected.into())
                .is_err(),
            "accepted remote binary {rejected:?}"
        );
    }
}

#[test]
fn every_bootstrap_owned_command_line_setting_is_rejected() {
    for option in [
        "-oProxyCommand=none",
        "-oProxyJump=jump.example",
        "-Jjump.example",
        "-oControlMaster=no",
        "-oControlPath=none",
        "-S/tmp/control",
        "-oControlPersist=no",
        "-oForkAfterAuthentication=no",
        "-oPermitLocalCommand=no",
        "-oLocalCommand=false",
        "-oRemoteCommand=none",
        "-oSessionType=default",
        "-oRequestTTY=no",
        "-oClearAllForwardings=yes",
        "-oForwardAgent=no",
        "-oForwardX11=no",
        "-oForwardX11Trusted=no",
        "-oTunnel=no",
        "-oStdinNull=yes",
    ] {
        assert!(
            SshPlan::new("alias".into(), "22".into(), vec![option.into()]).is_err(),
            "accepted bootstrap-owned option {option}"
        );
    }
}

#[test]
fn duplicate_allowed_values_use_the_first_command_line_value() {
    let config = temp_path("duplicate-config");
    fs::write(&config, "Host *\n  ConnectTimeout 17\n").unwrap();
    let plan = SshPlan::new(
        "example.invalid".into(),
        "22".into(),
        vec![
            "-oConnectTimeout=3".into(),
            "-oConnectTimeout=9".into(),
            format!("-F{}", config.display()),
        ],
    )
    .unwrap();
    let output = Command::new("ssh")
        .args(plan.config_query_args())
        .output()
        .unwrap();
    let _ = fs::remove_file(&config);
    assert!(
        output.status.success(),
        "ssh -G failed: {:?}",
        output.stderr
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.lines().any(|line| line == "connecttimeout 3"));

    let query = plan.config_query_args();
    let bootstrap = plan.bootstrap_args();
    assert!(!query
        .windows(2)
        .any(|pair| pair == ["-o", "ProxyCommand=none"]));
    assert_eq!(&bootstrap[..2], ["-o", "ProxyCommand=none"]);
}

#[test]
fn installed_openssh_honors_first_value_ownership_policy() {
    let config = temp_path("hostile-config");
    fs::write(
        &config,
        "Host *\n  ProxyCommand ssh -W %h:%p jump\n  ControlMaster yes\n  ControlPath /tmp/unsafe-control\n  ControlPersist yes\n  ForkAfterAuthentication yes\n  PermitLocalCommand yes\n  LocalCommand false\n  RemoteCommand false\n  SessionType none\n  RequestTTY force\n  ClearAllForwardings no\n  ForwardAgent yes\n  ForwardX11 yes\n  ForwardX11Trusted yes\n  Tunnel yes\n",
    )
    .unwrap();
    let plan = SshPlan::new(
        "example.invalid".into(),
        "22".into(),
        vec![format!("-F{}", config.display())],
    )
    .unwrap();
    let mut args = plan.bootstrap_args();
    args.insert(0, "-G".into());
    let output = Command::new("ssh").args(&args).output().unwrap();
    let _ = fs::remove_file(&config);
    assert!(
        output.status.success(),
        "ssh -G failed: {:?}",
        output.stderr
    );
    validate_effective_config(&output.stdout).unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    for expected in [
        "controlmaster false",
        "controlpersist no",
        "forkafterauthentication no",
        "permitlocalcommand no",
        "requesttty false",
        "stdinnull yes",
        "clearallforwardings yes",
        "forwardagent no",
        "forwardx11 no",
        "forwardx11trusted no",
        "tunnel false",
        "sessiontype default",
    ] {
        assert!(
            text.lines().any(|line| line == expected),
            "missing {expected}"
        );
    }
    assert!(!text.lines().any(|line| line.starts_with("proxycommand ")));
    assert!(!text.lines().any(|line| line.starts_with("controlpath ")));
    assert!(!text.lines().any(|line| line.starts_with("localcommand ")));
    assert!(!text.lines().any(|line| line.starts_with("remotecommand ")));
}

#[test]
fn effective_proxy_query_rejects_jump_or_command() {
    assert!(validate_effective_config(b"hostname direct\n").is_ok());
    assert!(validate_effective_config(b"proxycommand none\nproxyjump none\n").is_ok());
    for malformed in [
        b"".as_slice(),
        b"hostname\n",
        b"hostname direct\r\n",
        b"hostname direct\0tail\n",
        b"proxyjump jump.example\n",
        b"proxycommand ssh -W %h:%p jump\n",
    ] {
        assert!(
            validate_effective_config(malformed).is_err(),
            "accepted effective config {malformed:?}"
        );
    }
}

#[test]
fn connection_and_private_records_are_capped_canonical_and_policy_checked() {
    let limits = Limits::default();
    let longest = format!(
        "{} 65535 {} 65535",
        "7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
    );
    assert_eq!(longest.len(), SSH_CONNECTION_MAX);
    assert!(parse_ssh_connection(&longest).is_ok());
    assert!(parse_ssh_connection(&"1".repeat(SSH_CONNECTION_MAX + 1)).is_err());

    let authenticated = parse_ssh_connection("192.0.2.1 50000 192.0.2.2 22").unwrap();
    let policies = [
        StartUdpPolicy::RouteSelected,
        StartUdpPolicy::RouteSelectedPortRange {
            start: 4000,
            end: 4002,
        },
        StartUdpPolicy::Explicit("192.0.2.2:4444".parse().unwrap()),
    ];
    for policy in policies {
        let record = ServerStartRecord::try_new(authenticated, policy, &limits).unwrap();
        let wire = record.encode();
        assert!(wire.len() <= SERVER_START_MAX);
        let parsed = ServerStartRecord::parse(wire.trim_end_matches('\n'), &limits).unwrap();
        assert_eq!(parsed, record);
        assert_eq!(parsed.encode(), wire);
    }

    for policy in [
        StartUdpPolicy::RouteSelectedPortRange { start: 0, end: 1 },
        StartUdpPolicy::RouteSelectedPortRange { start: 2, end: 1 },
        StartUdpPolicy::Explicit("[::1]:4444".parse().unwrap()),
        StartUdpPolicy::Explicit("0.0.0.0:4444".parse().unwrap()),
        StartUdpPolicy::Explicit("192.0.2.2:0".parse().unwrap()),
    ] {
        assert!(ServerStartRecord::try_new(authenticated, policy, &limits).is_err());
    }

    for line in [
        "",
        "everssh-start v2 192.0.2.1 50000 192.0.2.2 22 route",
        "everssh-start v1 192.0.2.1 050000 192.0.2.2 22 route",
        "everssh-start v1 192.0.2.1 50000 192.0.2.2 22 unknown",
        "everssh-start v1 192.0.2.1 50000 192.0.2.2 22 route extra",
    ] {
        assert!(
            ServerStartRecord::parse(line, &limits).is_err(),
            "accepted {line:?}"
        );
    }
    assert!(ServerStartRecord::parse(&"x".repeat(SERVER_START_MAX), &limits).is_err());

    assert!(validate_release(RELEASE_RECORD).is_ok());
    for bad in [
        b"".as_slice(),
        b"everssh-release v1",
        b"everssh-release v1\r\n",
        b"everssh-release v1\nextra",
        b"everssh-release v2\n",
    ] {
        assert!(validate_release(bad).is_err());
    }
}

#[test]
fn option_table_accepts_only_attached_audited_elements_and_is_bounded() {
    let accepted = [
        "-4",
        "-6",
        "-F/dev/null",
        "-i/tmp/key",
        "-lalice",
        "-b192.0.2.3",
        "-Blo",
        "-oIdentityFile=/tmp/key",
        "-oCertificateFile=/tmp/cert",
        "-oIdentityAgent=SSH_AUTH_SOCK",
        "-oStrictHostKeyChecking=yes",
        "-oUser=alice",
        "-oAddressFamily=inet",
        "-oBindAddress=192.0.2.3",
        "-oConnectTimeout=5",
        "-oServerAliveInterval=10",
        "-oServerAliveCountMax=2",
        "-oTCPKeepAlive=yes",
    ];
    assert!(SshPlan::new(
        "alias".into(),
        "22".into(),
        accepted.iter().map(|value| (*value).to_owned()).collect()
    )
    .is_ok());

    for rejected in [
        "-F",
        "-i",
        "-l",
        "-b",
        "-B",
        "-oUser",
        "-oUser=",
        "-oUnknown=yes",
        "-oProxyJump=jump",
        "-oProxyCommand=none",
        "-oBatchMode=yes",
        "-oRequestTTY=no",
        "-oForwardAgent=no",
        "-oRemoteCommand=none",
        "-oSessionType=default",
        "-oControlPersist=no",
        "-Jjump",
        "-p22",
        "-tt",
        "-N",
        "-f",
        "-Wtarget:22",
        "-L1:localhost:1",
        "-R1:localhost:1",
        "-D1080",
        "-S/tmp/socket",
        "value with space",
        "value\n",
    ] {
        assert!(
            SshPlan::new("alias".into(), "22".into(), vec![rejected.into()]).is_err(),
            "accepted option {rejected:?}"
        );
    }
    assert!(SshPlan::new(
        "alias".into(),
        "22".into(),
        (0..129).map(|_| "-4".to_owned()).collect()
    )
    .is_err());
    assert!(SshPlan::new("a".repeat(4097), "22".into(), vec![]).is_err());
    assert!(SshPlan::new(
        "alias".into(),
        "22".into(),
        vec![format!("-i{}", "x".repeat(4096))]
    )
    .is_err());
}

#[test]
fn production_surface_has_one_runtime_and_no_shell_or_alternate_process_path() {
    let main = include_str!("../src/main.rs");
    let edge = include_str!("../src/edge.rs");
    let roles = include_str!("../src/roles.rs")
        .split("#[cfg(all(test")
        .next()
        .unwrap();
    let bootstrap = include_str!("../src/ssh_bootstrap.rs")
        .split("#[cfg(test)]")
        .next()
        .unwrap();
    for source in [main, edge, roles, bootstrap] {
        for forbidden in [
            "Command::new(\"sh\")",
            "Command::new(\"bash\")",
            "/bin/sh",
            "Runtime::new",
            "Builder::new_",
            "std::thread::spawn",
        ] {
            assert!(
                !source.contains(forbidden),
                "production Slice 3 source contains {forbidden}"
            );
        }
    }
    // The shared edge owns the single runtime-construction site; the thin
    // standalone main has none of its own.
    assert_eq!(edge.matches("runtime::build()").count(), 1);
    assert_eq!(main.matches("runtime::build()").count(), 0);
    assert!(!main.contains("tokio::io::stdin()") && !edge.contains("tokio::io::stdin()"));
    assert!(!main.contains("tokio::io::stdout()") && !edge.contains("tokio::io::stdout()"));
    assert_eq!(roles.matches("Command::new(self_exe)").count(), 1);
    assert_eq!(bootstrap.matches("Command::new(SSH_PROGRAM)").count(), 1);
}

#[test]
fn installed_query_observes_hostile_proxy_before_real_command_suppresses_it() {
    let config = temp_path("hostile-proxy-query");
    fs::write(
        &config,
        "Host *\n  ProxyJump jump.example\n  ControlMaster yes\n  ForkAfterAuthentication yes\n",
    )
    .unwrap();
    let plan = SshPlan::new(
        "example.invalid".into(),
        "22".into(),
        vec![format!("-F{}", config.display())],
    )
    .unwrap();

    let query = Command::new("ssh")
        .args(plan.config_query_args())
        .output()
        .unwrap();
    assert!(query.status.success(), "query stderr={:?}", query.stderr);
    assert!(validate_effective_config(&query.stdout).is_err());
    let query_text = String::from_utf8(query.stdout).unwrap();
    assert!(query_text
        .lines()
        .any(|line| line == "proxyjump jump.example"));

    let mut real_as_query = plan.bootstrap_args();
    real_as_query.insert(0, "-G".into());
    let real = Command::new("ssh").args(real_as_query).output().unwrap();
    let _ = fs::remove_file(&config);
    assert!(
        real.status.success(),
        "real-policy stderr={:?}",
        real.stderr
    );
    let real_text = String::from_utf8(real.stdout).unwrap();
    assert!(!real_text
        .lines()
        .any(|line| line.starts_with("proxyjump ") || line.starts_with("proxycommand ")));
    assert!(real_text.lines().any(|line| line == "controlmaster false"));
    assert!(real_text
        .lines()
        .any(|line| line == "forkafterauthentication no"));
}
