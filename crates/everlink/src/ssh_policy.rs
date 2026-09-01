//! Pure, shell-free OpenSSH argument policy.

use crate::error::Error;

pub const SSH_PROGRAM: &str = "ssh";
pub const REMOTE_BOOTSTRAP_COMMAND: &str = "everlink __bootstrap-parent-v1";
const REMOTE_BOOTSTRAP_ROLE: &str = "__bootstrap-parent-v1";

const SSH_ARGUMENT_MAX: usize = 4096;
const SSH_OPTION_COUNT_MAX: usize = 128;

const MANDATORY: &[&str] = &[
    "ProxyCommand=none",
    "ControlMaster=no",
    "ControlPath=none",
    "ControlPersist=no",
    "ForkAfterAuthentication=no",
    "PermitLocalCommand=no",
    "LocalCommand=none",
    "RemoteCommand=none",
    "SessionType=default",
    "RequestTTY=no",
    "ClearAllForwardings=yes",
    "ForwardAgent=no",
    "ForwardX11=no",
    "ForwardX11Trusted=no",
    "Tunnel=no",
    "StdinNull=yes",
];

const ALLOWED_O: &[&str] = &[
    "addkeystoagent",
    "addressfamily",
    "bindaddress",
    "bindinterface",
    "casignaturealgorithms",
    "certificatefile",
    "checkhostip",
    "connectionattempts",
    "connecttimeout",
    "globalknownhostsfile",
    "hashknownhosts",
    "hostkeyalgorithms",
    "hostkeyalias",
    "identitiesonly",
    "identityagent",
    "identityfile",
    "ipqos",
    "kbdinteractiveauthentication",
    "numberofpasswordprompts",
    "passwordauthentication",
    "pkcs11provider",
    "preferredauthentications",
    "pubkeyauthentication",
    "requiredrsasize",
    "securitykeyprovider",
    "serveralivecountmax",
    "serveraliveinterval",
    "stricthostkeychecking",
    "tcpkeepalive",
    "updatehostkeys",
    "user",
    "userknownhostsfile",
    "verifyhostkeydns",
];

#[derive(Clone, PartialEq, Eq)]
pub struct SshPlan {
    destination: String,
    port: u16,
    options: Vec<String>,
    remote_bootstrap_command: String,
}

impl std::fmt::Debug for SshPlan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SshPlan")
            .field("destination", &"<REDACTED>")
            .field("port", &self.port)
            .field("option_count", &self.options.len())
            .finish()
    }
}

impl SshPlan {
    pub fn new(destination: String, port: String, options: Vec<String>) -> Result<Self, Error> {
        validate_destination(&destination)?;
        let port = validate_port(&port)?;
        if options.len() > SSH_OPTION_COUNT_MAX {
            return Err(Error::InvalidSshArgument);
        }
        for option in &options {
            validate_option(option)?;
        }
        Ok(Self {
            destination,
            port,
            options,
            remote_bootstrap_command: REMOTE_BOOTSTRAP_COMMAND.to_owned(),
        })
    }

    /// Select a remote binary without relying on the remote login shell's
    /// non-interactive `PATH`. Only canonical absolute paths are accepted so
    /// the command remains a single, injection-safe remote shell word.
    pub fn with_remote_binary(mut self, remote_binary: String) -> Result<Self, Error> {
        validate_remote_binary(&remote_binary)?;
        self.remote_bootstrap_command = format!("{remote_binary} {REMOTE_BOOTSTRAP_ROLE}");
        Ok(self)
    }

    pub fn destination(&self) -> &str {
        &self.destination
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Arguments for an authoritative bounded `ssh -G` policy query. The
    /// anti-proxy value is deliberately absent so configured proxying remains
    /// observable and can be rejected.
    pub fn config_query_args(&self) -> Vec<String> {
        let mut args = vec!["-G".to_owned()];
        push_mandatory(
            &mut args,
            MANDATORY
                .iter()
                .copied()
                .filter(|value| !value.eq_ignore_ascii_case("ProxyCommand=none")),
        );
        args.push("-p".to_owned());
        args.push(self.port.to_string());
        args.extend(self.options.iter().cloned());
        args.push("--".to_owned());
        args.push(self.destination.clone());
        args
    }

    pub fn bootstrap_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        push_mandatory(&mut args, MANDATORY.iter().copied());
        args.push("-p".to_owned());
        args.push(self.port.to_string());
        args.extend(self.options.iter().cloned());
        args.push("--".to_owned());
        args.push(self.destination.clone());
        args.push(self.remote_bootstrap_command.clone());
        args
    }
}

fn push_mandatory<'a>(output: &mut Vec<String>, values: impl IntoIterator<Item = &'a str>) {
    for value in values {
        output.push("-o".to_owned());
        output.push(value.to_owned());
    }
}

fn validate_destination(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > SSH_ARGUMENT_MAX
        || value.starts_with('-')
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(Error::InvalidSshArgument);
    }
    Ok(())
}

fn validate_port(value: &str) -> Result<u16, Error> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::InvalidSshArgument);
    }
    let port = value
        .parse::<u16>()
        .map_err(|_| Error::InvalidSshArgument)?;
    if port == 0 || port.to_string() != value {
        return Err(Error::InvalidSshArgument);
    }
    Ok(port)
}

fn validate_remote_binary(value: &str) -> Result<(), Error> {
    let suffix_length = 1usize.saturating_add(REMOTE_BOOTSTRAP_ROLE.len());
    if !value.starts_with('/')
        || value.len() > SSH_ARGUMENT_MAX.saturating_sub(suffix_length)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
        || value[1..]
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(Error::InvalidSshArgument);
    }
    Ok(())
}

fn validate_option(option: &str) -> Result<(), Error> {
    if option.is_empty()
        || option.len() > SSH_ARGUMENT_MAX
        || option
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(Error::InvalidSshArgument);
    }
    if matches!(option, "-4" | "-6") {
        return Ok(());
    }
    for prefix in ["-F", "-i", "-l", "-b", "-B"] {
        if let Some(value) = option.strip_prefix(prefix) {
            return if value.is_empty() {
                Err(Error::InvalidSshArgument)
            } else {
                Ok(())
            };
        }
    }
    let body = option.strip_prefix("-o").ok_or(Error::InvalidSshArgument)?;
    let (name, value) = body.split_once('=').ok_or(Error::InvalidSshArgument)?;
    if name.is_empty() || value.is_empty() {
        return Err(Error::InvalidSshArgument);
    }
    let canonical = name.to_ascii_lowercase();
    if !ALLOWED_O.contains(&canonical.as_str()) {
        return Err(Error::InvalidSshArgument);
    }
    Ok(())
}

/// Inspect effective proxy fields from bounded canonical `ssh -G` bytes.
pub fn validate_effective_config(output: &[u8]) -> Result<(), Error> {
    if output.is_empty()
        || output.iter().any(|byte| {
            *byte == b'\0' || *byte == b'\r' || (*byte < b' ' && *byte != b'\n' && *byte != b'\t')
        })
    {
        return Err(Error::SshPolicyRejected);
    }

    let mut lines = 0usize;
    for line in output.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        lines = lines.saturating_add(1);
        let split = line
            .iter()
            .position(|byte| byte.is_ascii_whitespace())
            .ok_or(Error::SshPolicyRejected)?;
        let name = &line[..split];
        let value = line[split..]
            .iter()
            .position(|byte| !byte.is_ascii_whitespace())
            .map(|offset| &line[split + offset..])
            .ok_or(Error::SshPolicyRejected)?;
        if name.is_empty()
            || !name
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        {
            return Err(Error::SshPolicyRejected);
        }
        if (name.eq_ignore_ascii_case(b"proxycommand") || name.eq_ignore_ascii_case(b"proxyjump"))
            && !value.eq_ignore_ascii_case(b"none")
        {
            return Err(Error::SshPolicyRejected);
        }
    }
    if lines == 0 {
        return Err(Error::SshPolicyRejected);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn argv_is_ordered_fixed_and_has_no_batch_mode() {
        let plan = SshPlan::new(
            "user@alias".to_owned(),
            "2222".to_owned(),
            vec!["-i/tmp/key".to_owned(), "-oConnectTimeout=7".to_owned()],
        )
        .unwrap();
        let args = plan.bootstrap_args();
        assert_eq!(&args[..2], ["-o", "ProxyCommand=none"]);
        assert_eq!(args[args.len() - 3], "--");
        assert_eq!(args[args.len() - 2], "user@alias");
        assert_eq!(args.last().unwrap(), REMOTE_BOOTSTRAP_COMMAND);
        assert!(!args.iter().any(|arg| arg.contains("BatchMode")));
        assert_eq!(
            args.iter()
                .filter(|arg| arg.as_str() == "LocalCommand=none")
                .count(),
            1
        );
        assert!(
            args.iter().position(|arg| arg == "ControlMaster=no")
                < args.iter().position(|arg| arg == "-i/tmp/key")
        );
    }

    #[test]
    fn arguments_fail_closed() {
        for destination in ["", "-host", "host name", "host\nname"] {
            assert!(SshPlan::new(destination.into(), "22".into(), vec![]).is_err());
        }
        for port in ["", "0", "022", "+22", "65536"] {
            assert!(SshPlan::new("host".into(), port.into(), vec![]).is_err());
        }
        for option in [
            "-oProxyCommand=none",
            "-oBatchMode=yes",
            "-Jjump",
            "-p22",
            "-i",
            "-oUser",
            "-oUser=bad value",
            "-oRemoteCommand=none",
            "--bad",
        ] {
            assert!(SshPlan::new("host".into(), "22".into(), vec![option.into()]).is_err());
        }
    }

    #[test]
    fn explicit_remote_binary_is_absolute_canonical_and_shell_safe() {
        let plan = SshPlan::new("host".into(), "22".into(), vec![])
            .unwrap()
            .with_remote_binary("/home/appsmith/bin/everlink".into())
            .unwrap();
        assert_eq!(
            plan.bootstrap_args().last().unwrap(),
            "/home/appsmith/bin/everlink __bootstrap-parent-v1"
        );

        for rejected in [
            "",
            "everlink",
            "~/bin/everlink",
            "$HOME/bin/everlink",
            "/home/app smith/bin/everlink",
            "/home/appsmith/bin/../everlink",
            "/home//appsmith/bin/everlink",
            "/home/appsmith/bin/everlink;false",
        ] {
            assert!(
                SshPlan::new("host".into(), "22".into(), vec![])
                    .unwrap()
                    .with_remote_binary(rejected.into())
                    .is_err(),
                "accepted remote binary {rejected:?}"
            );
        }
    }

    #[test]
    fn effective_proxying_is_rejected() {
        assert!(validate_effective_config(b"user me\nproxycommand none\n").is_ok());
        assert!(validate_effective_config(b"proxyjump jump.example\n").is_err());
        assert!(validate_effective_config(b"proxycommand ssh -W %h:%p jump\n").is_err());
    }
}
