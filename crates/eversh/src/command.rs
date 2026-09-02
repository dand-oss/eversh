//! Pure, shell-free construction of every process invocation the supervisor
//! makes (design 7). Remote command strings contain only fixed command words,
//! validated conservative identifiers, and at most one bounded unpadded
//! base64url token; nothing here reads global state, spawns, or prints.

use crate::error::Error;
use crate::limits::Limits;
use crate::remote::{
    base64url_encode, validate_host, validate_name, validate_origin_label, ControlRequest,
};
use crate::role::{EVERLINK_ROLE, EVERPTY_ROLE, EVERPTY_ROLE_VERSION};
use std::ffi::OsString;

/// Maximum bytes for any single constructed shell word.
const WORD_MAX: usize = 4096;

/// Validate a bare remote command word (a binary name on the remote PATH).
fn validate_bare_word(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > WORD_MAX
        || value.starts_with('-')
        || value.starts_with('.')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(Error::RemoteWordInvalid);
    }
    Ok(())
}

/// Validate a canonical absolute path usable as one remote shell word.
fn validate_absolute_word(value: &str) -> Result<(), Error> {
    if !value.starts_with('/')
        || value.len() > WORD_MAX
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
        || value[1..]
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(Error::RemoteWordInvalid);
    }
    Ok(())
}

/// The remote eversh binary reference: a bare command word resolved by the
/// remote login shell's PATH or a canonical absolute path.
pub fn validate_remote_eversh(value: &str) -> Result<(), Error> {
    if value.starts_with('/') {
        validate_absolute_word(value)
    } else {
        validate_bare_word(value)
    }
}

/// Validate the local executable path for embedding in a single-quoted
/// ProxyCommand word: absolute UTF-8 without quotes or control bytes.
pub fn validate_self_exe(path: &std::path::Path) -> Result<&str, Error> {
    let text = path.to_str().ok_or(Error::SelfExeUnsafe)?;
    if !text.starts_with('/')
        || text.len() > WORD_MAX
        || text
            .chars()
            .any(|character| character.is_control() || character == '\'')
    {
        return Err(Error::SelfExeUnsafe);
    }
    Ok(text)
}

/// Single-quote one word for the ProxyCommand line (run by the user's local
/// shell). Embedded quotes, control bytes, and NUL are rejected, never
/// escaped: the input set is validated upstream, so rejection is a bug guard.
fn quote_single(word: &str) -> Result<String, Error> {
    if word
        .chars()
        .any(|character| character.is_control() || character == '\'')
    {
        return Err(Error::SelfExeUnsafe);
    }
    Ok(format!("'{word}'"))
}

/// Audit one user SSH option through everlink's applicable allowlist
/// (design 6.4) and confirm it stays a safe single-quoted word.
pub fn audit_ssh_option(option: &str) -> Result<(), Error> {
    everlink::ssh_policy::audit_ssh_option(option).map_err(|_| Error::SshOptionRejected)?;
    if option.contains('\'') {
        return Err(Error::SshOptionRejected);
    }
    Ok(())
}

/// Build the ProxyCommand string handed to the outer OpenSSH client: this
/// process re-invoked through its everlink role. `%n` preserves the original
/// destination token and `%p` the effective port, so ssh_config aliases and
/// port resolution stay authoritative (design 6.4).
///
/// `status_file`, when set, is appended as a `--status-file` ARGUMENT for
/// the local everlink `ssh-proxy` edge (design 3, 7). OpenSSH executes the
/// ProxyCommand line through the user's local shell, so the path travels in
/// everlink's own argv — a purely local handoff that no environment-
/// forwarding policy (`SendEnv`/`AcceptEnv`) can transmit remotely and no
/// ambient environment value can imitate. It inherits the exact same
/// single-quote rejection discipline as every other word: quotes, control
/// bytes (NUL included), and non-UTF-8 are rejected outright, never
/// escaped.
pub fn proxy_command(
    self_exe: &str,
    remote_eversh: &str,
    ssh_options: &[String],
    status_file: Option<&std::path::Path>,
) -> Result<String, Error> {
    validate_remote_eversh(remote_eversh)?;
    let mut command = quote_single(self_exe)?;
    command.push(' ');
    command.push_str(EVERLINK_ROLE);
    command.push_str(" ssh-proxy '%n' '%p' --remote-eversh ");
    command.push_str(&quote_single(remote_eversh)?);
    for option in ssh_options {
        audit_ssh_option(option)?;
        command.push_str(" --ssh-option ");
        command.push_str(&quote_single(option)?);
    }
    if let Some(path) = status_file {
        let word = path.to_str().ok_or(Error::StatusPathUnsafe)?;
        command.push_str(" --status-file ");
        command.push_str(&quote_single(word)?);
    }
    Ok(command)
}

/// Whether a local link-status file path can be embedded as the
/// single-quoted `--status-file` ProxyCommand word: UTF-8, no quotes, no
/// control bytes (NUL included), and bounded length — the same rejection
/// discipline as [`validate_self_exe`]. The supervisor's best-effort status
/// allocation uses this so an unembeddable state root degrades to
/// uninstrumented spawns (the safe exit-code-only default) instead of
/// failing a session outright.
pub fn status_word_safe(path: &std::path::Path) -> bool {
    path.to_str().is_some_and(|text| {
        text.len() <= WORD_MAX
            && !text
                .chars()
                .any(|character| character.is_control() || character == '\'')
    })
}

/// One remote everpty-role operation (the private versioned remote grammar).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteOp<'a> {
    AttachOrCreate {
        name: &'a str,
        request: &'a ControlRequest,
    },
    Attach {
        name: &'a str,
        request: &'a ControlRequest,
    },
    Observe {
        name: &'a str,
    },
    List {
        json: bool,
        filter_origin: Option<&'a str>,
    },
    Probe {
        name: &'a str,
    },
    Detach {
        name: &'a str,
    },
    Kill {
        name: &'a str,
    },
}

impl RemoteOp<'_> {
    /// Whether the operation drives the live terminal path (TTY required).
    pub fn interactive(&self) -> bool {
        matches!(self, Self::AttachOrCreate { .. } | Self::Attach { .. })
    }
}

fn checked_name(name: &str, limits: &Limits) -> Result<String, Error> {
    if !validate_name(name, limits) {
        return Err(Error::NameInvalid);
    }
    Ok(name.to_owned())
}

/// Build the exact remote command words for one operation: fixed words, one
/// validated conservative name, and at most one base64url token.
pub fn remote_words(
    remote_eversh: &str,
    op: &RemoteOp<'_>,
    limits: &Limits,
) -> Result<Vec<String>, Error> {
    validate_remote_eversh(remote_eversh)?;
    let mut words = vec![
        remote_eversh.to_owned(),
        EVERPTY_ROLE.to_owned(),
        EVERPTY_ROLE_VERSION.to_owned(),
    ];
    match op {
        RemoteOp::AttachOrCreate { name, request } => {
            words.push("attach-or-create".to_owned());
            words.push(checked_name(name, limits)?);
            words.push(base64url_encode(&request.encode(limits)?));
        }
        RemoteOp::Attach { name, request } => {
            words.push("attach".to_owned());
            words.push(checked_name(name, limits)?);
            words.push(base64url_encode(&request.encode(limits)?));
        }
        RemoteOp::Observe { name } => {
            words.push("observe".to_owned());
            words.push(checked_name(name, limits)?);
        }
        RemoteOp::List {
            json,
            filter_origin,
        } => {
            words.push("list".to_owned());
            words.push(if *json { "json" } else { "text" }.to_owned());
            if let Some(label) = filter_origin {
                validate_origin_label(label, limits)?;
                words.push(base64url_encode(label.as_bytes()));
            }
        }
        RemoteOp::Probe { name } => {
            words.push("probe".to_owned());
            words.push(checked_name(name, limits)?);
        }
        RemoteOp::Detach { name } => {
            words.push("detach".to_owned());
            words.push(checked_name(name, limits)?);
        }
        RemoteOp::Kill { name } => {
            words.push("kill".to_owned());
            words.push(checked_name(name, limits)?);
        }
    }
    Ok(words)
}

/// Build the complete outer `ssh` argument vector for one remote operation.
/// The ProxyCommand option is deliberately FIRST: OpenSSH takes the first
/// obtained value for an option, so nothing later can displace the everlink
/// transport. User options follow (already audited), then `-t` for the live
/// terminal path, `--`, the validated destination, and the remote words.
pub fn outer_ssh_args(
    proxy_command: &str,
    ssh_options: &[String],
    host: &str,
    remote: &[String],
    interactive: bool,
) -> Result<Vec<OsString>, Error> {
    validate_host(host)?;
    let mut args: Vec<OsString> = Vec::with_capacity(8 + ssh_options.len() + remote.len());
    args.push("-o".into());
    args.push(format!("ProxyCommand={proxy_command}").into());
    for option in ssh_options {
        audit_ssh_option(option)?;
        args.push(option.into());
    }
    if interactive {
        args.push("-t".into());
    }
    args.push("--".into());
    args.push(host.into());
    for word in remote {
        args.push(word.into());
    }
    Ok(args)
}

/// Split raw-mode trailing tokens (`eversh ssh HOST [-- TOKENS...]`) at the
/// first literal `--`: tokens before it are outer SSH options (placed before
/// the destination); tokens after it are a remote command (placed after the
/// destination, design 7). With no inner `--`, every token is an option —
/// identical to the pre-M4-finding-4 behavior, so existing raw invocations
/// keep working unchanged.
pub fn split_raw_tokens(tokens: &[String]) -> (&[String], &[String]) {
    match tokens.iter().position(|token| token == "--") {
        Some(index) => (&tokens[..index], &tokens[index + 1..]),
        None => (tokens, &[]),
    }
}

/// Filter SSH options down to the subset that passes the audited allowlist
/// (design 6.4). Raw mode's outer `ssh` invocation stays fully unaudited
/// (the escape hatch), but only the audited subset is safe to mirror into
/// the everlink bootstrap's ProxyCommand; a token that fails audit simply
/// stays outer-ssh-only and is never an error in raw mode.
pub fn audited_subset(options: &[String]) -> Vec<String> {
    options
        .iter()
        .filter(|option| audit_ssh_option(option).is_ok())
        .cloned()
        .collect()
}

/// Build the raw `eversh ssh` argument vector: our ProxyCommand first (its
/// value wins under OpenSSH first-value semantics), then the user's PRE
/// options verbatim, then the destination, then a POST remote command (both
/// halves produced by [`split_raw_tokens`]). Raw mode is the unaudited
/// escape hatch for the outer `ssh` invocation; it is never retried.
pub fn raw_ssh_args(
    proxy_command: &str,
    pre_options: &[String],
    host: &str,
    post_command: &[String],
) -> Result<Vec<OsString>, Error> {
    validate_host(host)?;
    let mut args: Vec<OsString> = Vec::with_capacity(4 + pre_options.len() + post_command.len());
    args.push("-o".into());
    args.push(format!("ProxyCommand={proxy_command}").into());
    for option in pre_options {
        args.push(option.into());
    }
    args.push("--".into());
    args.push(host.into());
    for word in post_command {
        args.push(word.into());
    }
    Ok(args)
}

/// Build one Kitty remote-control launch: a new tab running this executable's
/// attach command for one session. `--hold-on-error` keeps failed attaches
/// visible in their tab; cleanly ended commands close their tab (Kitty's
/// default), matching design 7.
pub fn kitty_launch_args(
    listen_on: Option<&str>,
    self_exe: &str,
    host: &str,
    name: &str,
    ssh_options: &[String],
    limits: &Limits,
) -> Result<Vec<OsString>, Error> {
    validate_host(host)?;
    let name = checked_name(name, limits)?;
    let mut args: Vec<OsString> = vec!["@".into()];
    if let Some(target) = listen_on {
        args.push("--to".into());
        args.push(target.into());
    }
    args.push("launch".into());
    args.push("--type=tab".into());
    args.push("--tab-title".into());
    args.push(format!("eversh {host} {name}").into());
    args.push("--".into());
    args.push(self_exe.into());
    args.push("attach".into());
    args.push(host.into());
    args.push(name.into());
    args.push("--hold-on-error".into());
    for option in ssh_options {
        audit_ssh_option(option)?;
        args.push("--ssh-option".into());
        args.push(option.into());
    }
    Ok(args)
}
