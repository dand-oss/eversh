//! eversh combined binary: pure role selection before any runtime, then the
//! supervisor CLI, the private everpty role edge, or the everlink role edge.
//! CLI parsing, environment capture, diagnostics, and exit mapping live here;
//! only the everlink role may build the single Tokio runtime.
#![cfg_attr(not(test), allow(clippy::print_stderr, clippy::print_stdout))]

use clap::{error::ErrorKind as ClapErrorKind, ArgAction, Parser, Subcommand};
use eversh::command::RemoteOp;
use eversh::role::{
    parse_everpty_role, select_role, EverptyRoleCommand, Role, EVERPTY_ROLE_VERSION,
};
use eversh::supervisor::{
    self, Config, Event, ExitKind, Notifier, ResumeFailure, SessionEnd, TransportFailure,
    PROBE_NOT_LIVE_EXIT, REMOTE_BUSY_EXIT,
};
use eversh::{Error, Limits};
use std::ffi::OsString;
use std::fmt::Write as _;
use std::io::{BufRead, Write as _};
use std::path::PathBuf;

fn main() {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let role_words: Vec<String> = args
        .iter()
        .take(1)
        .filter_map(|arg| arg.to_str().map(str::to_owned))
        .collect();
    match select_role(&role_words) {
        Role::Everlink => {
            let code = everlink::edge::run(
                everlink::edge::Invocation::CombinedEversh,
                args[1..].to_vec(),
            );
            std::process::exit(i32::from(code));
        }
        Role::Everpty => run_everpty_role(&args[1..]),
        Role::Supervisor => run_supervisor(),
    }
}

// ---------------------------------------------------------------------------
// everpty role edge (remote side of the private v1 grammar)
// ---------------------------------------------------------------------------

fn state_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::with_capacity(4);
    if let Some(path) = std::env::var_os("EVERSH_STATE_DIR") {
        candidates.push(PathBuf::from(path));
    }
    if let Some(path) = std::env::var_os("XDG_RUNTIME_DIR") {
        candidates.push(PathBuf::from(path).join("eversh"));
    }
    if let Some(path) = std::env::var_os("XDG_STATE_HOME") {
        candidates.push(PathBuf::from(path).join("eversh"));
    }
    if let Some(path) = std::env::var_os("HOME") {
        candidates.push(PathBuf::from(path).join(".local/state/eversh"));
    }
    candidates
}

fn captured_environment() -> Vec<OsString> {
    std::env::vars_os()
        .map(|(key, value)| {
            let mut entry = key;
            entry.push("=");
            entry.push(value);
            entry
        })
        .collect()
}

/// Exit code for role-protocol violations (bad grammar/token).
const ROLE_PROTOCOL_EXIT: u8 = 2;
/// Exit code when the remote role protocol version is unsupported.
const ROLE_VERSION_EXIT: u8 = 6;

fn run_everpty_role(args: &[OsString]) -> ! {
    let mut words = Vec::with_capacity(args.len());
    for arg in args {
        match arg.to_str() {
            Some(text) => words.push(text.to_owned()),
            None => {
                eprintln!("eversh: everpty role arguments must be UTF-8");
                std::process::exit(i32::from(ROLE_PROTOCOL_EXIT));
            }
        }
    }
    let limits = Limits::default();
    let parsed = match parse_everpty_role(&words, &limits) {
        Ok(parsed) => parsed,
        Err(Error::RoleVersionUnsupported) => {
            eprintln!(
                "eversh: everpty role remote protocol version is unsupported (this binary speaks {EVERPTY_ROLE_VERSION})"
            );
            std::process::exit(i32::from(ROLE_VERSION_EXIT));
        }
        Err(error) => {
            eprintln!("eversh: {error}");
            std::process::exit(i32::from(ROLE_PROTOCOL_EXIT));
        }
    };
    if let Err(error) = everpty::sys::ignore_sigpipe() {
        everpty_role_error(everpty::Error::Io(error));
    }
    match execute_everpty_role(parsed) {
        Ok(outcome) => everpty_role_outcome(outcome),
        Err(error) => everpty_role_error(error),
    }
}

fn everpty_context() -> everpty::run::Context {
    everpty::run::Context {
        state_candidates: state_candidates(),
        limits: everpty::Limits::default(),
    }
}

fn execute_everpty_role(
    parsed: EverptyRoleCommand,
) -> Result<everpty::run::Outcome, everpty::Error> {
    use everpty::frame::Role as PtyRole;
    use everpty::run::{self, AttachRequest, StartRequest};
    use std::os::fd::AsFd;
    use std::os::unix::ffi::OsStringExt;

    let context = everpty_context();
    let stdin_handle = std::io::stdin();
    let stdout_handle = std::io::stdout();
    let stdin = stdin_handle.as_fd();
    let stdout = stdout_handle.as_fd();
    match parsed {
        EverptyRoleCommand::AttachOrCreate { name, request } => {
            if request.take_over {
                // Takeover targets an existing session; only a session that
                // is not live falls through to the atomic attach-or-create.
                match run::attach(AttachRequest {
                    context: &context,
                    name: &name,
                    role: PtyRole::Writer,
                    take_over: true,
                    stdin,
                    stdout,
                }) {
                    Err(everpty::Error::NotLive) => {}
                    result => return result,
                }
            }
            run::attach_or_create(StartRequest {
                context,
                name,
                command: request
                    .child_argv
                    .into_iter()
                    .map(OsString::from_vec)
                    .collect(),
                default_shell: std::env::var_os("SHELL"),
                environment: captured_environment(),
                path: std::env::var_os("PATH"),
                origins: request.origins.into_iter().map(OsString::from).collect(),
                stdin,
                stdout,
            })
        }
        EverptyRoleCommand::Attach { name, request } => run::attach(AttachRequest {
            context: &context,
            name: &name,
            role: PtyRole::Writer,
            take_over: request.take_over,
            stdin,
            stdout,
        }),
        EverptyRoleCommand::Observe { name } => run::observe(AttachRequest {
            context: &context,
            name: &name,
            role: PtyRole::Observer,
            take_over: false,
            stdin,
            stdout,
        }),
        EverptyRoleCommand::List {
            json,
            filter_origin,
        } => {
            let mut sessions = run::list(&context)?;
            if let Some(label) = &filter_origin {
                sessions.retain(|meta| meta.origins().iter().any(|origin| origin == label));
            }
            let mut rendered = if json {
                let mut text = list_json(&sessions);
                text.push('\n');
                text
            } else {
                text_list(&sessions)
            };
            if !json && rendered.is_empty() {
                rendered = String::new();
            }
            write_stdout(&stdout_handle, rendered.as_bytes())?;
            Ok(everpty::run::Outcome::Success)
        }
        EverptyRoleCommand::Probe { name } => {
            let sessions = run::list(&context)?;
            if sessions.iter().any(|meta| meta.name() == name) {
                Ok(everpty::run::Outcome::Success)
            } else {
                eprintln!("eversh: session is not live");
                std::process::exit(i32::from(PROBE_NOT_LIVE_EXIT));
            }
        }
        EverptyRoleCommand::Detach { name } => run::detach(&context, &name),
        EverptyRoleCommand::Kill { name } => run::kill(&context, &name),
    }
}

fn write_stdout(stdout: &std::io::Stdout, bytes: &[u8]) -> Result<(), everpty::Error> {
    let mut output = stdout.lock();
    output.write_all(bytes)?;
    output.flush()?;
    Ok(())
}

/// Exact everpty exit mapping (kept byte-compatible with the standalone
/// everpty binary edge).
fn everpty_role_outcome(outcome: everpty::run::Outcome) -> ! {
    use everpty::run::Outcome;
    match outcome {
        Outcome::Success | Outcome::Detached => std::process::exit(0),
        Outcome::ChildExited(code) => std::process::exit(i32::from(code)),
        Outcome::ChildSignaled(signal) | Outcome::LocalSignaled(signal) => {
            let _ = everpty::sys::reraise_default(signal);
            std::process::exit(128 + signal);
        }
        Outcome::Broker(exit) => std::process::exit(i32::from(exit.suggested_exit_code)),
    }
}

fn everpty_role_error(error: everpty::Error) -> ! {
    let code: u8 = if matches!(error, everpty::Error::Busy { .. }) {
        REMOTE_BUSY_EXIT
    } else {
        1
    };
    eprintln!("eversh: {error}");
    std::process::exit(i32::from(code));
}

// The list renderers are kept byte-identical with the standalone everpty
// binary edge so both executables present the same discovery data (verified
// by a cross-binary test).

fn json_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch <= '\u{1f}' => {
                let _ = write!(out, "\\u{:04x}", ch as u32);
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
}

fn list_json(sessions: &[everpty::session::SessionMeta]) -> String {
    let mut out = String::from("{\"version\":1,\"sessions\":[");
    for (index, meta) in sessions.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        out.push_str("{\"name\":");
        json_string(&mut out, meta.name());
        let _ = write!(
            out,
            ",\"broker\":{{\"pid\":{},\"start_ticks\":\"{}\"}},\"child\":",
            meta.broker_pid(),
            meta.broker_start_ticks()
        );
        if let Some(child) = meta.child() {
            let _ = write!(
                out,
                "{{\"pid\":{},\"pgid\":{},\"start_ticks\":\"{}\"}}",
                child.pid(),
                child.pgid(),
                child.start_ticks()
            );
        } else {
            out.push_str("null");
        }
        let _ = write!(
            out,
            ",\"created_unix_ms\":\"{}\",\"executable\":",
            meta.created_unix_ms()
        );
        json_string(&mut out, meta.exec_label());
        let _ = write!(
            out,
            ",\"executable_truncated\":{},\"origins\":[",
            meta.exec_truncated()
        );
        for (origin_index, origin) in meta.origins().iter().enumerate() {
            if origin_index != 0 {
                out.push(',');
            }
            json_string(&mut out, origin);
        }
        out.push_str("]}");
    }
    out.push_str("]}");
    out
}

fn text_list(sessions: &[everpty::session::SessionMeta]) -> String {
    let mut out = String::new();
    for meta in sessions {
        match meta.child() {
            Some(child) => writeln!(
                out,
                "{}\t{}\t{}\t{}",
                meta.name(),
                meta.broker_pid(),
                child.pid(),
                meta.exec_label()
            )
            .expect("writing to a String cannot fail"),
            None => writeln!(
                out,
                "{}\t{}\t-\t{}",
                meta.name(),
                meta.broker_pid(),
                meta.exec_label()
            )
            .expect("writing to a String cannot fail"),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Supervisor CLI
// ---------------------------------------------------------------------------

#[derive(Debug, Parser)]
#[command(
    name = "eversh",
    version,
    about = "Roaming SSH session supervisor over everlink and everpty"
)]
struct Cli {
    /// Remote combined eversh binary (bare PATH word or absolute path).
    #[arg(long = "remote-eversh", value_name = "WORD_OR_PATH", global = true)]
    remote_eversh: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Connect to a host and attach-or-create a named session.
    Connect {
        host: String,
        /// Session name (generated when omitted; printed to stderr).
        #[arg(long)]
        session: Option<String>,
        #[arg(long = "take-over")]
        take_over: bool,
        /// One audited, self-contained OpenSSH option.
        #[arg(long = "ssh-option", value_name = "OPTION", action = ArgAction::Append, allow_hyphen_values = true)]
        ssh_option: Vec<String>,
        /// Child command and arguments after `--` (defaults to the remote
        /// login shell).
        #[arg(last = true, value_name = "COMMAND")]
        command: Vec<OsString>,
    },
    /// Attach to an existing named session as writer.
    Attach {
        host: String,
        name: String,
        #[arg(long = "take-over")]
        take_over: bool,
        /// Keep a failed attach visible until stdin is closed (Kitty tabs).
        #[arg(long = "hold-on-error", hide = true)]
        hold_on_error: bool,
        #[arg(long = "ssh-option", value_name = "OPTION", action = ArgAction::Append, allow_hyphen_values = true)]
        ssh_option: Vec<String>,
    },
    /// Observe a named session (future output only, no input).
    Observe {
        host: String,
        name: String,
        #[arg(long = "ssh-option", value_name = "OPTION", action = ArgAction::Append, allow_hyphen_values = true)]
        ssh_option: Vec<String>,
    },
    /// List sessions on a host.
    List {
        host: String,
        /// Show only sessions created from this local host name.
        #[arg(long = "local-host", value_name = "NAME")]
        local_host: Option<String>,
        #[arg(long)]
        json: bool,
        #[arg(long = "ssh-option", value_name = "OPTION", action = ArgAction::Append, allow_hyphen_values = true)]
        ssh_option: Vec<String>,
    },
    /// Re-attach every matching live session, one Kitty tab per session.
    ResumeAll {
        host: String,
        /// Match sessions created from this local host name (default: this
        /// machine's host name).
        #[arg(long = "local-host", value_name = "NAME")]
        local_host: Option<String>,
        #[arg(long = "ssh-option", value_name = "OPTION", action = ArgAction::Append, allow_hyphen_values = true)]
        ssh_option: Vec<String>,
    },
    /// Detach a session's current writer without sending a terminal byte.
    Detach {
        host: String,
        name: String,
        #[arg(long = "ssh-option", value_name = "OPTION", action = ArgAction::Append, allow_hyphen_values = true)]
        ssh_option: Vec<String>,
    },
    /// Kill a session.
    Kill {
        host: String,
        name: String,
        #[arg(long = "ssh-option", value_name = "OPTION", action = ArgAction::Append, allow_hyphen_values = true)]
        ssh_option: Vec<String>,
    },
    /// Raw OpenSSH over everlink (never restarted automatically).
    ///
    /// Tokens after `--` may contain one further literal `--`: tokens before
    /// it are outer SSH options (placed before the destination, verbatim,
    /// unaudited); tokens after it are a remote command (placed after the
    /// destination). With no inner `--`, every token is an SSH option
    /// (`eversh ssh HOST -- -4` behaves as before). Options that pass the
    /// audited allowlist (design 6.4) are also mirrored into the everlink
    /// bootstrap; options that fail the audit stay outer-ssh-only and are
    /// not an error in raw mode.
    Ssh {
        host: String,
        #[arg(last = true, value_name = "TOKENS")]
        tokens: Vec<String>,
    },
}

fn local_host_name() -> String {
    if let Ok(name) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            return trimmed.to_owned();
        }
    }
    if let Some(name) = std::env::var_os("HOSTNAME").and_then(|value| value.into_string().ok()) {
        if !name.is_empty() {
            return name;
        }
    }
    "unknown".to_owned()
}

fn build_config(remote_eversh: Option<String>) -> Result<Config, Error> {
    let self_exe = std::env::current_exe().map_err(Error::Io)?;
    Ok(Config {
        ssh_program: OsString::from("ssh"),
        kitty_program: OsString::from("kitty"),
        self_exe,
        remote_eversh: remote_eversh.unwrap_or_else(|| "eversh".to_owned()),
        kitty_listen_on: std::env::var_os("KITTY_LISTEN_ON")
            .and_then(|value| value.into_string().ok()),
        local_host: local_host_name(),
        // The same state-root precedence as the remote everpty role edge
        // (design 5.4), resolved locally: the highest-precedence candidate
        // becomes the private root eversh creates its per-spawn everlink
        // link-status files under (design 3, 7). `None` only when no
        // candidate resolves at all (no env var and no HOME); the
        // supervisor then skips status-file instrumentation entirely and
        // every 255 falls through to the safe unparseable/missing default.
        link_status_root: state_candidates().into_iter().next(),
        limits: Limits::default(),
    })
}

struct StderrNotifier;

impl Notifier for StderrNotifier {
    fn notify(&mut self, event: Event<'_>) {
        match event {
            Event::TransportInterrupted { attempt } => {
                eprintln!("eversh: transport interrupted (attempt {attempt})");
            }
            Event::Backoff { attempt, delay_ms } => {
                eprintln!("eversh: reconnect attempt {attempt} in {delay_ms} ms");
            }
            Event::Probing { name, attempt } => {
                eprintln!("eversh: probing session '{name}' (attempt {attempt})");
            }
            Event::SessionLive { attempt } => {
                eprintln!("eversh: session is live; reattaching (attempt {attempt})");
            }
            Event::SessionGone { name } => {
                eprintln!("eversh: session '{name}' is no longer live; not restarting it");
            }
            Event::ProbeUnreachable { attempt } => {
                eprintln!("eversh: host unreachable (attempt {attempt})");
            }
            Event::ProbeFailed { exit_code } => {
                eprintln!("eversh: probe failed with exit code {exit_code}");
            }
            Event::Reattaching { name, attempt } => {
                eprintln!("eversh: reattaching session '{name}' (attempt {attempt})");
            }
            Event::RetryExhausted { attempts } => {
                eprintln!("eversh: giving up after {attempts} reconnect attempts");
            }
            Event::RetryDeadlineExceeded => {
                eprintln!("eversh: reconnect deadline exceeded");
            }
            Event::ResumeLaunched { name } => {
                eprintln!("eversh: launched tab for session '{name}'");
            }
            Event::ResumeSkipped { name } => {
                eprintln!("eversh: session '{name}' skipped (resume cap reached)");
            }
            Event::SshFailed => {
                eprintln!("eversh: ssh reported failure with the transport intact");
            }
            Event::ReattachBusy { name, attempt } => {
                eprintln!(
                    "eversh: session '{name}' reported busy on reattach (attempt {attempt}); \
                     retrying without take-over"
                );
            }
        }
    }
}

fn exit_session_end(end: SessionEnd) -> ! {
    match end {
        SessionEnd::Remote(code) => std::process::exit(i32::from(code)),
        SessionEnd::SshSignaled(signal) => {
            eprintln!("eversh: ssh terminated by signal {signal}");
            std::process::exit(128 + signal);
        }
        SessionEnd::SshFailed => {
            eprintln!("eversh: ssh reported failure with the transport intact; not retried");
            std::process::exit(255);
        }
        SessionEnd::TransportFailed(reason) => {
            match reason {
                TransportFailure::SessionGone => eprintln!(
                    "eversh: transport failed and the session is not live; \
                     the child may have exited with the transport"
                ),
                TransportFailure::AttemptsExhausted => {
                    eprintln!("eversh: transport failed; reconnect attempts exhausted")
                }
                TransportFailure::DeadlineExceeded => {
                    eprintln!("eversh: transport failed; reconnect deadline exceeded")
                }
                TransportFailure::ProbeFailed(code) => {
                    eprintln!("eversh: transport failed; probe failed with exit code {code}")
                }
                TransportFailure::ProbeSignaled(signal) => {
                    eprintln!("eversh: transport failed; probe terminated by signal {signal}")
                }
                TransportFailure::Busy => eprintln!(
                    "eversh: transport failed; the session stayed busy (writer already \
                     attached) and was never retried with take-over"
                ),
            }
            std::process::exit(255);
        }
    }
}

fn exit_error(error: Error) -> ! {
    eprintln!("eversh: {error}");
    std::process::exit(1);
}

fn exit_kind(kind: ExitKind) -> ! {
    match kind {
        ExitKind::Code(code) => std::process::exit(i32::from(code)),
        ExitKind::Signaled(signal) => {
            eprintln!("eversh: ssh terminated by signal {signal}");
            std::process::exit(128 + signal);
        }
    }
}

/// Hold a failed Kitty-tab attach visible until the user closes the tab or
/// presses Enter (design 7: keep failed attaches visible).
fn hold_for_acknowledgement(code: i32) -> ! {
    eprintln!("eversh: attach failed with exit code {code}; press Enter to close");
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    std::process::exit(code);
}

fn run_supervisor() -> ! {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let code = if matches!(
                error.kind(),
                ClapErrorKind::DisplayHelp | ClapErrorKind::DisplayVersion
            ) {
                0
            } else {
                2
            };
            let _ = error.print();
            std::process::exit(code);
        }
    };
    let config = match build_config(cli.remote_eversh) {
        Ok(config) => config,
        Err(error) => exit_error(error),
    };
    let mut notifier = StderrNotifier;
    match cli.cmd {
        Cmd::Connect {
            host,
            session,
            take_over,
            ssh_option,
            command,
        } => {
            let name = session.unwrap_or_else(|| {
                let generated = supervisor::generated_session_name(&config.limits);
                eprintln!("eversh: session name {generated}");
                generated
            });
            let child_argv: Vec<Vec<u8>> = command
                .into_iter()
                .map(|arg| {
                    use std::os::unix::ffi::OsStringExt;
                    arg.into_vec()
                })
                .collect();
            match supervisor::connect(
                &config,
                &host,
                &name,
                take_over,
                child_argv,
                &ssh_option,
                &mut notifier,
            ) {
                Ok(end) => exit_session_end(end),
                Err(error) => exit_error(error),
            }
        }
        Cmd::Attach {
            host,
            name,
            take_over,
            hold_on_error,
            ssh_option,
        } => {
            match supervisor::attach(&config, &host, &name, take_over, &ssh_option, &mut notifier) {
                Ok(SessionEnd::Remote(0)) => std::process::exit(0),
                Ok(end) => {
                    if hold_on_error {
                        let code = match end {
                            SessionEnd::Remote(code) => i32::from(code),
                            SessionEnd::SshSignaled(signal) => 128 + signal,
                            SessionEnd::SshFailed => 255,
                            SessionEnd::TransportFailed(_) => 255,
                        };
                        hold_for_acknowledgement(code);
                    }
                    exit_session_end(end)
                }
                Err(error) => {
                    if hold_on_error {
                        eprintln!("eversh: {error}");
                        hold_for_acknowledgement(1);
                    }
                    exit_error(error)
                }
            }
        }
        Cmd::Observe {
            host,
            name,
            ssh_option,
        } => match supervisor::observe(&config, &host, &name, &ssh_option, &mut notifier) {
            Ok(end) => exit_session_end(end),
            Err(error) => exit_error(error),
        },
        Cmd::List {
            host,
            local_host,
            json,
            ssh_option,
        } => match supervisor::list(&config, &host, local_host.as_deref(), json, &ssh_option) {
            Ok(captured) => {
                let stdout = std::io::stdout();
                let mut lock = stdout.lock();
                if lock
                    .write_all(&captured.stdout)
                    .and_then(|()| lock.flush())
                    .is_err()
                {
                    std::process::exit(1);
                }
                drop(lock);
                exit_kind(captured.exit)
            }
            Err(error) => exit_error(error),
        },
        Cmd::ResumeAll {
            host,
            local_host,
            ssh_option,
        } => {
            let local = local_host.unwrap_or_else(|| config.local_host.clone());
            match supervisor::resume_all(&config, &host, &local, &ssh_option, &mut notifier) {
                Ok(report) => {
                    if report.launched.is_empty()
                        && report.failures.is_empty()
                        && report.skipped.is_empty()
                    {
                        eprintln!("eversh: no matching live sessions");
                    }
                    for (name, failure) in &report.failures {
                        match failure {
                            ResumeFailure::Spawn(kind) => eprintln!(
                                "eversh: session '{name}': kitty launch failed ({kind:?})"
                            ),
                            ResumeFailure::Exit(code) => eprintln!(
                                "eversh: session '{name}': kitty launch exited with code {code}"
                            ),
                            ResumeFailure::Signaled(signal) => eprintln!(
                                "eversh: session '{name}': kitty launch terminated by signal {signal}"
                            ),
                        }
                    }
                    let failed = !report.failures.is_empty() || !report.skipped.is_empty();
                    std::process::exit(if failed { 1 } else { 0 });
                }
                Err(error) => exit_error(error),
            }
        }
        Cmd::Detach {
            host,
            name,
            ssh_option,
        } => match supervisor::simple_remote(
            &config,
            &host,
            &RemoteOp::Detach { name: &name },
            &ssh_option,
        ) {
            Ok(kind) => exit_kind(kind),
            Err(error) => exit_error(error),
        },
        Cmd::Kill {
            host,
            name,
            ssh_option,
        } => match supervisor::simple_remote(
            &config,
            &host,
            &RemoteOp::Kill { name: &name },
            &ssh_option,
        ) {
            Ok(kind) => exit_kind(kind),
            Err(error) => exit_error(error),
        },
        Cmd::Ssh { host, tokens } => {
            let (pre, post) = eversh::command::split_raw_tokens(&tokens);
            match supervisor::raw_ssh(&config, &host, pre, post) {
                Ok(end) => exit_session_end(end),
                Err(error) => exit_error(error),
            }
        }
    }
}
