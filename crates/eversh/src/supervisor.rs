//! Thin supervision of OpenSSH, everlink, and Kitty processes (design 7).
//!
//! Every function here launches the installed `ssh` binary over the everlink
//! ProxyCommand and supervises it: eversh never relays or parses terminal
//! data, never builds a runtime, and preserves inherited stdin/stdout/stderr
//! for the live terminal path. Effective OpenSSH configuration resolution is
//! delegated to OpenSSH itself: ProxyCommand `%n`/`%p` carry the original
//! destination token and effective port into everlink, whose own `ssh -G`
//! verification rejects recursive proxying (design 6.4, 8).
//!
//! Reconnect contract (design 7): after an established named connect,
//! attach, or observe ends unexpectedly (OpenSSH's own exit code 255), a
//! fresh authenticated bootstrap probes whether the same broker is alive.
//! Retries reattach the SAME session with plain `attach` — a missing or
//! exited broker is never restarted, so no application work is duplicated —
//! under finite attempts, bounded exponential backoff with jitter, and an
//! overall deadline. Ambiguous concurrent transport/child failure is
//! reported as transport failure rather than inventing a child status.
#![cfg(unix)]

use crate::command::{
    kitty_launch_args, outer_ssh_args, proxy_command, raw_ssh_args, remote_words,
    validate_self_exe, RemoteOp,
};
use crate::error::Error;
use crate::limits::Limits;
use crate::remote::{origin_label, validate_host, validate_name, ControlRequest};
use std::ffi::OsString;
use std::io::Read;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// Typed configuration assembled at the binary edge. The library reads no
/// global arguments or environment.
#[derive(Debug, Clone)]
pub struct Config {
    /// The installed OpenSSH client (resolved via PATH when relative).
    pub ssh_program: OsString,
    /// The Kitty launcher used by resume-all.
    pub kitty_program: OsString,
    /// This executable, re-invoked as the local everlink role and by Kitty
    /// tabs.
    pub self_exe: PathBuf,
    /// The remote combined eversh binary: bare PATH word or absolute path.
    pub remote_eversh: String,
    /// `KITTY_LISTEN_ON` when present.
    pub kitty_listen_on: Option<String>,
    /// The local host name used for generated origin metadata.
    pub local_host: String,
    pub limits: Limits,
}

/// How a supervised process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitKind {
    Code(u8),
    Signaled(i32),
}

fn classify(status: ExitStatus) -> ExitKind {
    if let Some(code) = status.code() {
        ExitKind::Code((code & 0xff) as u8)
    } else {
        ExitKind::Signaled(status.signal().unwrap_or(0))
    }
}

/// OpenSSH reserves exit code 255 for its own failures; everything else is
/// the remote command's status.
const SSH_FAILURE: u8 = 255;

/// Why a reconnect sequence stopped without a remote status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportFailure {
    /// The broker no longer answers: the session ended or the child status
    /// was lost with the transport. Never restarted.
    SessionGone,
    /// The finite attempt budget was exhausted.
    AttemptsExhausted,
    /// The overall retry deadline passed.
    DeadlineExceeded,
    /// A probe failed with a non-transport error (broken remote install).
    ProbeFailed(u8),
    /// A probe was terminated locally.
    ProbeSignaled(i32),
}

/// The supervised outcome of a session-carrying invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEnd {
    /// The remote command's exit status (child exit, Busy, role errors) —
    /// returned unchanged.
    Remote(u8),
    /// The local ssh process was terminated by a signal.
    SshSignaled(i32),
    /// Transport failure without a recoverable session.
    TransportFailed(TransportFailure),
}

/// Progress events for the binary edge to present on stderr.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event<'a> {
    TransportInterrupted { attempt: u32 },
    Backoff { attempt: u32, delay_ms: u64 },
    Probing { name: &'a str, attempt: u32 },
    SessionLive { attempt: u32 },
    SessionGone { name: &'a str },
    ProbeUnreachable { attempt: u32 },
    ProbeFailed { exit_code: u8 },
    Reattaching { name: &'a str, attempt: u32 },
    RetryExhausted { attempts: u32 },
    RetryDeadlineExceeded,
    ResumeLaunched { name: &'a str },
    ResumeSkipped { name: &'a str },
}

pub trait Notifier {
    fn notify(&mut self, event: Event<'_>);
}

/// A Notifier that discards events (tests, non-interactive callers).
pub struct SilentNotifier;

impl Notifier for SilentNotifier {
    fn notify(&mut self, _event: Event<'_>) {}
}

fn proxy_for(config: &Config, ssh_options: &[String]) -> Result<String, Error> {
    let self_exe = validate_self_exe(&config.self_exe)?;
    proxy_command(self_exe, &config.remote_eversh, ssh_options)
}

fn spawn_inherited(config: &Config, args: &[OsString]) -> Result<ExitKind, Error> {
    let status = Command::new(&config.ssh_program).args(args).status()?;
    Ok(classify(status))
}

fn spawn_quiet(config: &Config, args: &[OsString]) -> Result<ExitKind, Error> {
    let status = Command::new(&config.ssh_program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .status()?;
    Ok(classify(status))
}

/// Captured non-interactive remote output plus its exit classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Captured {
    pub exit: ExitKind,
    pub stdout: Vec<u8>,
}

fn spawn_captured(config: &Config, args: &[OsString]) -> Result<Captured, Error> {
    let mut child = Command::new(&config.ssh_program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::Io(std::io::Error::other("captured stdout pipe missing")))?;
    let cap = config.limits.list_output_max;
    let mut collected = Vec::new();
    let mut chunk = [0u8; 8192];
    let overflow = loop {
        match stdout.read(&mut chunk) {
            Ok(0) => break false,
            Ok(count) => {
                if collected.len() + count > cap {
                    break true;
                }
                collected.extend_from_slice(&chunk[..count]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Error::Io(error));
            }
        }
    };
    if overflow {
        let _ = child.kill();
        let _ = child.wait();
        return Err(Error::ListOutputTooLarge);
    }
    drop(stdout);
    let status = child.wait()?;
    Ok(Captured {
        exit: classify(status),
        stdout: collected,
    })
}

/// The probe result for one fresh authenticated bootstrap (design 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeStatus {
    Live,
    NotLive,
    Unreachable,
    Failed(u8),
    Signaled(i32),
}

/// Remote probe exit code meaning "broker not live" (private role protocol).
pub const PROBE_NOT_LIVE_EXIT: u8 = 5;

fn probe(
    config: &Config,
    host: &str,
    name: &str,
    ssh_options: &[String],
) -> Result<ProbeStatus, Error> {
    let proxy = proxy_for(config, ssh_options)?;
    let words = remote_words(
        &config.remote_eversh,
        &RemoteOp::Probe { name },
        &config.limits,
    )?;
    let args = outer_ssh_args(&proxy, ssh_options, host, &words, false)?;
    Ok(match spawn_quiet(config, &args)? {
        ExitKind::Code(0) => ProbeStatus::Live,
        ExitKind::Code(PROBE_NOT_LIVE_EXIT) => ProbeStatus::NotLive,
        ExitKind::Code(SSH_FAILURE) => ProbeStatus::Unreachable,
        ExitKind::Code(code) => ProbeStatus::Failed(code),
        ExitKind::Signaled(signal) => ProbeStatus::Signaled(signal),
    })
}

fn backoff_delay(attempt: u32, limits: &Limits) -> Duration {
    let shift = attempt.saturating_sub(1).min(20);
    let raw = limits
        .retry_backoff_base_ms
        .saturating_mul(1u64 << shift)
        .min(limits.retry_backoff_cap_ms);
    Duration::from_millis(raw.saturating_add(jitter_below(raw / 2 + 1)))
}

fn jitter_below(bound: u64) -> u64 {
    use std::hash::{BuildHasher, Hasher};
    if bound <= 1 {
        return 0;
    }
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.subsec_nanos() as u64)
            .unwrap_or(0),
    );
    hasher.finish() % bound
}

struct SessionRun<'a> {
    host: &'a str,
    name: &'a str,
    take_over: bool,
    ssh_options: &'a [String],
    /// Observer sessions reattach with observe; writer sessions with attach.
    observer: bool,
}

/// Run one interactive/streaming remote operation and, on unexpected SSH
/// termination, reconnect the SAME session through probe-gated retries.
fn run_with_reconnect(
    config: &Config,
    run: SessionRun<'_>,
    first_op: RemoteOp<'_>,
    notifier: &mut dyn Notifier,
) -> Result<SessionEnd, Error> {
    config.limits.validate()?;
    validate_host(run.host)?;
    let proxy = proxy_for(config, run.ssh_options)?;
    let words = remote_words(&config.remote_eversh, &first_op, &config.limits)?;
    let interactive = first_op.interactive();
    let args = outer_ssh_args(&proxy, run.ssh_options, run.host, &words, interactive)?;
    match spawn_inherited(config, &args)? {
        ExitKind::Code(SSH_FAILURE) => {}
        ExitKind::Code(code) => return Ok(SessionEnd::Remote(code)),
        ExitKind::Signaled(signal) => return Ok(SessionEnd::SshSignaled(signal)),
    }
    reconnect(config, run, notifier)
}

fn reconnect(
    config: &Config,
    run: SessionRun<'_>,
    notifier: &mut dyn Notifier,
) -> Result<SessionEnd, Error> {
    let limits = &config.limits;
    let deadline = Instant::now() + Duration::from_millis(limits.retry_deadline_ms);
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        if attempt > limits.retry_attempts_max {
            notifier.notify(Event::RetryExhausted {
                attempts: limits.retry_attempts_max,
            });
            return Ok(SessionEnd::TransportFailed(
                TransportFailure::AttemptsExhausted,
            ));
        }
        let delay = backoff_delay(attempt, limits);
        if Instant::now() + delay >= deadline {
            notifier.notify(Event::RetryDeadlineExceeded);
            return Ok(SessionEnd::TransportFailed(
                TransportFailure::DeadlineExceeded,
            ));
        }
        notifier.notify(Event::Backoff {
            attempt,
            delay_ms: delay.as_millis() as u64,
        });
        std::thread::sleep(delay);
        notifier.notify(Event::Probing {
            name: run.name,
            attempt,
        });
        match probe(config, run.host, run.name, run.ssh_options)? {
            ProbeStatus::Live => {
                notifier.notify(Event::SessionLive { attempt });
            }
            ProbeStatus::NotLive => {
                notifier.notify(Event::SessionGone { name: run.name });
                return Ok(SessionEnd::TransportFailed(TransportFailure::SessionGone));
            }
            ProbeStatus::Unreachable => {
                notifier.notify(Event::ProbeUnreachable { attempt });
                continue;
            }
            ProbeStatus::Failed(code) => {
                notifier.notify(Event::ProbeFailed { exit_code: code });
                return Ok(SessionEnd::TransportFailed(TransportFailure::ProbeFailed(
                    code,
                )));
            }
            ProbeStatus::Signaled(signal) => {
                return Ok(SessionEnd::TransportFailed(
                    TransportFailure::ProbeSignaled(signal),
                ));
            }
        }
        notifier.notify(Event::Reattaching {
            name: run.name,
            attempt,
        });
        let request = ControlRequest {
            take_over: run.take_over,
            origins: Vec::new(),
            child_argv: Vec::new(),
        };
        let (op, interactive) = if run.observer {
            (RemoteOp::Observe { name: run.name }, false)
        } else {
            (
                RemoteOp::Attach {
                    name: run.name,
                    request: &request,
                },
                true,
            )
        };
        let proxy = proxy_for(config, run.ssh_options)?;
        let words = remote_words(&config.remote_eversh, &op, &config.limits)?;
        let args = outer_ssh_args(&proxy, run.ssh_options, run.host, &words, interactive)?;
        match spawn_inherited(config, &args)? {
            ExitKind::Code(SSH_FAILURE) => {
                notifier.notify(Event::TransportInterrupted { attempt });
            }
            ExitKind::Code(code) => return Ok(SessionEnd::Remote(code)),
            ExitKind::Signaled(signal) => return Ok(SessionEnd::SshSignaled(signal)),
        }
    }
}

/// Generate a conservative session name for an unnamed connect.
pub fn generated_session_name(limits: &Limits) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let mut name = format!("s{nanos}");
    name.truncate(limits.name_max);
    name
}

/// `eversh connect`: atomic remote attach-or-create plus reconnect.
pub fn connect(
    config: &Config,
    host: &str,
    name: &str,
    take_over: bool,
    child_argv: Vec<Vec<u8>>,
    ssh_options: &[String],
    notifier: &mut dyn Notifier,
) -> Result<SessionEnd, Error> {
    if !validate_name(name, &config.limits) {
        return Err(Error::NameInvalid);
    }
    let request = ControlRequest {
        take_over,
        origins: vec![origin_label(&config.local_host)],
        child_argv,
    };
    run_with_reconnect(
        config,
        SessionRun {
            host,
            name,
            take_over,
            ssh_options,
            observer: false,
        },
        RemoteOp::AttachOrCreate {
            name,
            request: &request,
        },
        notifier,
    )
}

/// `eversh attach`: writer attach to an existing named session.
pub fn attach(
    config: &Config,
    host: &str,
    name: &str,
    take_over: bool,
    ssh_options: &[String],
    notifier: &mut dyn Notifier,
) -> Result<SessionEnd, Error> {
    let request = ControlRequest {
        take_over,
        origins: Vec::new(),
        child_argv: Vec::new(),
    };
    run_with_reconnect(
        config,
        SessionRun {
            host,
            name,
            take_over,
            ssh_options,
            observer: false,
        },
        RemoteOp::Attach {
            name,
            request: &request,
        },
        notifier,
    )
}

/// `eversh observe`: future-output-only observer with reconnect.
pub fn observe(
    config: &Config,
    host: &str,
    name: &str,
    ssh_options: &[String],
    notifier: &mut dyn Notifier,
) -> Result<SessionEnd, Error> {
    run_with_reconnect(
        config,
        SessionRun {
            host,
            name,
            take_over: false,
            ssh_options,
            observer: true,
        },
        RemoteOp::Observe { name },
        notifier,
    )
}

/// `eversh list`: captured, bounded remote discovery output (passed through
/// verbatim by the edge).
pub fn list(
    config: &Config,
    host: &str,
    local_host: Option<&str>,
    json: bool,
    ssh_options: &[String],
) -> Result<Captured, Error> {
    config.limits.validate()?;
    let label = local_host.map(origin_label);
    let proxy = proxy_for(config, ssh_options)?;
    let words = remote_words(
        &config.remote_eversh,
        &RemoteOp::List {
            json,
            filter_origin: label.as_deref(),
        },
        &config.limits,
    )?;
    let args = outer_ssh_args(&proxy, ssh_options, host, &words, false)?;
    spawn_captured(config, &args)
}

/// `eversh detach` / `eversh kill`: exit status passthrough.
pub fn simple_remote(
    config: &Config,
    host: &str,
    op: &RemoteOp<'_>,
    ssh_options: &[String],
) -> Result<ExitKind, Error> {
    config.limits.validate()?;
    let proxy = proxy_for(config, ssh_options)?;
    let words = remote_words(&config.remote_eversh, op, &config.limits)?;
    let args = outer_ssh_args(&proxy, ssh_options, host, &words, false)?;
    spawn_quiet(config, &args)
}

/// `eversh ssh`: raw OpenSSH over everlink. Never restarted (design 7).
pub fn raw_ssh(config: &Config, host: &str, ssh_options: &[String]) -> Result<SessionEnd, Error> {
    config.limits.validate()?;
    // Raw options are passed verbatim (unaudited escape hatch), but the
    // ProxyCommand is still built only from audited inputs.
    let proxy = proxy_for(config, &[])?;
    let args = raw_ssh_args(&proxy, ssh_options, host)?;
    Ok(match spawn_inherited(config, &args)? {
        ExitKind::Code(code) => SessionEnd::Remote(code),
        ExitKind::Signaled(signal) => SessionEnd::SshSignaled(signal),
    })
}

/// The live session names this supervisor would resume (list text format,
/// filtered remotely by the local-host origin label).
pub fn session_names(
    config: &Config,
    host: &str,
    local_host: &str,
    ssh_options: &[String],
) -> Result<Vec<String>, Error> {
    config.limits.validate()?;
    let label = origin_label(local_host);
    let proxy = proxy_for(config, ssh_options)?;
    let words = remote_words(
        &config.remote_eversh,
        &RemoteOp::List {
            json: false,
            filter_origin: Some(&label),
        },
        &config.limits,
    )?;
    let args = outer_ssh_args(&proxy, ssh_options, host, &words, false)?;
    let captured = spawn_captured(config, &args)?;
    match captured.exit {
        ExitKind::Code(0) => {}
        ExitKind::Code(code) => return Err(Error::RemoteCommandFailed(code)),
        ExitKind::Signaled(signal) => return Err(Error::RemoteCommandSignaled(signal)),
    }
    let text = std::str::from_utf8(&captured.stdout).map_err(|_| Error::ListOutputInvalid)?;
    let mut names = Vec::new();
    for line in text.lines() {
        let name = line.split('\t').next().unwrap_or("");
        if !validate_name(name, &config.limits) {
            return Err(Error::ListOutputInvalid);
        }
        names.push(name.to_owned());
    }
    Ok(names)
}

/// Why one resume-all launch failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumeFailure {
    Spawn(std::io::ErrorKind),
    Exit(u8),
    Signaled(i32),
}

/// The complete resume-all outcome: every partial failure stays visible.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResumeReport {
    pub launched: Vec<String>,
    pub failures: Vec<(String, ResumeFailure)>,
    pub skipped: Vec<String>,
}

/// `eversh resume-all`: one Kitty tab per matching live session, targeting
/// `KITTY_LISTEN_ON` when available. Failed launches are reported, never
/// silently dropped; sessions beyond the configured cap are reported as
/// skipped.
pub fn resume_all(
    config: &Config,
    host: &str,
    local_host: &str,
    ssh_options: &[String],
    notifier: &mut dyn Notifier,
) -> Result<ResumeReport, Error> {
    config.limits.validate()?;
    let self_exe = validate_self_exe(&config.self_exe)?.to_owned();
    let names = session_names(config, host, local_host, ssh_options)?;
    let mut report = ResumeReport::default();
    for (index, name) in names.iter().enumerate() {
        if index >= config.limits.resume_sessions_max {
            notifier.notify(Event::ResumeSkipped { name });
            report.skipped.push(name.clone());
            continue;
        }
        let args = kitty_launch_args(
            config.kitty_listen_on.as_deref(),
            &self_exe,
            host,
            name,
            ssh_options,
            &config.limits,
        )?;
        let launched = Command::new(&config.kitty_program)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .status();
        match launched {
            Ok(status) => match classify(status) {
                ExitKind::Code(0) => {
                    notifier.notify(Event::ResumeLaunched { name });
                    report.launched.push(name.clone());
                }
                ExitKind::Code(code) => {
                    report
                        .failures
                        .push((name.clone(), ResumeFailure::Exit(code)));
                }
                ExitKind::Signaled(signal) => {
                    report
                        .failures
                        .push((name.clone(), ResumeFailure::Signaled(signal)));
                }
            },
            Err(error) => {
                report
                    .failures
                    .push((name.clone(), ResumeFailure::Spawn(error.kind())));
            }
        }
    }
    Ok(report)
}
