//! everpty binary edge: arguments, environment, diagnostics, and exit mapping.
#![cfg_attr(not(test), allow(clippy::print_stderr, clippy::print_stdout))]

use std::ffi::OsString;
use std::fmt::Write as _;
use std::io::Write as _;
use std::os::fd::AsFd;
use std::path::PathBuf;

use clap::{error::ErrorKind, Parser};
use everpty::frame::Role;
use everpty::run::{self, AttachRequest, Context, Outcome, StartRequest};
use everpty::{sys, Error, Limits};

#[derive(Debug, Parser)]
#[command(
    name = "everpty",
    version,
    about = "Named transparent PTY session broker"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, clap::Subcommand)]
enum Cmd {
    /// Start a named session and become its initial writer.
    Start {
        name: String,
        /// Command and arguments after `--` (defaults to $SHELL or /bin/sh).
        #[arg(last = true, value_name = "COMMAND")]
        command: Vec<OsString>,
    },
    /// Attach to a named session as writer.
    Attach {
        name: String,
        #[arg(long = "take-over")]
        take_over: bool,
    },
    /// Observe a named session.
    Observe { name: String },
    /// List sessions.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Print the session this process belongs to.
    Current,
    /// Detach the current writer of a session.
    Detach { name: String },
    /// Kill a session.
    Kill { name: String },
}

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

fn write_stdout(stdout: &std::io::Stdout, bytes: &[u8]) -> Result<(), Error> {
    let mut output = stdout.lock();
    output.write_all(bytes)?;
    output.flush()?;
    Ok(())
}

fn start_request<'a>(
    context: Context,
    name: String,
    command: Vec<OsString>,
    stdin: std::os::fd::BorrowedFd<'a>,
    stdout: std::os::fd::BorrowedFd<'a>,
) -> StartRequest<'a> {
    StartRequest {
        context,
        name,
        command,
        default_shell: std::env::var_os("SHELL"),
        environment: captured_environment(),
        path: std::env::var_os("PATH"),
        origins: Vec::new(),
        stdin,
        stdout,
    }
}

fn run_command(cli: Cli) -> Result<Outcome, Error> {
    let context = Context {
        state_candidates: state_candidates(),
        limits: Limits::default(),
    };
    let stdin_handle = std::io::stdin();
    let stdout_handle = std::io::stdout();
    let stdin = stdin_handle.as_fd();
    let stdout = stdout_handle.as_fd();
    match cli.cmd {
        Cmd::Start { name, command } => {
            run::start(start_request(context, name, command, stdin, stdout))
        }
        Cmd::Attach { name, take_over } => run::attach(AttachRequest {
            context: &context,
            name: &name,
            role: Role::Writer,
            take_over,
            stdin,
            stdout,
        }),
        Cmd::Observe { name } => run::observe(AttachRequest {
            context: &context,
            name: &name,
            role: Role::Observer,
            take_over: false,
            stdin,
            stdout,
        }),
        Cmd::List { json } => {
            let sessions = run::list(&context)?;
            let mut rendered = if json {
                list_json(&sessions)
            } else {
                text_list(&sessions)
            };
            if json {
                rendered.push('\n');
            }
            write_stdout(&stdout_handle, rendered.as_bytes())?;
            Ok(Outcome::Success)
        }
        Cmd::Current => {
            let current = std::env::var_os("EVERPTY_SESSION");
            let name = run::current(&context, current.as_deref())?;
            let mut rendered = name;
            rendered.push('\n');
            write_stdout(&stdout_handle, rendered.as_bytes())?;
            Ok(Outcome::Success)
        }
        Cmd::Detach { name } => run::detach(&context, &name),
        Cmd::Kill { name } => run::kill(&context, &name),
    }
}

fn exit_outcome(outcome: Outcome) -> ! {
    match outcome {
        Outcome::Success | Outcome::Detached => std::process::exit(0),
        Outcome::ChildExited(code) => std::process::exit(i32::from(code)),
        Outcome::ChildSignaled(signal) | Outcome::LocalSignaled(signal) => {
            let _ = sys::reraise_default(signal);
            std::process::exit(128 + signal);
        }
        Outcome::Broker(exit) => std::process::exit(i32::from(exit.suggested_exit_code)),
    }
}

fn exit_error(error: Error) -> ! {
    let code = if matches!(error, Error::Busy { .. }) {
        3
    } else {
        1
    };
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "everpty: {error}");
    std::process::exit(code);
}

fn main() {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let code = if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) {
                0
            } else {
                2
            };
            let _ = error.print();
            std::process::exit(code);
        }
    };
    if let Err(error) = sys::ignore_sigpipe() {
        exit_error(Error::Io(error));
    }
    match run_command(cli) {
        Ok(outcome) => exit_outcome(outcome),
        Err(error) => exit_error(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use everpty::session::{ChildMeta, SessionMeta};
    use std::ffi::OsStr;

    #[test]
    fn list_json_escapes_every_string_and_quotes_every_u64() {
        let limits = Limits::default();
        let meta = SessionMeta::new(
            "session",
            &limits,
            OsStr::new("x\"\\\n\u{1f}"),
            123,
            u64::MAX,
            u64::MAX - 1,
        )
        .expect("metadata")
        .with_origins(&limits, vec!["a\\b".into(), "line\n\u{1}".into()])
        .expect("origins")
        .with_child(ChildMeta::new(456, 457, u64::MAX - 2).expect("child"));
        assert_eq!(
            list_json(&[meta]),
            concat!(
                "{\"version\":1,\"sessions\":[{\"name\":\"session\",",
                "\"broker\":{\"pid\":123,\"start_ticks\":\"18446744073709551615\"},",
                "\"child\":{\"pid\":456,\"pgid\":457,",
                "\"start_ticks\":\"18446744073709551613\"},",
                "\"created_unix_ms\":\"18446744073709551614\",",
                "\"executable\":\"x\\\"\\\\\\n\\u001f\",",
                "\"executable_truncated\":false,",
                "\"origins\":[\"a\\\\b\",\"line\\n\\u0001\"]}]}"
            )
        );
    }
}
