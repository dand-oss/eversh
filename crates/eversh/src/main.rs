//! eversh combined binary: pure role selection before any runtime.
//!
//! `__everpty`/`__everlink` dispatch exactly one logical role; everything
//! else is the supervisor. Only the everlink role may build the single
//! Tokio runtime.
#![cfg_attr(not(test), allow(clippy::print_stderr))]

use clap::{Parser, Subcommand};
use eversh::role::{select_role, Role};

#[derive(Debug, Parser)]
#[command(
    name = "eversh",
    version,
    about = "eversh roaming SSH supervisor (M1 skeleton)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Connect to a host (optionally into a named session).
    Connect {
        host: String,
        #[arg(long)]
        session: Option<String>,
        #[arg(long)]
        take_over: bool,
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// Attach to an existing named session.
    Attach {
        host: String,
        name: String,
        #[arg(long)]
        take_over: bool,
    },
    /// Observe a named session without input.
    Observe { host: String, name: String },
    /// List sessions on a host.
    List {
        host: String,
        #[arg(long)]
        local_host: Option<String>,
    },
    /// Re-attach every matching live session.
    ResumeAll {
        host: String,
        #[arg(long)]
        local_host: Option<String>,
    },
    /// Detach a session's writer.
    Detach { host: String, name: String },
    /// Kill a session.
    Kill { host: String, name: String },
    /// Raw SSH passthrough (never restarted automatically).
    Ssh {
        host: String,
        #[arg(last = true)]
        options: Vec<String>,
    },
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match select_role(&argv) {
        Role::Everpty | Role::Everlink => {
            // Private role dispatch happens before any runtime construction
            // in the real flow (M2/M3); M1 documents and tests selection.
            eprintln!(
                "eversh: role {:?} is not implemented in M1",
                select_role(&argv)
            );
            std::process::exit(3);
        }
        Role::Supervisor => {
            let cli = Cli::parse();
            eprintln!("eversh: {:?} is not implemented in M1", cli.cmd);
            std::process::exit(3);
        }
    }
}
