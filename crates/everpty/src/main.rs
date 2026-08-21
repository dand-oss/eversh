//! everpty binary edge (M1: help + nonfunctional stubs).
#![cfg_attr(not(test), allow(clippy::print_stderr))]

use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "everpty",
    version,
    about = "Named PTY session broker (M1 skeleton)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, clap::Subcommand)]
enum Cmd {
    /// Start a named session and become its initial writer.
    Start { name: String },
    /// Attach to a named session as writer.
    Attach { name: String },
    /// Observe a named session.
    Observe { name: String },
    /// List sessions.
    List,
    /// Print the session this process belongs to.
    Current,
    /// Detach the current writer of a session.
    Detach { name: String },
    /// Kill a session.
    Kill { name: String },
}

fn main() {
    let cli = Cli::parse();
    eprintln!("everpty: {:?} is not implemented in M1", cli.cmd);
    std::process::exit(3);
}
