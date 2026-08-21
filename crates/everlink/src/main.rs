//! everlink binary edge (M1: help + nonfunctional stubs).
#![cfg_attr(not(test), allow(clippy::print_stderr))]

use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "everlink",
    version,
    about = "One-stream QUIC SSH transport over noq (M1 skeleton)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, clap::Subcommand)]
enum Cmd {
    /// ProxyCommand entry: bootstrap over SSH and bridge stdin/stdout.
    SshProxy { destination: String, port: String },
}

fn main() {
    let cli = Cli::parse();
    eprintln!("everlink: {:?} is not implemented in M1", cli.cmd);
    std::process::exit(3);
}
