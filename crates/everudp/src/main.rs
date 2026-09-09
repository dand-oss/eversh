//! Standalone everudp process edge.

use std::process::ExitCode;

fn main() -> ExitCode {
    ExitCode::from(everudp::edge::run(
        everudp::edge::Invocation::Standalone,
        std::env::args_os().skip(1).collect(),
    ))
}
