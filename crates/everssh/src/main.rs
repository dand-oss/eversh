//! Production everssh binary: the standalone entry to the shared role edge.

use std::process::ExitCode;

fn main() -> ExitCode {
    ExitCode::from(everssh::edge::run(
        everssh::edge::Invocation::Standalone,
        std::env::args_os().skip(1).collect(),
    ))
}
