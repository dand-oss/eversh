//! everpty: named PTY session broker for eversh.
//!
//! M1 scope: typed errors, wire-frame codec, limits, and pure lifecycle
//! state machines. No PTY syscalls, no broker loop (M2). Library code never
//! prints, reads global arguments, or exits.

pub mod error;
pub mod frame;
pub mod lifecycle;
pub mod limits;
pub mod sys;

pub use error::Error;
pub use limits::Limits;
