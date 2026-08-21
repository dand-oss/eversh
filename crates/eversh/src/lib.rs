//! eversh: the multi-role supervisor library for eversh.
//!
//! M1 scope: typed errors, bounded remote-control request encoding, session
//! name rules, socket path checks, and pure role selection. No process
//! supervision, no relay (M4+). Library code never prints, reads global
//! arguments, or exits; the supervisor never owns a PTY fd, QUIC endpoint,
//! or terminal relay loop.

pub mod error;
pub mod limits;
pub mod remote;
pub mod role;

pub use error::Error;
pub use limits::Limits;
