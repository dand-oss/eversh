//! everpty: named PTY session broker for eversh.
//!
//! M1 delivered typed errors, the wire-frame codec, limits, and pure
//! lifecycle state machines; M2 adds the audited syscall layer, session
//! state, and the child PTY lifecycle (no broker loop yet). Library
//! code never prints, reads global arguments, or exits — the post-fork
//! child's `_exit` is the one sanctioned exception.

pub mod child;
pub mod error;
pub mod frame;
pub mod lifecycle;
pub mod limits;
pub mod session;
pub mod sys;

pub use error::Error;
pub use limits::Limits;
