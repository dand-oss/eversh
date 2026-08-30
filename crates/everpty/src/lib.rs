//! everpty: named PTY session broker for eversh.
//!
//! M1 delivered typed errors, the wire-frame codec, limits, and pure
//! lifecycle state machines; M2 adds the audited syscall layer, session
//! state, the child PTY lifecycle, and the client/control connection
//! layer: a pure poll-event reducer over the M1 state machine, bounded
//! frame queues, and the single-threaded poll-loop broker skeleton.
//! Library code never prints, reads global arguments, or exits — the
//! post-fork child's `_exit` is the one sanctioned exception.

pub mod attach;
pub mod broker;
pub mod child;
pub mod client;
pub mod error;
pub mod frame;
pub mod lifecycle;
pub mod limits;
pub mod run;
pub mod session;
pub mod state;
pub mod sys;

pub use error::Error;
pub use limits::Limits;
