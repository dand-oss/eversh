//! everlink: one authenticated, ordered, byte-transparent OpenSSH stream
//! over QUIC via noq 1.1.1 (M0 selection).
//!
//! M3 Slice 2 scope: ephemeral identity, deterministic UDP policy, locked noq
//! transport, one-use admission, and one bounded opaque-byte bridge. No
//! executable role is enabled. Library code never prints, reads global
//! arguments, or exits.

pub mod admission;
pub mod bootstrap;
pub mod bridge;
pub mod error;
pub mod identity;
pub mod limits;
pub mod pinning;
pub mod runtime;
pub mod shutdown;
pub mod transport;

pub use bridge::{BridgeCompletion, DrainStatus, FinalizeStatus, TargetBridge};
pub use error::Error;
pub use limits::Limits;
pub use shutdown::{
    CopyDirection, CopyOperation, DeadlineKind, Phase, RequestStatus, Shutdown, ShutdownSnapshot,
    TerminalCause, TransitionError,
};
