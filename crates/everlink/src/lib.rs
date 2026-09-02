//! everlink: one authenticated, ordered, byte-transparent OpenSSH stream
//! over QUIC via noq 1.1.1 (M0 selection).
//!
//! M3 Slice 3 scope: typed OpenSSH bootstrap roles, deterministic UDP policy,
//! pinned one-use noq admission, and one bounded opaque-byte stdio/TCP bridge.
//! Library code never prints, reads global arguments/environment, exits, or
//! constructs a runtime.

pub mod admission;
pub mod bootstrap;
pub mod bridge;
#[cfg(feature = "cli")]
pub mod edge;
pub mod error;
pub mod identity;
pub mod limits;
pub mod link_status;
pub mod pinning;
pub mod role_protocol;
pub mod roles;
pub mod runtime;
pub mod shutdown;
pub mod ssh_bootstrap;
pub mod ssh_policy;
pub mod transport;

pub use bridge::{BridgeCompletion, DrainStatus, FinalizeStatus, StdioBridge, TargetBridge};
pub use error::Error;
pub use limits::Limits;
pub use shutdown::{
    CopyDirection, CopyOperation, DeadlineKind, Phase, RequestStatus, Shutdown, ShutdownSnapshot,
    TerminalCause, TransitionError,
};
