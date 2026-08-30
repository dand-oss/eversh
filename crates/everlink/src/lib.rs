//! everlink: one authenticated, ordered, byte-transparent OpenSSH stream
//! over QUIC via noq 1.1.1 (M0 selection).
//!
//! M3 Slice 1 scope: ephemeral identity, deterministic UDP policy, locked noq
//! transport, and one-use stream admission. No bridge or executable role is
//! enabled. Library code never prints, reads global arguments, or exits.

pub mod admission;
pub mod bootstrap;
pub mod error;
pub mod identity;
pub mod limits;
pub mod pinning;
pub mod runtime;
pub mod transport;

pub use error::Error;
pub use limits::Limits;
