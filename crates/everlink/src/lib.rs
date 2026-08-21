//! everlink: one authenticated, ordered, byte-transparent OpenSSH stream
//! over QUIC via noq 1.1.1 (M0 selection).
//!
//! M1 scope: typed errors, bootstrap-record and auth-frame codecs, SPKI
//! pinning types, limits. No endpoint, no bridge (M3). Library code never
//! prints, reads global arguments, or exits.

pub mod error;
pub mod limits;

pub use error::Error;
pub use limits::Limits;
