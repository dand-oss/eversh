//! noq-m0: disposable M0 feasibility spike for eversh.
//!
//! Proves whether noq 1.1.1 (rustls + ring + runtime-tokio + bloom) can carry one
//! authenticated, ordered, byte-transparent OpenSSH stream over QUIC with bounded
//! resources, real address migration, hard failure without replay, and finite
//! Request -> Drain -> Finalize shutdown. Nothing here is production protocol;
//! M1 owns the real schemas.

pub mod config;
pub mod pinning;
pub mod protocol;
pub mod shutdown;
pub mod spike;

pub const ALPN: &[&[u8]] = &[b"eversh-link/1"];
pub const PROTOCOL_VERSION: u8 = 1;
