//! Stage D everudp spike core.
//!
//! This workspace is deliberately not a member of the production Cargo
//! workspace and must never be imported by everpty, everssh, or eversh.
//! It answers one preregistered question: with identical bounded
//! echo-prediction state logic, can a direct-UDP transport match zmosh
//! latency and beat everssh v2 by the frozen Stage D thresholds?

pub mod aead;
pub mod frame;
pub mod quic;
pub mod state;
pub mod transport;

/// Monotonic milliseconds since process start. All benchmark samples in one
/// process use this single clock.
pub fn bench_ms() -> u128 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis()
}
