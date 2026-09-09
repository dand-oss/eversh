//! The single Tokio runtime owner (design 6.3).
//!
//! M1 exposes only the construction counter used by the role-isolation
//! tests: every non-everssh role must leave `constructions()` at zero. The
//! actual runtime is built in M3; nothing here ever creates a second
//! runtime or enters one from library code.

use std::sync::atomic::{AtomicU64, Ordering};

static CONSTRUCTIONS: AtomicU64 = AtomicU64::new(0);

/// Number of runtimes constructed in this process (test observability).
pub fn constructions() -> u64 {
    CONSTRUCTIONS.load(Ordering::SeqCst)
}

/// Construct the single owned runtime (M3 will configure it; M1 only
/// proves the accounting so role isolation is testable now).
pub fn build() -> Result<tokio::runtime::Runtime, std::io::Error> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    CONSTRUCTIONS.fetch_add(1, Ordering::SeqCst);
    Ok(rt)
}
