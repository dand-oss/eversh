//! Controlled version-skew fixtures against the v2 protocol edge.
//!
//! The pinned pre-v2 whole product is commit `43e80cc` (binary `everlink`,
//! bootstrap prefix `everlink v1`, ALPN `eversh-link/1`). These fixtures
//! prove that recognizable old-peer records are diagnosed as version skew
//! and fail closed; the companion `tests/net/test-version-skew.sh` drives
//! both real binaries for the whole-product matrix.

use everssh::bootstrap::{BootstrapRecord, ALPN};
use everssh::limits::Limits;
use everssh::role_protocol::{validate_release, ServerStartRecord};
use everssh::Error;

const OLD_BOOTSTRAP: &str = "everlink v1 127.0.0.1 4433 4242424242424242424242424242424242424242424242424242424242424242 0909090909090909090909090909090909090909090909090909090909090909 4242";
const OLD_START: &str = "everlink-start v1 192.0.2.1 50000 192.0.2.2 22 route";

#[test]
fn old_bootstrap_prefix_fails_closed_as_version_skew() {
    let limits = Limits::default();
    assert!(matches!(
        BootstrapRecord::parse(OLD_BOOTSTRAP, &limits),
        Err(Error::VersionUnsupported)
    ));
    // The same component explicitly naming its old wire version is skew,
    // not corruption, even when all remaining fields are well formed.
    let explicit_old = OLD_BOOTSTRAP.replacen("everlink v1", "everssh v1", 1);
    assert!(matches!(
        BootstrapRecord::parse(&explicit_old, &limits),
        Err(Error::VersionUnsupported)
    ));
}

#[test]
fn old_private_process_records_are_rejected() {
    let limits = Limits::default();
    assert!(validate_release(b"everlink-release v1\n").is_err());
    assert!(matches!(
        ServerStartRecord::parse(OLD_START, &limits),
        Err(Error::ServerStartMalformed)
    ));
}

#[test]
fn alpn_edge_has_no_shared_offer_with_pre_v2() {
    assert_eq!(ALPN, &[b"everssh-link/2".as_slice()]);
    assert!(ALPN.iter().all(|offer| *offer != b"eversh-link/1"));
}

#[test]
fn version_diagnostic_requires_coordinated_upgrade() {
    let message = Error::VersionUnsupported.to_string();
    assert!(
        message.contains("unsupported protocol version"),
        "{message}"
    );
    assert!(message.contains("coordinated everssh upgrade"), "{message}");
}
