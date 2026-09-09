use everssh::bootstrap::sha256;
use everssh::pinning::extract_spki;
use everudp::{ClientIdentity, GatewayIdentity};

#[test]
fn gateway_and_client_identities_are_distinct_valid_spki_keys() {
    let gateway = GatewayIdentity::generate().expect("gateway identity");
    let client = ClientIdentity::generate().expect("client identity");

    assert_ne!(gateway.spki_sha256(), client.spki_sha256());
    assert_eq!(
        gateway.spki_sha256(),
        sha256(extract_spki(gateway.certificate_der()).expect("gateway SPKI"))
    );
    assert_eq!(
        client.spki_sha256(),
        sha256(extract_spki(client.certificate_der()).expect("client SPKI"))
    );
}

#[test]
fn identity_debug_never_exposes_private_key_material() {
    let gateway = GatewayIdentity::generate().expect("gateway identity");
    let client = ClientIdentity::generate().expect("client identity");
    let debug = format!("{gateway:?} {client:?}");
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains("private_key_der"));
}
