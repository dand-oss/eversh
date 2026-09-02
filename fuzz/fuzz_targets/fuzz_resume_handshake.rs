#![no_main]

use everssh::association::{ClientHello, ServerHello};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(hello) = ClientHello::decode_exact(data) {
        let encoded = hello.encode();
        assert_eq!(encoded.as_slice(), data, "client hello round-trip");
        assert_eq!(ClientHello::decode_exact(encoded.as_slice()).unwrap(), hello);
    }
    if let Ok(hello) = ServerHello::decode_exact(data) {
        let encoded = hello.encode();
        assert_eq!(encoded.as_slice(), data, "server hello round-trip");
        assert_eq!(ServerHello::decode_exact(encoded.as_slice()).unwrap(), hello);
    }
});
