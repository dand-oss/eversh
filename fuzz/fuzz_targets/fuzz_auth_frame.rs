#![no_main]

use everssh::bootstrap::{decode_auth_frame, encode_auth_frame};
use everssh::limits::Limits;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let l = Limits::default();
    if let Ok((token, port)) = decode_auth_frame(data, &l) {
        let re = encode_auth_frame(&token, port, &l);
        assert_eq!(re, data, "auth frame round-trip");
    }
});
