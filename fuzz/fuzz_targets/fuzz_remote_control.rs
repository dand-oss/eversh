#![no_main]

use eversh::limits::Limits;
use eversh::remote::{base64url_decode, base64url_encode, ControlRequest, RemoteRequest};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let l = Limits::default();
    if let Ok(r) = RemoteRequest::decode(data, &l) {
        // NUL-free args by construction; re-encode must round-trip.
        if let Ok(re) = r.encode(&l) {
            let again = RemoteRequest::decode(&re, &l).expect("re-decode");
            assert_eq!(again, r, "request round-trip");
        }
    }

    // The typed M4 control request: decode is total, canonical, and bounded.
    if let Ok(request) = ControlRequest::decode(data, &l) {
        let re = request.encode(&l).expect("decoded request re-encodes");
        assert_eq!(re, data, "control-request decoding accepts only canon");
        for origin in &request.origins {
            assert!(!origin.is_empty() && origin.len() <= l.origin_label_max);
        }
        for arg in &request.child_argv {
            assert!(!arg.contains(&0), "NUL in decoded argv");
        }
    }

    // Unpadded base64url: encode/decode round-trip exactly, and decode of
    // arbitrary text never accepts a non-canonical spelling.
    let encoded = base64url_encode(data);
    assert!(encoded.len() <= data.len().div_ceil(3) * 4);
    let decoded = base64url_decode(&encoded, data.len().max(1)).expect("own encoding decodes");
    assert_eq!(decoded, data, "base64url round-trip");
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(bytes) = base64url_decode(text, l.remote_control_max) {
            assert_eq!(
                base64url_encode(&bytes),
                text,
                "decode accepts only the canonical unpadded spelling"
            );
        }
    }
});
