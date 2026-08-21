#![no_main]

use eversh::limits::Limits;
use eversh::remote::RemoteRequest;
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
});
