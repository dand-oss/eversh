#![no_main]

use everpty::limits::Limits;
use everpty::session::SessionMeta;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = Limits::default();
    if let Ok(metadata) = SessionMeta::decode(data, &limits) {
        let mut canonical = Vec::new();
        metadata
            .encode_into(&limits, &mut canonical)
            .expect("decoded metadata must encode");
        assert_eq!(canonical, data, "metadata encoding is canonical");
        let decoded = SessionMeta::decode(&canonical, &limits).expect("canonical re-decode");
        assert_eq!(decoded, metadata, "metadata round-trip");
    }
});
