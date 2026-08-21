#![no_main]

use everpty::frame::Frame;
use everpty::limits::Limits;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Decoding arbitrary bytes must never panic; oversized bodies must be
    // rejected by the header before any payload allocation.
    let l = Limits::default();
    if data.len() >= everpty::frame::HEADER_LEN {
        let _ = Frame::validate_header(data, &l);
    }
    if let Ok((frame, used)) = Frame::decode(data, &l) {
        let re = frame.encode();
        assert_eq!(used, re.len(), "canonical encoding length");
        assert_eq!(&data[..used], &re[..], "canonical encoding bytes");
    }
});
