#![no_main]

use everssh::bootstrap::BootstrapRecord;
use everssh::limits::Limits;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let l = Limits::default();
    if let Ok(s) = std::str::from_utf8(data) {
        let s = s.trim_end_matches('\n');
        if let Ok(r) = BootstrapRecord::parse(s, &l) {
            let re = r.encode();
            let round = re.trim_end_matches('\n');
            let again = BootstrapRecord::parse(round, &l).expect("re-parse");
            assert_eq!(again, r, "record round-trip");
        }
    }
});
