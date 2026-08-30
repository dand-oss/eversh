#![no_main]

use everpty::sys;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((parent_pid, start_ticks)) = sys::parse_proc_stat(data) {
        assert!(parent_pid >= 0, "the total parser rejects negative pids");
        let _ = start_ticks;
    }
});
