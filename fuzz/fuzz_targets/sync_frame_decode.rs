#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    iroh_db_fuzz::exercise_sync_frame_decode(data);
});
