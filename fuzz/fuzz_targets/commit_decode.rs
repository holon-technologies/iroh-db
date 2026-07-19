#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = iroh_db_core::CommitEnvelope::decode_canonical(data);
    let _ = iroh_db_core::CommitBody::decode_canonical(data);
});
