#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = iroh_db_sync::SyncFrame::decode_canonical(data);
    let _ = iroh_db_sync::GossipHint::decode_canonical(data);
});
