use std::{fs, path::Path};

use iroh_db_fuzz::{
    exercise_commit_decode, exercise_crdt_merge, exercise_security_decode, exercise_state_decode,
    exercise_sync_frame_decode,
};

const MAX_SEED_BYTES: u64 = 1024 * 1024;
type FuzzHarness = fn(&[u8]);

#[test]
fn every_fuzz_target_replays_a_retained_bounded_corpus() {
    let targets: &[(&str, FuzzHarness)] = &[
        ("commit_decode", exercise_commit_decode),
        ("sync_frame_decode", exercise_sync_frame_decode),
        ("security_decode", exercise_security_decode),
        ("state_decode", exercise_state_decode),
        ("crdt_merge", exercise_crdt_merge),
    ];
    let corpus_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");

    for (target, exercise) in targets {
        let target_corpus = corpus_root.join(target);
        let mut seeds = fs::read_dir(&target_corpus)
            .unwrap_or_else(|error| panic!("missing corpus for {target}: {error}"))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        seeds.sort_by_key(fs::DirEntry::file_name);
        assert!(!seeds.is_empty(), "corpus for {target} is empty");

        for seed in seeds {
            let metadata = seed.metadata().unwrap();
            assert!(metadata.is_file(), "corpus entries must be files");
            assert!(
                metadata.len() <= MAX_SEED_BYTES,
                "{} exceeds the retained-seed limit",
                seed.path().display()
            );
            let bytes = fs::read(seed.path()).unwrap();
            exercise(&bytes);
        }
    }
}
