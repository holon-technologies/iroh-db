use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};

use iroh_db_core::{
    AuthorId, BlobHash, CapabilityId, CommitBody, CommitEnvelope, CommitHeader, CommitId, CrdtKind,
    DomainId, FieldDescriptor, MigrationId, SchemaActivation, SchemaDescriptor, SchemaId,
    TransactionId, staging_digest,
};
use iroh_db_security::{DomainKey, IrohSigner, seal_commit};
use iroh_db_store::{
    ApplyOutcome, BlobStore, BlobStoreError, IndexValue, MaterializedRecord, SnapshotBaseline,
    Store, StoreError,
};

#[derive(Default)]
struct MemoryBlobs {
    blobs: Mutex<BTreeMap<BlobHash, Vec<u8>>>,
    fail_put: Mutex<bool>,
}

impl MemoryBlobs {
    fn set_fail_put(&self, fail: bool) {
        *self.fail_put.lock().unwrap() = fail;
    }

    fn contains(&self, hash: BlobHash) -> bool {
        self.blobs.lock().unwrap().contains_key(&hash)
    }
}

impl BlobStore for MemoryBlobs {
    fn put<'a>(
        &'a self,
        bytes: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<BlobHash, BlobStoreError>> + Send + 'a>> {
        Box::pin(async move {
            if *self.fail_put.lock().unwrap() {
                return Err(BlobStoreError::new("injected put failure"));
            }
            let hash = BlobHash::from_bytes(*blake3::hash(&bytes).as_bytes());
            self.blobs.lock().unwrap().insert(hash, bytes);
            Ok(hash)
        })
    }

    fn get<'a>(
        &'a self,
        hash: BlobHash,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, BlobStoreError>> + Send + 'a>> {
        Box::pin(async move { Ok(self.blobs.lock().unwrap().get(&hash).cloned()) })
    }

    fn list<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<BlobHash>, BlobStoreError>> + Send + 'a>> {
        Box::pin(async move { Ok(self.blobs.lock().unwrap().keys().copied().collect()) })
    }
}

#[test]
fn metadata_store_accepts_an_explicit_cache_bound() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open_with_cache_size(
        directory.path(),
        Arc::new(MemoryBlobs::default()),
        8 * 1024 * 1024,
    )
    .unwrap();

    drop(store);
}

#[test]
fn format_four_is_rejected_instead_of_implicitly_migrated() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("FORMAT"), "iroh-db 4.0\n").unwrap();
    assert!(matches!(
        Store::open(directory.path(), Arc::new(MemoryBlobs::default())),
        Err(StoreError::UnsupportedFormat)
    ));
}

#[tokio::test]
async fn format_five_is_shadow_migrated_and_preserved() {
    let directory = tempfile::tempdir().unwrap();
    let blobs = Arc::new(MemoryBlobs::default());
    let signer = IrohSigner::generate();
    let key = DomainKey::generate().unwrap();
    let domain = DomainId::from_bytes(id(44));
    let envelope = commit(&signer, &key, domain, 0, vec![]);

    let store = Store::open(directory.path(), blobs.clone()).unwrap();
    store.persist_commit(&envelope).await.unwrap();
    drop(store);

    // Simulate the last supported directory marker. The metadata file contains
    // only compatible v5 data; v6 must copy it rather than reinterpret it.
    std::fs::rename(
        directory.path().join("meta-v6.redb"),
        directory.path().join("meta.redb"),
    )
    .unwrap();
    std::fs::write(directory.path().join("FORMAT"), "iroh-db 5.0\n").unwrap();
    let migrated = Store::open(directory.path(), blobs).unwrap();

    assert!(
        migrated
            .contains_commit(domain, envelope.commit_id())
            .unwrap()
    );
    assert_eq!(
        std::fs::read_to_string(directory.path().join("FORMAT")).unwrap(),
        "iroh-db 6.0\n"
    );
    assert!(directory.path().join("meta-v5.redb").is_file());
    assert!(directory.path().join("meta-v6.redb").is_file());
    assert!(directory.path().join("meta.redb").is_file());
}

#[tokio::test]
async fn interrupted_v5_shadow_migration_restarts_from_preserved_source() {
    let directory = tempfile::tempdir().unwrap();
    let blobs = Arc::new(MemoryBlobs::default());
    let signer = IrohSigner::generate();
    let key = DomainKey::generate().unwrap();
    let domain = DomainId::from_bytes(id(49));
    let envelope = commit(&signer, &key, domain, 0, vec![]);
    let store = Store::open(directory.path(), blobs.clone()).unwrap();
    store.persist_commit(&envelope).await.unwrap();
    drop(store);

    std::fs::rename(
        directory.path().join("meta-v6.redb"),
        directory.path().join("meta.redb"),
    )
    .unwrap();
    std::fs::copy(
        directory.path().join("meta.redb"),
        directory.path().join("meta-v5.redb"),
    )
    .unwrap();
    std::fs::write(directory.path().join("meta-v6.redb"), b"partial").unwrap();
    std::fs::write(directory.path().join("tmp/meta-v6.redb"), b"partial").unwrap();
    std::fs::write(directory.path().join("FORMAT"), "iroh-db 5.0\n").unwrap();

    let recovered = Store::open(directory.path(), blobs).unwrap();
    assert!(
        recovered
            .contains_commit(domain, envelope.commit_id())
            .unwrap()
    );
    assert_eq!(
        std::fs::read_to_string(directory.path().join("FORMAT")).unwrap(),
        "iroh-db 6.0\n"
    );
}

#[test]
fn snapshot_install_publishes_active_schema_cut_atomically() {
    let directory = tempfile::tempdir().unwrap();
    let domain = DomainId::from_bytes(id(45));
    let from = SchemaDescriptor::new(
        "snapshot-migration",
        1,
        vec![FieldDescriptor::new(1, "id", CrdtKind::Immutable, "String").record_id()],
    )
    .unwrap();
    let to = SchemaDescriptor::new(
        "snapshot-migration",
        2,
        vec![
            FieldDescriptor::new(1, "id", CrdtKind::Immutable, "String").record_id(),
            FieldDescriptor::new(2, "title", CrdtKind::Lww, "String"),
        ],
    )
    .unwrap();
    let activation = SchemaActivation::new(
        MigrationId::from_bytes(id(46)),
        from,
        to.clone(),
        0,
        staging_digest(&[]).unwrap(),
    )
    .unwrap();
    let baseline = SnapshotBaseline::new(
        domain,
        0,
        BlobHash::from_bytes(id(47)),
        id(48),
        vec![],
        vec![],
    )
    .unwrap();
    let store = Store::open(directory.path(), Arc::new(MemoryBlobs::default())).unwrap();
    store
        .install_snapshot(
            domain,
            &[],
            &[],
            &[],
            &[],
            std::slice::from_ref(&activation),
            1,
            &baseline,
        )
        .unwrap();

    assert_eq!(
        store
            .active_schema_activation(domain, to.collection_id())
            .unwrap(),
        Some(activation)
    );
    assert_eq!(store.snapshot_observed_at(domain).unwrap(), Some(1));
}

fn id(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn commit(
    signer: &IrohSigner,
    key: &DomainKey,
    domain: DomainId,
    sequence: u64,
    dependencies: Vec<CommitId>,
) -> CommitEnvelope {
    commit_variant(signer, key, domain, sequence, dependencies, 1)
}

fn commit_variant(
    signer: &IrohSigner,
    key: &DomainKey,
    domain: DomainId,
    sequence: u64,
    dependencies: Vec<CommitId>,
    variant: u8,
) -> CommitEnvelope {
    commit_at_epoch(signer, key, domain, 1, sequence, dependencies, variant)
}

#[allow(clippy::too_many_arguments)]
fn commit_at_epoch(
    signer: &IrohSigner,
    key: &DomainKey,
    domain: DomainId,
    epoch: u64,
    sequence: u64,
    dependencies: Vec<CommitId>,
    variant: u8,
) -> CommitEnvelope {
    let sequence_byte = u8::try_from(sequence).unwrap();
    let header = CommitHeader::new(
        domain,
        epoch,
        signer.author(),
        sequence,
        dependencies,
        CapabilityId::from_bytes(id(4)),
        vec![SchemaId::from_bytes(id(5))],
        [sequence_byte + variant; 24],
    )
    .unwrap();
    let body = CommitBody::new(
        TransactionId::from_bytes([sequence_byte + variant; 32]),
        Vec::new(),
    )
    .unwrap();
    seal_commit(header, &body, key, signer).unwrap()
}

#[tokio::test]
async fn stored_commit_export_can_stop_at_an_epoch_boundary() {
    let directory = tempfile::tempdir().unwrap();
    let blobs = Arc::new(MemoryBlobs::default());
    let signer = IrohSigner::from_secret_bytes(id(7));
    let key = DomainKey::from_bytes(id(8));
    let domain = DomainId::from_bytes(id(1));
    let first = commit_at_epoch(&signer, &key, domain, 0, 0, Vec::new(), 1);
    let second = commit_at_epoch(&signer, &key, domain, 1, 1, vec![first.commit_id()], 1);
    let store = Store::open(directory.path(), blobs).unwrap();
    store.persist_commit(&first).await.unwrap();
    store.persist_commit(&second).await.unwrap();

    assert_eq!(
        store.list_stored_commit_ids_through(domain, 0).unwrap(),
        vec![first.commit_id()]
    );
    let mut both = vec![first.commit_id(), second.commit_id()];
    both.sort_unstable();
    assert_eq!(
        store.list_stored_commit_ids_through(domain, 1).unwrap(),
        both
    );
}

#[tokio::test]
async fn commits_are_blob_first_atomic_idempotent_and_reopenable() {
    let directory = tempfile::tempdir().unwrap();
    let blobs = Arc::new(MemoryBlobs::default());
    let signer = IrohSigner::from_secret_bytes(id(7));
    let key = DomainKey::from_bytes(id(8));
    let domain = DomainId::from_bytes(id(1));
    let first = commit(&signer, &key, domain, 0, Vec::new());
    let first_id = first.commit_id();

    let store = Store::open(directory.path(), blobs.clone()).unwrap();
    assert_eq!(
        store.persist_commit(&first).await.unwrap(),
        ApplyOutcome::Applied(first_id)
    );
    assert!(blobs.contains(BlobHash::from_bytes(first_id.to_bytes())));
    assert!(store.contains_commit(domain, first_id).unwrap());
    assert_eq!(
        store.last_sequence(domain, signer.author()).unwrap(),
        Some(0)
    );
    assert_eq!(store.frontier(domain).unwrap(), vec![first_id]);
    assert_eq!(
        store.persist_commit(&first).await.unwrap(),
        ApplyOutcome::Duplicate(first_id)
    );

    let second = commit(&signer, &key, domain, 1, vec![first_id]);
    let second_id = second.commit_id();
    assert_eq!(
        store.persist_commit(&second).await.unwrap(),
        ApplyOutcome::Applied(second_id)
    );
    assert_eq!(store.frontier(domain).unwrap(), vec![second_id]);
    drop(store);

    let reopened = Store::open(directory.path(), blobs).unwrap();
    assert!(reopened.contains_commit(domain, first_id).unwrap());
    assert!(reopened.contains_commit(domain, second_id).unwrap());
    assert_eq!(
        reopened.last_sequence(domain, signer.author()).unwrap(),
        Some(1)
    );
}

#[tokio::test]
async fn blob_first_commit_orphans_are_detected_without_misclassifying_other_blobs() {
    let directory = tempfile::tempdir().unwrap();
    let blobs = Arc::new(MemoryBlobs::default());
    let signer = IrohSigner::from_secret_bytes(id(7));
    let key = DomainKey::from_bytes(id(8));
    let domain = DomainId::from_bytes(id(1));
    let accepted = commit(&signer, &key, domain, 0, Vec::new());
    let orphan = commit(&signer, &key, domain, 1, vec![accepted.commit_id()]);
    let store = Store::open(directory.path(), blobs.clone()).unwrap();
    store.persist_commit(&accepted).await.unwrap();
    blobs.put(orphan.encode_canonical()).await.unwrap();
    blobs.put(b"not a commit".to_vec()).await.unwrap();

    assert_eq!(
        store.scan_commit_orphans().await.unwrap(),
        vec![orphan.commit_id()]
    );
}

#[tokio::test]
async fn blob_failure_or_sequence_gap_never_mutates_metadata() {
    let directory = tempfile::tempdir().unwrap();
    let blobs = Arc::new(MemoryBlobs::default());
    let signer = IrohSigner::from_secret_bytes(id(7));
    let key = DomainKey::from_bytes(id(8));
    let domain = DomainId::from_bytes(id(1));
    let first = commit(&signer, &key, domain, 0, Vec::new());
    let first_id = first.commit_id();
    let store = Store::open(directory.path(), blobs.clone()).unwrap();

    blobs.set_fail_put(true);
    assert!(matches!(
        store.persist_commit(&first).await,
        Err(StoreError::Blob(_))
    ));
    assert!(!store.contains_commit(domain, first_id).unwrap());

    blobs.set_fail_put(false);
    let gap = commit(&signer, &key, domain, 2, Vec::new());
    assert_eq!(
        store.persist_commit(&gap).await,
        Err(StoreError::SequenceGap {
            expected: 0,
            actual: 2,
        })
    );
    assert!(!store.contains_commit(domain, gap.commit_id()).unwrap());
    assert_eq!(store.last_sequence(domain, signer.author()).unwrap(), None);
}

#[tokio::test]
async fn next_author_sequence_must_extend_its_previous_commit() {
    let directory = tempfile::tempdir().unwrap();
    let blobs = Arc::new(MemoryBlobs::default());
    let first_author = IrohSigner::from_secret_bytes(id(7));
    let other_author = IrohSigner::from_secret_bytes(id(9));
    let key = DomainKey::from_bytes(id(8));
    let domain = DomainId::from_bytes(id(1));
    let store = Store::open(directory.path(), blobs).unwrap();

    let first = commit(&first_author, &key, domain, 0, Vec::new());
    let unrelated = commit(&other_author, &key, domain, 0, Vec::new());
    store.persist_commit(&first).await.unwrap();
    store.persist_commit(&unrelated).await.unwrap();

    let detached = commit(&first_author, &key, domain, 1, vec![unrelated.commit_id()]);
    assert_eq!(
        store.persist_commit(&detached).await,
        Err(StoreError::AuthorChainMissing {
            previous: first.commit_id(),
        })
    );
    assert!(!store.contains_commit(domain, detached.commit_id()).unwrap());
    assert_eq!(
        store.last_sequence(domain, first_author.author()).unwrap(),
        Some(0)
    );

    let bridge = commit(
        &other_author,
        &key,
        domain,
        1,
        vec![first.commit_id(), unrelated.commit_id()],
    );
    store.persist_commit(&bridge).await.unwrap();
    let linked = commit(&first_author, &key, domain, 1, vec![bridge.commit_id()]);
    assert_eq!(
        store.persist_commit(&linked).await.unwrap(),
        ApplyOutcome::Applied(linked.commit_id())
    );
}

#[tokio::test]
async fn distinct_commits_at_one_author_sequence_are_equivocation_evidence() {
    let first_directory = tempfile::tempdir().unwrap();
    let second_directory = tempfile::tempdir().unwrap();
    let first_blobs = Arc::new(MemoryBlobs::default());
    let second_blobs = Arc::new(MemoryBlobs::default());
    let signer = IrohSigner::from_secret_bytes(id(7));
    let key = DomainKey::from_bytes(id(8));
    let domain = DomainId::from_bytes(id(1));
    let left = commit_variant(&signer, &key, domain, 0, Vec::new(), 1);
    let right = commit_variant(&signer, &key, domain, 0, Vec::new(), 2);
    let (first_id, second_id) = if left.commit_id() < right.commit_id() {
        (left.commit_id(), right.commit_id())
    } else {
        (right.commit_id(), left.commit_id())
    };

    let first_store = Store::open(first_directory.path(), first_blobs).unwrap();
    first_store.persist_commit(&left).await.unwrap();
    assert_eq!(
        first_store.persist_commit(&right).await,
        Err(StoreError::AuthorEquivocation {
            author: signer.author(),
            sequence: 0,
            first: first_id,
            second: second_id,
        })
    );

    let second_store = Store::open(second_directory.path(), second_blobs).unwrap();
    second_store.persist_commit(&right).await.unwrap();
    assert_eq!(
        second_store.persist_commit(&left).await,
        Err(StoreError::AuthorEquivocation {
            author: signer.author(),
            sequence: 0,
            first: first_id,
            second: second_id,
        })
    );
}

#[tokio::test]
async fn records_schemas_and_indexes_publish_atomically_with_commit_metadata() {
    let directory = tempfile::tempdir().unwrap();
    let blobs = Arc::new(MemoryBlobs::default());
    let signer = IrohSigner::from_secret_bytes([31; 32]);
    let key = DomainKey::from_bytes([32; 32]);
    let domain = DomainId::from_bytes([33; 32]);
    let schema = SchemaDescriptor::new(
        "tracks",
        1,
        vec![
            FieldDescriptor::new(1, "id", CrdtKind::Immutable, "String").record_id(),
            FieldDescriptor::new(2, "artist", CrdtKind::Lww, "String").indexed(),
        ],
    )
    .unwrap();
    let first = commit(&signer, &key, domain, 0, Vec::new());
    let record_id = vec![0x67, 0x74, 0x72, 0x61, 0x63, 0x6b, 0x2d, 0x31];
    let artist = vec![
        0x6f, 0x4d, 0x61, 0x73, 0x73, 0x69, 0x76, 0x65, 0x20, 0x41, 0x74, 0x74, 0x61, 0x63, 0x6b,
    ];
    let mutation = MaterializedRecord::upsert(
        schema.clone(),
        record_id.clone(),
        b"canonical record state".to_vec(),
        vec![IndexValue::new(2, artist.clone())],
    )
    .unwrap();

    let store = Store::open(directory.path(), blobs.clone()).unwrap();
    assert_eq!(
        store
            .persist_commit_with_records(&first, &[mutation])
            .await
            .unwrap(),
        ApplyOutcome::Applied(first.commit_id())
    );
    assert_eq!(
        store
            .get_record(domain, schema.collection_id(), &record_id)
            .unwrap(),
        Some(b"canonical record state".to_vec())
    );
    assert_eq!(
        store
            .lookup_equal(domain, schema.collection_id(), 2, &artist)
            .unwrap(),
        vec![record_id.clone()]
    );
    assert_eq!(
        store
            .registered_schema(domain, schema.collection_id(), 1)
            .unwrap(),
        Some(schema.clone())
    );

    let conflicting = SchemaDescriptor::new(
        "tracks",
        1,
        vec![
            FieldDescriptor::new(1, "id", CrdtKind::Immutable, "String").record_id(),
            FieldDescriptor::new(2, "performer", CrdtKind::Lww, "String").indexed(),
        ],
    )
    .unwrap();
    let second = commit(&signer, &key, domain, 1, vec![first.commit_id()]);
    let invalid = MaterializedRecord::upsert(
        conflicting,
        record_id.clone(),
        b"must not become visible".to_vec(),
        Vec::new(),
    )
    .unwrap();
    assert!(matches!(
        store.persist_commit_with_records(&second, &[invalid]).await,
        Err(StoreError::SchemaMismatch { .. })
    ));
    assert!(!store.contains_commit(domain, second.commit_id()).unwrap());
    assert_eq!(
        store
            .get_record(domain, schema.collection_id(), &record_id)
            .unwrap(),
        Some(b"canonical record state".to_vec())
    );
}

#[tokio::test]
async fn snapshot_install_rejects_noncanonical_causal_baselines_atomically() {
    let directory = tempfile::tempdir().unwrap();
    let blobs = Arc::new(MemoryBlobs::default());
    let signer = IrohSigner::from_secret_bytes(id(7));
    let key = DomainKey::from_bytes(id(8));
    let domain = DomainId::from_bytes(id(1));
    let accepted = commit(&signer, &key, domain, 0, Vec::new());
    let accepted_id = accepted.commit_id();
    let outside_coverage = CommitId::from_bytes(id(99));
    let store = Store::open(directory.path(), blobs).unwrap();
    store.persist_commit(&accepted).await.unwrap();
    let baseline = |frontier: Vec<CommitId>, author_sequences: Vec<(AuthorId, u64)>| {
        SnapshotBaseline::new(
            domain,
            0,
            BlobHash::from_bytes(id(88)),
            id(89),
            frontier,
            author_sequences,
        )
        .unwrap()
    };

    assert!(
        store
            .install_snapshot(
                domain,
                &[],
                &[accepted_id],
                &[outside_coverage],
                &[(signer.author(), 0)],
                &[],
                1,
                &baseline(vec![outside_coverage], vec![(signer.author(), 0)]),
            )
            .is_err()
    );
    assert_eq!(store.frontier(domain).unwrap(), vec![accepted_id]);

    assert!(
        store
            .install_snapshot(
                domain,
                &[],
                &[accepted_id, accepted_id],
                &[accepted_id],
                &[(signer.author(), 0)],
                &[],
                1,
                &baseline(vec![accepted_id], vec![(signer.author(), 0)]),
            )
            .is_err()
    );
    assert_eq!(store.frontier(domain).unwrap(), vec![accepted_id]);

    let first_author = AuthorId::from_bytes(id(9));
    let second_author = AuthorId::from_bytes(id(6));
    assert!(first_author > second_author);
    assert!(
        store
            .install_snapshot(
                domain,
                &[],
                &[accepted_id],
                &[accepted_id],
                &[(first_author, 0), (second_author, 0)],
                &[],
                1,
                &baseline(vec![accepted_id], vec![(signer.author(), 0)]),
            )
            .is_err()
    );
    assert_eq!(store.frontier(domain).unwrap(), vec![accepted_id]);

    let schema = SchemaDescriptor::new(
        "snapshot-records",
        1,
        vec![FieldDescriptor::new(1, "id", CrdtKind::Immutable, "String").record_id()],
    )
    .unwrap();
    let record =
        MaterializedRecord::upsert(schema, b"duplicate".to_vec(), b"state".to_vec(), Vec::new())
            .unwrap();
    assert!(
        store
            .install_snapshot(
                domain,
                &[record.clone(), record],
                &[accepted_id],
                &[accepted_id],
                &[(signer.author(), 0)],
                &[],
                1,
                &baseline(vec![accepted_id], vec![(signer.author(), 0)]),
            )
            .is_err()
    );
    assert_eq!(store.frontier(domain).unwrap(), vec![accepted_id]);
    assert_eq!(store.snapshot_observed_at(domain).unwrap(), None);
}

#[tokio::test]
async fn snapshot_tail_preflight_uses_signed_domain_baseline() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path(), Arc::new(MemoryBlobs::default())).unwrap();
    let domain = DomainId::from_bytes(id(1));
    let other_domain = DomainId::from_bytes(id(2));
    let baseline_author = IrohSigner::from_secret_bytes(id(7));
    let fresh_author = IrohSigner::from_secret_bytes(id(9));
    let key = DomainKey::from_bytes(id(8));
    let opaque_frontier = CommitId::from_bytes(id(77));
    let author_floor = vec![(baseline_author.author(), 0)];
    let baseline = SnapshotBaseline::new(
        domain,
        1,
        BlobHash::from_bytes(id(88)),
        id(89),
        vec![opaque_frontier],
        author_floor.clone(),
    )
    .unwrap();
    store
        .install_snapshot(
            domain,
            &[],
            &[opaque_frontier],
            &[opaque_frontier],
            &author_floor,
            &[],
            1,
            &baseline,
        )
        .unwrap();

    let blind = commit(&fresh_author, &key, domain, 0, Vec::new());
    assert!(matches!(
        store.persist_commit(&blind).await,
        Ok(ApplyOutcome::Applied(_))
    ));
    let first_tail = commit(&fresh_author, &key, domain, 1, vec![blind.commit_id()]);
    assert!(matches!(
        store.persist_commit(&first_tail).await,
        Ok(ApplyOutcome::Applied(_))
    ));
    let concurrent_tail = commit(&baseline_author, &key, domain, 1, vec![opaque_frontier]);
    assert!(matches!(
        store.persist_commit(&concurrent_tail).await,
        Ok(ApplyOutcome::Applied(_))
    ));

    assert!(store.contains_commit(domain, opaque_frontier).unwrap());
    assert!(
        !store
            .contains_commit(other_domain, opaque_frontier)
            .unwrap()
    );
    let cross_domain = commit(
        &IrohSigner::from_secret_bytes(id(11)),
        &key,
        other_domain,
        0,
        vec![opaque_frontier],
    );
    assert_eq!(
        store.persist_commit(&cross_domain).await,
        Err(StoreError::MissingDependency(opaque_frontier))
    );
}

#[tokio::test]
async fn retained_snapshot_frontier_remains_accepted_after_quarantine() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path(), Arc::new(MemoryBlobs::default())).unwrap();
    let domain = DomainId::from_bytes(id(1));
    let baseline_author = IrohSigner::from_secret_bytes(id(7));
    let descendant_author = IrohSigner::from_secret_bytes(id(9));
    let key = DomainKey::from_bytes(id(8));
    let retained = commit(&baseline_author, &key, domain, 0, Vec::new());
    let retained_id = retained.commit_id();
    store.persist_commit(&retained).await.unwrap();

    let author_floor = vec![(baseline_author.author(), 0)];
    let baseline = SnapshotBaseline::new(
        domain,
        1,
        BlobHash::from_bytes(id(88)),
        id(89),
        vec![retained_id],
        author_floor.clone(),
    )
    .unwrap();
    store
        .install_snapshot(
            domain,
            &[],
            &[retained_id],
            &[retained_id],
            &author_floor,
            &[],
            1,
            &baseline,
        )
        .unwrap();

    let evidence = commit_variant(&baseline_author, &key, domain, 0, Vec::new(), 2);
    store
        .quarantine_equivocation(
            &evidence,
            &[retained_id],
            &[retained_id],
            &author_floor,
            &[],
            &[],
        )
        .await
        .unwrap();
    assert!(store.is_commit_quarantined(retained_id).unwrap());

    let descendant = commit(&descendant_author, &key, domain, 0, vec![retained_id]);
    assert!(matches!(
        store.persist_commit(&descendant).await,
        Ok(ApplyOutcome::Applied(_))
    ));
}

#[tokio::test]
async fn blob_ownership_is_domain_isolated_idempotent_and_reopenable() {
    let directory = tempfile::tempdir().unwrap();
    let blobs = Arc::new(MemoryBlobs::default());
    let first_domain = DomainId::from_bytes(id(1));
    let second_domain = DomainId::from_bytes(id(2));
    let application_hash = BlobHash::from_bytes(id(44));
    let signer = IrohSigner::from_secret_bytes(id(7));
    let key = DomainKey::from_bytes(id(8));
    let accepted = commit(&signer, &key, first_domain, 0, Vec::new());
    let accepted_hash = BlobHash::from_bytes(accepted.commit_id().to_bytes());
    let store = Store::open(directory.path(), blobs.clone()).unwrap();
    store.persist_commit(&accepted).await.unwrap();
    store.claim_blob(first_domain, application_hash).unwrap();
    store.claim_blob(first_domain, application_hash).unwrap();

    assert!(store.owns_blob(first_domain, application_hash).unwrap());
    assert!(!store.owns_blob(second_domain, application_hash).unwrap());
    assert!(store.owns_blob(first_domain, accepted_hash).unwrap());
    assert!(!store.owns_blob(second_domain, accepted_hash).unwrap());
    drop(store);

    let reopened = Store::open(directory.path(), blobs).unwrap();
    assert!(reopened.owns_blob(first_domain, application_hash).unwrap());
    assert!(!reopened.owns_blob(second_domain, application_hash).unwrap());
}
