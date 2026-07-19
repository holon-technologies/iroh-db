use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};

use iroh_db_core::{
    BlobHash, CapabilityId, CommitBody, CommitEnvelope, CommitHeader, CommitId, CrdtKind, DomainId,
    FieldDescriptor, SchemaDescriptor, SchemaId, TransactionId,
};
use iroh_db_security::{DomainKey, IrohSigner, seal_commit};
use iroh_db_store::{
    ApplyOutcome, BlobStore, BlobStoreError, IndexValue, MaterializedRecord, Store, StoreError,
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
    let sequence_byte = u8::try_from(sequence).unwrap();
    let header = CommitHeader::new(
        domain,
        1,
        signer.author(),
        sequence,
        dependencies,
        CapabilityId::from_bytes(id(4)),
        vec![SchemaId::from_bytes(id(5))],
        [sequence_byte + 1; 24],
    )
    .unwrap();
    let body = CommitBody::new(TransactionId::from_bytes([sequence_byte; 32]), Vec::new()).unwrap();
    seal_commit(header, &body, key, signer).unwrap()
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
    assert!(store.contains_commit(first_id).unwrap());
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
    assert!(reopened.contains_commit(first_id).unwrap());
    assert!(reopened.contains_commit(second_id).unwrap());
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
    assert!(!store.contains_commit(first_id).unwrap());

    blobs.set_fail_put(false);
    let gap = commit(&signer, &key, domain, 2, Vec::new());
    assert_eq!(
        store.persist_commit(&gap).await,
        Err(StoreError::SequenceGap {
            expected: 0,
            actual: 2,
        })
    );
    assert!(!store.contains_commit(gap.commit_id()).unwrap());
    assert_eq!(store.last_sequence(domain, signer.author()).unwrap(), None);
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
    assert!(!store.contains_commit(second.commit_id()).unwrap());
    assert_eq!(
        store
            .get_record(domain, schema.collection_id(), &record_id)
            .unwrap(),
        Some(b"canonical record state".to_vec())
    );
}
