use std::sync::Arc;

use iroh_db_blobs::IrohBlobStore;
use iroh_db_core::{
    BlobHash, CapabilityId, CommitBody, CommitHeader, DomainId, SchemaId, TransactionId,
};
use iroh_db_security::{DomainKey, IrohSigner, seal_commit};
use iroh_db_store::{ApplyOutcome, BlobStore, Store};

#[tokio::test]
async fn iroh_blob_store_is_content_addressed_and_reopenable() {
    let directory = tempfile::tempdir().unwrap();
    let bytes = b"immutable commit bytes".to_vec();
    let expected = BlobHash::from_bytes(*blake3::hash(&bytes).as_bytes());

    let store = IrohBlobStore::load(directory.path()).await.unwrap();
    let hash = store.put(bytes.clone()).await.unwrap();
    assert_eq!(hash, expected);
    assert_eq!(store.get(hash).await.unwrap(), Some(bytes.clone()));
    store.shutdown().await.unwrap();
    drop(store);

    let reopened = IrohBlobStore::load(directory.path()).await.unwrap();
    assert_eq!(reopened.get(hash).await.unwrap(), Some(bytes));
    assert_eq!(
        reopened.get(BlobHash::from_bytes([99; 32])).await.unwrap(),
        None
    );
}

#[tokio::test]
async fn metadata_and_real_commit_blob_survive_a_clean_restart() {
    let directory = tempfile::tempdir().unwrap();
    let blobs_path = directory.path().join("blobs");
    let database_path = directory.path().join("database");
    let signer = IrohSigner::from_secret_bytes([7; 32]);
    let header = CommitHeader::new(
        DomainId::from_bytes([1; 32]),
        0,
        signer.author(),
        0,
        Vec::new(),
        CapabilityId::from_bytes([2; 32]),
        vec![SchemaId::from_bytes([3; 32])],
        [4; 24],
    )
    .unwrap();
    let body = CommitBody::new(TransactionId::from_bytes([5; 32]), Vec::new()).unwrap();
    let commit = seal_commit(header, &body, &DomainKey::from_bytes([6; 32]), &signer).unwrap();
    let commit_id = commit.commit_id();

    let blobs = Arc::new(IrohBlobStore::load(&blobs_path).await.unwrap());
    let store = Store::open(&database_path, blobs.clone()).unwrap();
    assert_eq!(
        store.persist_commit(&commit).await.unwrap(),
        ApplyOutcome::Applied(commit_id)
    );
    drop(store);
    blobs.shutdown().await.unwrap();
    drop(blobs);

    let reopened_blobs = Arc::new(IrohBlobStore::load(&blobs_path).await.unwrap());
    let reopened = Store::open(&database_path, reopened_blobs.clone()).unwrap();
    assert_eq!(reopened.load_commit(commit_id).await.unwrap(), commit);
    drop(reopened);
    reopened_blobs.shutdown().await.unwrap();
}
