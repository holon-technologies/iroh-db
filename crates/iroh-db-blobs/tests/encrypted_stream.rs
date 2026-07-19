use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use iroh_db_blobs::{BlobEngine, BlobError};
use iroh_db_core::{BlobHash, DomainId};
use iroh_db_security::DomainKey;
use iroh_db_store::{BlobFuture, BlobStore};
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};

#[derive(Default)]
struct CountingBlobs {
    values: Mutex<BTreeMap<BlobHash, Vec<u8>>>,
    reads: AtomicUsize,
}

impl CountingBlobs {
    fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }

    fn corrupt_everything_except(&self, preserved: BlobHash) {
        for (hash, value) in self.values.lock().unwrap().iter_mut() {
            if *hash != preserved && !value.is_empty() {
                value[0] ^= 1;
            }
        }
    }
}

impl BlobStore for CountingBlobs {
    fn put(&self, bytes: Vec<u8>) -> BlobFuture<'_, BlobHash> {
        Box::pin(async move {
            let hash = BlobHash::from_bytes(*blake3::hash(&bytes).as_bytes());
            self.values.lock().unwrap().insert(hash, bytes);
            Ok(hash)
        })
    }

    fn get(&self, hash: BlobHash) -> BlobFuture<'_, Option<Vec<u8>>> {
        Box::pin(async move {
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(self.values.lock().unwrap().get(&hash).cloned())
        })
    }

    fn list(&self) -> BlobFuture<'_, Vec<BlobHash>> {
        Box::pin(async move { Ok(self.values.lock().unwrap().keys().copied().collect()) })
    }
}

#[tokio::test]
async fn encrypted_blob_stream_fetches_only_chunks_that_are_read_or_sought() {
    const CHUNK_SIZE: usize = 64 * 1024;
    let store = Arc::new(CountingBlobs::default());
    let engine = BlobEngine::with_chunk_size(
        store.clone(),
        DomainId::from_bytes([1; 32]),
        CHUNK_SIZE,
        DomainKey::from_bytes([2; 32]),
    )
    .unwrap();
    let mut input = vec![b'a'; CHUNK_SIZE];
    input.extend(vec![b'b'; CHUNK_SIZE]);
    input.extend(vec![b'c'; CHUNK_SIZE]);
    let reference = engine
        .import_bytes(input.clone(), Some("audio/test".into()))
        .await
        .unwrap();

    let mut stream = engine.open(&reference).await.unwrap();
    assert_eq!(store.reads(), 1, "opening fetches only the manifest");
    let mut first = [0_u8; 3];
    stream.read_exact(&mut first).await.unwrap();
    assert_eq!(&first, b"aaa");
    assert_eq!(store.reads(), 2, "the first read fetches one chunk");

    stream
        .seek(std::io::SeekFrom::Start((input.len() - 3) as u64))
        .await
        .unwrap();
    let mut end = Vec::new();
    stream.read_to_end(&mut end).await.unwrap();
    assert_eq!(end, b"ccc");
    assert_eq!(store.reads(), 3, "seeking skips the middle chunk");
}

#[tokio::test]
async fn chunk_authentication_fails_before_corrupt_plaintext_is_returned() {
    let store = Arc::new(CountingBlobs::default());
    let engine = BlobEngine::with_chunk_size(
        store.clone(),
        DomainId::from_bytes([3; 32]),
        64 * 1024,
        DomainKey::from_bytes([4; 32]),
    )
    .unwrap();
    let reference = engine
        .import_bytes(b"abcdefgh".to_vec(), None)
        .await
        .unwrap();
    let mut stream = engine.open(&reference).await.unwrap();
    store.corrupt_everything_except(reference.manifest_hash());

    let mut output = Vec::new();
    let error = stream.read_to_end(&mut output).await.unwrap_err();
    assert!(output.is_empty());
    assert_eq!(
        error
            .get_ref()
            .and_then(|source| source.downcast_ref::<BlobError>()),
        Some(&BlobError::HashMismatch)
    );
}

#[tokio::test]
async fn import_reader_streams_chunks_and_preserves_media_metadata() {
    let store = Arc::new(CountingBlobs::default());
    let engine = BlobEngine::with_chunk_size(
        store,
        DomainId::from_bytes([5; 32]),
        64 * 1024,
        DomainKey::from_bytes([6; 32]),
    )
    .unwrap();
    let input = vec![42_u8; 130_000];
    let reference = engine
        .import_reader(input.as_slice(), Some("application/test".into()))
        .await
        .unwrap();
    let mut stream = engine.open(&reference).await.unwrap();
    assert_eq!(stream.media_type(), Some("application/test"));
    let mut output = Vec::new();
    stream.read_to_end(&mut output).await.unwrap();
    assert_eq!(output, input);
}
