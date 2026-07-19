use std::{future::Future, pin::Pin};

use iroh_db_core::BlobHash;

/// A boxed future returned by an immutable blob repository.
pub type BlobFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, BlobStoreError>> + Send + 'a>>;

/// The minimal immutable-byte boundary required by the metadata store.
pub trait BlobStore: Send + Sync + 'static {
    /// Stores exact bytes durably and returns their BLAKE3 content hash.
    fn put(&self, bytes: Vec<u8>) -> BlobFuture<'_, BlobHash>;

    /// Loads exact bytes when the hash is available locally.
    fn get(&self, hash: BlobHash) -> BlobFuture<'_, Option<Vec<u8>>>;

    /// Lists locally complete immutable objects in deterministic hash order.
    fn list(&self) -> BlobFuture<'_, Vec<BlobHash>>;
}

/// An implementation-independent blob repository failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("blob store operation failed: {message}")]
pub struct BlobStoreError {
    message: String,
}

impl BlobStoreError {
    /// Constructs a redacted operational error.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}
