use std::path::Path;
use std::time::Duration;

use iroh_blobs::{Hash, store::fs::FsStore};
use iroh_db_core::BlobHash;
use iroh_db_store::{BlobFuture, BlobStore, BlobStoreError};
use tokio::io::AsyncReadExt;

/// Default upper bound for the iroh-blobs metadata userspace page cache.
pub const DEFAULT_METADATA_CACHE_SIZE: usize = 8 * 1024 * 1024;

/// Non-owning iroh-blobs provider handler that leaves the shared local store running on shutdown.
#[derive(Debug, Clone)]
pub struct BlobProtocol {
    store: iroh_blobs::api::Store,
    events: iroh_blobs::provider::events::EventSender,
}

impl iroh::protocol::ProtocolHandler for BlobProtocol {
    async fn accept(
        &self,
        connection: iroh::endpoint::Connection,
    ) -> Result<(), iroh::protocol::AcceptError> {
        iroh_blobs::provider::handle_connection(
            connection,
            self.store.clone(),
            self.events.clone(),
        )
        .await;
        Ok(())
    }
}

/// Durable local blob storage backed by iroh-blobs.
#[derive(Debug, Clone)]
pub struct IrohBlobStore {
    inner: FsStore,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TransferStats {
    pub(crate) bytes: u64,
    pub(crate) elapsed: Duration,
}

impl IrohBlobStore {
    /// Opens or creates an iroh-blobs filesystem store at `root`.
    pub async fn load(root: impl AsRef<Path>) -> Result<Self, BlobStoreError> {
        Self::load_with_cache_size(root, DEFAULT_METADATA_CACHE_SIZE).await
    }

    /// Opens an iroh-blobs filesystem store with an explicit metadata cache bound.
    pub async fn load_with_cache_size(
        root: impl AsRef<Path>,
        cache_size: usize,
    ) -> Result<Self, BlobStoreError> {
        let root = root.as_ref();
        let mut options = iroh_blobs::store::fs::options::Options::new(root);
        options.redb_cache_size = cache_size;
        let inner = FsStore::load_with_opts(root.join("blobs.db"), options)
            .await
            .map_err(|error| BlobStoreError::new(error.to_string()))?;
        Ok(Self { inner })
    }

    /// Flushes persistent state and shuts down the underlying store actor.
    ///
    /// All clones become inoperable after this call.
    pub async fn shutdown(&self) -> Result<(), BlobStoreError> {
        self.inner
            .shutdown()
            .await
            .map_err(|error| BlobStoreError::new(error.to_string()))
    }

    /// Creates a provider protocol over this store without transferring shutdown ownership.
    pub fn protocol(&self) -> BlobProtocol {
        self.protocol_with_events(iroh_blobs::provider::events::EventSender::DEFAULT)
    }

    /// Creates a provider protocol using iroh-blobs' request interception hooks.
    pub fn protocol_with_events(
        &self,
        events: iroh_blobs::provider::events::EventSender,
    ) -> BlobProtocol {
        BlobProtocol {
            store: self.inner.clone().into(),
            events,
        }
    }

    /// Downloads and verifies one complete immutable object over an iroh-blobs connection.
    pub async fn fetch(
        &self,
        connection: iroh::endpoint::Connection,
        hash: BlobHash,
    ) -> Result<(), BlobStoreError> {
        self.fetch_with_stats(connection, hash).await.map(|_| ())
    }

    pub(crate) async fn fetch_with_stats(
        &self,
        connection: iroh::endpoint::Connection,
        hash: BlobHash,
    ) -> Result<TransferStats, BlobStoreError> {
        let stats = self
            .inner
            .remote()
            .fetch(connection, Hash::from_bytes(hash.to_bytes()))
            .await
            .map_err(|error| BlobStoreError::new(error.to_string()))?;
        Ok(TransferStats {
            bytes: stats.total_bytes_read(),
            elapsed: stats.elapsed,
        })
    }

    /// Reads one locally complete immutable object by content hash.
    pub async fn read(&self, hash: BlobHash) -> Result<Option<Vec<u8>>, BlobStoreError> {
        BlobStore::get(self, hash).await
    }
}

impl BlobStore for IrohBlobStore {
    fn put(&self, bytes: Vec<u8>) -> BlobFuture<'_, BlobHash> {
        Box::pin(async move {
            let tag = self
                .inner
                .add_bytes(bytes)
                .await
                .map_err(|error| BlobStoreError::new(error.to_string()))?;
            Ok(BlobHash::from_bytes(*tag.hash.as_bytes()))
        })
    }

    fn get(&self, hash: BlobHash) -> BlobFuture<'_, Option<Vec<u8>>> {
        Box::pin(async move {
            let hash = Hash::from_bytes(hash.to_bytes());
            let present = self
                .inner
                .has(hash)
                .await
                .map_err(|error| BlobStoreError::new(error.to_string()))?;
            if !present {
                return Ok(None);
            }

            let mut reader = self.inner.reader(hash);
            let mut bytes = Vec::new();
            reader
                .read_to_end(&mut bytes)
                .await
                .map_err(|error| BlobStoreError::new(error.to_string()))?;
            Ok(Some(bytes))
        })
    }

    fn list(&self) -> BlobFuture<'_, Vec<BlobHash>> {
        Box::pin(async move {
            let mut hashes = self
                .inner
                .list()
                .hashes()
                .await
                .map_err(|error| BlobStoreError::new(error.to_string()))?
                .into_iter()
                .map(|hash| BlobHash::from_bytes(*hash.as_bytes()))
                .collect::<Vec<_>>();
            hashes.sort_unstable();
            Ok(hashes)
        })
    }
}
