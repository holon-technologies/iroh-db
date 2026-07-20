use std::{
    collections::BTreeMap,
    future::Future,
    io::{Error as IoError, ErrorKind, SeekFrom},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use iroh_db_core::BlobHash;
use iroh_db_security::DomainKey;
use iroh_db_store::BlobStore;
use tokio::io::{AsyncRead, AsyncSeek, ReadBuf};

use crate::{
    BlobError,
    engine::{MAX_CHUNK_SIZE, MIN_CHUNK_SIZE, decrypt_chunk},
    model::{ChunkDescriptor, ManifestBody, ManifestEnvelope},
    scheduler::BlobPriority,
};

type ChunkFuture = Pin<Box<dyn Future<Output = Result<Vec<u8>, BlobError>> + Send + 'static>>;
pub(crate) type ChunkFetcher = Arc<
    dyn Fn(
            BlobHash,
            u64,
            BlobPriority,
            bool,
        ) -> Pin<Box<dyn Future<Output = Result<(), BlobError>> + Send + 'static>>
        + Send
        + Sync,
>;

/// Lazy authenticated plaintext reader over independently encrypted chunks.
pub struct BlobStream {
    store: Arc<dyn BlobStore>,
    key: DomainKey,
    envelope: ManifestEnvelope,
    manifest: ManifestBody,
    position: u64,
    cached: Option<(usize, Vec<u8>)>,
    pending: Option<(usize, ChunkFuture)>,
    fetcher: Option<ChunkFetcher>,
    priority: BlobPriority,
    prefetch_chunks: usize,
    prefetch_anchor: Option<usize>,
    prefetch_tasks: BTreeMap<usize, tokio::task::JoinHandle<()>>,
}

impl BlobStream {
    pub(crate) fn new(
        store: Arc<dyn BlobStore>,
        key: DomainKey,
        envelope: ManifestEnvelope,
        manifest: ManifestBody,
    ) -> Self {
        Self {
            store,
            key,
            envelope,
            manifest,
            position: 0,
            cached: None,
            pending: None,
            fetcher: None,
            priority: BlobPriority::Normal,
            prefetch_chunks: 0,
            prefetch_anchor: None,
            prefetch_tasks: BTreeMap::new(),
        }
    }

    pub(crate) fn with_fetcher(
        mut self,
        fetcher: ChunkFetcher,
        priority: BlobPriority,
        prefetch_chunks: u8,
    ) -> Self {
        self.fetcher = Some(fetcher);
        self.priority = priority;
        self.prefetch_chunks = usize::from(prefetch_chunks.min(16));
        self
    }

    /// Returns the authenticated plaintext length.
    pub const fn len(&self) -> u64 {
        self.manifest.plaintext_len
    }

    /// Returns whether the authenticated blob is empty.
    pub const fn is_empty(&self) -> bool {
        self.manifest.plaintext_len == 0
    }

    /// Returns the authenticated media type supplied at import time.
    pub fn media_type(&self) -> Option<&str> {
        self.manifest.media_type.as_deref()
    }

    fn begin_chunk_load(&mut self, index: usize) {
        let store = self.store.clone();
        let key = self.key.clone();
        let domain_id = self.envelope.domain_id;
        let epoch = self.envelope.epoch;
        let salt = self.envelope.salt;
        let descriptor = self.manifest.chunks[index].clone();
        let fetcher = self.fetcher.clone();
        let priority = self.priority;
        let future = Box::pin(async move {
            if let Some(fetcher) = fetcher {
                fetcher(
                    descriptor.ciphertext_hash,
                    u64::from(descriptor.plaintext_len) + 16,
                    priority,
                    priority == BlobPriority::High,
                )
                .await?;
            }
            let ciphertext = store
                .get(descriptor.ciphertext_hash)
                .await
                .map_err(BlobError::from)?
                .ok_or(BlobError::MissingBlob(descriptor.ciphertext_hash))?;
            decrypt_chunk(&key, domain_id, epoch, &salt, &descriptor, &ciphertext)
        });
        self.pending = Some((index, future));
    }

    fn schedule_prefetch(&mut self, index: usize) {
        if self.prefetch_chunks == 0 || self.prefetch_anchor == Some(index) {
            return;
        }
        self.prefetch_anchor = Some(index);
        let Some(fetcher) = self.fetcher.clone() else {
            return;
        };
        let priority = self.priority.lower();
        let window_end = index
            .saturating_add(self.prefetch_chunks)
            .min(self.manifest.chunks.len().saturating_sub(1));
        self.prefetch_tasks.retain(|task_index, task| {
            let keep = !task.is_finished() && *task_index >= index && *task_index <= window_end;
            if !keep && !task.is_finished() {
                task.abort();
            }
            keep
        });
        let descriptors = self
            .manifest
            .chunks
            .iter()
            .enumerate()
            .skip(index.saturating_add(1))
            .take(self.prefetch_chunks)
            .map(|(task_index, descriptor)| (task_index, descriptor.clone()))
            .collect::<Vec<_>>();
        for (task_index, descriptor) in descriptors {
            if self.prefetch_tasks.contains_key(&task_index) {
                continue;
            }
            let fetcher = fetcher.clone();
            let store = self.store.clone();
            let task = tokio::spawn(async move {
                if store
                    .get(descriptor.ciphertext_hash)
                    .await
                    .ok()
                    .flatten()
                    .is_none()
                {
                    let _ = fetcher(
                        descriptor.ciphertext_hash,
                        u64::from(descriptor.plaintext_len) + 16,
                        priority,
                        false,
                    )
                    .await;
                }
            });
            self.prefetch_tasks.insert(task_index, task);
        }
    }

    fn cancel_prefetch(&mut self) {
        for (_, task) in std::mem::take(&mut self.prefetch_tasks) {
            task.abort();
        }
        self.prefetch_anchor = None;
    }
}

impl AsyncRead for BlobStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if self.position >= self.manifest.plaintext_len || output.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            let chunk_size = u64::from(self.manifest.chunk_size);
            let chunk_index_u64 = self.position / chunk_size;
            let chunk_index = usize::try_from(chunk_index_u64).map_err(|error| {
                IoError::new(ErrorKind::InvalidData, BlobError::Codec(error.to_string()))
            })?;
            self.schedule_prefetch(chunk_index);
            if let Some((cached_index, bytes)) = &self.cached
                && *cached_index == chunk_index
            {
                let offset = usize::try_from(self.position % chunk_size).map_err(|error| {
                    IoError::new(ErrorKind::InvalidData, BlobError::Codec(error.to_string()))
                })?;
                let available = &bytes[offset..];
                let count = available.len().min(output.remaining());
                output.put_slice(&available[..count]);
                self.position += u64::try_from(count).map_err(|error| {
                    IoError::new(ErrorKind::InvalidData, BlobError::Codec(error.to_string()))
                })?;
                return Poll::Ready(Ok(()));
            }

            if self
                .pending
                .as_ref()
                .is_none_or(|(pending_index, _)| *pending_index != chunk_index)
            {
                self.begin_chunk_load(chunk_index);
            }
            let (pending_index, future) = self
                .pending
                .as_mut()
                .expect("a chunk future was just installed");
            match future.as_mut().poll(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(bytes)) => {
                    let index = *pending_index;
                    self.pending = None;
                    self.cached = Some((index, bytes));
                }
                Poll::Ready(Err(error)) => {
                    self.pending = None;
                    return Poll::Ready(Err(IoError::new(ErrorKind::InvalidData, error)));
                }
            }
        }
    }
}

impl AsyncSeek for BlobStream {
    fn start_seek(mut self: Pin<&mut Self>, position: SeekFrom) -> std::io::Result<()> {
        let base = match position {
            SeekFrom::Start(position) => i128::from(position),
            SeekFrom::End(offset) => i128::from(self.manifest.plaintext_len) + i128::from(offset),
            SeekFrom::Current(offset) => i128::from(self.position) + i128::from(offset),
        };
        let position = u64::try_from(base)
            .map_err(|_| IoError::new(ErrorKind::InvalidInput, "seek before start"))?;
        self.position = position;
        self.pending = None;
        self.cancel_prefetch();
        Ok(())
    }

    fn poll_complete(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<std::io::Result<u64>> {
        Poll::Ready(Ok(self.position))
    }
}

impl Drop for BlobStream {
    fn drop(&mut self) {
        self.cancel_prefetch();
    }
}

pub(crate) fn validate_manifest(manifest: &ManifestBody) -> Result<(), BlobError> {
    let chunk_size = manifest.chunk_size as usize;
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
        return Err(BlobError::InvalidManifest);
    }
    let mut total = 0_u64;
    for (index, chunk) in manifest.chunks.iter().enumerate() {
        let expected_index = u32::try_from(index).map_err(|_| BlobError::InvalidManifest)?;
        if chunk.index != expected_index
            || chunk.plaintext_len == 0
            || chunk.plaintext_len as usize > chunk_size
        {
            return Err(BlobError::InvalidManifest);
        }
        if index + 1 != manifest.chunks.len() && chunk.plaintext_len as usize != chunk_size {
            return Err(BlobError::InvalidManifest);
        }
        total = total
            .checked_add(u64::from(chunk.plaintext_len))
            .ok_or(BlobError::InvalidManifest)?;
    }
    if total != manifest.plaintext_len
        || (manifest.plaintext_len == 0) != manifest.chunks.is_empty()
    {
        return Err(BlobError::InvalidManifest);
    }
    Ok(())
}

#[allow(dead_code)]
fn _descriptor_is_send(_: &ChunkDescriptor) {}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use iroh_db_core::DomainId;
    use iroh_db_store::{BlobFuture, BlobStoreError};
    use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};

    use super::*;

    struct EmptyStore;

    impl BlobStore for EmptyStore {
        fn put(&self, _bytes: Vec<u8>) -> BlobFuture<'_, BlobHash> {
            Box::pin(async { Err(BlobStoreError::new("put is unused")) })
        }

        fn get(&self, _hash: BlobHash) -> BlobFuture<'_, Option<Vec<u8>>> {
            Box::pin(async { Ok(None) })
        }

        fn list(&self) -> BlobFuture<'_, Vec<BlobHash>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    #[tokio::test]
    async fn cached_chunk_read_restarts_prefetch_after_seek() {
        const CHUNK_SIZE: usize = 64 * 1024;
        let chunk_size = u32::try_from(CHUNK_SIZE).unwrap();
        let chunks = (0_u8..3)
            .map(|index| ChunkDescriptor {
                index: u32::from(index),
                plaintext_len: chunk_size,
                ciphertext_hash: BlobHash::from_bytes([index + 1; 32]),
                nonce: [index; 24],
            })
            .collect();
        let envelope = ManifestEnvelope {
            version: 1,
            domain_id: DomainId::from_bytes([1; 32]),
            epoch: 0,
            salt: [2; 32],
            nonce: [3; 24],
            ciphertext: Vec::new(),
        };
        let body = ManifestBody {
            plaintext_len: u64::try_from(CHUNK_SIZE * 3).unwrap(),
            plaintext_hash: [4; 32],
            chunk_size,
            chunks,
            media_type: None,
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let fetch_calls = calls.clone();
        let fetcher: ChunkFetcher = Arc::new(move |_, _, _, _| {
            let fetch_calls = fetch_calls.clone();
            Box::pin(async move {
                fetch_calls.fetch_add(1, Ordering::Relaxed);
                Ok(())
            })
        });
        let mut stream = BlobStream::new(
            Arc::new(EmptyStore),
            DomainKey::from_bytes([5; 32]),
            envelope,
            body,
        )
        .with_fetcher(fetcher, BlobPriority::High, 2);
        stream.cached = Some((0, vec![7; CHUNK_SIZE]));

        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).await.unwrap();
        wait_for_calls(&calls, 2).await;
        stream.seek(SeekFrom::Start(1024)).await.unwrap();
        stream.read_exact(&mut byte).await.unwrap();
        wait_for_calls(&calls, 4).await;
    }

    async fn wait_for_calls(calls: &AtomicUsize, expected: usize) {
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while calls.load(Ordering::Relaxed) < expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}
