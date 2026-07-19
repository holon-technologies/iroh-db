use std::{
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
};

type ChunkFuture = Pin<Box<dyn Future<Output = Result<Vec<u8>, BlobError>> + Send + 'static>>;
pub(crate) type ChunkFetcher = Arc<
    dyn Fn(BlobHash) -> Pin<Box<dyn Future<Output = Result<(), BlobError>> + Send + 'static>>
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
        }
    }

    pub(crate) fn with_fetcher(mut self, fetcher: ChunkFetcher) -> Self {
        self.fetcher = Some(fetcher);
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
        let future = Box::pin(async move {
            let mut ciphertext = store
                .get(descriptor.ciphertext_hash)
                .await
                .map_err(BlobError::from)?;
            if ciphertext.is_none()
                && let Some(fetcher) = fetcher
            {
                fetcher(descriptor.ciphertext_hash).await?;
                ciphertext = store
                    .get(descriptor.ciphertext_hash)
                    .await
                    .map_err(BlobError::from)?;
            }
            let ciphertext =
                ciphertext.ok_or(BlobError::MissingBlob(descriptor.ciphertext_hash))?;
            decrypt_chunk(&key, domain_id, epoch, &salt, &descriptor, &ciphertext)
        });
        self.pending = Some((index, future));
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
        Ok(())
    }

    fn poll_complete(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<std::io::Result<u64>> {
        Poll::Ready(Ok(self.position))
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
