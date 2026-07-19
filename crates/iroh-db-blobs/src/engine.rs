use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead as _, KeyInit as _, Payload},
};
use iroh_db_core::{BlobHash, DomainId};
use iroh_db_security::DomainKey;
use iroh_db_store::{BlobStore, BlobStoreError};
use tokio::io::{AsyncRead, AsyncReadExt as _};

use crate::{
    BlobError, BlobRef, BlobStream, IrohBlobStore,
    model::{ChunkDescriptor, ManifestBody, ManifestEnvelope},
    stream::validate_manifest,
};

pub(crate) const FORMAT_VERSION: u16 = 1;
pub(crate) const MIN_CHUNK_SIZE: usize = 64 * 1024;
pub(crate) const MAX_CHUNK_SIZE: usize = 8 * 1024 * 1024;
pub(crate) const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;

/// Application scheduling class for remote blob reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BlobPriority {
    High,
    #[default]
    Normal,
    Low,
}

/// Bounded remote streaming policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchOptions {
    pub priority: BlobPriority,
    pub prefetch_chunks: u8,
}

impl Default for FetchOptions {
    fn default() -> Self {
        Self {
            priority: BlobPriority::Normal,
            prefetch_chunks: 2,
        }
    }
}

#[derive(Default)]
struct FetchCounters {
    provider_attempts: AtomicU64,
    chunks_fetched: AtomicU64,
}

/// Live, lock-free counters for one lazy multi-provider stream.
#[derive(Clone, Default)]
pub struct FetchMetrics(Arc<FetchCounters>);

impl FetchMetrics {
    pub fn provider_attempts(&self) -> u64 {
        self.0.provider_attempts.load(Ordering::Relaxed)
    }

    pub fn chunks_fetched(&self) -> u64 {
        self.0.chunks_fetched.load(Ordering::Relaxed)
    }
}

#[derive(Clone)]
struct ProviderPool {
    local: IrohBlobStore,
    claims: Arc<dyn BlobStore>,
    providers: Arc<Vec<iroh::endpoint::Connection>>,
    next: Arc<AtomicUsize>,
    metrics: FetchMetrics,
}

impl ProviderPool {
    async fn fetch(&self, hash: BlobHash) -> Result<(), BlobError> {
        self.fetch_unclaimed(hash).await?;
        self.claims.claim(hash).await.map_err(BlobError::from)
    }

    async fn fetch_unclaimed(&self, hash: BlobHash) -> Result<(), BlobError> {
        if self.providers.is_empty() {
            return Err(BlobError::NoProviders);
        }
        let start = self.next.fetch_add(1, Ordering::Relaxed) % self.providers.len();
        let mut last_error = None;
        for offset in 0..self.providers.len() {
            let index = (start + offset) % self.providers.len();
            self.metrics
                .0
                .provider_attempts
                .fetch_add(1, Ordering::Relaxed);
            match self.local.fetch(self.providers[index].clone(), hash).await {
                Ok(()) => {
                    self.metrics
                        .0
                        .chunks_fetched
                        .fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.map_or(BlobError::NoProviders, BlobError::from))
    }
}

/// Domain-bound encrypted blob import and streaming engine.
#[derive(Clone)]
pub struct BlobEngine {
    pub(crate) store: Arc<dyn BlobStore>,
    pub(crate) domain_id: DomainId,
    pub(crate) epoch: u64,
    pub(crate) chunk_size: usize,
    pub(crate) key: DomainKey,
}

impl BlobEngine {
    /// Creates an engine using one-MiB encrypted chunks.
    pub fn new(store: Arc<dyn BlobStore>, domain_id: DomainId, key: DomainKey) -> Self {
        Self {
            store,
            domain_id,
            epoch: 0,
            chunk_size: DEFAULT_CHUNK_SIZE,
            key,
        }
    }

    /// Creates an engine bound to an explicit domain key epoch.
    pub fn new_at_epoch(
        store: Arc<dyn BlobStore>,
        domain_id: DomainId,
        epoch: u64,
        key: DomainKey,
    ) -> Self {
        Self {
            store,
            domain_id,
            epoch,
            chunk_size: DEFAULT_CHUNK_SIZE,
            key,
        }
    }

    /// Creates an engine with an explicit 64-KiB through 8-MiB chunk size.
    pub fn with_chunk_size(
        store: Arc<dyn BlobStore>,
        domain_id: DomainId,
        chunk_size: usize,
        key: DomainKey,
    ) -> Result<Self, BlobError> {
        if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
            return Err(BlobError::InvalidChunkSize(chunk_size));
        }
        Ok(Self {
            store,
            domain_id,
            epoch: 0,
            chunk_size,
            key,
        })
    }

    /// Encrypts, hashes and persists chunks followed by their encrypted manifest.
    pub async fn import_bytes(
        &self,
        bytes: Vec<u8>,
        media_type: Option<String>,
    ) -> Result<BlobRef, BlobError> {
        self.import_reader(bytes.as_slice(), media_type).await
    }

    /// Incrementally encrypts and persists an asynchronous plaintext stream.
    pub async fn import_reader(
        &self,
        mut reader: impl AsyncRead + Unpin,
        media_type: Option<String>,
    ) -> Result<BlobRef, BlobError> {
        let mut salt = [0_u8; 32];
        getrandom::fill(&mut salt).map_err(|_| BlobError::RandomnessUnavailable)?;
        let mut chunks = Vec::new();
        let mut plaintext_len = 0_u64;
        let mut plaintext_hasher = blake3::Hasher::new();
        loop {
            let mut plaintext = vec![0_u8; self.chunk_size];
            let mut filled = 0;
            while filled < plaintext.len() {
                let count = reader
                    .read(&mut plaintext[filled..])
                    .await
                    .map_err(|error| BlobError::Read(error.to_string()))?;
                if count == 0 {
                    break;
                }
                filled += count;
            }
            if filled == 0 {
                break;
            }
            plaintext.truncate(filled);
            let index = chunks.len();
            let index = u32::try_from(index).map_err(|_| BlobError::BlobTooLarge)?;
            let chunk_plaintext_len =
                u32::try_from(plaintext.len()).map_err(|_| BlobError::BlobTooLarge)?;
            let mut nonce = [0_u8; 24];
            getrandom::fill(&mut nonce).map_err(|_| BlobError::RandomnessUnavailable)?;
            let ciphertext = encrypt_chunk(
                &self.key,
                self.domain_id,
                self.epoch,
                &salt,
                index,
                chunk_plaintext_len,
                nonce,
                &plaintext,
            )?;
            let ciphertext_hash = self.store.put(ciphertext).await.map_err(BlobError::from)?;
            chunks.push(ChunkDescriptor {
                index,
                plaintext_len: chunk_plaintext_len,
                ciphertext_hash,
                nonce,
            });
            plaintext_hasher.update(&plaintext);
            plaintext_len = plaintext_len
                .checked_add(u64::try_from(filled).map_err(|_| BlobError::BlobTooLarge)?)
                .ok_or(BlobError::BlobTooLarge)?;
            if filled < self.chunk_size {
                break;
            }
        }
        let chunk_size = u32::try_from(self.chunk_size).map_err(|_| BlobError::BlobTooLarge)?;
        let body = ManifestBody {
            plaintext_len,
            plaintext_hash: *plaintext_hasher.finalize().as_bytes(),
            chunk_size,
            chunks,
            media_type,
        };
        let plaintext = minicbor::to_vec(&body).map_err(codec_error)?;
        let mut nonce = [0_u8; 24];
        getrandom::fill(&mut nonce).map_err(|_| BlobError::RandomnessUnavailable)?;
        let ciphertext = encrypt_manifest(
            &self.key,
            self.domain_id,
            self.epoch,
            &salt,
            nonce,
            &plaintext,
        )?;
        let envelope = ManifestEnvelope {
            version: FORMAT_VERSION,
            domain_id: self.domain_id,
            epoch: self.epoch,
            salt,
            nonce,
            ciphertext,
        };
        let encoded = minicbor::to_vec(envelope).map_err(codec_error)?;
        let manifest_hash = self.store.put(encoded).await.map_err(BlobError::from)?;
        Ok(BlobRef::new(self.domain_id, self.epoch, manifest_hash))
    }

    /// Authenticates a manifest and returns a lazy chunk stream.
    pub async fn open(&self, reference: &BlobRef) -> Result<BlobStream, BlobError> {
        if reference.domain_id() != self.domain_id || reference.epoch() != self.epoch {
            return Err(BlobError::WrongDomainOrEpoch);
        }
        let encoded = self
            .store
            .get(reference.manifest_hash())
            .await
            .map_err(BlobError::from)?
            .ok_or(BlobError::MissingBlob(reference.manifest_hash()))?;
        verify_hash(reference.manifest_hash(), &encoded)?;
        let envelope: ManifestEnvelope = decode_canonical(&encoded)?;
        if envelope.version != FORMAT_VERSION
            || envelope.domain_id != self.domain_id
            || envelope.epoch != self.epoch
        {
            return Err(BlobError::WrongDomainOrEpoch);
        }
        let plaintext = decrypt_manifest(&self.key, &envelope)?;
        let body: ManifestBody = decode_canonical(&plaintext)?;
        validate_manifest(&body)?;
        Ok(BlobStream::new(
            self.store.clone(),
            self.key.clone(),
            envelope,
            body,
        ))
    }

    /// Opens immediately after fetching only the manifest; chunks are pulled lazily across peers.
    pub async fn open_from_providers(
        &self,
        local: IrohBlobStore,
        providers: Vec<iroh::endpoint::Connection>,
        reference: &BlobRef,
        options: FetchOptions,
    ) -> Result<(BlobStream, FetchMetrics), BlobError> {
        if reference.domain_id() != self.domain_id || reference.epoch() != self.epoch {
            return Err(BlobError::WrongDomainOrEpoch);
        }
        let metrics = FetchMetrics::default();
        let pool = ProviderPool {
            local,
            claims: self.store.clone(),
            providers: Arc::new(providers),
            next: Arc::new(AtomicUsize::new(match options.priority {
                BlobPriority::High | BlobPriority::Normal => 0,
                BlobPriority::Low => 1,
            })),
            metrics: metrics.clone(),
        };
        if self
            .store
            .get(reference.manifest_hash())
            .await
            .map_err(BlobError::from)?
            .is_none()
        {
            pool.fetch_unclaimed(reference.manifest_hash()).await?;
        }
        let encoded = self
            .store
            .get(reference.manifest_hash())
            .await
            .map_err(BlobError::from)?
            .ok_or(BlobError::MissingBlob(reference.manifest_hash()))?;
        verify_hash(reference.manifest_hash(), &encoded)?;
        let envelope: ManifestEnvelope = decode_canonical(&encoded)?;
        if envelope.version != FORMAT_VERSION
            || envelope.domain_id != self.domain_id
            || envelope.epoch != self.epoch
        {
            return Err(BlobError::WrongDomainOrEpoch);
        }
        let plaintext = decrypt_manifest(&self.key, &envelope)?;
        let body: ManifestBody = decode_canonical(&plaintext)?;
        validate_manifest(&body)?;
        self.store
            .claim(reference.manifest_hash())
            .await
            .map_err(BlobError::from)?;

        for descriptor in body
            .chunks
            .iter()
            .take(usize::from(options.prefetch_chunks.min(16)))
            .cloned()
        {
            let pool = pool.clone();
            let store = self.store.clone();
            tokio::spawn(async move {
                if store
                    .get(descriptor.ciphertext_hash)
                    .await
                    .ok()
                    .flatten()
                    .is_none()
                {
                    let _ = pool.fetch(descriptor.ciphertext_hash).await;
                }
            });
        }
        let fetch_pool = pool.clone();
        let fetcher = Arc::new(move |hash| {
            let pool = fetch_pool.clone();
            let future: Pin<Box<dyn Future<Output = Result<(), BlobError>> + Send + 'static>> =
                Box::pin(async move { pool.fetch(hash).await });
            future
        });
        Ok((
            BlobStream::new(self.store.clone(), self.key.clone(), envelope, body)
                .with_fetcher(fetcher),
            metrics,
        ))
    }

    /// Fetches, verifies, authenticates, and stores a remote encrypted manifest and all chunks.
    pub async fn fetch_from(
        &self,
        local: &IrohBlobStore,
        connection: iroh::endpoint::Connection,
        reference: &BlobRef,
    ) -> Result<(), BlobError> {
        if reference.domain_id() != self.domain_id || reference.epoch() != self.epoch {
            return Err(BlobError::WrongDomainOrEpoch);
        }
        local
            .fetch(connection.clone(), reference.manifest_hash())
            .await
            .map_err(BlobError::from)?;
        let encoded = self
            .store
            .get(reference.manifest_hash())
            .await
            .map_err(BlobError::from)?
            .ok_or(BlobError::MissingBlob(reference.manifest_hash()))?;
        verify_hash(reference.manifest_hash(), &encoded)?;
        let envelope: ManifestEnvelope = decode_canonical(&encoded)?;
        if envelope.version != FORMAT_VERSION
            || envelope.domain_id != self.domain_id
            || envelope.epoch != self.epoch
        {
            return Err(BlobError::WrongDomainOrEpoch);
        }
        let plaintext = decrypt_manifest(&self.key, &envelope)?;
        let body: ManifestBody = decode_canonical(&plaintext)?;
        validate_manifest(&body)?;
        self.store
            .claim(reference.manifest_hash())
            .await
            .map_err(BlobError::from)?;
        for chunk in body.chunks {
            local
                .fetch(connection.clone(), chunk.ciphertext_hash)
                .await
                .map_err(BlobError::from)?;
            self.store
                .claim(chunk.ciphertext_hash)
                .await
                .map_err(BlobError::from)?;
        }
        Ok(())
    }
}

pub(crate) fn decrypt_chunk(
    key: &DomainKey,
    domain_id: DomainId,
    epoch: u64,
    salt: &[u8; 32],
    descriptor: &ChunkDescriptor,
    ciphertext: &[u8],
) -> Result<Vec<u8>, BlobError> {
    verify_hash(descriptor.ciphertext_hash, ciphertext)?;
    let key = chunk_key(key, domain_id, epoch, salt, descriptor.index)?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let aad = chunk_aad(
        domain_id,
        epoch,
        salt,
        descriptor.index,
        descriptor.plaintext_len,
    );
    let plaintext = cipher
        .decrypt(
            &XNonce::from(descriptor.nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| BlobError::AuthenticationFailed)?;
    if plaintext.len() != descriptor.plaintext_len as usize {
        return Err(BlobError::InvalidManifest);
    }
    Ok(plaintext)
}

// Keeping every authenticated field explicit makes key/nonce/AAD review straightforward.
#[allow(clippy::too_many_arguments)]
fn encrypt_chunk(
    key: &DomainKey,
    domain_id: DomainId,
    epoch: u64,
    salt: &[u8; 32],
    index: u32,
    plaintext_len: u32,
    nonce: [u8; 24],
    plaintext: &[u8],
) -> Result<Vec<u8>, BlobError> {
    let key = chunk_key(key, domain_id, epoch, salt, index)?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let aad = chunk_aad(domain_id, epoch, salt, index, plaintext_len);
    cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| BlobError::EncryptionFailed)
}

fn chunk_key(
    key: &DomainKey,
    domain_id: DomainId,
    epoch: u64,
    salt: &[u8; 32],
    index: u32,
) -> Result<zeroize::Zeroizing<[u8; 32]>, BlobError> {
    let mut derivation_salt = Vec::with_capacity(64);
    derivation_salt.extend_from_slice(domain_id.as_bytes());
    derivation_salt.extend_from_slice(salt);
    let mut context = Vec::with_capacity(37);
    context.extend_from_slice(b"iroh-db/blob-chunk/v1");
    context.extend_from_slice(&epoch.to_be_bytes());
    context.extend_from_slice(&index.to_be_bytes());
    key.derive_subkey(&derivation_salt, &context)
        .map_err(|_| BlobError::KeyDerivationFailed)
}

fn chunk_aad(
    domain_id: DomainId,
    epoch: u64,
    salt: &[u8; 32],
    index: u32,
    plaintext_len: u32,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(80);
    aad.extend_from_slice(b"iroh-db/blob-chunk-aad/v1");
    aad.extend_from_slice(domain_id.as_bytes());
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad.extend_from_slice(salt);
    aad.extend_from_slice(&index.to_be_bytes());
    aad.extend_from_slice(&plaintext_len.to_be_bytes());
    aad
}

fn encrypt_manifest(
    key: &DomainKey,
    domain_id: DomainId,
    epoch: u64,
    salt: &[u8; 32],
    nonce: [u8; 24],
    plaintext: &[u8],
) -> Result<Vec<u8>, BlobError> {
    let key = manifest_key(key, domain_id, epoch, salt)?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let aad = manifest_aad(domain_id, epoch, salt, &nonce);
    cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| BlobError::EncryptionFailed)
}

fn decrypt_manifest(key: &DomainKey, envelope: &ManifestEnvelope) -> Result<Vec<u8>, BlobError> {
    let key = manifest_key(key, envelope.domain_id, envelope.epoch, &envelope.salt)?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let aad = manifest_aad(
        envelope.domain_id,
        envelope.epoch,
        &envelope.salt,
        &envelope.nonce,
    );
    cipher
        .decrypt(
            &XNonce::from(envelope.nonce),
            Payload {
                msg: &envelope.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| BlobError::AuthenticationFailed)
}

fn manifest_key(
    key: &DomainKey,
    domain_id: DomainId,
    epoch: u64,
    salt: &[u8; 32],
) -> Result<zeroize::Zeroizing<[u8; 32]>, BlobError> {
    let mut derivation_salt = Vec::with_capacity(64);
    derivation_salt.extend_from_slice(domain_id.as_bytes());
    derivation_salt.extend_from_slice(salt);
    let mut context = Vec::with_capacity(32);
    context.extend_from_slice(b"iroh-db/blob-manifest/v1");
    context.extend_from_slice(&epoch.to_be_bytes());
    key.derive_subkey(&derivation_salt, &context)
        .map_err(|_| BlobError::KeyDerivationFailed)
}

fn manifest_aad(domain_id: DomainId, epoch: u64, salt: &[u8; 32], nonce: &[u8; 24]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(104);
    aad.extend_from_slice(b"iroh-db/blob-manifest-aad/v1");
    aad.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    aad.extend_from_slice(domain_id.as_bytes());
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad.extend_from_slice(salt);
    aad.extend_from_slice(nonce);
    aad
}

pub(crate) fn verify_hash(expected: BlobHash, bytes: &[u8]) -> Result<(), BlobError> {
    let actual = BlobHash::from_bytes(*blake3::hash(bytes).as_bytes());
    if actual != expected {
        return Err(BlobError::HashMismatch);
    }
    Ok(())
}

fn decode_canonical<T>(bytes: &[u8]) -> Result<T, BlobError>
where
    T: minicbor::Encode<()> + for<'value> minicbor::Decode<'value, ()>,
{
    let mut decoder = minicbor::Decoder::new(bytes);
    let value = decoder.decode().map_err(codec_error)?;
    if decoder.position() != bytes.len() {
        return Err(BlobError::InvalidManifest);
    }
    let canonical = minicbor::to_vec(&value).map_err(codec_error)?;
    if canonical != bytes {
        return Err(BlobError::InvalidManifest);
    }
    Ok(value)
}

#[allow(clippy::needless_pass_by_value)]
fn codec_error(error: impl std::fmt::Display) -> BlobError {
    BlobError::Codec(error.to_string())
}

impl From<BlobStoreError> for BlobError {
    fn from(error: BlobStoreError) -> Self {
        Self::Store(error.to_string())
    }
}
