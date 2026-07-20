use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead as _, KeyInit as _, Payload},
};
use iroh_db_core::{BlobHash, DomainId};
use iroh_db_security::DomainKey;
use iroh_db_store::{BlobStore, BlobStoreError};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _},
    sync::Notify,
};

use crate::{
    BlobError, BlobRef, BlobStream, IrohBlobStore,
    model::{ChunkDescriptor, ManifestBody, ManifestEnvelope},
    scheduler::{
        BlobPriority, FetchScheduler, PrioritySignal, ProviderBook, ProviderMetrics, TransferPermit,
    },
    stream::validate_manifest,
};

pub(crate) const FORMAT_VERSION: u16 = 1;
pub(crate) const MIN_CHUNK_SIZE: usize = 64 * 1024;
pub(crate) const MAX_CHUNK_SIZE: usize = 8 * 1024 * 1024;
pub(crate) const DEFAULT_CHUNK_SIZE: usize = 4 * 1024 * 1024;

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
    bytes_fetched: AtomicU64,
    retries: AtomicU64,
    hedged_attempts: AtomicU64,
    cache_hits: AtomicU64,
}

/// Live, lock-free counters for one lazy multi-provider stream.
#[derive(Clone)]
pub struct FetchMetrics {
    counters: Arc<FetchCounters>,
    providers: Arc<Mutex<ProviderBook>>,
}

impl Default for FetchMetrics {
    fn default() -> Self {
        Self::new(0)
    }
}

impl FetchMetrics {
    fn new(providers: usize) -> Self {
        Self {
            counters: Arc::new(FetchCounters::default()),
            providers: Arc::new(Mutex::new(ProviderBook::new(providers))),
        }
    }

    pub fn provider_attempts(&self) -> u64 {
        self.counters.provider_attempts.load(Ordering::Relaxed)
    }

    pub fn chunks_fetched(&self) -> u64 {
        self.counters.chunks_fetched.load(Ordering::Relaxed)
    }

    pub fn bytes_fetched(&self) -> u64 {
        self.counters.bytes_fetched.load(Ordering::Relaxed)
    }

    pub fn retries(&self) -> u64 {
        self.counters.retries.load(Ordering::Relaxed)
    }

    pub fn hedged_attempts(&self) -> u64 {
        self.counters.hedged_attempts.load(Ordering::Relaxed)
    }

    pub fn cache_hits(&self) -> u64 {
        self.counters.cache_hits.load(Ordering::Relaxed)
    }

    pub fn providers(&self) -> Vec<ProviderMetrics> {
        self.providers
            .lock()
            .map_or_else(|_| Vec::new(), |book| book.snapshots(Instant::now()))
    }
}

#[derive(Clone)]
struct ProviderPool {
    local: IrohBlobStore,
    claims: Arc<dyn BlobStore>,
    providers: Arc<Vec<iroh::endpoint::Connection>>,
    scheduler: FetchScheduler,
    available: Arc<Notify>,
    in_flight: Arc<Mutex<BTreeMap<BlobHash, Arc<SharedFetch>>>>,
    metrics: FetchMetrics,
}

impl ProviderPool {
    async fn fetch(
        &self,
        hash: BlobHash,
        expected_bytes: u64,
        priority: BlobPriority,
        allow_hedge: bool,
    ) -> Result<(), BlobError> {
        loop {
            if self
                .claims
                .get(hash)
                .await
                .map_err(BlobError::from)?
                .is_some()
            {
                self.metrics
                    .counters
                    .cache_hits
                    .fetch_add(1, Ordering::Relaxed);
                return self.claims.claim(hash).await.map_err(BlobError::from);
            }
            let (shared, leader) = {
                let mut in_flight = self
                    .in_flight
                    .lock()
                    .map_err(|_| BlobError::SchedulerUnavailable)?;
                if let Some(shared) = in_flight.get(&hash) {
                    shared.promote(priority, allow_hedge);
                    (shared.clone(), false)
                } else {
                    let shared = Arc::new(SharedFetch::new(priority, allow_hedge));
                    in_flight.insert(hash, shared.clone());
                    (shared, true)
                }
            };
            if leader {
                let owner = SharedFetchOwner::new(self.clone(), hash, shared.clone());
                let result = async {
                    self.fetch_unclaimed_with_policy(hash, expected_bytes, &shared)
                        .await?;
                    self.claims.claim(hash).await.map_err(BlobError::from)
                }
                .await;
                return owner.complete(result);
            }
            match shared.wait().await {
                Err(BlobError::FetchCancelled) => {}
                result => return result,
            }
        }
    }

    async fn fetch_unclaimed(
        &self,
        hash: BlobHash,
        expected_bytes: u64,
        priority: BlobPriority,
        allow_hedge: bool,
    ) -> Result<(), BlobError> {
        let policy = Arc::new(SharedFetch::new(priority, allow_hedge));
        self.fetch_unclaimed_with_policy(hash, expected_bytes, &policy)
            .await
    }

    async fn fetch_unclaimed_with_policy(
        &self,
        hash: BlobHash,
        expected_bytes: u64,
        policy: &Arc<SharedFetch>,
    ) -> Result<(), BlobError> {
        if self.providers.is_empty() {
            return Err(BlobError::NoProviders);
        }
        let mut excluded = BTreeSet::new();
        let mut last_error = None;
        while excluded.len() < self.providers.len() {
            if !excluded.is_empty() {
                self.metrics
                    .counters
                    .retries
                    .fetch_add(1, Ordering::Relaxed);
            }
            let attempt = self.reserve(&excluded, expected_bytes, policy).await?;
            match self
                .run_attempt(attempt, hash, expected_bytes, policy, &excluded)
                .await?
            {
                AttemptResult::Success => {
                    self.record_success();
                    return Ok(());
                }
                AttemptResult::Failed(failures) => {
                    for (provider, error) in failures {
                        excluded.insert(provider);
                        last_error = Some(error);
                    }
                }
            }
        }
        Err(last_error.unwrap_or(BlobError::NoProviders))
    }

    async fn run_attempt(
        &self,
        attempt: RemoteAttempt,
        hash: BlobHash,
        expected_bytes: u64,
        policy: &Arc<SharedFetch>,
        excluded: &BTreeSet<usize>,
    ) -> Result<AttemptResult, BlobError> {
        let provider = attempt.provider;
        if self.providers.len() - excluded.len() <= 1 {
            return Ok(single_attempt_result(
                provider,
                self.execute(attempt, hash, expected_bytes).await,
            ));
        }
        let mut primary = Box::pin(self.execute(attempt, hash, expected_bytes));
        loop {
            let promoted = policy.promoted.notified();
            if policy.should_hedge() {
                break;
            }
            tokio::select! {
                result = &mut primary => return Ok(single_attempt_result(provider, result)),
                () = promoted => {}
            }
        }
        let delay = self.hedge_delay(provider)?;
        tokio::select! {
            result = &mut primary => return Ok(single_attempt_result(provider, result)),
            () = tokio::time::sleep(delay) => {}
        }

        let mut hedge_excluded = excluded.clone();
        hedge_excluded.insert(provider);
        let mut reservation = Box::pin(self.reserve(&hedge_excluded, expected_bytes, policy));
        let hedge = tokio::select! {
            result = &mut primary => return Ok(single_attempt_result(provider, result)),
            reservation = &mut reservation => reservation?,
        };
        let hedge_provider = hedge.provider;
        self.metrics
            .counters
            .hedged_attempts
            .fetch_add(1, Ordering::Relaxed);
        let mut secondary = Box::pin(self.execute(hedge, hash, expected_bytes));
        let first_failure = tokio::select! {
            result = &mut primary => match result {
                Ok(()) => return Ok(AttemptResult::Success),
                Err(error) => (provider, error),
            },
            result = &mut secondary => match result {
                Ok(()) => return Ok(AttemptResult::Success),
                Err(error) => (hedge_provider, error),
            },
        };
        let second_failure = if first_failure.0 == provider {
            secondary.await.err().map(|error| (hedge_provider, error))
        } else {
            primary.await.err().map(|error| (provider, error))
        };
        Ok(second_failure.map_or(AttemptResult::Success, |failure| {
            AttemptResult::Failed(vec![first_failure, failure])
        }))
    }

    async fn reserve(
        &self,
        excluded: &BTreeSet<usize>,
        expected_bytes: u64,
        policy: &Arc<SharedFetch>,
    ) -> Result<RemoteAttempt, BlobError> {
        loop {
            let notified = self.available.notified();
            let permit = self
                .scheduler
                .acquire_promotable(policy.priority.clone())
                .await?;
            let (provider, delay) = {
                let mut book = self
                    .metrics
                    .providers
                    .lock()
                    .map_err(|_| BlobError::SchedulerUnavailable)?;
                let now = Instant::now();
                (
                    book.select(excluded, expected_bytes, now),
                    book.next_ready(excluded, now),
                )
            };
            if let Some(provider) = provider {
                return Ok(RemoteAttempt {
                    provider,
                    permit: Some(permit),
                    providers: self.metrics.providers.clone(),
                    available: self.available.clone(),
                    finished: false,
                });
            }
            drop(permit);
            if excluded.len() == self.providers.len() {
                return Err(BlobError::NoProviders);
            }
            if let Some(delay) = delay {
                tokio::select! {
                    () = notified => {}
                    () = tokio::time::sleep(delay) => {}
                }
            } else {
                notified.await;
            }
        }
    }

    async fn execute(
        &self,
        mut attempt: RemoteAttempt,
        hash: BlobHash,
        expected_bytes: u64,
    ) -> Result<(), BlobError> {
        self.metrics
            .counters
            .provider_attempts
            .fetch_add(1, Ordering::Relaxed);
        let provider = attempt.provider;
        match self
            .local
            .fetch_with_stats(self.providers[provider].clone(), hash)
            .await
        {
            Ok(stats) => {
                let bytes = stats.bytes.max(expected_bytes).max(1);
                attempt.success(bytes, stats.elapsed)?;
                self.metrics
                    .counters
                    .bytes_fetched
                    .fetch_add(bytes, Ordering::Relaxed);
                Ok(())
            }
            Err(error) => {
                attempt.failure()?;
                Err(BlobError::from(error))
            }
        }
    }

    fn hedge_delay(&self, provider: usize) -> Result<Duration, BlobError> {
        self.metrics
            .providers
            .lock()
            .map_err(|_| BlobError::SchedulerUnavailable)
            .map(|book| book.hedge_delay(provider))
    }

    fn record_success(&self) {
        self.metrics
            .counters
            .chunks_fetched
            .fetch_add(1, Ordering::Relaxed);
    }
}

enum AttemptResult {
    Success,
    Failed(Vec<(usize, BlobError)>),
}

fn single_attempt_result(provider: usize, result: Result<(), BlobError>) -> AttemptResult {
    match result {
        Ok(()) => AttemptResult::Success,
        Err(error) => AttemptResult::Failed(vec![(provider, error)]),
    }
}

struct SharedFetch {
    priority: PrioritySignal,
    allow_hedge: AtomicBool,
    promoted: Notify,
    result: Mutex<Option<Result<(), BlobError>>>,
    completed: Notify,
}

impl SharedFetch {
    fn new(priority: BlobPriority, allow_hedge: bool) -> Self {
        Self {
            priority: PrioritySignal::new(priority),
            allow_hedge: AtomicBool::new(allow_hedge),
            promoted: Notify::new(),
            result: Mutex::new(None),
            completed: Notify::new(),
        }
    }

    fn promote(&self, priority: BlobPriority, allow_hedge: bool) {
        let previous = self.priority.get();
        self.priority.promote(priority);
        let hedge_was_enabled = self.allow_hedge.fetch_or(allow_hedge, Ordering::AcqRel);
        if self.priority.get() != previous || (allow_hedge && !hedge_was_enabled) {
            self.promoted.notify_waiters();
        }
    }

    fn should_hedge(&self) -> bool {
        self.priority.get() == BlobPriority::High && self.allow_hedge.load(Ordering::Acquire)
    }

    async fn wait(&self) -> Result<(), BlobError> {
        loop {
            let notified = self.completed.notified();
            if let Some(result) = self
                .result
                .lock()
                .map_err(|_| BlobError::SchedulerUnavailable)?
                .clone()
            {
                return result;
            }
            notified.await;
        }
    }

    fn complete(&self, result: Result<(), BlobError>) {
        if let Ok(mut slot) = self.result.lock() {
            *slot = Some(result);
        }
        self.completed.notify_waiters();
    }
}

struct SharedFetchOwner {
    pool: ProviderPool,
    hash: BlobHash,
    shared: Arc<SharedFetch>,
    completed: bool,
}

impl SharedFetchOwner {
    fn new(pool: ProviderPool, hash: BlobHash, shared: Arc<SharedFetch>) -> Self {
        Self {
            pool,
            hash,
            shared,
            completed: false,
        }
    }

    fn complete(mut self, result: Result<(), BlobError>) -> Result<(), BlobError> {
        self.shared.complete(result.clone());
        self.remove();
        self.completed = true;
        result
    }

    fn remove(&self) {
        if let Ok(mut in_flight) = self.pool.in_flight.lock() {
            in_flight.remove(&self.hash);
        }
    }
}

impl Drop for SharedFetchOwner {
    fn drop(&mut self) {
        if !self.completed {
            self.shared.complete(Err(BlobError::FetchCancelled));
            self.remove();
        }
    }
}

struct RemoteAttempt {
    provider: usize,
    permit: Option<TransferPermit>,
    providers: Arc<Mutex<ProviderBook>>,
    available: Arc<Notify>,
    finished: bool,
}

impl RemoteAttempt {
    fn success(&mut self, bytes: u64, elapsed: Duration) -> Result<(), BlobError> {
        self.providers
            .lock()
            .map_err(|_| BlobError::SchedulerUnavailable)?
            .finish_success(self.provider, bytes, elapsed);
        self.finish();
        Ok(())
    }

    fn failure(&mut self) -> Result<(), BlobError> {
        self.providers
            .lock()
            .map_err(|_| BlobError::SchedulerUnavailable)?
            .finish_failure(self.provider, Instant::now());
        self.finish();
        Ok(())
    }

    fn finish(&mut self) {
        self.finished = true;
        self.permit.take();
        self.available.notify_waiters();
    }
}

impl Drop for RemoteAttempt {
    fn drop(&mut self) {
        if !self.finished {
            if let Ok(mut providers) = self.providers.lock() {
                providers.cancel(self.provider);
            }
            self.permit.take();
            self.available.notify_waiters();
        }
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
    pub(crate) scheduler: FetchScheduler,
}

impl BlobEngine {
    /// Creates an engine using four-MiB encrypted chunks.
    pub fn new(store: Arc<dyn BlobStore>, domain_id: DomainId, key: DomainKey) -> Self {
        Self {
            store,
            domain_id,
            epoch: 0,
            chunk_size: DEFAULT_CHUNK_SIZE,
            key,
            scheduler: FetchScheduler::default(),
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
            scheduler: FetchScheduler::default(),
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
            scheduler: FetchScheduler::default(),
        })
    }

    /// Shares process-wide transfer admission with other engines.
    #[must_use]
    pub fn with_fetch_scheduler(mut self, scheduler: FetchScheduler) -> Self {
        self.scheduler = scheduler;
        self
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
        mut providers: Vec<iroh::endpoint::Connection>,
        reference: &BlobRef,
        options: FetchOptions,
    ) -> Result<(BlobStream, FetchMetrics), BlobError> {
        if reference.domain_id() != self.domain_id || reference.epoch() != self.epoch {
            return Err(BlobError::WrongDomainOrEpoch);
        }
        let mut endpoint_ids = BTreeSet::new();
        providers.retain(|connection| endpoint_ids.insert(connection.remote_id()));
        let metrics = FetchMetrics::new(providers.len());
        let pool = ProviderPool {
            local,
            claims: self.store.clone(),
            providers: Arc::new(providers),
            scheduler: self.scheduler.clone(),
            available: Arc::new(Notify::new()),
            in_flight: Arc::new(Mutex::new(BTreeMap::new())),
            metrics: metrics.clone(),
        };
        if self
            .store
            .get(reference.manifest_hash())
            .await
            .map_err(BlobError::from)?
            .is_none()
        {
            pool.fetch_unclaimed(
                reference.manifest_hash(),
                0,
                options.priority,
                options.priority == BlobPriority::High,
            )
            .await?;
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

        let fetch_pool = pool.clone();
        let fetcher = Arc::new(move |hash, expected_bytes, priority, allow_hedge| {
            let pool = fetch_pool.clone();
            let future: Pin<Box<dyn Future<Output = Result<(), BlobError>> + Send + 'static>> =
                Box::pin(async move {
                    pool.fetch(hash, expected_bytes, priority, allow_hedge)
                        .await
                });
            future
        });
        Ok((
            BlobStream::new(self.store.clone(), self.key.clone(), envelope, body).with_fetcher(
                fetcher,
                options.priority,
                options.prefetch_chunks,
            ),
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

#[cfg(test)]
mod tests {
    use iroh::{Endpoint, RelayMode, endpoint::presets, protocol::Router};
    use iroh_blobs::provider::events::{EventMask, EventSender, ProviderMessage, RequestMode};

    use super::*;

    #[tokio::test]
    async fn stalled_high_priority_fetch_hedges_to_another_provider() {
        let bytes = vec![42_u8; 1024 * 1024];
        let (slow_dir, slow_store, slow_router, hash) =
            start_provider(&bytes, Some(Duration::from_millis(500))).await;
        let (fast_dir, fast_store, fast_router, fast_hash) = start_provider(&bytes, None).await;
        assert_eq!(hash, fast_hash);
        let client_dir = tempfile::tempdir().unwrap();
        let client_store = IrohBlobStore::load(client_dir.path()).await.unwrap();
        let endpoint = Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let slow = endpoint
            .connect(slow_router.endpoint().addr(), iroh_blobs::ALPN)
            .await
            .unwrap();
        let fast = endpoint
            .connect(fast_router.endpoint().addr(), iroh_blobs::ALPN)
            .await
            .unwrap();
        let metrics = FetchMetrics::new(2);
        let pool = ProviderPool {
            local: client_store.clone(),
            claims: Arc::new(client_store.clone()),
            providers: Arc::new(vec![slow, fast]),
            scheduler: FetchScheduler::default(),
            available: Arc::new(Notify::new()),
            in_flight: Arc::new(Mutex::new(BTreeMap::new())),
            metrics: metrics.clone(),
        };

        tokio::time::timeout(
            Duration::from_secs(2),
            pool.fetch_unclaimed(hash, bytes.len() as u64, BlobPriority::High, true),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(metrics.hedged_attempts(), 1);
        assert_eq!(metrics.chunks_fetched(), 1);
        assert_eq!(metrics.providers()[1].successes(), 1);

        endpoint.close().await;
        slow_router.shutdown().await.unwrap();
        fast_router.shutdown().await.unwrap();
        client_store.shutdown().await.unwrap();
        slow_store.shutdown().await.unwrap();
        fast_store.shutdown().await.unwrap();
        drop((slow_dir, fast_dir));
    }

    async fn start_provider(
        bytes: &[u8],
        delay: Option<Duration>,
    ) -> (tempfile::TempDir, IrohBlobStore, Router, BlobHash) {
        let directory = tempfile::tempdir().unwrap();
        let store = IrohBlobStore::load(directory.path()).await.unwrap();
        let hash = store.put(bytes.to_vec()).await.unwrap();
        let events = delay.map_or(EventSender::DEFAULT, |delay| {
            let mask = EventMask {
                get: RequestMode::Intercept,
                ..EventMask::DEFAULT
            };
            let (events, mut receiver) = EventSender::channel(8, mask);
            tokio::spawn(async move {
                while let Some(message) = receiver.recv().await {
                    if let ProviderMessage::GetRequestReceived(message) = message {
                        tokio::time::sleep(delay).await;
                        let _ignored = message.tx.send(Ok(())).await;
                    }
                }
            });
            events
        });
        let endpoint = Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let router = Router::builder(endpoint)
            .accept(iroh_blobs::ALPN, store.protocol_with_events(events))
            .spawn();
        (directory, store, router, hash)
    }
}
