use std::{sync::Arc, time::Duration};

use iroh::{Endpoint, RelayMode, endpoint::presets, protocol::Router};
use iroh_blobs::provider::events::{EventMask, EventSender, ProviderMessage, RequestMode};
use iroh_db_blobs::{BlobEngine, BlobPriority, BlobRef, FetchOptions, IrohBlobStore};
use iroh_db_core::DomainId;
use iroh_db_security::DomainKey;
use iroh_db_store::BlobStore as _;
use tokio::io::AsyncReadExt as _;

const MEBIBYTE: usize = 1024 * 1024;
const MEBIBYTE_F64: f64 = 1024.0 * 1024.0;
const FIXTURE_SIZE: usize = 64 * MEBIBYTE;
const PROVIDER_DELAY: Duration = Duration::from_millis(50);
const PROVIDER_CAPACITY_MIB_PER_SECOND: f64 = 80.0;
const CONSUMER_DEMAND_MIB_PER_SECOND: f64 = 24.0;
const MEASURED_TRIALS: usize = 3;

fn main() {
    tokio::runtime::Runtime::new().unwrap().block_on(run());
}

async fn run() {
    let owner_dir = tempfile::tempdir().unwrap();
    let replica_dir = tempfile::tempdir().unwrap();
    let owner_store = IrohBlobStore::load(owner_dir.path()).await.unwrap();
    let replica_store = IrohBlobStore::load(replica_dir.path()).await.unwrap();
    let domain_id = DomainId::from_bytes([7; 32]);
    let key = DomainKey::from_bytes([9; 32]);
    let owner_engine = BlobEngine::new(Arc::new(owner_store.clone()), domain_id, key.clone());
    let reference = owner_engine
        .import_bytes(vec![42_u8; FIXTURE_SIZE], None)
        .await
        .unwrap();
    copy_objects(&owner_store, &replica_store).await;

    let mut local = owner_engine.open(&reference).await.unwrap();
    let local_started = std::time::Instant::now();
    tokio::io::copy(&mut local, &mut tokio::io::sink())
        .await
        .unwrap();
    let local_rate = rate(local_started.elapsed().as_secs_f64());

    let owner_router = start_shaped_provider(&owner_store).await;
    let replica_router = start_shaped_provider(&replica_store).await;
    let endpoint = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let mut trial_rates = Vec::with_capacity(MEASURED_TRIALS);
    let mut minimum_playback_providers = usize::MAX;
    for _ in 0..MEASURED_TRIALS {
        let (trial_rate, transferred, playback_providers) = run_trial(
            &endpoint,
            &owner_router,
            &replica_router,
            &reference,
            domain_id,
            key.clone(),
        )
        .await;
        assert_eq!(transferred, u64::try_from(FIXTURE_SIZE).unwrap());
        minimum_playback_providers = minimum_playback_providers.min(playback_providers);
        trial_rates.push(trial_rate);
    }
    trial_rates.sort_by(f64::total_cmp);
    let remote_rate = trial_rates[MEASURED_TRIALS / 2];
    let aggregate_provider_rate = PROVIDER_CAPACITY_MIB_PER_SECOND * 2.0;
    let qualification_floor = aggregate_provider_rate
        .min(local_rate)
        .min(CONSUMER_DEMAND_MIB_PER_SECOND)
        * 0.9;
    println!(
        "iroh-db shaped encrypted multi-source stream: {remote_rate:.1} MiB/s \
         (local {local_rate:.1}, provider capacity {aggregate_provider_rate:.1}, paced demand \
         {CONSUMER_DEMAND_MIB_PER_SECOND:.1}, 90% floor {qualification_floor:.1}, \
         {minimum_playback_providers} minimum playback providers, trials {trial_rates:?})"
    );
    assert_eq!(minimum_playback_providers, 2);
    assert!(remote_rate >= qualification_floor);

    drop((local, owner_engine));
    endpoint.close().await;
    owner_router.shutdown().await.unwrap();
    replica_router.shutdown().await.unwrap();
    replica_store.shutdown().await.unwrap();
    owner_store.shutdown().await.unwrap();
}

async fn run_trial(
    endpoint: &Endpoint,
    owner_router: &Router,
    replica_router: &Router,
    reference: &BlobRef,
    domain_id: DomainId,
    key: DomainKey,
) -> (f64, u64, usize) {
    let consumer_dir = tempfile::tempdir().unwrap();
    let consumer_store = IrohBlobStore::load(consumer_dir.path()).await.unwrap();
    let owner = endpoint
        .connect(owner_router.endpoint().addr(), iroh_blobs::ALPN)
        .await
        .unwrap();
    let replica = endpoint
        .connect(replica_router.endpoint().addr(), iroh_blobs::ALPN)
        .await
        .unwrap();
    let consumer_engine = BlobEngine::new(Arc::new(consumer_store.clone()), domain_id, key);
    let (mut remote, metrics) = consumer_engine
        .open_from_providers(
            consumer_store.clone(),
            vec![owner, replica],
            reference,
            FetchOptions {
                priority: BlobPriority::High,
                prefetch_chunks: 16,
            },
        )
        .await
        .unwrap();
    // Manifest transfer warms the authenticated connection before measurement.
    let successes_before = metrics
        .providers()
        .into_iter()
        .map(|provider| provider.successes())
        .collect::<Vec<_>>();
    let remote_started = std::time::Instant::now();
    let transferred = consume_at_rate(&mut remote).await;
    let remote_rate = rate(remote_started.elapsed().as_secs_f64());
    let playback_providers = metrics
        .providers()
        .iter()
        .zip(successes_before)
        .filter(|(provider, before)| provider.successes() > *before)
        .count();
    drop((remote, consumer_engine));
    consumer_store.shutdown().await.unwrap();
    (remote_rate, transferred, playback_providers)
}

async fn copy_objects(source: &IrohBlobStore, destination: &IrohBlobStore) {
    for hash in source.list().await.unwrap() {
        let bytes = source.get(hash).await.unwrap().unwrap();
        assert_eq!(destination.put(bytes).await.unwrap(), hash);
    }
}

async fn start_shaped_provider(store: &IrohBlobStore) -> Router {
    let mask = EventMask {
        get: RequestMode::Intercept,
        ..EventMask::DEFAULT
    };
    let (events, mut receiver) = EventSender::channel(32, mask);
    tokio::spawn(async move {
        while let Some(message) = receiver.recv().await {
            if let ProviderMessage::GetRequestReceived(message) = message {
                // Serial approval makes each provider a controlled 4 MiB / 50 ms service.
                tokio::time::sleep(PROVIDER_DELAY).await;
                let _ignored = message.tx.send(Ok(())).await;
            }
        }
    });
    let endpoint = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    Router::builder(endpoint)
        .accept(iroh_blobs::ALPN, store.protocol_with_events(events))
        .spawn()
}

async fn consume_at_rate(reader: &mut (impl tokio::io::AsyncRead + Unpin)) -> u64 {
    let started = tokio::time::Instant::now();
    let bytes_per_second = CONSUMER_DEMAND_MIB_PER_SECOND * MEBIBYTE_F64;
    let mut buffer = vec![0_u8; 256 * 1024];
    let mut total = 0_u64;
    loop {
        let count = reader.read(&mut buffer).await.unwrap();
        if count == 0 {
            return total;
        }
        total += u64::try_from(count).unwrap();
        let total_f64 = f64::from(u32::try_from(total).unwrap());
        let target = started + Duration::from_secs_f64(total_f64 / bytes_per_second);
        tokio::time::sleep_until(target).await;
    }
}

fn rate(elapsed: f64) -> f64 {
    f64::from(u32::try_from(FIXTURE_SIZE).unwrap()) / MEBIBYTE_F64 / elapsed
}
