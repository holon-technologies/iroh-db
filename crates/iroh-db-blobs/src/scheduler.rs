use std::{
    collections::{BTreeSet, VecDeque},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    time::{Duration, Instant},
};

use tokio::sync::oneshot;

use crate::BlobError;

const PRIORITY_CYCLE: [usize; 7] = [0, 0, 0, 0, 1, 1, 2];
const DEFAULT_GLOBAL_TRANSFERS: usize = 8;
const DEFAULT_PROVIDER_TRANSFERS: u16 = 4;
const INITIAL_BACKOFF: Duration = Duration::from_millis(50);
const MAX_BACKOFF: Duration = Duration::from_secs(2);

/// Application scheduling class for remote blob reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BlobPriority {
    High,
    #[default]
    Normal,
    Low,
}

impl BlobPriority {
    pub(crate) const fn queue(self) -> usize {
        match self {
            Self::High => 0,
            Self::Normal => 1,
            Self::Low => 2,
        }
    }

    pub(crate) const fn lower(self) -> Self {
        match self {
            Self::High => Self::Normal,
            Self::Normal | Self::Low => Self::Low,
        }
    }

    const fn rank(self) -> u8 {
        match self {
            Self::Low => 0,
            Self::Normal => 1,
            Self::High => 2,
        }
    }

    const fn from_rank(rank: u8) -> Self {
        match rank {
            2 => Self::High,
            1 => Self::Normal,
            _ => Self::Low,
        }
    }
}

/// Shared effective priority for one coalesced immutable-object fetch.
#[derive(Clone)]
pub(crate) struct PrioritySignal {
    rank: Arc<AtomicU8>,
}

impl PrioritySignal {
    pub(crate) fn new(priority: BlobPriority) -> Self {
        Self {
            rank: Arc::new(AtomicU8::new(priority.rank())),
        }
    }

    pub(crate) fn get(&self) -> BlobPriority {
        BlobPriority::from_rank(self.rank.load(Ordering::Acquire))
    }

    pub(crate) fn promote(&self, priority: BlobPriority) {
        self.rank.fetch_max(priority.rank(), Ordering::AcqRel);
    }
}

/// Process-local weighted transfer admission shared by blob engines.
#[derive(Clone)]
pub struct FetchScheduler {
    admission: Arc<Admission>,
}

impl Default for FetchScheduler {
    fn default() -> Self {
        Self::new(DEFAULT_GLOBAL_TRANSFERS).expect("default transfer limit is non-zero")
    }
}

impl FetchScheduler {
    /// Creates a scheduler with a bounded number of simultaneous remote objects.
    pub fn new(max_concurrent: usize) -> Result<Self, BlobError> {
        if max_concurrent == 0 {
            return Err(BlobError::InvalidFetchConcurrency(max_concurrent));
        }
        Ok(Self {
            admission: Arc::new(Admission {
                max_concurrent,
                state: Mutex::new(AdmissionState::default()),
            }),
        })
    }

    #[cfg(test)]
    pub(crate) async fn acquire(
        &self,
        priority: BlobPriority,
    ) -> Result<TransferPermit, BlobError> {
        self.acquire_promotable(PrioritySignal::new(priority)).await
    }

    pub(crate) async fn acquire_promotable(
        &self,
        priority: PrioritySignal,
    ) -> Result<TransferPermit, BlobError> {
        let (sender, receiver) = oneshot::channel();
        {
            let mut state = self
                .admission
                .state
                .lock()
                .map_err(|_| BlobError::SchedulerUnavailable)?;
            state.queues[priority.get().queue()].push_back(AdmissionWaiter { sender, priority });
            self.admission.dispatch(&mut state);
        }
        receiver.await.map_err(|_| BlobError::SchedulerUnavailable)
    }

    #[cfg(test)]
    fn queued(&self) -> [usize; 3] {
        let state = self.admission.state.lock().unwrap();
        std::array::from_fn(|index| state.queues[index].len())
    }
}

struct Admission {
    max_concurrent: usize,
    state: Mutex<AdmissionState>,
}

#[derive(Default)]
struct AdmissionState {
    in_flight: usize,
    cursor: usize,
    queues: [VecDeque<AdmissionWaiter>; 3],
}

struct AdmissionWaiter {
    sender: oneshot::Sender<TransferPermit>,
    priority: PrioritySignal,
}

impl Admission {
    fn dispatch(self: &Arc<Self>, state: &mut AdmissionState) {
        while state.in_flight < self.max_concurrent {
            reclassify_waiters(state);
            let Some(queue) = next_queue(state) else {
                break;
            };
            let Some(waiter) = state.queues[queue].pop_front() else {
                continue;
            };
            let permit = TransferPermit {
                admission: self.clone(),
                active: true,
            };
            match waiter.sender.send(permit) {
                Ok(()) => state.in_flight += 1,
                Err(mut permit) => permit.active = false,
            }
        }
    }

    fn release(self: &Arc<Self>) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.in_flight = state.in_flight.saturating_sub(1);
        self.dispatch(&mut state);
    }
}

fn reclassify_waiters(state: &mut AdmissionState) {
    let mut waiters = Vec::new();
    for queue in &mut state.queues {
        waiters.extend(queue.drain(..));
    }
    for waiter in waiters {
        state.queues[waiter.priority.get().queue()].push_back(waiter);
    }
}

fn next_queue(state: &mut AdmissionState) -> Option<usize> {
    for _ in 0..PRIORITY_CYCLE.len() {
        let queue = PRIORITY_CYCLE[state.cursor];
        state.cursor = (state.cursor + 1) % PRIORITY_CYCLE.len();
        if !state.queues[queue].is_empty() {
            return Some(queue);
        }
    }
    None
}

pub(crate) struct TransferPermit {
    admission: Arc<Admission>,
    active: bool,
}

impl Drop for TransferPermit {
    fn drop(&mut self) {
        if self.active {
            self.active = false;
            self.admission.release();
        }
    }
}

/// Low-cardinality local quality observations for one provider slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderMetrics {
    pub(crate) slot: usize,
    pub(crate) successes: u64,
    pub(crate) failures: u64,
    pub(crate) latency: Duration,
    pub(crate) bytes_per_second: u64,
    pub(crate) in_flight: u16,
    pub(crate) cooling_down: bool,
}

impl ProviderMetrics {
    pub const fn slot(&self) -> usize {
        self.slot
    }

    pub const fn successes(&self) -> u64 {
        self.successes
    }

    pub const fn failures(&self) -> u64 {
        self.failures
    }

    pub const fn latency(&self) -> Duration {
        self.latency
    }

    pub const fn bytes_per_second(&self) -> u64 {
        self.bytes_per_second
    }

    pub const fn in_flight(&self) -> u16 {
        self.in_flight
    }

    pub const fn cooling_down(&self) -> bool {
        self.cooling_down
    }
}

#[derive(Debug, Default)]
struct ProviderState {
    successes: u64,
    failures: u64,
    consecutive_failures: u32,
    latency_micros: Option<u64>,
    bytes_per_second: Option<u64>,
    in_flight: u16,
    retry_at: Option<Instant>,
}

#[derive(Debug)]
pub(crate) struct ProviderBook {
    states: Vec<ProviderState>,
    exploration_cursor: usize,
    per_provider_limit: u16,
}

impl ProviderBook {
    pub(crate) fn new(providers: usize) -> Self {
        Self {
            states: (0..providers).map(|_| ProviderState::default()).collect(),
            exploration_cursor: 0,
            per_provider_limit: DEFAULT_PROVIDER_TRANSFERS,
        }
    }

    pub(crate) fn select(
        &mut self,
        excluded: &BTreeSet<usize>,
        expected_bytes: u64,
        now: Instant,
    ) -> Option<usize> {
        let len = self.states.len();
        for offset in 0..len {
            let index = (self.exploration_cursor + offset) % len;
            let state = &self.states[index];
            if eligible(state, excluded, index, now, self.per_provider_limit)
                && state.successes == 0
                && state.failures == 0
            {
                self.exploration_cursor = (index + 1) % len;
                self.states[index].in_flight += 1;
                return Some(index);
            }
        }

        let selected = self
            .states
            .iter()
            .enumerate()
            .filter(|(index, state)| {
                eligible(state, excluded, *index, now, self.per_provider_limit)
            })
            .min_by_key(|(_, state)| provider_score(state, expected_bytes))
            .map(|(index, _)| index)?;
        self.states[selected].in_flight += 1;
        Some(selected)
    }

    pub(crate) fn next_ready(&self, excluded: &BTreeSet<usize>, now: Instant) -> Option<Duration> {
        self.states
            .iter()
            .enumerate()
            .filter(|(index, state)| {
                !excluded.contains(index) && state.in_flight < self.per_provider_limit
            })
            .filter_map(|(_, state)| state.retry_at)
            .filter_map(|retry_at| retry_at.checked_duration_since(now))
            .min()
    }

    pub(crate) fn finish_success(&mut self, provider: usize, bytes: u64, elapsed: Duration) {
        let state = &mut self.states[provider];
        state.in_flight = state.in_flight.saturating_sub(1);
        state.successes += 1;
        state.consecutive_failures = 0;
        state.retry_at = None;
        let elapsed_micros = u64::try_from(elapsed.as_micros())
            .unwrap_or(u64::MAX)
            .max(1);
        update_ewma(&mut state.latency_micros, elapsed_micros);
        update_ewma(
            &mut state.bytes_per_second,
            bytes.saturating_mul(1_000_000) / elapsed_micros,
        );
    }

    pub(crate) fn finish_failure(&mut self, provider: usize, now: Instant) {
        let state = &mut self.states[provider];
        state.in_flight = state.in_flight.saturating_sub(1);
        state.failures += 1;
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        let shift = state.consecutive_failures.saturating_sub(1).min(6);
        let multiplier = 1_u32 << shift;
        let base = (INITIAL_BACKOFF * multiplier).min(MAX_BACKOFF);
        let provider = u32::try_from(provider).unwrap_or(u32::MAX);
        let jitter_percent = provider
            .wrapping_mul(17)
            .wrapping_add(state.consecutive_failures.wrapping_mul(13))
            % 21;
        let jitter = base * jitter_percent / 100;
        state.retry_at = Some(now + (base + jitter).min(MAX_BACKOFF));
    }

    pub(crate) fn cancel(&mut self, provider: usize) {
        self.states[provider].in_flight = self.states[provider].in_flight.saturating_sub(1);
    }

    pub(crate) fn hedge_delay(&self, provider: usize) -> Duration {
        Duration::from_micros(
            self.states[provider]
                .latency_micros
                .map_or(150_000, |latency| latency.saturating_mul(2))
                .clamp(50_000, 500_000),
        )
    }

    pub(crate) fn snapshots(&self, now: Instant) -> Vec<ProviderMetrics> {
        self.states
            .iter()
            .enumerate()
            .map(|(slot, state)| ProviderMetrics {
                slot,
                successes: state.successes,
                failures: state.failures,
                latency: Duration::from_micros(state.latency_micros.unwrap_or_default()),
                bytes_per_second: state.bytes_per_second.unwrap_or_default(),
                in_flight: state.in_flight,
                cooling_down: state.retry_at.is_some_and(|retry_at| retry_at > now),
            })
            .collect()
    }
}

fn eligible(
    state: &ProviderState,
    excluded: &BTreeSet<usize>,
    index: usize,
    now: Instant,
    per_provider_limit: u16,
) -> bool {
    !excluded.contains(&index)
        && state.in_flight < per_provider_limit
        && state.retry_at.is_none_or(|retry_at| retry_at <= now)
}

fn provider_score(state: &ProviderState, expected_bytes: u64) -> u128 {
    let latency = u128::from(state.latency_micros.unwrap_or(100_000));
    let throughput = u128::from(state.bytes_per_second.unwrap_or(1024 * 1024).max(1));
    latency
        + u128::from(expected_bytes).saturating_mul(1_000_000) / throughput
        + u128::from(state.consecutive_failures) * 250_000
        + u128::from(state.in_flight) * 50_000
}

fn update_ewma(value: &mut Option<u64>, sample: u64) {
    *value = Some(value.map_or(sample, |old| {
        old.saturating_mul(3).saturating_add(sample) / 4
    }));
}

#[cfg(test)]
mod tests {
    use tokio::sync::mpsc;

    use super::*;

    #[test]
    fn unknown_providers_are_explored_before_reuse() {
        let now = Instant::now();
        let mut providers = ProviderBook::new(3);
        let first = providers.select(&BTreeSet::new(), 1024, now).unwrap();
        providers.cancel(first);
        let second = providers.select(&BTreeSet::new(), 1024, now).unwrap();
        providers.cancel(second);
        let third = providers.select(&BTreeSet::new(), 1024, now).unwrap();
        assert_eq!([first, second, third], [0, 1, 2]);
    }

    #[test]
    fn measured_completion_time_beats_round_robin_order() {
        let now = Instant::now();
        let mut providers = ProviderBook::new(2);
        providers.finish_success(0, 1024, Duration::from_millis(200));
        providers.finish_success(1, 1024, Duration::from_millis(20));
        let selected = providers.select(&BTreeSet::new(), 1024, now).unwrap();
        assert_eq!(selected, 1);
    }

    #[test]
    fn failed_provider_cools_down_while_an_alternative_is_ready() {
        let now = Instant::now();
        let mut providers = ProviderBook::new(2);
        providers.finish_failure(0, now);
        let selected = providers.select(&BTreeSet::new(), 1024, now).unwrap();
        assert_eq!(selected, 1);
        assert_eq!(providers.next_ready(&BTreeSet::from([0, 1]), now), None);
    }

    #[test]
    fn provider_concurrency_and_backoff_are_bounded() {
        let now = Instant::now();
        let mut providers = ProviderBook::new(1);
        let reservations = (0..DEFAULT_PROVIDER_TRANSFERS)
            .map(|_| providers.select(&BTreeSet::new(), 1024, now).unwrap())
            .collect::<Vec<_>>();
        assert!(reservations.iter().all(|provider| *provider == 0));
        assert_eq!(providers.select(&BTreeSet::new(), 1024, now), None);
        for provider in reservations.iter().take(reservations.len() - 1) {
            providers.cancel(*provider);
        }
        providers.finish_failure(*reservations.last().unwrap(), now);
        let delay = providers.next_ready(&BTreeSet::new(), now).unwrap();
        assert!(delay >= INITIAL_BACKOFF);
        assert!(delay <= INITIAL_BACKOFF + INITIAL_BACKOFF / 5);
        assert_eq!(providers.select(&BTreeSet::new(), 1024, now), None);
        assert_eq!(
            providers.select(&BTreeSet::new(), 1024, now + delay),
            Some(0)
        );
    }

    #[test]
    fn hedge_delay_tracks_latency_with_strict_bounds() {
        let mut providers = ProviderBook::new(1);
        assert_eq!(providers.hedge_delay(0), Duration::from_millis(150));
        providers.finish_success(0, 1024, Duration::from_millis(10));
        assert_eq!(providers.hedge_delay(0), Duration::from_millis(50));
        providers.finish_success(0, 1024, Duration::from_secs(5));
        assert_eq!(providers.hedge_delay(0), Duration::from_millis(500));
    }

    #[tokio::test]
    async fn admission_uses_four_two_one_weighting_without_starvation() {
        let scheduler = FetchScheduler::new(1).unwrap();
        let blocker = scheduler.acquire(BlobPriority::High).await.unwrap();
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let mut tasks = Vec::new();
        for (priority, count) in [
            (BlobPriority::High, 4),
            (BlobPriority::Normal, 2),
            (BlobPriority::Low, 1),
        ] {
            for _ in 0..count {
                let scheduler = scheduler.clone();
                let sender = sender.clone();
                tasks.push(tokio::spawn(async move {
                    let _permit = scheduler.acquire(priority).await.unwrap();
                    sender.send(priority).unwrap();
                }));
            }
        }
        while scheduler.queued() != [4, 2, 1] {
            tokio::task::yield_now().await;
        }
        drop(blocker);
        let mut order = Vec::new();
        for _ in 0..7 {
            order.push(receiver.recv().await.unwrap());
        }
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(
            order,
            [
                BlobPriority::High,
                BlobPriority::High,
                BlobPriority::High,
                BlobPriority::Normal,
                BlobPriority::Normal,
                BlobPriority::Low,
                BlobPriority::High,
            ]
        );
    }

    #[tokio::test]
    async fn cancelled_waiter_does_not_leak_capacity() {
        let scheduler = FetchScheduler::new(1).unwrap();
        let blocker = scheduler.acquire(BlobPriority::Normal).await.unwrap();
        let waiting_scheduler = scheduler.clone();
        let waiter =
            tokio::spawn(
                async move { waiting_scheduler.acquire(BlobPriority::Low).await.unwrap() },
            );
        while scheduler.queued() != [0, 0, 1] {
            tokio::task::yield_now().await;
        }
        waiter.abort();
        drop(blocker);
        let _permit = tokio::time::timeout(
            Duration::from_secs(1),
            scheduler.acquire(BlobPriority::High),
        )
        .await
        .unwrap()
        .unwrap();
    }

    #[tokio::test]
    async fn coalesced_waiter_can_be_promoted_out_of_the_low_queue() {
        let scheduler = FetchScheduler::new(1).unwrap();
        let blocker = scheduler.acquire(BlobPriority::Low).await.unwrap();
        let promoted = PrioritySignal::new(BlobPriority::Low);
        let promoted_scheduler = scheduler.clone();
        let promoted_signal = promoted.clone();
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let promoted_sender = sender.clone();
        let promoted_task = tokio::spawn(async move {
            let _permit = promoted_scheduler
                .acquire_promotable(promoted_signal)
                .await
                .unwrap();
            promoted_sender.send(BlobPriority::High).unwrap();
        });
        while scheduler.queued() != [0, 0, 1] {
            tokio::task::yield_now().await;
        }
        let normal_scheduler = scheduler.clone();
        let normal_task = tokio::spawn(async move {
            let _permit = normal_scheduler
                .acquire(BlobPriority::Normal)
                .await
                .unwrap();
            sender.send(BlobPriority::Normal).unwrap();
        });
        while scheduler.queued() != [0, 1, 1] {
            tokio::task::yield_now().await;
        }
        promoted.promote(BlobPriority::High);
        drop(blocker);
        assert_eq!(receiver.recv().await, Some(BlobPriority::High));
        assert_eq!(receiver.recv().await, Some(BlobPriority::Normal));
        promoted_task.await.unwrap();
        normal_task.await.unwrap();
    }
}
