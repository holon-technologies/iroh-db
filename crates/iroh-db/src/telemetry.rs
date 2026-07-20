use std::{
    sync::atomic::{AtomicU8, AtomicU64, Ordering},
    time::Duration,
};

/// Aggregate latency evidence without high-cardinality labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LatencyMetrics {
    samples: u64,
    failures: u64,
    total: Duration,
    maximum: Duration,
}

impl LatencyMetrics {
    /// Number of completed operations observed.
    pub const fn samples(self) -> u64 {
        self.samples
    }

    /// Number of observed operations that returned an error.
    pub const fn failures(self) -> u64 {
        self.failures
    }

    /// Sum of all observed operation durations.
    pub const fn total(self) -> Duration {
        self.total
    }

    /// Largest observed operation duration.
    pub const fn maximum(self) -> Duration {
        self.maximum
    }
}

#[derive(Debug, Default)]
struct LatencyRecorder {
    samples: AtomicU64,
    failures: AtomicU64,
    total_nanos: AtomicU64,
    maximum_nanos: AtomicU64,
}

impl LatencyRecorder {
    fn observe(&self, elapsed: Duration, failed: bool) {
        let nanos = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        saturating_add(&self.samples, 1);
        if failed {
            saturating_add(&self.failures, 1);
        }
        saturating_add(&self.total_nanos, nanos);
        self.maximum_nanos.fetch_max(nanos, Ordering::Relaxed);
    }

    fn snapshot(&self) -> LatencyMetrics {
        LatencyMetrics {
            samples: self.samples.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
            total: Duration::from_nanos(self.total_nanos.load(Ordering::Relaxed)),
            maximum: Duration::from_nanos(self.maximum_nanos.load(Ordering::Relaxed)),
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct Telemetry {
    local_apply: LatencyRecorder,
    query: LatencyRecorder,
    index_records_scanned: AtomicU64,
    reconciliation_commits_scanned: AtomicU64,
    equivocation_quarantines: AtomicU64,
    schema_rebases: AtomicU64,
    sync_rounds: AtomicU64,
    sync_failures: AtomicU64,
    sync_received: AtomicU64,
    sync_sent: AtomicU64,
    snapshots_created: AtomicU64,
    snapshots_installed: AtomicU64,
    repairs_succeeded: AtomicU64,
    repairs_failed: AtomicU64,
    last_repair_consistency: AtomicU8,
}

impl Telemetry {
    pub(crate) fn observe_local_apply(&self, elapsed: Duration, failed: bool) {
        self.local_apply.observe(elapsed, failed);
    }

    pub(crate) fn observe_query(&self, elapsed: Duration, failed: bool) {
        self.query.observe(elapsed, failed);
    }

    pub(crate) fn add_index_records_scanned(&self, records: usize) {
        saturating_add(
            &self.index_records_scanned,
            u64::try_from(records).unwrap_or(u64::MAX),
        );
    }

    pub(crate) fn add_reconciliation_commits_scanned(&self, commits: usize) {
        saturating_add(
            &self.reconciliation_commits_scanned,
            u64::try_from(commits).unwrap_or(u64::MAX),
        );
    }

    pub(crate) fn record_equivocation_quarantine(&self) {
        saturating_add(&self.equivocation_quarantines, 1);
    }

    pub(crate) fn record_schema_rebase(&self) {
        saturating_add(&self.schema_rebases, 1);
    }

    pub(crate) fn record_sync(&self, received: usize, sent: usize, failed: bool) {
        saturating_add(&self.sync_rounds, 1);
        if failed {
            saturating_add(&self.sync_failures, 1);
        }
        saturating_add(
            &self.sync_received,
            u64::try_from(received).unwrap_or(u64::MAX),
        );
        saturating_add(&self.sync_sent, u64::try_from(sent).unwrap_or(u64::MAX));
    }

    pub(crate) fn record_snapshot_created(&self) {
        saturating_add(&self.snapshots_created, 1);
    }

    pub(crate) fn record_snapshot_installed(&self) {
        saturating_add(&self.snapshots_installed, 1);
    }

    pub(crate) fn record_repair(&self, consistent: Option<bool>) {
        if let Some(consistent) = consistent {
            saturating_add(&self.repairs_succeeded, 1);
            self.last_repair_consistency
                .store(if consistent { 2 } else { 1 }, Ordering::Relaxed);
        } else {
            saturating_add(&self.repairs_failed, 1);
            self.last_repair_consistency.store(0, Ordering::Relaxed);
        }
    }

    pub(crate) fn snapshot(&self) -> RuntimeMetrics {
        RuntimeMetrics {
            local_apply: self.local_apply.snapshot(),
            query: self.query.snapshot(),
            index_records_scanned: self.index_records_scanned.load(Ordering::Relaxed),
            reconciliation_commits_scanned: self
                .reconciliation_commits_scanned
                .load(Ordering::Relaxed),
            equivocation_quarantines: self.equivocation_quarantines.load(Ordering::Relaxed),
            schema_rebases: self.schema_rebases.load(Ordering::Relaxed),
            sync_rounds: self.sync_rounds.load(Ordering::Relaxed),
            sync_failures: self.sync_failures.load(Ordering::Relaxed),
            sync_received: self.sync_received.load(Ordering::Relaxed),
            sync_sent: self.sync_sent.load(Ordering::Relaxed),
            snapshots_created: self.snapshots_created.load(Ordering::Relaxed),
            snapshots_installed: self.snapshots_installed.load(Ordering::Relaxed),
            repairs_succeeded: self.repairs_succeeded.load(Ordering::Relaxed),
            repairs_failed: self.repairs_failed.load(Ordering::Relaxed),
            last_repair_derived_consistent: match self
                .last_repair_consistency
                .load(Ordering::Relaxed)
            {
                1 => Some(false),
                2 => Some(true),
                _ => None,
            },
        }
    }
}

fn saturating_add(counter: &AtomicU64, value: u64) {
    let _previous = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(value))
    });
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RuntimeMetrics {
    pub(crate) local_apply: LatencyMetrics,
    pub(crate) query: LatencyMetrics,
    pub(crate) index_records_scanned: u64,
    pub(crate) reconciliation_commits_scanned: u64,
    pub(crate) equivocation_quarantines: u64,
    pub(crate) schema_rebases: u64,
    pub(crate) sync_rounds: u64,
    pub(crate) sync_failures: u64,
    pub(crate) sync_received: u64,
    pub(crate) sync_sent: u64,
    pub(crate) snapshots_created: u64,
    pub(crate) snapshots_installed: u64,
    pub(crate) repairs_succeeded: u64,
    pub(crate) repairs_failed: u64,
    pub(crate) last_repair_derived_consistent: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_saturate_instead_of_wrapping() {
        let counter = AtomicU64::new(u64::MAX);
        saturating_add(&counter, 1);
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    }
}
