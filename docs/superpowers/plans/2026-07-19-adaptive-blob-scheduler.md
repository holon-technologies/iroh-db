# Adaptive Blob Scheduler Plan

- Status: Complete
- Design: `docs/superpowers/specs/2026-07-19-adaptive-blob-scheduler-design.md`

## Task 1: Preserve behavioral gaps as RED tests

Add deterministic scheduler tests for weighted admission, provider exploration,
EWMA ranking, bounded backoff, per-provider concurrency, and hedge selection.
Extend stream tests to observe a moving prefetch window and cancellation after
seek. The tests must fail against the round-robin implementation for behavioral
reasons, not missing symbols alone.

## Task 2: Add shared weighted transfer admission

Implement a cloneable scheduler shared by all blob engines belonging to one
database. Use cancellation-safe queued permits and a 4:2:1 high/normal/low
cycle, a global cap, and a per-provider cap. Integrate it without changing the
durable manifest or public `BlobStream` read/seek contract.

## Task 3: Add adaptive provider execution

Record verified iroh-blobs transfer bytes and elapsed time, calculate bounded
EWMA estimates, rotate unknown-provider exploration, penalize errors/in-flight
work, and retry after bounded deterministic backoff. Add one adaptive hedge for
stalled high-priority foreground chunks and expose low-cardinality metrics.

## Task 4: Make prefetch positional and cancellable

Move initial fire-and-forget prefetch into `BlobStream`. Maintain the configured
window after the active chunk, downgrade its priority, coalesce duplicate hash
fetches, abort obsolete work on seek, and abort all work on drop.

## Task 5: Qualify and checkpoint

Add controlled scheduler and real-network benchmark evidence, update the M4
gate to describe actual behavior, run format/Clippy/tests/docs/fuzz/policy and
package gates, obtain independent review, and commit only with no Critical or
Important findings.

## Evidence

- RED: the initial round-robin selector failed provider exploration, measured
  completion-time ranking, and failure-cooldown tests.
- GREEN: eight deterministic scheduler tests cover admission fairness,
  cancellation, coalesced priority promotion, provider exploration/ranking,
  cooldown, concurrency/backoff, and hedge bounds.
- GREEN: a real two-provider iroh test proves that a stalled high-priority
  transfer is hedged and completed by the alternate provider.
- GREEN: integration tests cover provider failover plus a prefetch window that
  moves after seek while reporting cache and provider-quality metrics.
- Benchmark: two consecutive invocations of the shaped 64 MiB encrypted
  multi-source benchmark produced a 24.0 MiB/s median across three fresh-cache
  trials against a 21.6 MiB/s floor (90% of actually paced 24 MiB/s demand),
  with both providers serving timed playback objects after connection warm-up.
- Release gates: format, Clippy with warnings denied, workspace tests, docs,
  fuzz-target checks, `cargo deny`, packaged-crate verification, and workspace
  publish dry-run all passed.
- Independent review found no remaining Critical or Important issues and marked
  the checkpoint ready after reproducing the three-trial benchmark gate.
