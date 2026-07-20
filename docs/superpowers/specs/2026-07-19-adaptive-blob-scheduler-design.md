# Adaptive Blob Scheduler Design

- Status: Approved by standing user approval
- Date: 2026-07-19

## Outcome

Close the gap between the Milestone 4 vision and the current round-robin blob
fetcher. Remote streams must learn which authenticated providers are currently
useful, bound resource use, favor foreground playback without starving lower
classes, hedge stalled high-priority chunks, and cancel obsolete read-ahead on
seek. iroh-blobs continues to own QUIC transfer and content-hash verification;
iroh-db schedules only immutable manifest objects.

## Scheduling Boundaries

A process-wide scheduler is shared by every `BlobEngine` created by one
`IrohDb`. It enforces a bounded global transfer count and admits queued work
with deterministic weighted round-robin service across high, normal, and low
classes. The weights are 4:2:1. Empty classes are skipped, so capacity is never
left idle, while a continuously queued low class still receives service.

Each remote stream owns provider observations because connection quality and
availability are local and short lived. A provider has a per-stream concurrency
cap, exponentially bounded error backoff, in-flight count, EWMA verified
transfer latency, EWMA verified throughput, and success/failure counters. The
selection score estimates completion time for the requested object, then adds
bounded recent-error and in-flight penalties. Unmeasured providers receive
stable rotating exploration priority so initial traffic is distributed.

## Fetch Lifecycle

Foreground chunk work enters at the application's requested priority. Bounded
sequential read-ahead enters one class lower, ensuring cache warming cannot
overtake an active playback read. A successful iroh-blobs fetch contributes its
verified byte and elapsed-time statistics to provider learning. A failed fetch
penalizes only that local provider and retries another provider. When all
providers are cooling down, the scheduler waits only until the earliest bounded
retry deadline rather than busy-looping or failing prematurely.

High-priority foreground work may start one hedge after the adaptive stall
deadline. The first verified success wins and the loser is cancelled. Hedging
is bounded to one extra attempt, never targets the same provider, observes both
global and per-provider limits, and is counted explicitly. Normal, low, and
read-ahead work do not hedge.

Connections are deduplicated by their authenticated iroh endpoint ID before
provider slots are assigned. Waiting for a provider cap or cooldown never holds
a global transfer permit. If a foreground read joins a coalesced read-ahead
request, the shared request is promoted in the admission queue and gains the
foreground hedge policy.

## Streaming and Cancellation

`BlobStream` retains at most the current decrypted chunk. Encrypted chunks live
in the iroh-blobs store and are claimed for the domain only after a verified
fetch. Read-ahead tasks are owned by the stream. Reading a new chunk maintains a
bounded window after that chunk; seeking aborts the old window before scheduling
the new one (including a seek within the currently cached chunk), and dropping
the stream aborts all outstanding read-ahead.
Concurrent foreground/read-ahead requests for one hash are coalesced inside the
provider pool so only one remote transfer owns the object.

## Metrics and Privacy

Per-stream metrics expose attempts, successful objects, verified transfer
bytes, cache hits, retries, hedges, and provider snapshots containing only a
stable numeric slot, counters, EWMA latency/throughput, backoff state, and
in-flight count. Endpoint IDs, blob hashes, domain IDs, and application values
are never metric labels.

## Failure Semantics

- Hash verification remains inside iroh-blobs and AEAD verification remains
  before plaintext release.
- Every provider failure or timeout remains retryable until all distinct
  providers fail the object attempt.
- Cancellation releases global and provider capacity through RAII guards.
- Poisoned scheduler state fails closed as an explicit blob scheduling error;
  it never bypasses limits.
- Provider learning is ephemeral and never becomes authorization or global
  reputation.

## Qualification

Deterministic unit tests prove weighted fairness, no starvation, adaptive
ranking, backoff, bounded provider concurrency, hedge selection, and cancelled
waiter cleanup. Stream tests prove moving read-ahead and seek/drop cancellation.
The real-network test proves failover and multi-provider use. A controlled
benchmark runs three fresh-cache trials with shaped providers and paced demand.
Both providers must serve timed playback objects in every trial, and median
sequential throughput must reach at least 90% of the slowest of aggregate
provider capacity, local encrypted-store capacity, or consumer demand after
authenticated connection warm-up.
