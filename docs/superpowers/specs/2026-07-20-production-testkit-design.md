# Production Testkit and Soak Qualification Design

- Status: Approved by standing user approval
- Date: 2026-07-20

## Outcome

Replace the placeholder `iroh-db-testkit` crate with a reusable, real-iroh
fault-injection harness. Production qualification must be able to create an
isolated multi-peer domain, apply deterministic link and node failures, restart
durable peers, enforce per-operation deadlines, converge the live topology, and
report evidence without duplicating cluster orchestration in each test.

The extended churn gate will use this harness and accept an exact elapsed
duration. A release operator can therefore request 72 hours directly instead
of guessing a machine-specific round count.

## Scope and Boundaries

`TestCluster` owns temporary database directories, one `IrohDb` handle per
peer, and optional running `SyncNode` instances. It uses the production
endpoint, sync, blob, authorization, and storage paths; it does not emulate or
replace iroh. Tests remain responsible for application schemas and mutations.

The harness is an operational testing API, not a durable or wire protocol.
It may evolve before 1.0 without changing database compatibility.

## Public Interface

- `TestCluster::new(peer_count)` creates one domain, attaches the remaining
  peers, installs mutual device trust, starts every sync node, and rejects
  clusters smaller than two peers.
- `peer`, `root`, and `node_addr` expose bounded indexed access without
  transferring ownership.
- `sync` reconciles a directed edge under a configurable timeout.
- `FaultStep` represents `Sync`, `StopNode`, `StartNode`, and
  `RestartPeer`. `apply_schedule` executes steps in order and returns typed
  counts.
- `restart_peer` shuts down networking, closes the database, reopens the same
  directory and restarts networking. It fails explicitly when application
  handles keep the peer open.
- `converge` reconciles every running directed edge. `convergence` returns
  the shared state root or a typed divergence error.
- `shutdown` stops all nodes and cleanly closes all stores.
- `rotating_partition(round, peers)` returns the deterministic two-edge
  schedule used by churn qualification.

Every index, node state, database error, timeout, and divergence is a typed
`TestkitError`. Timeouts cancel the attempted future and never convert a
partial result into success.

## Churn Qualification

The ordinary test continues to run a small fixed round count. The ignored
production soak accepts:

- `IROH_DB_SOAK_DURATION_SECS` for an exact minimum wall-clock duration;
- `IROH_DB_SOAK_ROUNDS` as a deterministic bounded alternative;
- `IROH_DB_SOAK_RESTART_EVERY` to inject periodic durable peer restarts;
- `IROH_DB_SOAK_RECORD_SLOTS` to bound live records independently of history;
- `IROH_DB_SOAK_METRICS_PATH` to retain Linux resource samples;
- `IROH_DB_SOAK_MAX_RSS_ANON_KIB` to fail before anonymous-memory exhaustion;
- `IROH_DB_SOAK_MIN_ROUND_MILLIS` to bound qualification commit-log growth;
- `IROH_DB_SOAK_OPERATION_TIMEOUT_SECS` for each network/lifecycle action.

Duration takes precedence over rounds. The loop records the actual completed
rounds, elapsed time, sync count, and restart count, then performs a full-mesh
convergence and verifies identical state roots and the exact application record
count. The 72-hour release command uses `259200` seconds, 256 record slots per
peer, a 256 MiB anonymous-RSS budget, and a one-second minimum round duration,
and retains stdout plus TSV metrics.

## Failure and Recovery

- Invalid peer counts or indices fail before mutation.
- Starting a running node, stopping a stopped node, or syncing through a
  stopped endpoint fails explicitly.
- A failed restart leaves that slot stopped rather than inventing an in-memory
  replacement.
- Cluster shutdown attempts every node and database even if an earlier cleanup
  fails, returning the first error only after best-effort cleanup.
- Temporary directories remain owned until shutdown/drop, so durable restart
  paths remain valid throughout a test.

## Validation

Tests must prove cluster creation and sync convergence, stopped-link rejection,
stop/start recovery, durable restart identity/state preservation, deterministic
schedule counts, timeout validation, and clean shutdown. The existing churn
test must be rewritten onto the testkit and exercise a periodic restart in its
normal accelerated lane.

The checkpoint passes focused testkit/churn tests, full workspace
format/Clippy/tests/docs/fuzz/policy/package gates, and independent review with
no Critical or Important findings.
