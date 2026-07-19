# Durable Snapshot Recovery Plan

- Status: Complete

## Goal and Constraints

Make verification, repair, causal validation, and equivocation quarantine
reconstruct snapshot-bootstrapped domains from one immutable signed baseline
plus retained tail commits. Preserve snapshot wire v2, typed merge semantics,
atomic metadata mutation, bounded inputs, and fail-closed authority checks.

### Task 1: Capture incorrect snapshot recovery behavior

**Resources:** `crates/iroh-db/tests/operations.rs`,
`crates/iroh-db/tests/remote_apply.rs`, snapshot/network fixtures
**Depends on:** current format-4 checkpoint tree
**Interfaces and state:** observable verification report, repaired state root,
materialized records, frontier, author sequences, quarantine result
**Implementation:** add RED integration tests for valid materialized corruption
after snapshot+tail and for post-snapshot equivocation preserving snapshot base
state and causal metadata.
**Failure behavior:** tests must show the current false-positive verification or
tail-only rebuild, not fail from fixture setup.
**Validation:** run each focused test before implementation and retain its
expected failing assertion.

### Task 2: Persist the immutable baseline reference atomically

**Resources:** `iroh-db-store::Store`, snapshot tables/installation, format
policy, `iroh-db::Snapshot`
**Depends on:** Task 1
**Interfaces and state:** canonical bounded `SnapshotBaseline` with domain,
epoch, manifest hash, state root, frontier, and author floors; format 5 table
**Implementation:** validate and store the baseline in the same redb transaction
as records/coverage/frontier/sequences; expose strict lookup and consistency
checks; initialize and clear the table with snapshot metadata.
**Failure behavior:** malformed/cross-domain/missing baseline fails before state
mutation; format 4 is rejected explicitly.
**Validation:** store round-trip, malformed metadata, atomic rejection, restart,
and format tests.

### Task 3: Reconstruct snapshot plus tail deterministically

**Resources:** `snapshot.rs`, `db.rs::{dependency_context,
materialize_commit_ids,rebuild_mutations}`, typed `RecordAdapter`
**Depends on:** Task 2
**Interfaces and state:** one internal reconstruction function returning the
complete canonical `Vec<MaterializedRecord>` and verified baseline metadata
**Implementation:** authenticate historical snapshot authority, decode base
records, use signed baseline author floors for opaque dependencies, materialize
tail heads, and merge/delete them over the base map through typed adapters.
**Failure behavior:** missing blob/key/schema/capability/control evidence aborts
without mutation.
**Validation:** corruption detection/repair and snapshot+tail state-root tests
turn GREEN; full-history rebuild tests remain green.

### Task 4: Reuse reconstruction for quarantine recovery

**Resources:** `IrohDb::quarantine_equivocation`,
`Store::quarantine_equivocation`, frontier/head tables
**Depends on:** Task 3
**Interfaces and state:** quarantine receives complete rebuilt records,
baseline-aware frontier, author floors, and retained tail heads
**Implementation:** seed graph roots/frontier/sequences from the signed
baseline, remove invalid tail descendants, reconstruct surviving state, and
commit evidence plus all derived metadata atomically.
**Failure behavior:** any reconstruction error leaves the prior accepted state
and quarantine tables unchanged.
**Validation:** post-snapshot equivocation regression turns GREEN in both
receipt orders and after restart.

### Task 5: Verify, review, and checkpoint

**Resources:** compatibility/M5 evidence, full workspace and dependency gates
**Depends on:** Tasks 1–4
**Interfaces and state:** documented format 5 and truthful verification claims
**Implementation:** update docs; run format, strict Clippy, full workspace tests,
docs, fuzz build, dependency policy, diff audit, and independent security/code
review; commit only with no Critical or Important finding.
**Failure behavior:** any failed gate or unresolved high-severity review blocks
the checkpoint commit.
**Validation:** record exact commands and results here, then mark complete.

## Completion Evidence

The two focused regressions were observed RED before implementation:

- snapshot-plus-tail verification reported derived state as consistent after
  valid materialized state was corrupted;
- post-snapshot equivocation quarantine rebuilt only the retained tail and
  produced a state-root mismatch instead of preserving the signed baseline.

The completed implementation passed:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo check --manifest-path fuzz/Cargo.toml --all-targets
cargo test --workspace
git diff --check
cargo deny check bans sources
```

This includes the store format/atomicity tests, both equivocation receipt
orders, restart recovery, cross-domain dependency rejection, historical
checkpoint authority, control-rotation locking, workspace documentation tests,
and the fuzz workspace build. The existing extended soak test remains
explicitly ignored.

The full `cargo deny check` still reports the repository's pre-existing
transitive license and unmaintained-advisory baseline. The `bans` and `sources`
policy gates pass, and this checkpoint introduces no new dependency-policy
category.

Independent review identified mutable-frontier, fresh-author,
cross-domain-coverage, truncated-capability-anchor, and control/data race risks.
The final pass additionally found that already-retained baseline commits were
not receiving snapshot coverage, which could make a quarantined baseline
frontier unusable as a dependency. Every finding was fixed and covered by a
regression before the reviewer reported no remaining Critical or Important
issues and marked the checkpoint ready.
