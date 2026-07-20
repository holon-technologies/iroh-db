# Schema Migration Design

Status: Implemented and qualified, excluding the separately tracked literal
72-hour soak release gate.

## Problem

Milestone 5 promises migrations and a supported-version matrix. The Rust schema
contract promises a new version plus an application-registered deterministic
migration. This design defines the API and durable protocol now implemented by
store format 6 and sync protocol 3.

## Public API

`IrohDb::builder(path)` owns a migration registry. A step registers two record
types and a pure synchronous transform:

```rust
let db = IrohDb::builder(path)
    .migration::<TrackV1, TrackV2>(|old| Ok(TrackV2::from(old)))?
    .open()
    .await?;
```

Opening registers all historical and current record adapters before recovery,
then resumes any staged migration for each locally attached domain. A direct
`run_migrations()` method exposes progress and lets applications choose when a
large migration consumes resources. Only one adjacent step may exist for an
exact source schema ID.

The report contains staged, already-staged, activated, and already-activated
counts plus activation commit IDs. Remote acceptance separately returns the
typed `SchemaRebaseRequired` outcome. Errors identify missing steps,
incompatible descriptors, authority, bounded-resource, and frozen-transition
failures without exposing record data.

## Durable protocol

Two new canonical commit operations are introduced:

- `SchemaStage`: migration ID, from/to schema IDs, source record ID, and one
  canonical target `MaterializedRecord`.
- `SchemaActivate`: migration ID, complete from/to descriptors, and the selected
  staging digest/count. The exact adjacent `from` descriptor identifies its
  predecessor schema; the commit DAG provides the causal predecessor cut.

The migration ID is a domain-separated hash of the domain, exact from/to schema
IDs, and canonical source-state cut. The predecessor is unambiguous because
only adjacent activation chains are accepted. The staging digest hashes the
complete canonical stage objects in source-record-ID order. Commit dependencies
independently bind the stage commit IDs and activation cut, and acceptance
proves every selected stage is in that ancestry.

Stage operations are idempotent by `(migration ID, record ID)`, while the stage
itself commits to the source-state hash. A different target for that key is
coordinator equivocation and freezes activation. Stage records live in a
versioned redb table and are never returned by ordinary reads. The coordinator
serializes one local attempt across all bounded stage commits and activation;
after a crash, an unchanged source cut resumes the same attempt and a changed
cut receives a new ID without mutating or deleting the old evidence.

Activation reconstructs source state at its dependency cut, proves exact
record-ID coverage, verifies the digest, and publishes the target records,
indexes, active descriptor, and activation head in one redb transaction. The
commit log remains the authority for every derived table.

## Concurrency

An accepted activation defines the causal cut for its source schema. Source
operations not in that ancestry are retained but excluded from visible state
and returned as `SchemaRebaseRequired`. Target-schema writes are accepted only
after activation. Staged target operations are not normal writes.

Two activations with the same predecessor must be byte-identical in semantic
content. Different signed candidates freeze the collection. Later versions form
one adjacent activation chain.

## Store format and recovery

The directory format advances from 5 to 6. Migration creates a sibling
`meta-v6.redb`, copies and integrity-checks v5 state, fsyncs it, then atomically
selects it through `FORMAT` while retaining both the original `meta.redb` and a
`meta-v5.redb` preservation copy. Open discards interrupted v6 candidates and
rebuilds them from preserved v5 metadata; it never mutates the only good v5
copy.

V6 adds active-schema, schema-activation, staged-record, fork-evidence, and a
reserved migration-checkpoint table. Resumption currently derives progress
directly from immutable staged commits; the reserved checkpoint cannot
authorize activation. Verification and repair rebuild active state and staging
from immutable history. Backup and restore include version metadata but never
trust derived tables without the signed commits.

## Compatibility

Sync negotiation advertises the supported protocol range and refuses schema
activation below the new minimum. Golden fixtures cover both new operations,
the v5-to-v6 directory migration, and fail-closed handling of unknown future
versions. The compatibility matrix exercises v5 open/migrate, v6 reopen,
sync-version overlap, and non-overlap.

## Acceptance

The checkpoint is complete only when staged multi-batch migration survives
faults at every phase; offline writes converge to the same active v2 state in
both receipt orders and are surfaced for rebase; full replay, snapshot-tail,
repair, backup/restore, and reopen have equal state roots; and the supported
version matrix passes on Rust 1.91 and stable.
