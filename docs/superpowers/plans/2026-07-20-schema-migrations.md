# Causal Schema Migration Plan

- Status: Complete
- Design: `docs/superpowers/specs/2026-07-20-schema-migration-design.md`
- ADR: `docs/adr/0007-causal-schema-migrations.md`

## Goal

Close the missing Milestone 5 migration and supported-version requirements
without making mutable materialized tables authoritative or sacrificing
offline-write convergence.

### Task 1: Capture public and causal migration gaps as RED tests — Complete

**Resources:** facade migration integration tests, store format tests, sync
compatibility tests
**Implementation:** specify builder registration, multi-batch resume, atomic
activation, old-schema rebase, rebuild equality, and v5-to-v6 recovery
**Failure behavior:** the tests initially fail on absent public types/opcodes and
unsupported v5 migration
**Validation:** failures name missing migration behavior rather than test setup

### Task 2: Add canonical migration objects and version negotiation — Complete

**Resources:** `iroh-db-core`, `iroh-db-sync`, golden fixtures
**Depends on:** Task 1
**Implementation:** add bounded stage/activate codecs, migration IDs/digests,
strict unknown-version handling, and supported-range handshake
**Failure behavior:** malformed, oversized, downgraded, or noncanonical objects
fail before state mutation
**Validation:** golden, truncation, trailing-data, and overlap/non-overlap tests

### Task 3: Add v6 shadow directory migration and derived tables — Complete

**Resources:** `iroh-db-store`, format fixtures, fault injection
**Depends on:** Task 2
**Implementation:** copy v5 metadata into a verified v6 candidate; add active,
activation, staging, and checkpoint tables; retain the prior metadata file
**Failure behavior:** every injected interruption reopens v5 or resumes the v6
candidate without partial visibility
**Validation:** phase-by-phase crash matrix and state-root equality

### Task 4: Implement registry, staging, activation, and rebase APIs — Complete

**Resources:** facade builder/database/transaction paths
**Depends on:** Tasks 2–3
**Implementation:** type-erase exact adjacent migration steps, retain historical
adapters, stage bounded commits, validate coverage, activate atomically, and
surface old-schema commits for explicit rebase
**Failure behavior:** missing steps, key changes, unauthorized coordination,
incomplete staging, and forks fail closed
**Validation:** local, reopen, remote, partition, and opposite-order tests

### Task 5: Integrate rebuild, snapshots, repair, backup, and observability — Complete

**Resources:** snapshot and operations modules, CLI/reports/metrics
**Depends on:** Task 4
**Implementation:** replay migration history into the same active state; include
migration verification and progress in operational reports
**Failure behavior:** repair stays shadow-first and backup/restore never trusts
unverified migration tables
**Validation:** full replay/snapshot-tail/repair/restore roots match

### Task 6: Qualify, review, document, and commit — Complete

**Depends on:** Tasks 1–5
**Implementation:** update compatibility and milestone evidence, run the full
MSRV/stable/release/fuzz gates, perform architecture and security review, and
commit cleanly
**Validation:** no unresolved Critical or Important finding and the supported
version matrix is green
