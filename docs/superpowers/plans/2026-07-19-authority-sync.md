# Authority Synchronization Implementation Plan

- Status: Complete

## Goal

Make signed control transitions, capability evidence, and epoch-key delivery a
normal part of authenticated peer reconciliation while preserving causal-cut,
revocation, and controller-fork invariants.

## Tasks

### Task 1: Versioned authority wire frames

Advance the sync ALPN and canonical frame version. Add bounded authority-state,
domain-authentication, and control-grant messages with strict shape and golden
codec tests. Domain proofs bind the selected historical epoch.

Status: Complete. `/iroh-db/sync/2` now negotiates authority state, binds domain
proofs to an explicit retained epoch, and strictly bounds capability evidence
and control-grant frames. Existing invitation and same-epoch sync flows remain
compatible with the new sequence.

### Task 2: Deterministic authority export

Expose the accepted control chain in sequence order, exact control lookup, and
commit IDs filtered through an epoch. Export only validated capability chains
needed to verify transition authority.

Status: Complete. The store reconstructs the accepted chain from immutable
predecessors, validates sequence continuity, exposes exact objects, and filters
stored commit references at historical epoch boundaries while preserving active
snapshot coverage.

### Task 3: Shared live domain context

Replace clone-local epoch seeds with one per-domain context shared by database,
collection, blob, and sync handles. Successful network rotation updates all
handles atomically; stale on-disk recovery remains digest-bound.

Status: Complete. Every handle for a domain shares one live seed context.
Local and network rotation activation updates existing database, collection,
blob, and sync handles without weakening durable head/key recovery.

### Task 4: Phased reconciliation

Authenticate at the newest common epoch, reconcile each transition's causal
cut, disclose the next key only to a non-revoked authorized endpoint, apply and
activate it, then reconcile the current tail. Exchange same-slot conflicting
heads as fork evidence.

Status: Complete. Real iroh sessions authenticate at a retained common epoch,
reconcile each historical cut, apply digest-bound grants in order, validate
peer capability evidence without receipt-order replacement, and exchange
same-height signed heads as durable fork evidence before tail sync.

### Task 5: Attack and recovery verification

Prove one- and multi-epoch automatic catch-up, controller transfer, restart,
revoked-peer denial, wrong digest, missing cut, forged capability, sibling
forks, and no key disclosure before authorization. Run the full workspace and
dependency-policy gates and obtain independent read-only review before commit.

Status: Complete. Focused tests cover one- and multi-epoch catch-up with an
intermediate causal cut, revocation denial, controller-transfer mesh sync,
snapshot-tail preservation, shared-handle activation, strict frame bounds,
atomic capability/control and invitation import, disclosure serialization, and
secret-redacted diagnostics. `cargo fmt --all -- --check`, strict workspace
Clippy, and `cargo test --workspace` pass on the final tree. Independent review
found no Critical or Important issues and marked the checkpoint ready to
commit. `cargo deny check` retains the documented dependency baseline: bans and
sources pass, while seven transitive-license entries and the existing
`atomic-polyfill`, `paste`, and `proc-macro-error` maintenance advisories remain
open.
