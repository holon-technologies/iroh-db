# ADR 0010: Bounded Causal Maintenance and Frontier Sync

Status: Accepted
Date: 2026-07-20

## Context

The first production soak exposed two history-dependent paths. Applying an
ordinary commit decrypted every retained commit to recover record heads and
causal context, and author-chain validation recursively loaded ancestry.
Synchronization also exchanged every accepted commit ID during every session.
All three costs grew with total history even when a transaction touched a new
record and peers differed by only one commit.

Immutable signed commits remain the source of truth, but replaying that source
for each write is not compatible with a long-lived local-first database.

## Decision

The store maintains rebuildable, domain-scoped derived indexes for inclusive
commit version vectors, current per-record causal heads, and author sequence
slots. A commit publishes its immutable blob first, then atomically publishes
metadata, materialized records, indexes, causal context, and record-head
replacements in one redb transaction. Missing or stale derived indexes are
rebuilt deterministically from accepted encrypted commit history; snapshots
establish an empty record-head tail over their signed causal baseline.

Normal reconciliation reads only the affected records' current causal heads.
Author-chain validation uses indexed version vectors and falls back to history
traversal only while upgrading an older store.

Sync protocol v4 exchanges the bounded causal frontier as dependency-discovery
roots. Receivers fetch missing immutable commits through iroh-blobs and walk
their dependency closure until reaching locally accepted history or a signed
snapshot baseline. Protocol v3 is not negotiated because it interpreted the
same frame as a complete accepted set.

## Consequences

Ordinary write and steady-state sync cost is bounded by affected record heads,
active writers, and the actual missing dependency tail rather than total
history. Reopening a pre-index store may perform one bounded full replay, and a
large genuinely missing tail still requires proportional transfer and apply
work. The derived tables can always be discarded and rebuilt; they never
become an independent authority or weaken commit signature, encryption,
capability, dependency, or snapshot validation.
