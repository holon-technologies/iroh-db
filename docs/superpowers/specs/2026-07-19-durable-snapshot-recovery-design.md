# Durable Snapshot Recovery Design

- Status: Approved under the user's standing architecture approval
- Date: 2026-07-19

## Outcome

A database that compacted history through a signed snapshot can verify and
repair its derived state as rigorously as a full-history database. Authority
or commit equivocation after bootstrap cannot erase snapshot-derived records,
reset the causal frontier, or advance causal context using later commits.

## Chosen Source of Truth

The immutable encrypted signed snapshot remains the base source of truth.
Store format 5 retains a small canonical baseline record containing its domain,
epoch, manifest hash, state root, signed frontier, and signed per-author
sequence floor. Existing snapshot coverage remains the set of compacted commit
IDs. The database does not duplicate a second mutable copy of baseline records.

Alternatives rejected:

- Treating snapshot-derived tables as already verified cannot detect later
  corruption and makes repair circular.
- Reporting snapshot verification as unavailable leaves the production verify
  and repair promises unfulfilled.
- Persisting duplicate plaintext baseline records creates another mutable
  authority source and doubles sensitive state.

## Installation and Persistence

Snapshot decoding, signature verification, permission checks, state-root
verification, and causal metadata validation complete before mutation. One
redb transaction then installs materialized state, coverage, frontier, author
floors, and the canonical snapshot-baseline reference. Coverage without a
baseline, or a baseline without locally readable authenticated blob content,
fails closed.

The baseline reference contains no plaintext or key. The snapshot manifest and
chunks remain ordinary encrypted domain-owned iroh blobs. Installing a newer
snapshot atomically replaces the prior baseline and its coverage.

## Historical Snapshot Authorization

Reverification does not require the snapshot signer to remain active forever.
It verifies the immutable signature and the exact historical capability chain
at the snapshot's signed authority position. Each capability anchor must match
genesis or a retained accepted control ID, the leaf must name the signer and
permit `Snapshot` at that epoch, and no subject revocation effective at or
before the snapshot position may invalidate a chain link. Later revocation does
not retroactively invalidate an already accepted snapshot.

## Deterministic Reconstruction

Reconstruction performs:

1. load and authenticate the retained encrypted snapshot;
2. compare its signed state root, frontier, and author floors with the durable
   baseline record;
3. decode canonical baseline materialized records;
4. validate and materialize all accepted retained tail commits;
5. merge tail record heads over baseline records through the registered typed
   record adapters; and
6. compare or atomically replace current derived state.

Snapshot frontier commits are opaque graph roots. Tail graph traversal treats
coverage hits as those roots, and missing-dependency causal context uses only
the signed snapshot author floors—not mutable current author sequences that may
include later or concurrent commits.

## Equivocation Recovery

Quarantine rebuild uses the same snapshot-plus-tail reconstruction. Its new
frontier is computed over both baseline frontier roots and surviving tail
commits, preserving any baseline root not causally superseded. Author sequence
floors begin at the signed snapshot values and advance only through surviving
tail commits; author-head IDs continue to name only retained tail blobs.

All quarantine evidence, rebuilt records, frontier, author floors, and heads
commit atomically. A reconstruction failure leaves accepted state unchanged.

## Compatibility and Failure Semantics

- Store format advances from 4 to 5; pre-release formats are rejected rather
  than guessed or mutated in place.
- Snapshot wire format 2 remains unchanged.
- Full-history stores need no baseline and retain ordinary replay behavior.
- Missing/corrupt baseline metadata, blob bytes, epoch keys, signatures,
  capability history, or registered schemas cause verify/repair/quarantine to
  fail without changing derived state.
- Verification reports `derived_consistent = false` for a valid reconstructed
  candidate that differs from current materialization; repair installs that
  candidate atomically and then verifies it.

## Validation

Regression coverage must prove snapshot-derived corruption is detected and
repaired, snapshot-plus-tail reconstruction matches the source state root,
baseline causal floors exclude future tail sequences, post-snapshot
equivocation preserves base records/frontier/floors, missing baseline data fails
closed, restart retains repairability, and full-history rebuild behavior is
unchanged.
