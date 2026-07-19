# ADR 0001: Authoritative causal commit kernel

- Status: Accepted
- Date: 2026-07-19
- Decision owner: iroh-db protocol

## Context

The first implementation serialized caller-constructed CRDT field state inside
`FieldStateMerge` operations. Although the enclosing commit was signed, dots,
version vectors, counter component authors, and list element identities were not
bound to that signature. Local writes also installed prepared materializations
directly while received commits and rebuilds used a separate convergence path.
An authorized Byzantine writer could therefore forge causal identities, and a
valid local transaction could materialize differently after replay.

The durable store also enforced contiguous author sequence numbers without
proving that a new commit causally extended the author's preceding commit.
Equivocating commits could consequently become first-arrival-wins state.

## Decision

1. The signed commit envelope is the sole authority for operation identity.
   Every generated dot is `(header.author, header.author_sequence,
   canonical_operation_index)`.
2. Operation context is derived from the declared dependency DAG. Serialized
   application input may provide values and observed intent, but never trusted
   author identities or causal clocks.
3. A commit with author sequence `n > 0` is accepted only when the accepted
   commit at `n - 1` is in its dependency ancestry. Sequence zero must have no
   preceding author commit.
4. Two distinct commits for the same `(domain, author, sequence)` are
   equivocation evidence. The author branch at that sequence and every commit
   causally descending from it are quarantined; materialized state is rebuilt
   without the quarantined subgraph. Arrival order must not select application
   state.
5. Local commits, remote commits, rebuild, snapshot-tail application, restore,
   and repair all call one validation/materialization kernel before atomically
   publishing commit metadata and derived records.
6. One transaction may mutate a record at most once. This invariant is enforced
   before signing locally and after decryption remotely.

## Initial `put` semantics

`put` remains a whole-record convenience API. Before signing, iroh-db rewrites
the record's replicated field state into canonical commit-owned state while
preserving its visible application values. Causally superseded record heads are
removed by the commit DAG; concurrent record heads are merged with the declared
field CRDT. A later typed mutation API may encode smaller intent operations, but
it must use the same dot allocator and apply kernel.

## Compatibility

This decision intentionally tightens semantic validation without preserving
legacy commit acceptance. The repository is greenfield and has no published
wire-format stability commitment. Existing local test databases must be
recreated. A future released format must introduce an explicit protocol-major
migration instead of weakening these checks.

## Failure behavior

- Missing dependencies and author-chain gaps are rejected before metadata or
  materialized state changes.
- Duplicate identical commits remain idempotent.
- Equivocation stores bounded evidence, quarantines the affected subgraph, and
  atomically replaces derived state before reads resume.
- Invalid causal payloads are rejected without publishing their blob as accepted
  history.
- Operation-index exhaustion rejects the transaction before signing.

## Verification

Adversarial tests cover missing author predecessors, same-sequence
equivocation in opposite receipt orders, forged authors/clocks, duplicate record
mutations, local-versus-replay state-root equality, and multi-peer convergence
after quarantine.
