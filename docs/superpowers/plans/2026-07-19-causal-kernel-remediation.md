# Causal Kernel Remediation Plan

## Goal and boundary

Make the signed commit envelope authoritative for causality and guarantee that
local execution, remote receipt, and rebuild produce identical materialized
state. Success means adversarial author-chain, equivocation, and forged-causality
tests pass in every receipt order. This plan does not repair snapshot authority,
control-chain conflict resolution, projection re-encryption, blob epoch lookup,
or network scalability; those follow after the data kernel is trustworthy.

The accepted design is `docs/adr/0001-authoritative-causal-kernel.md`. Rust,
canonical CBOR, redb, iroh-blobs, XChaCha20-Poly1305, and Ed25519 remain unchanged.
Because the repository is greenfield, semantic compatibility with previously
generated test commits is a non-goal.

### Task 1: Enforce an unbroken per-author commit chain

**Resources:** `crates/iroh-db-store/src/store.rs`,
`crates/iroh-db-store/tests/durable_commits.rs`, commit metadata tables

**Depends on:** accepted ADR 0001

**Interfaces and state:** Track the accepted commit ID for every
`(domain, author, sequence)`. Sequence `n` must name sequence `n - 1` in its
dependency ancestry. Exact duplicate IDs remain idempotent.

**Implementation:** Add RED tests for a present but unrelated dependency and
same-author sequence reuse. Add durable author-head/sequence-to-commit metadata,
ancestry validation, and typed errors. Include snapshot baseline behavior in the
stored representation instead of bypassing chain checks silently.

**Failure behavior:** Reject gaps and unrelated chains before changing accepted
metadata, frontier, records, or indexes. Blob-first orphan scanning may report an
uploaded rejected blob.

**Validation:** Focused durable-store tests, reopen tests, and existing snapshot
tests.

### Task 2: Quarantine equivocation independently of arrival order

**Resources:** store commit/quarantine/frontier metadata, facade apply kernel,
remote and network reconciliation tests

**Depends on:** Task 1

**Interfaces and state:** Equivocation is two different commit IDs for the same
author sequence. Quarantine begins at that sequence and includes every accepted
descendant. Quarantined blobs remain immutable evidence but are not accepted
history or synchronization frontier.

**Implementation:** Add RED opposite-order tests. Persist bounded equivocation
evidence, compute the invalid descendant closure, recompute accepted author heads
and frontier, and atomically publish rebuilt materialized state through the
facade kernel.

**Failure behavior:** Reads never observe a half-quarantined state. Future
commits depending on quarantined history are rejected with a typed quarantine
error. Repair can retry interrupted materialization from immutable evidence.

**Validation:** Two replicas receiving both branches in opposite orders converge
to the same state root and accepted frontier.

### Task 3: Make causal identities database-owned

**Resources:** `iroh-db-core/src/{causality,crdt,record}.rs`, derive expansion,
commit operations, facade record adapters

**Depends on:** Task 1

**Interfaces and state:** A canonical allocator emits monotonically increasing
operation indexes under the envelope author/sequence. Dependency ancestry
produces the only accepted version vector. Typed `put` input contributes visible
values, not trusted causal identities.

**Implementation:** Add RED forged-dot/context/counter-author tests. Add field
normalization and validation hooks for every built-in CRDT, emit them from
`IrohRecord`, normalize before local signing, and require byte-identical canonical
normalization after remote decryption.

**Failure behavior:** Operation-index exhaustion and malformed or noncanonical
state reject the whole commit. No accepted metadata or derived state changes.

**Validation:** Unit tests for every CRDT, forged remote commits, and generated
record contract tests.

### Task 4: Route local and remote writes through one apply kernel

**Resources:** `crates/iroh-db/src/db.rs`, transaction tests, remote apply tests,
rebuild and snapshot-tail paths

**Depends on:** Tasks 1 and 3

**Interfaces and state:** The kernel accepts an authenticated envelope and open
body, validates header/body/schema/causality/authorization, resolves record
heads, and atomically persists its computed mutations. Local code only prepares
and signs an envelope before invoking the same kernel.

**Implementation:** First add RED tests for duplicate mutations and stale local
record replacement. Reject duplicate targets before signing. Extract one kernel
from remote apply, call it locally, and use its validation/materialization helpers
from rebuild and restore.

**Failure behavior:** A rejected local transaction consumes no durable author
sequence. Subscribers receive changes only after atomic publication.

**Validation:** Local state root equals a fresh full replay after every tested
transaction; focused transaction, remote, rebuild, and snapshot suites pass.

### Task 5: Complete protocol verification

**Resources:** workspace tests, Clippy, rustfmt, dependency policy, compatibility
and milestone documentation

**Depends on:** Tasks 1–4

**Interfaces and state:** Document the tightened semantic protocol boundary and
remaining remediation milestones.

**Implementation:** Refactor only with focused suites green. Update compatibility
and milestone claims to match evidence.

**Failure behavior:** Do not publish or mark the causal remediation complete when
any convergence, rebuild, format, lint, or test gate is red.

**Validation:** `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace`, and `cargo deny check`. Record dependency-policy
failures separately from causal-kernel correctness.
