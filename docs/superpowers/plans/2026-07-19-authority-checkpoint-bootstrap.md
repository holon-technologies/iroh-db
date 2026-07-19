# Authority Checkpoint Bootstrap Plan

- Status: Complete

## Goal

Implement the approved authority-checkpoint design so a new endpoint can join
an already-rotated domain, install a current snapshot, and reconcile its tail
without replaying private historical commits or weakening control validation.

### Task 1: Capture the missing behavior as RED tests

**Resources:** invitation security tests, store control-authority tests,
`crates/iroh-db/tests/{rotation,network_sync,sharing}.rs`

**Implementation:** Add regressions for rotated invitation import, tampered
checkpoint rejection with unchanged state, checkpoint restart/repair,
post-checkpoint rotation, and snapshot-plus-tail convergence.

**Validation:** Focused tests fail on the current v1 invitation because its
sequence-one target capability has no locally accepted control proof.

Status: Complete. The epoch-one import regression failed against invitation v1
with an invalid future anchor, then passed after checkpoint import.

### Task 2: Define and validate invitation v2

**Resources:** `iroh-db-security::Invitation`, canonical codecs, capability and
control types

**Implementation:** Sign the exact control head, controller chain, inviter
capability, and canonical subject-revocation accumulator. Enforce bounds,
sorting, chain relationships, epoch/head consistency, permissions, and
revocation checks. Retain a genesis convenience path and reject v1.

**Validation:** Canonical round-trip/golden, truncation, trailing bytes,
tampering, wrong controller, stale target anchor, unsorted revocations, and
oversize tests.

Status: Complete. Invitation v2 embeds a separately signed canonical checkpoint
with exact head, canonical evidence and active-capability IDs for all active
members, inviter/controller grants, and the subject-revocation accumulator.
Genesis uses the same format with no head.

### Task 3: Persist an atomic authority baseline

**Resources:** store control tables, capability authorization, verification and
repair, format policy

**Implementation:** Add the signed baseline table and immutable capability
evidence, store format 4, atomic checkpoint import, baseline-aware accepted-control and
exact-anchor lookup, and repair derived from the signed invitation plus later
controls. Replace sequence-minus-one indexing with signed sequence lookup.

**Validation:** Rejection leaves all authority tables unchanged; restart
preserves authorization; subject revocations remain fail-closed and repairable;
a valid next controller transition applies from the baseline.

Status: Complete. The signed checkpoint itself is the capability allowlist,
avoiding mutable derived allowlist state. Accepted control traversal starts at
the baseline and signed sequence lookup replaces vector-offset assumptions.

### Task 4: Integrate facade invitation and snapshot bootstrap

**Resources:** `IrohDb::{invite,import_invitation,import_ticket}`, online
invitation exchange, snapshot bootstrap and sync

**Implementation:** Build checkpoints while holding the authority gate, import
them before storing the epoch seed, and expose the existing snapshot reference
as the immutable state handoff. Ensure an invitation importer can authorize the
snapshot signer and fetch only the post-snapshot commit tail.

**Validation:** A never-before-seen device imports at epoch greater than zero,
does not possess old epoch keys, installs the exact current snapshot, receives
one tail commit, rotates again, restarts, and remains convergent.

Status: Complete. New members import current authority before the epoch key,
authorize the snapshot signer and existing writers, install current state,
reconcile owner- and omitted-writer-authored tail commits, restart, and accept
the next control transition. Signed successor controls can nominate exact
historical admin evidence omitted by the checkpoint without bypassing
revocation or permission checks.

### Task 5: Verify, review, and checkpoint

**Resources:** compatibility docs, operations verification/repair, full gates

**Implementation:** Update durable-format policy and threat boundaries; run
format, strict Clippy, full workspace tests, dependency policy, diff audit, and
independent security review. Commit only with no Critical or Important finding.

Status: Complete. Formatting and strict workspace Clippy pass; the complete
workspace test suite passes, including 18 network-sync and 15 control-authority
tests; dependency bans/sources and diff checks pass. Independent security
review found no remaining Critical or Important issues after regressions for
key binding, endpoint binding, durable baseline equivocation, genesis mesh
compatibility, omitted historical anchors, active writer evidence, successor
nomination, and exact active-owner preservation.
