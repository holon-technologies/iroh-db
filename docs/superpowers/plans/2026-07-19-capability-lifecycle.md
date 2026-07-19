# Capability Lifecycle Anchoring Plan

- Status: Complete

## Goal and Success

Enforce exact control-head and chain-wide revocation semantics for every
capability authorization and installation. Revoked delegation subtrees and
alternate historical grants must fail, while a post-revocation certificate can
re-authorize the same endpoint.

## Decisions and Constraints

- Follow the approved capability lifecycle design.
- Use capability wire format v2 with an exact `(sequence, control ID)` anchor;
  reject the pre-release sequence-only v1 format.
- Keep the signed control chain authoritative and the subject-revocation table
  derived and repairable.
- Serialize issuance and authority mutation with the existing control gate.
- Execute test-first and stop this slice at a clean reviewed commit.

### Task 1: Observable lifecycle failures

**Resources:** `crates/iroh-db-store/tests/control_authority.rs`,
`crates/iroh-db-security/tests/authority.rs`
**Depends on:** committed authority synchronization checkpoint `7375a46`
**Interfaces and state:** capability chains, active leaf selection, control
sequence anchors, subject revocation transitions
**Implementation:** Add failing regressions for descendant invalidation,
alternate historical replay, future anchors, and post-revocation reissue.
**Failure behavior:** Each rejected path must prove the active capability and
control head remain unchanged.
**Validation:** Run the focused security and store authority suites and retain
the expected RED evidence before implementation.

Status: Complete. The new tests failed on descendant survival and historical
grant replay before implementation, then passed after lifecycle enforcement.

### Task 2: Signed issuance anchors

**Resources:** `CapabilityCertificate` in
`crates/iroh-db-security/src/authority.rs`; `IrohDb::issue_capability_guarded`
in `crates/iroh-db/src/db.rs`
**Depends on:** Task 1
**Interfaces and state:** Add an explicit exact-head delegation method;
delegation anchors are monotonic from issuer to child. The facade supplies the
current durable control sequence and transition ID under its writer guard.
**Implementation:** Preserve the existing delegation API as an inherited-anchor
convenience and use the explicit anchored path for live issuance.
**Failure behavior:** Backward or inconsistent same-sequence anchors fail in
the security layer; future and wrong-head anchors fail at store validation.
**Validation:** Canonical round-trip and delegation narrowing tests plus focused
facade issuance tests.

Status: Complete. Capability v2 signs the exact accepted control position,
delegation rejects backward or inconsistent anchors, and live issuance records
the durable sequence and transition ID under the authority writer guard.

### Task 3: Chain-wide authorization and subject revocations

**Resources:** `Store::authorize_capability`, capability installation helpers,
control application, table initialization, verification/repair paths in
`crates/iroh-db-store/src/store.rs`
**Depends on:** Task 2
**Interfaces and state:** Add `subject_revocations_v1` keyed by
`domain_id || subject`, storing the greatest accepted control sequence.
**Implementation:** Update it atomically during control application. Validate
the complete root-to-leaf chain against explicit ID revocations, subject
revocation anchors, and the exact accepted control head for authorization and all
network/invitation installation paths.
**Failure behavior:** Missing, future, revoked, cross-domain, or structurally
invalid evidence fails before active selection changes.
**Validation:** Task 1 regressions turn green; opposite receipt orders and
restart retain the same result.

Status: Complete. Authorization and installation validate every chain link and
exact head, control application records subject revocations atomically,
successor chains cannot be revoked by their transition, and corrupted derived
metadata fails closed until reconstructed from control.

### Task 4: Verification, repair, compatibility, and review

**Resources:** verification/repair implementation, `docs/compatibility.md`,
Milestone 3/5 evidence, this plan
**Depends on:** Task 3
**Interfaces and state:** Subject revocations are declared rebuildable derived
metadata and included in live verification.
**Implementation:** Reconstruct/check the table from accepted controls, update
compatibility documentation, run focused network reconciliation, full gates,
dependency policy, and independent security review.
**Failure behavior:** Repair builds the replacement mapping before one metadata
transaction; it never invents authority absent from signed controls.
**Validation:** Format, strict Clippy, full workspace tests, dependency-policy
baseline, diff audit, and reviewer approval with no Critical/Important findings.

Status: Complete. Store format 3 and compatibility policy are updated. Focused
authority and network regressions pass, including deferred authentication for
ahead refreshed grants. Strict Clippy and the full workspace suite pass;
dependency bans/sources pass with the unchanged duplicate-version warning
baseline. Independent security review reports no Critical or Important
findings and marks the checkpoint ready to commit.

## Execution

Use `superpowers:executing-plans`, `superpowers:test-driven-development`, and
`security-review` in the current checkout. The tasks are tightly coupled and do
not require sub-agent implementation.
