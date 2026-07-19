# Capability Lifecycle Anchoring Design

- Status: Approved under the user's standing architecture approval
- Date: 2026-07-19

## Outcome

Revocation applies to an endpoint's entire delegated authority subtree without
making endpoint identities permanently unusable. A capability issued after the
latest accepted revocation may authorize the endpoint again; older certificates
and descendants rooted through revoked authority remain invalid.

## Chosen Model

Every capability records the exact accepted control position at which it was
issued as `(issued_control_sequence, issued_control_head)`. The genesis root is
`(0, None)`; every non-genesis anchor is `(N, Some(control_id_at_N))`.
Delegation may only move this anchor forward, and delegation at the same
sequence must retain the same head ID. A certificate is usable only when:

1. its sequence exists in the accepted control chain and its head ID exactly
   matches the signed transition at that sequence;
2. its anchor is at least the latest revocation sequence for its subject;
3. its immutable capability ID is not explicitly revoked;
4. every certificate from the descriptor root through the leaf satisfies the
   same checks; and
5. the leaf is the subject's selected active capability and grants the requested
   permission at the requested epoch.

The store maintains a derived `subject_revocations_v1` table keyed by domain and
endpoint. Applying a control transition updates that table even when the subject
has no active certificate. The signed control chain remains the source of truth;
the table is rebuildable metadata.

## Why This Model

- Permanent endpoint tombstones would be simple but would make re-invitation and
  device recovery impossible.
- Revoking only the active capability ID leaves alternate historical grants and
  delegated descendants replayable.
- Reissuing every capability at every epoch would couple ordinary rotation to
  the whole membership graph and make offline operation unnecessarily brittle.

Sequence alone is insufficient because an inviter can pre-sign a certificate
claiming a future sequence, hold it until that sequence exists, and replay it
after a revocation in that slot. Binding the signed transition ID makes the
future anchor unknowable until the controller creates the transition. This
requires capability format v2; pre-release v1 certificates are rejected rather
than ambiguously upgraded. Existing v2 sequence-zero roots remain valid until
their subject or an ancestor in their chain is revoked.

## Issuance and Re-Invitation

The facade reads the durable control head while holding the authority writer
guard and signs new delegated certificates with that exact sequence and head
ID. A subject revoked by transition `R` can be invited again only with a new
certificate anchored to `R` or later. A revoked issuer cannot create a usable descendant:
the issuer's own chain link fails before the descendant is considered.

## Failure and Recovery

Capability-chain installation validates every signature, delegation edge,
anchor, subject revocation, and explicit capability revocation before opening a
write transaction. Rejection leaves capability and active-selection tables
unchanged. Control application writes the control head, explicit certificate
revocation, subject revocation sequence, active selection removal, and trust
removal in one transaction.

A control transition is rejected before it is observed when it revokes any
subject in its designated successor capability chain. This prevents an invalid
observation from poisoning a control slot and prevents a committed transition
from immediately stranding its successor controller.

During phased synchronization, a known peer may present an active capability
anchored ahead of the receiver. The receiver authenticates the common epoch
with its already-active capability, reconciles signed controls, then retries
installation and full authorization before current-epoch data exchange. A new,
untrusted peer cannot use this deferred path.

If the derived subject-revocation table is missing or corrupt, verification and
repair reconstruct it from the accepted signed control chain before authority
can be trusted. No receipt order may clear a newer revocation sequence.

## Validation

Regression coverage must prove:

- revoking an issuer disables an already-active descendant;
- replaying a non-active historical certificate after subject revocation fails;
- a freshly anchored certificate can re-authorize that subject;
- pre-signed future-sequence and wrong-head certificates fail closed;
- a transition cannot revoke an ancestor of its successor controller chain;
- a lagging known peer can reconcile an ahead peer's refreshed active grant;
- malformed or revoked chains leave active capability state unchanged; and
- one- and multi-epoch network reconciliation still converge.

## Scope Boundary

This design hardens capability lifecycle semantics. Bootstrapping a brand-new
member directly into an already-rotated domain also requires a current-state
snapshot plus signed authority proof; that is the next independent production
slice and must not weaken these chain rules.
