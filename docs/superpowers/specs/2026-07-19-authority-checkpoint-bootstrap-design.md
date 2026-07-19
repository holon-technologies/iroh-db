# Authority Checkpoint Bootstrap Design

- Status: Approved under the user's standing architecture approval
- Date: 2026-07-19

## Outcome

A brand-new endpoint can accept a targeted invitation at the current epoch of
an already-rotated domain, install a current signed snapshot, and synchronize
only the post-snapshot tail. It does not need old epoch keys, old data commits,
or every historical control cut.

## Trust Boundary

Skipping history necessarily introduces a checkpoint trust decision. The
target explicitly trusts the endpoint from which it accepts the targeted,
signed invitation to attest to the accepted authority position. This is the
authority analogue of the existing authorized snapshot boundary: signatures
prove who attested and that bytes were not changed, not Byzantine consensus or
global freshness.

An offline invitation can always be stale if a formerly authorized device was
revoked after producing it. No peer-to-peer protocol without a global clock or
consensus can prove that an offline prefix is the latest state. Online import
must therefore require the invitation issuer to equal the authenticated iroh
endpoint selected by the user. Ordinary synchronization detects a conflicting
equal-sequence head and durably freezes rather than choosing by receipt order,
including when the checkpoint intentionally omitted that head's predecessor.

## Invitation v2 Checkpoint

Invitation format v2 signs all of:

- the immutable domain descriptor;
- the current epoch seed;
- the target's root-to-leaf capability chain;
- the accepted control head, or genesis when sequence is zero;
- the designated controller's capability chain;
- the canonical capability evidence and exact active grant IDs for every
  locally active domain member;
- the greatest accepted revocation sequence for every revoked subject;
- the inviter endpoint and its authorizing capability; and
- the target endpoint and a fresh nonce.

All collections are canonical, sorted, duplicate-free, and bounded. The target
leaf must be anchored to the signed current head, permit `Read` at the current
epoch, and be signed by the inviter. The inviter capability must permit
`Invite`; the controller leaf must match the head's exact controller capability
and permit `Admin`. A non-genesis epoch key must match the key-distribution
digest in the signed control head. Every included capability is checked against
the signed revocation accumulator.

The checkpoint allowlist is the set of immutable capability IDs included in
the authority evidence. It authorizes anchors strictly older than a truncated baseline
only as checkpoint evidence. Genesis retains ordinary sequence-zero validation,
and capabilities at or after a non-genesis baseline must bind to an exact
retained control ID.

## Durable Baseline

Store format 4 persists the canonical standalone signed checkpoint—never the
invitation's plaintext epoch key—as an authority baseline. Atomic import installs:

- descriptor, baseline control head/object/slot, and revocation accumulator;
- checkpoint capability evidence; the signed checkpoint ID set is the
  immutable allowlist and needs no mutable derived table;
- the exact signed active capability set, including existing writers needed to
  authenticate post-snapshot tail commits;
- provider trust entries for every checkpoint-active subject, while active
  capabilities continue to gate every permission; and
- no data commits or materialized application state.

The accepted control-chain iterator begins at the baseline transition and then
follows locally accepted successors. Repair derives baseline revocations and
capability allowances from the persisted signed invitation, then applies later
controls. A missing, malformed, mismatched, or unverifiable baseline fails
closed.

Control lookup is by signed sequence rather than vector offset, so checkpointed
stores can advance normally. Equal-slot fork validation uses the signed
baseline head's attested author when its predecessor was compacted. A
checkpointed node is not required to serve
pre-baseline transitions to an older peer; that peer must obtain a checkpoint
plus current snapshot from an authorized current member or reconcile through a
peer retaining the missing history.

A valid post-baseline control may nominate an exact historical successor chain
that the checkpoint omitted. That exception is scoped to the capability ID
signed into the new control; delegation signatures, subject revocations,
permissions, controller identity, and the current controller's authority still
validate before any evidence or head mutation.

## Snapshot and Tail

Authority import and state import remain separate atomic operations:

1. import invitation v2 and current epoch key;
2. fetch the immutable snapshot through authorized `iroh-blobs`;
3. validate its signature, `Snapshot` capability, epoch, and exact control head;
4. atomically install materialized state and causal coverage; and
5. run ordinary sync for recent commits.

This keeps invitations small and reusable for offline tickets while all large
immutable state continues to use iroh-blobs. If snapshot fetch fails, authority
remains valid but the local materialized state is empty and retryable.

## Failure Semantics

- Checkpoint validation completes before descriptor, capability, control,
  trust, revocation, or key-vault mutation.
- Key storage happens only after the authority transaction commits; failure is
  surfaced and the deterministic authority import is idempotent for retry.
- A checkpoint cannot replace an existing different baseline or active control
  branch.
- Post-baseline controls retain the existing causal-cut, controller,
  equivocation, key-staging, and atomic-application rules.
- Snapshot rejection never rolls authority backward and never mutates current
  materialized state.

## Validation

Regression coverage must prove rotated online and offline invitation import,
checkpoint tamper rejection, revocation-accumulator repair, restart, current
snapshot plus tail convergence, no old-key requirement, post-baseline rotation,
and fail-closed equal-sequence conflicts.
