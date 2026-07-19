# ADR 0002: Authorized snapshot trust chain

- Status: Accepted
- Date: 2026-07-19
- Decision owner: iroh-db protocol

## Context

Snapshots allow a node to accept materialized state without replaying the
covered commit history. Hashes, canonical encoding, encryption, and signatures
prove integrity and provenance, but they do not prove that the state was
computed honestly. Snapshot installation therefore crosses a stronger trust
boundary than ordinary read or write access.

The initial implementation accepted any trusted device signature. It did not
bind the signed snapshot to an epoch, control head, or capability, and it
installed caller-supplied causal baselines without validating their shape. A
trusted writer without snapshot authority could consequently replace a peer's
derived state, and stale authority could survive an epoch transition.

## Decision

1. Capability-controlled domains require the signer to hold the exact active
   capability with `Snapshot` permission both when creating and when installing
   a snapshot.
2. The signed snapshot content includes the domain ID, encryption epoch, current
   control-head ID, signer capability ID, canonical materialized records,
   covered commits, frontier, and per-author sequence baseline.
3. Installation requires the captured epoch and control head to equal local
   durable authority. A snapshot is never implicitly rebased across control or
   key rotation.
4. Default private domains have no replicated descriptor or capability chain.
   They retain the existing implicit all-permissions capability derived from the
   domain ID, but the signer must still be in that domain's trusted-device set.
5. Frontier, coverage, author-sequence, and record ordering are canonical and
   duplicate-free. Every frontier commit is covered. Invalid metadata is
   rejected before a redb write transaction can replace active state.
6. Snapshot installation remains one atomic derived-state transaction. Any
   decoding, integrity, authority, schema, index, or causal-baseline failure
   leaves the old state and indexes intact.

## Trust and compatibility

An authorized snapshot signer can still attest to semantically false but
internally consistent state. This is an explicit trust grant, not Byzantine
consensus. Future M-of-N attestations may narrow that trust without changing the
single-author rule in this format major.

The snapshot format advances to version 2. Version 1 snapshots are rejected.
The repository is greenfield and has no released snapshot compatibility
commitment; preserving the unsafe acceptance behavior is a non-goal.

## Failure behavior

- Missing, inactive, revoked, epoch-invalid, or permission-insufficient
  capabilities return an authorization error.
- A stale epoch or control head returns a snapshot validation error.
- Noncanonical, duplicate, or inconsistent causal metadata returns a snapshot
  validation error.
- Rejection never changes records, indexes, frontier, coverage, or author
  sequence baselines.

## Verification

Tests cover creation without `Snapshot`, installation after authority changes,
malformed frontier and sequence baselines, private-domain compatibility,
snapshot-tail reconciliation, and state preservation after every rejection.
