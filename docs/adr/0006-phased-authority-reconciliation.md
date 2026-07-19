# ADR 0006: Phased Authority Reconciliation

- Status: Accepted
- Date: 2026-07-19

## Context

The data sync protocol currently authenticates with the active domain key. After
rotation, a non-revoked but lagging member cannot authenticate to obtain the
transition or its next key. Applying control first is also unsafe: a transition
is valid only when the receiver has materialized its exact causal cut.

Control objects are safe to replicate, but epoch keys are disclosure-sensitive.
The QUIC peer identity, capability state, revocation state, and transition key
digest must all agree before a key leaves a device.

## Decision

Sync version 2 performs authority reconciliation before current-epoch tail
reconciliation:

1. Peers exchange domain epoch, sequence, and canonical control head.
2. They authenticate the session with the newest epoch both can prove, binding
   the proof to the QUIC endpoint, domain, epoch, and both fresh nonces.
3. For each missing transition, peers first reconcile commits visible through
   its previous epoch until the receiver has the transition's exact causal cut.
4. The ahead peer sends the canonical signed transition and the next epoch key
   only when the authenticated receiver remains trusted and has `READ` plus
   `FETCH_BLOBS` at the new epoch. Required capability-chain objects accompany
   the transition but grant no authority until locally validated.
5. The receiver durably stages the digest-matching key, atomically installs the
   signed successor capability evidence with the control head, and activates
   the staged key. Invalid evidence changes neither active capability nor head.
6. The process repeats for every missed epoch, then ordinary bidirectional tail
   reconciliation runs at the common active epoch.

An equal-sequence head mismatch is not resolved by receipt order. Each side
observes the other's signed sibling so the existing durable equivocation rule
freezes the domain. A strict ancestor mismatch, missing key, missing cut,
revoked receiver, or invalid capability chain aborts without disclosing later
keys.

The control ALPN advances to `/iroh-db/sync/2`; version 1 peers are incompatible
and fail negotiation rather than interpreting a changed frame shape.

## Consequences

- Multi-epoch catch-up is deterministic and never requires rollback.
- Revoked peers can retain old plaintext but cannot receive future epoch keys.
- Control synchronization reuses authenticated iroh QUIC and iroh-blobs; it
  introduces no replacement transport.
- Sync may stop at a causal boundary when old-epoch offline writes require an
  explicit application rebase.
