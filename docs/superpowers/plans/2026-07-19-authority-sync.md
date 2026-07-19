# Authority Synchronization Implementation Plan

- Status: In progress

## Goal

Make signed control transitions, capability evidence, and epoch-key delivery a
normal part of authenticated peer reconciliation while preserving causal-cut,
revocation, and controller-fork invariants.

## Tasks

### Task 1: Versioned authority wire frames

Advance the sync ALPN and canonical frame version. Add bounded authority-state,
domain-authentication, and control-grant messages with strict shape and golden
codec tests. Domain proofs bind the selected historical epoch.

Status: Complete. `/iroh-db/sync/2` now negotiates authority state, binds domain
proofs to an explicit retained epoch, and strictly bounds capability evidence
and control-grant frames. Existing invitation and same-epoch sync flows remain
compatible with the new sequence.

### Task 2: Deterministic authority export

Expose the accepted control chain in sequence order, exact control lookup, and
commit IDs filtered through an epoch. Export only validated capability chains
needed to verify transition authority.

### Task 3: Shared live domain context

Replace clone-local epoch seeds with one per-domain context shared by database,
collection, blob, and sync handles. Successful network rotation updates all
handles atomically; stale on-disk recovery remains digest-bound.

### Task 4: Phased reconciliation

Authenticate at the newest common epoch, reconcile each transition's causal
cut, disclose the next key only to a non-revoked authorized endpoint, apply and
activate it, then reconcile the current tail. Exchange same-slot conflicting
heads as fork evidence.

### Task 5: Attack and recovery verification

Prove one- and multi-epoch automatic catch-up, controller transfer, restart,
revoked-peer denial, wrong digest, missing cut, forged capability, sibling
forks, and no key disclosure before authorization. Run the full workspace and
dependency-policy gates and obtain independent read-only review before commit.
