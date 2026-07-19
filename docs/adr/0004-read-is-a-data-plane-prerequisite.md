# ADR 0004: Read is a data-plane prerequisite

- Status: Accepted
- Date: 2026-07-19
- Decision owner: iroh-db protocol

## Context

Domain invitations necessarily grant `Read`, but active grants can later be
replaced or revoked. Synchronization originally checked trusted-device status,
and blob transfer checked only `FetchBlobs`. Because a domain invitation carries
the symmetric domain key, an endpoint retaining `FetchBlobs` without `Read`
could otherwise continue downloading and decrypting records, snapshots, and
application blobs.

## Decision

1. `Read` is the base authorization for receiving any domain data.
2. Network blob GETs require both current `Read` and current `FetchBlobs`.
   `FetchBlobs` is an additive transport permission, not an independent content
   disclosure grant.
3. Sync handshakes require `Read` for both authenticated endpoints. The current
   bidirectional protocol does not expose a write-only session mode.
4. Snapshot bootstrap requires receiver `Read` plus `FetchBlobs`; snapshot
   creation and attestation still require the separate `Snapshot` permission.
5. Gossip join, announce, and hint-triggered sync require current `Read` because
   hints disclose commit availability metadata.
6. Permission checks use current durable epoch and active capability state and
   fail closed for stale nodes. Provider-side state is authoritative even when a
   peer has not yet learned that its local capability was replaced.

## Consequences

Already materialized or downloaded plaintext cannot be revoked. These checks
prevent future network disclosure, consistent with forward-only revocation.
Applications needing write-only ingestion require a future separately designed
protocol that does not reveal frontiers or download blobs.

## Verification

Tests replace an invited endpoint's authoritative active grant with
`FetchBlobs`-only and prove that sync and snapshot bootstrap fail without
installing state. Existing read/write sync, snapshot, gossip, and blob streaming
tests remain green.
