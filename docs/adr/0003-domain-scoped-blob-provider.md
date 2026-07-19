# ADR 0003: Domain-scoped iroh-blobs provider authorization

- Status: Accepted
- Date: 2026-07-19
- Decision owner: iroh-db protocol

## Context

iroh-blobs provides verified streaming, range transfer, and storage, but it does
not define iroh-db domain authorization. The initial router mounted the shared
filesystem store directly on the standard iroh-blobs ALPN. Any endpoint that
could connect could request any known ciphertext hash from every domain in the
device store. Client-side trusted-device checks did not protect the provider and
did not enforce the explicit `FetchBlobs` capability.

Replacing iroh-blobs transport would duplicate protocol, verification, and
streaming work that belongs upstream. Authorizing an endpoint once per
connection would also be insufficient: revocation can occur while a connection
is open, and a device may store blobs from several independently authorized
domains.

## Decision

1. iroh-db continues to mount the standard iroh-blobs ALPN and delegates all
   byte transfer, range handling, and verification to iroh-blobs.
2. The iroh-blobs provider event interceptor rejects a connection unless its
   authenticated QUIC endpoint currently has `FetchBlobs` in the `SyncNode`'s
   selected domain. Private domains use their existing trusted-device implicit
   capability.
3. Every individual GET revalidates the endpoint against the current durable
   epoch and capability state. Revocation and epoch rotation therefore take
   effect for subsequent requests on already-open connections.
4. Every GET hash must be owned by the selected domain. Ownership includes
   accepted commit blobs and encrypted application/snapshot manifest and chunk
   blobs. Ownership metadata is local, rebuildable bookkeeping; immutable bytes
   remain in the shared iroh-blobs store.
5. Getter-defined multi-hash requests are rejected because authorizing only a
   root hash does not prove ownership of every requested object. Observe and
   push requests are rejected. iroh-db currently uses one exact-hash GET per
   immutable object.
6. Downloaded, authenticated manifests and chunks are claimed for the receiving
   domain so an authorized cache can safely become a later provider.
7. Client APIs also fail early when the local endpoint lacks `FetchBlobs`, but
   provider-side checks are authoritative.

## Privacy and failure behavior

- A caller with a known hash but no current capability receives only a generic
  iroh-blobs permission failure.
- A caller authorized in domain A cannot retrieve a domain B object from a node
  serving domain A, even when both domains share one physical blob store.
- Stale nodes fail closed after local control rotation.
- Missing ownership metadata causes availability loss, never cross-domain data
  disclosure. Repair may rebuild ownership from accepted commit metadata and
  authenticated manifests.
- Ciphertext sizes, timing, and endpoint connectivity remain visible as stated
  in the threat model.

## Compatibility

No custom blob wire protocol or ALPN is introduced. Existing callers still use
iroh-blobs connections, but unauthenticated raw access and multi-hash/observe
requests are intentionally rejected. This is a greenfield authorization
tightening.

## Verification

Tests cover missing `FetchBlobs`, cross-domain hash requests against a shared
store, ordinary commit synchronization, snapshot bootstrap, application blob
streaming, revocation, and cached-provider behavior.
