# Domain-Scoped Blob Authorization Plan

- Status: Complete
- Completed: 2026-07-19

## Goal and boundary

Make every network blob read require current domain permission and exact object
ownership while continuing to use iroh-blobs for transport, verified ranges,
and streaming. Success means a peer cannot fetch a blob without `FetchBlobs` or
cross from one authorized domain into another device-local domain by guessing a
hash.

The accepted design is `docs/adr/0003-domain-scoped-blob-provider.md`. This plan
does not replace iroh-blobs, introduce a new ALPN, implement public unauthenticated
distribution, add bandwidth quotas, or add provider discovery. Rust, redb,
iroh, iroh-blobs, and the existing capability model remain unchanged.

### Task 1: Prove the provider bypasses capability and domain boundaries

**Resources:** `crates/iroh-db/tests/network_sync.rs`, public blob fetch API,
multi-domain handles sharing one local iroh-blobs store

**Depends on:** ADR 0003

**Interfaces and state:** Provider authorization is based on authenticated
endpoint, selected domain, current epoch, exact permission, and exact hash.

**Implementation:** Add RED tests showing a trusted member without
`FetchBlobs` can currently fetch and that a provider node serving domain A can
currently return a known domain B blob from the shared store.

**Failure behavior:** Rejected network operations do not install foreign or
unauthorized bytes into the receiver's local store.

**Validation:** Focused real-iroh tests fail for the expected successful-bypass
reason before implementation.

### Task 2: Track domain ownership for immutable blobs

**Resources:** `crates/iroh-db-store/src/{blob,store}.rs`, facade domain-bound
blob-store wrapper, `iroh-db-blobs::BlobEngine`, durable ownership tests

**Depends on:** Task 1

**Interfaces and state:** A rebuildable redb table maps `(DomainId, BlobHash)`
to ownership. Accepted commit metadata is also authoritative ownership. A
domain-bound `BlobStore` claims every imported or remotely cached manifest and
chunk.

**Implementation:** Add RED store ownership isolation tests. Add atomic claim
and lookup APIs, a default `BlobStore::claim` hook, and a facade wrapper that
claims successful puts. Make remote eager and lazy fetch paths call `claim`
after verified transfer.

**Failure behavior:** Failed puts/fetches never claim absent bytes. Duplicate
claims are idempotent. A missing claim denies serving the hash.

**Validation:** Store reopen/isolation tests and encrypted eager/lazy blob tests.

### Task 3: Intercept and authorize iroh-blobs provider requests

**Resources:** `crates/iroh-db-blobs/src/local.rs`,
`crates/iroh-db/src/network.rs`, iroh-blobs provider `EventSender`

**Depends on:** Task 2

**Interfaces and state:** Connection IDs map to authenticated endpoint IDs.
Connection and each GET require current `FetchBlobs`; GET additionally requires
selected-domain ownership and one-blob ranges. GET-many, observe, and push fail
closed.

**Implementation:** Expose provider construction with an event interceptor.
Run a bounded event task per `SyncNode`, clean connection state on close, and
mount the intercepted provider on the existing iroh-blobs ALPN. Add local
early authorization to fetch/bootstrap/stream/sync paths.

**Failure behavior:** Unknown connections, stale nodes, revoked capabilities,
event-channel failure, non-blob ranges, and unowned hashes all reject with a
generic permission result.

**Validation:** Both RED bypass tests turn green; existing bidirectional sync,
snapshot bootstrap, and multi-source streaming remain green.

### Task 4: Verify and checkpoint the blob boundary

**Resources:** security review, workspace tests, rustfmt, Clippy, dependency
policy, ADR and plan

**Depends on:** Tasks 1-3

**Interfaces and state:** iroh-blobs remains the data plane; iroh-db owns only
authorization and ownership semantics.

**Implementation:** Inspect all iroh-blobs connection sites and provider mounts
for bypasses. Refactor only with focused tests green, record evidence, and commit
the completed checkpoint.

**Failure behavior:** Do not claim completion while a raw provider bypass,
cross-domain leak, sync regression, format, lint, or workspace test is red.

**Validation:** `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace`, and `cargo deny check`; record pre-existing policy
failures separately.

## Completion evidence

- The pre-implementation tests demonstrated both bypasses: a trusted endpoint
  without `FetchBlobs` downloaded an application blob, and a domain-B blob was
  served by a node selected for domain A.
- Raw provider, public API, cross-domain isolation, durable ownership,
  bidirectional sync, snapshot bootstrap, and lazy multi-source cache-provider
  tests pass after the implementation.
- Format check, strict workspace Clippy, and the complete workspace test suite
  pass. The existing extended soak remains explicitly ignored.
- `cargo deny check` remains red on the pre-existing license allowlist and the
  existing unmaintained transitive advisories for `atomic-polyfill`, `paste`,
  and `proc-macro-error`. No dependency or lockfile changed in this checkpoint.
