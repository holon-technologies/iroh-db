# iroh-db Architecture and Protocol Design

Status: Accepted
Date: 2026-07-19
Scope: Milestone 0 design gate and the normative architecture for Milestones 1–5.

## 1. Scope

This document defines the greenfield architecture of `iroh-db`: crate boundaries, public Rust API, immutable commit format, deterministic CRDT semantics, local storage, domain authorization and encryption, synchronization, blob manifests and scheduling, snapshots, operational behavior, and milestone gates.

The user-provided vision is the product authority. Requirements marked **Confirmed** come from that vision. Decisions marked **Proposed** resolve implementation questions in service of the long-term design. There is no legacy implementation or compatibility constraint.

## 2. Goals

- Local reads and writes complete without network access.
- A domain transaction produces exactly one immutable, signed, encrypted commit and applies atomically.
- Any set of valid commits converges to byte-equivalent materialized state independent of receipt order.
- Device, transport, routing, relay, NAT traversal, blob transfer, blob verification, and gossip remain owned by iroh crates.
- Domain membership, capabilities, encrypted epochs, CRDTs, queries, materialization, snapshots, and sharing remain owned by `iroh-db`.
- The primary API is typed, idiomatic Rust and does not expose SQL concepts.
- All indexes and materialized records can be deleted and rebuilt from commit and snapshot blobs.
- A new device can bootstrap from a trusted snapshot plus recent commits.
- Blob reads are verified, seekable, encrypted, stream before full download, and can use multiple providers at manifest-chunk granularity.
- Each milestone is independently tested and accepted before work starts on the next milestone.

## 3. Non-Goals

- SQL, joins, foreign keys, globally ordered transactions, cross-domain atomicity, remote erasure, global uniqueness, Byzantine consensus, server-authoritative coordination, and arbitrary user merge functions.
- Hiding ciphertext sizes, traffic timing, endpoint participation, or already downloaded plaintext from a compromised or revoked member.
- Browser, mobile FFI, or non-Rust APIs before the Rust protocol and crate APIs are stable.
- Reimplementing iroh transports, relays, discovery, gossip dissemination, BLAKE3 verification, or blob transfer.

## 4. System Context

```text
Rust application
  -> iroh-db typed API
    -> transactions / queries / subscriptions / domains / blobs
      -> commit validation + CRDT materializer + indexes + snapshots
        -> redb metadata database
        -> iroh-blobs immutable byte store
        -> iroh Endpoint + Router
           -> iroh-gossip announcement plane
           -> iroh-db sync ALPN control plane
           -> iroh-blobs transfer plane
```

The current upstream architecture exposes `iroh::Endpoint` for authenticated QUIC connections, `iroh::protocol::Router` for ALPN routing, `iroh-gossip` for topic dissemination, and `iroh-blobs` for content-addressed verified storage and seekable transfer. `iroh-docs` is deliberately not used as the database core: it is a latest-entry key/value sync protocol, while `iroh-db` requires atomic multi-record commits, field-level CRDT semantics, encrypted domain control epochs, typed secondary indexes, and snapshot validation. We may reuse implementation ideas, but not couple the durable format to `iroh-docs` semantics.

### 4.1 Alternatives Considered

1. **Build the full network and blob stack in `iroh-db`** — rejected because it duplicates iroh, increases protocol surface, and directly violates the thin-layer goal.
2. **Encode records directly into `iroh-docs` entries** — attractive for an early sync demo, but rejected as the durable foundation because atomic multi-record commits, record-field causal context, private control epochs, typed index rebuilds, and strict domain revocation cuts would become conventions layered over a different authority model. That creates two competing histories and makes validation ambiguous.
3. **Use iroh for transport/gossip/blobs and add one commit-DAG sync protocol** — selected. It introduces only database semantics that upstream does not own, keeps immutable bytes interoperable with iroh-blobs, and allows upstream multi-provider improvements to replace internal scheduling pieces later.

For local metadata, SQLite was considered but rejected because SQL must not shape internal contracts and typed binary CRDT state would still require a custom layer. A custom LSM was rejected as unnecessary storage-engine work. `redb` is selected for embedded ACID transactions, pure Rust deployment, ordered keys, and rebuildable table storage; it is an implementation dependency rather than a protocol contract.

## 5. Workspace and Dependency Direction

The workspace contains these crates:

| Crate | Responsibility | May depend on |
| --- | --- | --- |
| `iroh-db-core` | IDs, wire values, records, commits, CRDT engine, domain rules | foundational serialization/crypto only |
| `iroh-db-store` | redb tables, atomic apply, recovery, migrations | core, iroh-blobs store traits |
| `iroh-db-query` | expressions, index planning, pagination, subscriptions | core, store |
| `iroh-db-security` | signatures, capabilities, epochs, key provider, AEAD | core, iroh identity types |
| `iroh-db-blobs` | encrypted manifests, streams, cache, provider scheduler | core, security, iroh-blobs |
| `iroh-db-sync` | ALPN protocol, gossip announcements, frontier reconciliation | core, store, security, blobs, iroh, iroh-gossip |
| `iroh-db-derive` | `IrohRecord` procedural derive | proc-macro dependencies only |
| `iroh-db` | stable facade and orchestration | all library crates |
| `iroh-db-cli` | inspect, verify, repair, backup, sync diagnostics | facade |
| `iroh-db-testkit` | deterministic identities, virtual peers, fixtures, fault injection | all library crates |

Dependency arrows point inward. Core never depends on storage, networking, async runtimes, or derive. Public users normally depend only on `iroh-db` and `iroh-db-derive`.

## 6. Public Rust API

The intended stable shape is:

```rust
#[derive(IrohRecord)]
#[iroh_db(collection = "tracks", version = 1)]
struct Track {
    #[iroh_db(id, field = 1)]
    id: TrackId,
    #[iroh_db(field = 2, index)]
    title: Lww<String>,
    #[iroh_db(field = 3, index)]
    artist: Lww<String>,
    #[iroh_db(field = 4)]
    tags: OrSet<String>,
    #[iroh_db(field = 5)]
    audio: BlobRef,
}

let db = IrohDb::open("./app.irohdb").await?;
let tracks = db.collection::<Track>(); // default private domain

tracks.put(track).await?;

let rows = tracks
    .query()
    .filter(Track::artist.eq("Massive Attack"))
    .order_by(Track::title.asc())
    .limit(100)
    .fetch()
    .await?;

db.domain(shared_domain)
    .transaction(|tx| async move {
        tx.collection::<Track>().put(first)?;
        tx.collection::<Track>().put(second)?;
        Ok(())
    })
    .await?;
```

`IrohRecord` generates a schema descriptor, stable numeric field IDs, a collection ID, encode/decode and merge adapters, typed query field constants, and index extractors. Explicit numeric field IDs are strongly recommended; an omitted field ID is a deterministic hash of the declared field name and becomes frozen when the schema is first registered. A changed descriptor with the same collection/version fails to open. Schema evolution requires a new version plus a deterministic migration registered by the application.

`put` emits mergeable field fragments, not blind replacement. CRDT wrappers retain the causal metadata necessary to construct safe remove/update operations from stale offline state. A lower-level `update` builder will emit smaller deltas. Reads return owned immutable snapshots. Transactions use optimistic concurrency against the local domain frontier and retry only when explicitly requested.

The default domain is a locally created private multi-writer domain. Cross-domain transactions are rejected at type/API boundaries.

## 7. Identifiers and Canonical Encoding

All persistent IDs are fixed-size values with explicit domain separation:

- `DomainId`: 32 random bytes.
- `CollectionId`: BLAKE3(`"iroh-db/collection/v1" || declared collection name`).
- `RecordId`: application bytes, canonically encoded, maximum 1 KiB.
- `CommitId`, `SnapshotId`, chunk and manifest links: the iroh-blobs BLAKE3 hash of the exact stored blob bytes.
- `CapabilityId`: BLAKE3 of canonical capability certificate bytes.
- `SchemaId`: BLAKE3 of the canonical schema descriptor.
- `Dot`: endpoint ID, author sequence, operation index.

Durable protocol objects use a small custom canonical codec implemented over `minicbor`: integer field keys, definite-length maps/arrays, shortest integer encodings, sorted map keys, no floats in protocol metadata, no duplicate or unknown required fields, and strict decode limits. Numeric tags are append-only. Signatures and hashes cover exact canonical bytes prefixed by a protocol-specific context string. Serde formats and Rust enum ordinals are never protocol contracts.

Every durable object starts with `{ magic, format_major, format_minor, kind }`. Readers reject unsupported majors, ignore explicitly length-delimited optional minor fields, and preserve opaque extension fields when forwarding.

## 8. Commit Model and Format

One committed domain transaction creates one commit blob. The canonical outer object is:

```text
CommitEnvelopeV1 {
  domain_id: DomainId,
  epoch: u64,
  author: EndpointId,
  author_seq: u64,
  dependencies: sorted unique [CommitId],
  capability_id: CapabilityId,
  schema_ids: sorted unique [SchemaId],
  nonce: [u8; 24],
  ciphertext: bytes,
  signature: Ed25519Signature
}
```

The signature covers the domain-separated canonical envelope without `signature`. The ciphertext is XChaCha20-Poly1305 over `CommitBodyV1`; associated data is the canonical public header through `schema_ids`. The body contains a transaction ID, ordered operations, optional encrypted capability-chain material, and extension fields. Operations identify collection, record key, field ID, CRDT opcode, and canonical payload. The operation index participates in its `Dot`.

Rules:

1. Each author sequence starts at zero and increments by exactly one within a domain. Sequence gaps are staged, never guessed.
2. Dependencies are an antichain representing the complete frontier observed by the writer. The previous commit by that author must be a dependency or ancestor.
3. A commit is valid only if its hash, signature, canonical form, AEAD tag, sequence, dependencies, capability, epoch, consistency mode, schema, and operations all validate.
4. Missing dependencies or keys put a commit in bounded quarantine. Invalid commits are retained only in diagnostic metadata and are never announced or applied.
5. Duplicate commit IDs are idempotent.
6. Every valid operation is applied in one redb write transaction. Partial record visibility is impossible.
7. Receipt time and wall-clock time never affect convergence.

Commit dependencies form the source-of-truth DAG. A per-domain version vector and frontier are derived metadata.

## 9. Deterministic CRDT Semantics

All ordering uses unsigned bytewise canonical ordering. Hash-map iteration order, locale, platform clocks, and Rust implementation details never affect output.

### 9.1 Causality

Each applied commit derives a version vector from the componentwise maximum of dependency vectors plus its author sequence. Operations inherit that causal context and have a unique `Dot`. `A` happens after `B` when A's context covers B's dot. Otherwise they are concurrent.

### 9.2 Built-in Types

| Type | State and merge rule |
| --- | --- |
| `Lww<T>` | Causal register. A causally later assignment wins. Concurrent assignments use the lexicographically greatest dot. The name is API shorthand; wall clocks are not used. |
| `OrSet<T>` | Add-wins observed-remove set. Adds carry dots. Remove carries only the observed add context, so concurrent unseen adds survive. Tombstones compact only below an accepted snapshot frontier. |
| `GrowOnlySet<T>` | Canonically encoded values merged by set union. Removal is impossible. |
| `PnCounter` | Per-author grow-only positive and negative components; merge uses componentwise maximum and value is sum(P)-sum(N), checked for overflow. |
| `MultiValue<T>` | Keeps all causally maximal assignments. A later assignment replaces observed values; concurrent assignments remain sorted by dot. `read_one` returns a conflict error when more than one remains. |
| `Immutable<T>` | Write-once multi-value register. Equal concurrent values coalesce; unequal values produce a permanent typed conflict until an explicit schema migration resolves it. |
| `OrderedList<T>` | Replicated growable array. Insert IDs are dots, each insert references an existing predecessor or root, concurrent siblings order by dot, and removes are observed tombstones. Missing predecessors stage the operation. |

Record existence is an add-wins observed-remove map keyed by `(collection, record id)`. Deleting a record removes only observed incarnations; a concurrent creation/update survives. Index entries are derived only from live record incarnations.

Canonical state equality is tested by applying every permutation of generated valid operations in property tests. Fuzzers target codecs, merge laws, malicious causal metadata, overflow, tombstone compaction, and snapshot equivalence. User-defined merge functions are never accepted into replicated schemas.

## 10. Domain Consistency and Control Plane

Each domain has an immutable genesis descriptor and a linear control chain. Data commits form a DAG; membership, key epochs, consistency-mode changes, snapshot-authority changes, and writer transfer are single-successor control commits signed by the designated controller under an active admin/revoke capability. The genesis owner is the first controller and a transition may designate its successor. Competing successors are controller equivocation: replicas retain both immutable objects and freeze the domain fail-closed rather than selecting by arrival order or reorganizing keys and accepted encrypted writes. This gives the security control plane deterministic serialization without globally ordering application data.

- **MultiWriter**: any active capability with `WRITE` may author data commits.
- **SingleWriter**: only the endpoint named by the active control state may author data commits. Transfer is a control commit.
- **AppendOnly**: a writer may create a new record exactly once. Updates, deletes, reused record IDs, and non-immutable record fields are rejected by schema validation.

Consistency mode is fixed at genesis in v1. A future mode change requires a new domain and projection, avoiding ambiguous historical validation.

## 11. Capabilities, Invitations, and Revocation

A capability certificate contains:

```text
CapabilityV1 {
  domain_id,
  subject_endpoint,
  issuer_capability,
  permissions,
  delegation_permissions,
  issued_control_seq,
  valid_from_epoch,
  valid_through_epoch?,
  nonce,
  issuer_endpoint,
  signature
}
```

Permissions are `READ`, `WRITE`, `INVITE`, `REVOKE`, `FETCH_BLOBS`, `SNAPSHOT`, and `ADMIN`. `ADMIN` does not implicitly bypass explicit operation validation. Delegation can only reduce permissions and epoch/time scope. Capability chains terminate at the genesis owner capability, have a bounded depth of eight, and are validated against the control state in the commit's dependency context.

Invitations travel over the same authenticated iroh-db ALPN connection, not gossip. QUIC already authenticates both endpoints and encrypts transit. An invitation carries the certificate chain, current domain descriptor/frontier, and the current epoch key. Exportable offline tickets are encrypted with a random one-time 256-bit bearer secret; possession of the ticket alone is insufficient unless the embedded certificate names the importing endpoint.

Revocation is a control commit that simultaneously advances the domain epoch, defines the accepted old-epoch frontier, issues new capabilities as needed, and distributes a new random 256-bit domain key to remaining members over authenticated sessions. After accepting epoch `N+1`, a node accepts epoch `N` commits only if they are ancestors of the epoch transition's cut frontier. This deterministically excludes post-revocation old-key forks, including legitimate offline writes not included at the cut. Applications surface those local commits as `RebaseRequired`; they are never silently discarded and can be projected into a new authorized transaction where policy permits.

Revocation cannot erase plaintext or keys already obtained by a former member. This limitation is visible in API documentation and CLI output.

## 12. Encryption and Key Handling

- Domain content uses independent random 256-bit epoch keys.
- Commit and snapshot bodies use XChaCha20-Poly1305 with random 192-bit nonces and header associated data.
- Blob chunk keys are derived with HKDF-SHA256 from the epoch key, a random blob salt, chunk index, and `"iroh-db/blob-chunk/v1"`; each chunk also has a random nonce. Keys are never reused across object kinds.
- Endpoint Ed25519 keys sign commits, snapshots, capabilities, and control objects using distinct domain-separation contexts.
- Secret material is zeroized where practical and never included in tracing, errors, debug formatting, backups without explicit key export, or gossip.
- A `KeyProvider` trait isolates key storage. The initial file provider requires owner-only permissions and derives a key-vault encryption key from a dedicated local master key. OS keychain/HSM providers can replace it. A compromised unlocked device is outside the confidentiality boundary.

Cryptographic algorithms and canonical format versions are explicit. Algorithm migration uses a new format major and a control-plane transition; silent negotiation or downgrade is forbidden.

## 13. Local Storage Format

An `*.irohdb` directory contains:

```text
meta.redb          transactional metadata, materialized records, indexes
blobs/             iroh-blobs filesystem store (commits, snapshots, manifests, chunks)
keys/              key-provider data; never inside snapshots
locks/             single-process writer lock
tmp/               recoverable imports and downloads
FORMAT             directory format major/minor and store UUID
```

Major redb tables are versioned and prefixed by domain:

- domain descriptor and control head
- accepted commit metadata, commit DAG edges, author sequences, version vectors, frontier
- quarantined commit reason and retry dependencies
- collection schema registry
- live materialized field state and record-existence state
- primary and secondary indexes
- subscription change sequence and bounded replay log
- snapshot catalog and trusted snapshot authorities
- blob ownership, pins, reachability, cache class, and provider hints
- migration and repair checkpoints

Commit, snapshot, manifest, and chunk bytes exist only in the iroh-blobs store. redb stores hashes and validated metadata. Index keys are `(domain, collection, index id, canonical value, record id)` and support equality, range, order, and stable cursor pagination. Index definitions include collation and null policy; v1 supports bytewise canonical scalar ordering only.

Write order is: construct and validate object -> add blob and make durable -> atomically insert commit metadata/materialization/indexes/frontier in redb -> publish local subscription event -> asynchronously announce. A crash before redb commit leaves an unreachable blob collected later. A crash after redb commit is safe because the blob was durable first. Store opening validates `FORMAT`, replays incomplete migration/repair checkpoints, and verifies all newly referenced blobs exist.

Single-process writes use an exclusive lock. Read handles may be concurrent. No network or async task is held across a redb write transaction.

## 14. Query and Subscription Semantics

V1 supports primary key, equality, inclusive/exclusive ranges, compound ordering, limits, opaque stable cursors, and live subscriptions. There are no joins.

Queries read a single local redb snapshot and therefore observe an atomic local frontier. A cursor encodes schema ID, index ID, last canonical key, last record ID, query-direction bit, and a MAC under a local store key. A changed schema/index invalidates the cursor with a typed error.

Subscriptions emit `Initial`, then ordered local `Change` batches keyed by monotonically increasing local apply sequence. A batch corresponds to one commit and includes inserted/updated/removed record IDs plus the new frontier. Slow consumers receive `Lagged` and must re-query; storage is never blocked. Network origin is metadata only and does not change semantics.

## 15. Blob Format and Streaming

Small values remain in encrypted commit bodies. First-class blobs use an encrypted manifest:

```text
BlobRefV1 { domain_id, epoch, encrypted_manifest_hash }

EncryptedManifestV1 {
  public_header: { domain_id, epoch, nonce, ciphertext_len },
  ciphertext: ManifestBodyV1,
  tag
}

ManifestBodyV1 {
  blob_salt,
  plaintext_len,
  media_type?,
  chunk_size,
  chunks: [{ index, plaintext_len, ciphertext_hash, nonce }],
  plaintext_hash?,
  extensions
}
```

The original proposed default was 1 MiB; measured Milestone 4 work superseded
it with the 4 MiB default recorded in ADR 0009. Chunk size remains configurable
from 64 KiB through 8 MiB before import. Each independently encrypted chunk is one ordinary iroh blob, so iroh-blobs owns transfer and BLAKE3 verification. The manifest is normally small and must authenticate before chunks are requested. Domain projection decrypts and re-encrypts into a new manifest; ciphertext links are never shared across security domains.

`BlobStream` implements asynchronous read and seek. Opening fetches/decrypts the manifest, then requests only chunks intersecting the read range. Read-ahead is adaptive and bounded. Seeking cancels unneeded queued chunks but keeps verified ciphertext in cache. Plaintext is streamed through bounded buffers and is not persisted unless explicitly exported.

Cache tiers are RAM decrypted buffers, encrypted disk cache, and pinned encrypted storage. RAM plaintext is bounded and zeroized on eviction where practical. Disk and pinned layers contain ciphertext only. Garbage collection traces live record refs, commit/snapshot retention, active transfers, batches, and explicit pins.

## 16. Multi-Provider Scheduler

The scheduler operates above iroh-blobs without replacing it. Its unit of scheduling is a manifest chunk. Provider availability comes from authenticated sync responses, bounded gossip hints, successful history, and optional content discovery. Hints are never authorization.

Selection scores providers by verified throughput, latency, recent errors, connection cost, and requested priority. The scheduler supports retry, exponential backoff with jitter, per-peer and global concurrency caps, bounded hedging for stalled high-priority chunks, cancellation, sequential prefetch, and fair weighted bandwidth classes. A chunk is accepted only after iroh-blobs hash verification and AEAD authentication. Bad providers are penalized locally; no global reputation is claimed.

If upstream iroh-blobs adds native multi-provider fan-in, the scheduler delegates to it behind an internal adapter while preserving the public stream API and manifest format.

## 17. Sync and Gossip Protocol

The sole custom ALPN is `/iroh-db/sync/1`. `iroh::protocol::Router` hosts it beside iroh-blobs and iroh-gossip.

Gossip topics are domain-scoped, unguessable IDs derived from an epoch announcement secret. Messages are small signed hints containing protocol version, domain/epoch pseudonym, commit or snapshot hash, approximate frontier digest, provider endpoint, and expiry counter. Gossip never carries operations, blob bytes, capabilities, keys, collection names, record IDs, or plaintext metadata. Messages are deduplicated and size/rate limited; missing gossip only delays sync.

An authenticated sync session uses length-delimited canonical frames with a 1 MiB default and 8 MiB absolute control-frame limit:

1. `Hello`: supported protocol/format versions, endpoint nonce, resource limits.
2. `DomainRequest` / `DomainAccept`: prove current read capability without disclosing unrelated domains.
3. `Frontier`: version vector, frontier IDs, control head, snapshot preference.
4. `Need`: missing author ranges, explicit dependency hashes, or snapshot request.
5. `Refs`: bounded commit/snapshot/manifest hashes and authorized provider claims.
6. `Ack` / `Done` / typed `Error`.

Actual immutable bytes are always fetched through iroh-blobs. On receipt, hashes, signatures, dependencies, epoch/control authorization, and ciphertext are validated before atomic apply. Dependency resolution is breadth-first with hard bounds on depth, total refs, bytes, concurrent fetches, and quarantine. Peers may resume sessions idempotently. A peer learns nothing about domains for which it cannot prove capability possession.

## 18. Sharing by Projection

Sharing copies selected application-visible state into an independent destination-domain transaction. A projection has a stable application-defined ID and optional source cursor for idempotency, but does not create a cryptographic link exposed to destination members. Source commit IDs, private history, deleted values, private capabilities, and source blob ciphertext never enter the destination domain. Referenced blobs are re-encrypted for the destination epoch.

Bidirectional sharing is two explicit projections with application conflict policy; it is never an implicit cross-domain transaction.

## 19. Snapshots

A snapshot is an immutable encrypted blob containing domain ID/epoch, schema descriptors, canonical materialized CRDT states, indexes or index rebuild hints, commit frontier, version vector, control head, blob reachability roots, state root, creator, and signature. Index payloads are optional because they are rebuildable.

Snapshot authority is an explicit capability. A bootstrap node accepts a snapshot only when:

- its hash/signature/canonical encoding/AEAD validate;
- the signer has `SNAPSHOT` permission at the captured control head;
- all schemas and format majors are supported;
- its frontier/control head match the signed body;
- its state root matches decoded canonical state.

This verifies internal integrity, not honest computation. Skipping history necessarily trusts the configured snapshot authority. High-assurance domains may require M-of-N matching snapshot attestations in a future minor version. Nodes retain or can fetch the frontier/control proof needed to validate recent commits. Snapshot installation is staged and atomically switches materialized roots; failure leaves the old state intact.

## 20. Failure, Recovery, and Abuse Bounds

- Offline writes remain local commits and synchronize later.
- Reordering and missing dependencies stage commits until bounded resolution succeeds.
- Duplicate frames/blobs/commits are idempotent.
- Invalid signatures, AEAD tags, schema operations, capabilities, or control branches never mutate materialized state.
- Store crashes recover from durable blobs and redb atomicity; `verify` and `repair` can rebuild derived state into a shadow database and atomically replace it.
- Missing gossip is repaired by explicit peer sync.
- Slow or malicious peers are constrained by handshake deadlines, frame limits, range limits, quotas, per-domain quarantine caps, and cancellation.
- Blob providers cannot corrupt data undetected; they can deny or delay service, which retries and multi-provider scheduling mitigate.
- Disk-full and key-unavailable errors are explicit, leave commits unapplied, and are retryable after remediation.

## 21. Threat Model

### Protected Assets

Domain plaintext, domain keys, endpoint secret keys, membership and capability data, commit authenticity, materialized integrity, availability of local accepted data, and separation between domains.

### Adversaries

Unauthenticated internet peers, malicious blob/gossip providers, revoked members, authorized writers producing adversarial inputs, replaying peers, relays observing metadata, and attackers controlling storage bytes while the process is stopped.

### Guarantees

- iroh authenticates the remote endpoint and encrypts transport.
- Object signatures bind authorship and exact bytes.
- AEAD protects domain content from non-members and detects storage/network modification.
- Capability and epoch validation prevents unauthorized future commits from applying.
- Canonical codecs, CRDT validation, resource limits, and atomic application protect integrity and local availability.
- Independent encryption, history, gossip topic derivation, and projection preserve domain separation.

### Explicit Limitations

Traffic analysis and ciphertext sizes are visible. A relay sees endpoint connectivity metadata. Authorized members can exfiltrate plaintext. Revocation is forward-only. A compromised unlocked device defeats its local confidentiality. Snapshot bootstrap trusts configured authorities. Availability has no global guarantee. Endpoint Sybil identities are cheap. No Byzantine consensus means authorized writers can submit semantically undesirable but schema-valid data.

### Required Security Verification

Threat-model review precedes Milestone 2 and repeats for Milestones 3 and 5. CI includes dependency auditing, secret scanning, unsafe-code policy, codec/CRDT fuzzing, property tests, malformed protocol corpora, replay/revocation tests, and denial-of-service limit tests. Cryptographic code uses audited crates rather than custom primitives.

## 22. Observability, Backup, and Compatibility

Structured tracing and metrics report local apply latency, query latency, index scans, frontier size, quarantine reasons, sync rounds, bytes requested/verified, cache hit rate, provider score, snapshot age, and repair results. Labels never contain record IDs, collection values, capability bytes, keys, or plaintext.

A backup is a signed, versioned catalog plus selected immutable ciphertext blobs and optionally a separately encrypted key export. Restore verifies every hash/signature before opening. Repair never overwrites the only copy: it builds a shadow metadata store and swaps only after verification.

Wire, object, schema, and directory formats version independently. Major versions require explicit migration. Sync negotiates the highest mutually supported version without downgrade below a locally configured minimum. Golden byte fixtures are permanent compatibility tests.

## 23. Milestones and Acceptance Gates

### Milestone 0 — Architecture

Deliver this accepted design, split reference documents as implementation begins, protocol golden vectors, and an ADR log for changed decisions. Gate: no unresolved decision blocks Milestone 1; an implementation plan has crate-level steps and verification.

### Milestone 1 — Embedded Database

Deliver the workspace, IDs/codecs, all CRDTs, derive macro, default/private domains, local atomic transactions, redb commit metadata/materialization/indexes, typed queries/cursors/subscriptions, local iroh-blobs storage, encrypted chunk manifests, read/seek streaming, snapshots, recovery, and examples. No endpoint is opened. Gate: unit/property/integration tests pass; reopen/rebuild/snapshot equivalence is proven; public example compiles.

### Milestone 2 — Distributed Sync

Deliver iroh endpoint/router integration, gossip hints, sync ALPN, capability proof, dependency fetching through iroh-blobs, two-peer reconciliation, offline concurrent writes, encrypted domains, and snapshot bootstrap. Gate: deterministic two/three-peer partition tests converge; malformed and unauthorized inputs do not apply; restart during every sync stage recovers.

### Milestone 3 — Sharing

Deliver invitation sessions/tickets, delegated capabilities, multiple domains, linear control chain, epoch rotation/revocation cut, multi-device user grouping metadata, projection API, and rebase-required recovery. Gate: a revoked member cannot apply or decrypt post-cut data; private history never appears in destination fixtures; invitation/capability attack matrix passes.

### Milestone 4 — Blob Performance

Deliver provider discovery adapter, multi-provider chunk scheduler, prioritization, retry/hedging, RAM/disk/pinned caches, prefetch, bandwidth fairness, cancellation, metrics, and benchmark suite. Gate: seeking fetches only intersecting chunks; corruption is detected; providers can disappear mid-stream; on a controlled LAN, sustained sequential playback reaches at least 90% of the slowest of aggregate provider capacity, local disk read capacity, or consumer demand after warm-up.

### Milestone 5 — Production

Deliver CLI, backup/restore, verify/repair, migrations, compatibility fixtures, fuzz targets, fault injection, long-running partition/reconnect tests, observability, security audit checklist, documentation, MSRV policy, and release automation. Gate: 72-hour churn test has no divergence/leak/deadlock; restore and full rebuild match state roots; supported-version matrix passes; all fuzz corpora are clean; performance regressions stay within declared budgets.

Every gate is recorded in `docs/milestones/MN.md` with exact commands, results, known limitations, and the next-milestone approval.

## 24. Implementation Strategy

Milestone 1 builds a vertical slice before broadening: one record schema, one transaction, one commit blob, one materialized read, one equality index, one subscription, one encrypted blob stream, and reopen. It then generalizes through the remaining CRDTs, query operators, snapshots, and derive diagnostics. Later milestones add adapters around this kernel; network input passes through the same validation/apply path as local commits.

All behavior changes start with failing executable tests. Protocol and crypto work adds golden vectors and negative tests before implementation. Public APIs remain narrow until the milestone gate. Unsafe Rust is denied by default and requires a documented module-level exception.

## 25. Verification Matrix

| Invariant | Primary verification |
| --- | --- |
| Offline reads/writes | integration test with networking feature disabled |
| One transaction, one atomic commit | crash/fault-injection around blob/redb boundaries |
| Convergence | generated operation permutations across all CRDTs |
| Durable canonical format | checked-in golden bytes and cross-version decode tests |
| Authorization | capability-chain/revocation/control-fork attack matrix |
| Confidentiality | ciphertext fixture inspection and wrong-domain/epoch key tests |
| Rebuildability | delete derived redb tables and compare canonical state root |
| Snapshot bootstrap | snapshot+tail result equals full replay |
| Domain separation | projection and key/topic/link non-equality tests |
| Sync recovery | partitions, reorder, duplicates, dropped gossip, restart |
| Blob verification/seek | corruption, range accounting, cache, provider loss tests |
| Compatibility | MSRV and supported protocol-format version matrix |

## 26. Evidence

### Confirmed

- The complete product vision, philosophy, responsibility split, data model, milestones, and exclusions are supplied directly by the user in this thread.
- The workspace is empty and is not currently a Git repository as of 2026-07-19.
- Current official iroh documentation identifies `Endpoint`, authenticated endpoint IDs, QUIC streams, relays, NAT traversal, and ALPN routing as iroh responsibilities.
- Current official iroh-blobs documentation provides BLAKE3 content addressing, verified/resumable range transfer, filesystem storage, and an async read/seek blob reader.
- Current official iroh-gossip documentation provides topic subscription and announcement dissemination.

### Proposed

- redb metadata storage, canonical numeric-key CBOR, XChaCha20-Poly1305/HKDF-SHA256, causal LWW rather than wall-clock LWW, the linear domain control chain, deterministic revocation cut, one-MiB encrypted chunks, explicit snapshot trust, and all measurable acceptance gates.

## 27. Open Questions

No question blocks implementation. The following are intentionally deferred compatibility decisions with defined defaults:

- MSRV: Rust 1.91, matching the selected current iroh 1.0.2, iroh-blobs 0.103.0, and iroh-gossip 0.101.0 releases; CI also tests current stable.
- OS keychains: ship the file `KeyProvider` first and add platform providers without changing durable domain formats.
- Multi-signature snapshots: reserve extension tags; v1 trusts one explicitly authorized snapshot signer.
- Upstream native blob fan-in: keep the provider scheduler behind an adapter and delegate when upstream semantics satisfy the manifest contract.
- Non-Rust and SQL frontends: excluded until after Milestone 5 and protocol stability.

## 28. Approval

Approved by the user on 2026-07-19 with standing approval for milestone execution. Any later change to canonical formats, CRDT semantics, security boundaries, revocation behavior, or snapshot trust still requires an ADR; local reversible implementation details do not.
