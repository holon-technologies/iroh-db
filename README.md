# iroh-db

`iroh-db` is a Rust-native, local-first distributed database built as a semantic layer over iroh. Local reads and writes never require a network; immutable encrypted commits synchronize asynchronously over authenticated iroh QUIC and iroh-blobs.

The implemented M0–M5 architecture is documented in [the design specification](docs/superpowers/specs/2026-07-19-iroh-db-design.md), with reproducible evidence in [the milestone gates](docs/milestones).

## Typed local-first API

Schemas are Rust types and replicated fields use permanent built-in CRDT semantics.

```rust,no_run
let db = IrohDb::open("./music.irohdb").await?;
let tracks = db.collection::<Track>();

tracks.put(track).await?;
let massive_attack = tracks
    .query()
    .filter(Track::artist.eq("Massive Attack"))
    .fetch()
    .await?;
```

Transactions are atomic inside exactly one domain. Queries support primary-key lookup, equality, ranges, ordering, MAC-bound cursor pagination, and subscriptions. Materialized records and indexes are rebuildable from signed commits and snapshots.

## Domains, sharing, and sync

`create_domain` selects `MultiWriter`, `SingleWriter`, or `AppendOnly`. Signed capabilities grant explicit endpoint-bound rights. Invitations work as a target-authenticated online exchange or a one-use encrypted offline ticket. Revocation creates a signed causal cut, rotates the epoch key/topic, retains historical keys for existing members, and returns rejected old-epoch forks as `RebaseRequired`.

```rust,no_run
let shared = db.create_domain(ConsistencyMode::MultiWriter)?;
let invitation = shared.invite(
    member_endpoint,
    PermissionSet::from_permissions(&[
        Permission::Read,
        Permission::Write,
        Permission::FetchBlobs,
    ]),
    PermissionSet::empty(),
    None,
)?;

let node = shared.start_sync().await?;
node.offer_invitation(&invitation)?;
```

Gossip carries only signed availability hints. The sole database control ALPN exchanges bounded hashes, frontiers, domain proofs, and invitations; immutable bytes are always transferred and verified by iroh-blobs. Explicit sync repairs missed gossip, partitions, duplicates, and reordered delivery. Snapshot bootstrap avoids replaying old history.

Sharing private state is an explicit typed projection into an independent destination-domain transaction. Source commits, dependencies, capabilities, keys, and hidden history are never copied.

## Encrypted blob streaming

Blob manifests and independent chunks are content-addressed and encrypted. `BlobStream` implements lazy `AsyncRead + AsyncSeek`. Remote open fetches only the manifest; reads and seeks request intersecting chunks plus bounded prefetch. The scheduler rotates across iroh-blobs providers, retries provider loss, caches ciphertext on disk, keeps one bounded plaintext RAM chunk, and exposes low-cardinality transfer metrics.

## Operations

Live verification checks immutable hashes, canonical codecs, signatures, epoch decryption, dependencies, orphans, and typed rebuild equality. Repair builds candidate state before an atomic metadata swap. Closed-store backup is checksummed, optionally includes the separately encrypted key vault, and restore verifies all paths and hashes before creating a new destination.

```console
iroh-db-cli verify ./app.irohdb
iroh-db-cli repair-indexes ./app.irohdb
iroh-db-cli backup ./app.irohdb ./backup --include-keys
iroh-db-cli restore ./backup ./restored.irohdb
```

See [compatibility policy](docs/compatibility.md) and [security policy](SECURITY.md). Already downloaded plaintext cannot be revoked. Compromised unlocked devices, traffic analysis, and denial of service remain outside the confidentiality boundary.

## Development

```console
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo doc --workspace --no-deps
cargo bench -p iroh-db-blobs --bench local_stream
```

The MSRV is Rust 1.91. Fuzz targets live in `fuzz/`; the extended reconnect soak is an ignored test controlled by `IROH_DB_SOAK_ROUNDS`.

## License

Licensed under either Apache-2.0 or MIT, at your option.
