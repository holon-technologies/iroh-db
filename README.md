# iroh-db

[![CI](https://github.com/holon-technologies/iroh-db/actions/workflows/ci.yml/badge.svg)](https://github.com/holon-technologies/iroh-db/actions/workflows/ci.yml)
[![Rustdocs](https://img.shields.io/badge/docs-rustdoc-4d76ae)](https://holon-technologies.github.io/iroh-db/iroh_db/)
[![License: MIT OR Apache--2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

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

Transactions are atomic inside exactly one domain. Queries support primary-key lookup, equality, ranges, compound ordering, MAC-bound cursor pagination, and subscriptions whose change batches include the resulting frontier. Materialized records and indexes are rebuildable from signed commits and snapshots.

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

Blob manifests and independent chunks are content-addressed and encrypted. `BlobStream` implements lazy `AsyncRead + AsyncSeek`. Remote open fetches only the manifest; reads and seeks request intersecting chunks plus bounded prefetch. A shared weighted scheduler learns provider latency and verified throughput, applies bounded concurrency/backoff, hedges stalled high-priority chunks, coalesces duplicate requests, and cancels obsolete read-ahead on seek. Ciphertext is cached on disk, one bounded plaintext chunk stays in RAM, and low-cardinality metrics expose transfer and provider quality without endpoint or content labels.

## Operations

Live verification checks immutable hashes, canonical codecs, signatures, epoch decryption, dependencies, orphans, and typed rebuild equality. A standalone CLI cannot contain application record adapters, so it reports `typed_rebuild=false`; applications register their Rust types before claiming full replay equivalence. Repair builds candidate state before an atomic metadata swap. Closed-store backup uses a canonical endpoint-signed catalog, optionally includes the separately encrypted key vault, and restore verifies all paths, signatures, and hashes before atomically publishing a new destination.

```console
iroh-db-cli inspect ./app.irohdb
iroh-db-cli verify ./app.irohdb
iroh-db-cli repair-indexes ./app.irohdb
iroh-db-cli backup ./app.irohdb ./backup --include-keys
iroh-db-cli restore ./backup ./restored.irohdb --expect-signer <endpoint-id>
```

`restore_backup` verifies an archive's embedded self-signature. Use
`restore_backup_from` (or `--expect-signer`) whenever the expected source
identity is part of the trust decision. Applications can replace the default
owner-only file vault through `IrohDbBuilder::key_provider`; backups for an
external provider use `backup_closed_with_signer`, while the provider's own
secret storage remains an independent backup responsibility.

See [compatibility policy](docs/compatibility.md) and [security policy](SECURITY.md). Already downloaded plaintext cannot be revoked. Compromised unlocked devices, traffic analysis, and denial of service remain outside the confidentiality boundary.

## Development

```console
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo bench -p iroh-db-blobs --bench local_stream
cargo bench -p iroh-db --bench multisource_stream
```

The MSRV is Rust 1.91. Five fuzz targets and their retained corpora live in
`fuzz/`. Stable release checks replay every retained seed:

```console
cargo test --manifest-path fuzz/Cargo.toml --test corpus
```

Mutation runs require nightly cargo-fuzz. For example:

```console
cargo +nightly fuzz run security_decode fuzz/corpus/security_decode -- \
  -max_total_time=600 -timeout=10 -rss_limit_mb=4096
```

The retained corpus combines hostile boundary inputs with structure-aware
valid seeds whose mutable suffixes produce canonical commit, signed security,
sync/gossip, schema, and materialized-state objects. The weekly/manual `fuzz
qualification` workflow runs all five targets in parallel and retains evolved
corpora and crash artifacts. Minimized crashing inputs are promoted into the
corresponding checked-in corpus after the fix.

The reusable
`iroh-db-testkit` crate creates real-iroh temporary clusters with bounded sync,
node stop/start, durable restart, deterministic fault schedules, and canonical
convergence reports. The extended qualification soak accepts an exact duration:

```console
IROH_DB_SOAK_DURATION_SECS=259200 \
IROH_DB_SOAK_RESTART_EVERY=97 \
IROH_DB_SOAK_RECORD_SLOTS=256 \
IROH_DB_SOAK_MAX_RSS_ANON_KIB=262144 \
IROH_DB_SOAK_OPERATION_TIMEOUT_SECS=30 \
IROH_DB_SOAK_METRICS_PATH=iroh-db-soak-metrics.tsv \
  cargo test --locked -p iroh-db-testkit --test churn extended_partition_reconnect_soak -- --ignored --exact --nocapture
```

The monthly/manual `production soak` workflow runs that 72-hour gate on an
explicitly labelled self-hosted runner and retains both its log and Linux
process/host resource metrics. The live record keyspace is bounded so the run
measures lifecycle retention separately from intentional database growth, and
the test aborts if anonymous RSS exceeds its 256 MiB qualification budget.

## License

Licensed under either [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.
Reviewed dependency license notices are listed in
[`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md).
