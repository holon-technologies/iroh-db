# Production Readiness Audit

Date: 2026-07-20
Candidate status: implementation audit complete; final qualification and the
literal 72-hour soak remain release gates.

This audit maps the accepted architecture and every Milestone 0–5 gate to
executable evidence. A check is not considered complete merely because an API
exists; the cited test must exercise its failure boundary or equivalence claim.

## Milestone 0 — Architecture

| Requirement | Evidence |
| --- | --- |
| Accepted architecture, protocol, CRDT, storage, blob, capability, and threat model | `docs/superpowers/specs/2026-07-19-iroh-db-design.md`; `docs/milestones/M0.md` |
| Crate-level execution plan and milestone sequencing | `docs/superpowers/plans/2026-07-19-program-plan.md` and milestone plans |
| Consequential decisions remain reviewable | ADRs 0001–0009; golden protocol/object tests |
| No unresolved implementation-blocking decision | Design section 27 and compatibility defaults |

## Milestone 1 — Embedded Database

| Requirement | Direct evidence |
| --- | --- |
| Offline typed reads/writes and one atomic commit per transaction | `embedded_database::typed_put_get_query_subscription_transaction_and_reopen`; `local_transaction_rejects_multiple_mutations_of_one_record` |
| Stable IDs, schemas, canonical commits, and derive diagnostics | core codec/schema/identity tests and `iroh-db-derive/tests/ui.rs` |
| Permanent deterministic semantics for all built-in CRDTs | `crdt_semantics.rs`, `crdt_properties.rs`, and the CRDT fuzz harness |
| Equality, ranges, compound ordering, stable authenticated pagination | `range_order_and_mac_bound_cursor_pagination_are_stable`; `compound_ordering_uses_every_typed_clause_before_primary_key` |
| Initial/change subscriptions with bounded lag and post-commit frontier | embedded database subscription assertions and facade lag handling |
| Encrypted lazy local blob read/seek and corruption rejection | `encrypted_stream.rs` |
| Snapshot/replay/reopen equivalence and atomic rejection | `snapshot_rebuild.rs`; durable snapshot store tests |
| Replaceable key provider with owner-only encrypted file default | `an_application_supplied_key_provider_is_independent_of_the_store_directory`; `local_credentials.rs` |

## Milestone 2 — Distributed Sync

| Requirement | Direct evidence |
| --- | --- |
| iroh Endpoint/QUIC/Router, iroh-gossip hints, and iroh-blobs byte transfer | `network_sync.rs`, `frame_codec.rs`, and `gossip_hint.rs`; dependency-direction inspection |
| Offline two-peer reconciliation and deterministic three-peer convergence | `one_real_iroh_session_reconciles_both_offline_peers_via_blobs`; `three_partitioned_peers_converge_after_reordered_pairwise_sessions` |
| Authorization and malformed input fail before mutation | unauthorized real-session/direct-apply tests and sync codec corpora |
| Missing gossip, duplicates, reordered dependencies, and clean restart recover | network sync restart/gossip tests and testkit cluster tests |
| Encrypted snapshot bootstrap fetches only recent tail | `encrypted_snapshot_bootstrap_fetches_only_the_commit_tail` |
| Sync metrics cover successful and failed rounds without content labels | network sync operational-metric assertions and `OperationalMetrics` |

## Milestone 3 — Sharing

| Requirement | Direct evidence |
| --- | --- |
| Signed descriptors, bounded delegated capabilities, invitations, and one-use tickets | security authority/invitation tests and `sharing.rs` |
| Multiple isolated domains and endpoint-based device grouping | `multiple_domains.rs`; `m3_modes_projection.rs` |
| Linear designated control, transfer, and fail-closed equivocation | control authority store tests and `rotation.rs` |
| Epoch rotation/revocation cut and explicit old-write rebase | rotation and network epoch-sync tests |
| Revoked member cannot receive/decrypt future epoch | `sync_never_delivers_a_rotated_key_to_a_revoked_member` |
| Projection copies visible state into independent history only | `projection_creates_independent_history_and_groups_remain_ux_metadata` |

## Milestone 4 — Blob Performance

| Requirement | Direct evidence |
| --- | --- |
| Manifest-first multi-provider encrypted streaming | `blob_multisource.rs` |
| Seek/range accounting and provider loss/corruption recovery | blob multisource and encrypted stream tests |
| Priority fairness, provider scoring, retry/backoff, hedging, cancellation, and coalescing | scheduler/engine unit tests |
| Bounded RAM plaintext and encrypted persistent cache/pins | stream implementation, cache-hit assertions, and encrypted-store fixtures |
| Per-stream fetch/provider observations | `FetchMetrics`, `ProviderMetrics`, and blob multisource assertions |
| Executable local and shaped multi-provider performance budgets | `local_stream` and `multisource_stream` benchmarks; final candidate reruns are required below |

## Milestone 5 — Production

| Requirement | Direct evidence |
| --- | --- |
| Cryptographic/structural verification and application-registered typed replay | `operations.rs` verification, snapshot-plus-tail repair, and standalone-scope tests |
| Atomic typed repair and standalone secondary-index repair | repair equivalence tests; `standalone_index_repair_rebuilds_secondary_entries_from_durable_record_keys` |
| Signed, versioned, streaming, non-overwriting backup/restore | backup golden bytes, signature-domain test, tamper/signer-pin/path tests, state-root restore equivalence |
| External-provider backup without copying provider secrets | embedded external-provider backup/restore test |
| Operational CLI | CLI parsing tests plus `inspect`, `verify`, `repair-indexes`, `backup`, and signer-pinned `restore` |
| Structured low-cardinality observability | static tracing spans; latency/index/quarantine/rebase/sync/snapshot/repair metric assertions |
| Durable causal schema migrations | `schema_migration.rs`, ADR 0007, v5→v6 migration tests |
| Compatibility/MSRV/dependency/release policy | compatibility matrix, CI workflows, `deny.toml`, package verifier, release workflow |
| Fuzz and fault injection | five retained-corpus harnesses; production testkit cluster and churn tests |
| 72-hour partition/reconnect/restart gate | Harness/workflow delivered; final exact-duration run is still pending and cannot be substituted by accelerated rounds |

## Final Candidate Qualification

Before the candidate commit can be called production-ready, retain successful
output for all of the following on that exact tree:

```console
cargo fmt --all -- --check
cargo fmt --manifest-path fuzz/Cargo.toml --all -- --check
CARGO_BUILD_JOBS=1 CARGO_PROFILE_DEV_DEBUG=0 cargo clippy --workspace --all-targets --all-features -- -D warnings
CARGO_BUILD_JOBS=1 CARGO_PROFILE_DEV_DEBUG=0 cargo clippy --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings
CARGO_BUILD_JOBS=1 CARGO_PROFILE_DEV_DEBUG=0 cargo test --workspace --all-features
CARGO_PROFILE_DEV_DEBUG=0 cargo doc --workspace --no-deps
cargo check --manifest-path fuzz/Cargo.toml --all-targets
cargo test --manifest-path fuzz/Cargo.toml
cargo deny check
cargo deny --manifest-path fuzz/Cargo.toml check
bash scripts/verify-packages.sh
bash scripts/verify-release-ready.sh
cargo publish --workspace --dry-run --no-verify
cargo bench -p iroh-db-blobs --bench local_stream
cargo bench -p iroh-db --bench multisource_stream
```

Then run from that exact committed tree:

```console
IROH_DB_SOAK_DURATION_SECS=259200 \
IROH_DB_SOAK_RESTART_EVERY=97 \
IROH_DB_SOAK_RECORD_SLOTS=256 \
IROH_DB_SOAK_MAX_RSS_ANON_KIB=262144 \
IROH_DB_SOAK_MIN_ROUND_MILLIS=1000 \
IROH_DB_SOAK_OPERATION_TIMEOUT_SECS=30 \
IROH_DB_SOAK_METRICS_PATH=iroh-db-soak-metrics.tsv \
  cargo test -p iroh-db-testkit --test churn extended_partition_reconnect_soak -- --ignored --nocapture
```

Only a completed wall-clock run with no divergence, leak, deadlock, timeout, or
unexpected process exit closes the final gate. Run it on a dedicated Linux host
without unrelated memory- or I/O-intensive workloads, and retain the TSV
resource evidence alongside the test log. The metrics capture total,
anonymous, file-backed, and shared process RSS; thread and descriptor counts;
host available memory; and memory-pressure stall data every 25 rounds and at a
synchronization failure. Anonymous RSS above the configured 256 MiB budget
fails the test immediately. The official one-second minimum round duration
still exercises approximately 259,000 rounds while preventing benchmark-speed
commit production from exhausting the qualification volume.

The qualification attempt started on 2026-07-20 was invalidated after 4,744.93
seconds. It completed 20,000 rounds and 206 durable restarts before a sync
operation timed out during simultaneous host-wide memory pressure. At the same
timestamp, systemd-journald reported memory-pressure cache flushes, multiple
Docker health checks and container-runtime operations timed out, and an
unrelated rejected user service was in a three-second restart loop. That
service was stopped before rerunning qualification. Because the external
sampler produced no rows, resource sampling now runs inside the test process
and the official workflow retains its TSV output. This invalidated attempt is
not production-readiness evidence and does not reduce the next 72-hour gate.

A second attempt from commit `a431ab2282f58048ed0178aae7a1c873eee6e510`
was deliberately stopped on 2026-07-21 after 78,450 rounds, 156,900 syncs, and
808 restarts in approximately 5.87 hours. Total RSS rose from 13,108 KiB to
4,051,832 KiB at approximately 689,922 KiB/hour while threads and descriptors
remained stable. The workload also created three permanent record IDs per
round, so it conflated live-data growth with lifecycle retention. The run is
invalid and cannot qualify a release.

Focused bounded-keyspace diagnostics identified redb's 1 GiB default userspace
cache in both the iroh-db metadata store and the iroh-blobs metadata store. A
three-peer process therefore had six caches able to retain roughly 6 GiB. Both
owners now default to explicit 8 MiB bounds and expose lower-level cache-size
overrides. The qualification keyspace is bounded at 256 records per peer and
telemetry separates anonymous from file-backed RSS. A 2,000-round regression
completed 4,006 syncs and 64 restarts; after warm-up anonymous RSS stayed
between 74,220 and 93,768 KiB, ended at 84,608 KiB, and had a negative fitted
slope over rounds 1,000 through 2,000.

The new telemetry also exposed a separate linear worker retention issue across
same-process database reopens. Focused tests isolated it to the upstream
`iroh-blobs` filesystem runtime rather than iroh networking. `iroh-db` pins the
audited fork commit and carries regressions for database-only, network-only, and
combined peer restarts; the fix is proposed upstream in
[iroh-blobs PR #246](https://github.com/n0-computer/iroh-blobs/pull/246). The
temporary Git source and dependency-policy exception must be removed in favor
of the first crates.io release containing that fix before publishing
`iroh-db` crates. The release workflow enforces this by running
`scripts/verify-release-ready.sh` before any publish dry-run.

Package-archive verification patches Cargo's normalized `iroh-blobs` registry
dependency back to this exact resolved development source, so it can validate
the archive contents and current dependency graph. This does not relax the
release gate: publication remains blocked while any Git dependency is present.
