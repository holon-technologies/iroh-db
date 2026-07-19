# Changelog

All notable changes are documented here. The project follows semantic versioning after 1.0; before 1.0, durable and wire compatibility follow `docs/compatibility.md`.

## 0.1.0 — 2026-07-19

- Typed local-first records, CRDT fields, transactions, queries, indexes, subscriptions, snapshots, and encrypted blobs.
- Authenticated iroh synchronization, iroh-gossip hints, and iroh-blobs immutable transfer.
- Signed capability domains, invitations, epoch rotation/revocation, device groups, and projection sharing.
- Lazy multi-provider encrypted blob streaming with seek, retry, prefetch, and transfer counters.
- Verification, repair, checksummed backup/restore, operational metrics, CLI, CI, fuzz targets, and churn/soak harnesses.
- Durable authenticated snapshot baselines make verification, repair, and equivocation quarantine reconstruct snapshot-plus-tail state without trusting mutable materialized tables.
