# ADR 0012: Bounded Metadata Caches

Status: Accepted
Date: 2026-07-21

## Context

The second production-soak attempt showed monotonic total RSS growth of about
690 MiB/hour while worker threads and file descriptors remained stable. The
workload created three permanent records per round, but a bounded-keyspace
diagnostic still showed history-proportional anonymous RSS.

redb 4.1 defaults to a 1 GiB userspace page cache per database. Every iroh-db
instance owns one redb database for typed metadata and one through iroh-blobs
for immutable-blob metadata. The three-peer qualification process therefore
allowed six caches to grow toward roughly 6 GiB. This was bounded cache growth,
not unreachable heap objects, but it could still exhaust a production host.

## Decision

The iroh-db metadata store and iroh-blobs adapter each set an explicit 8 MiB
default redb cache bound. Both lower-level store APIs accept an override for
deployments that deliberately trade memory for cache hit rate. The pinned
iroh-blobs fork exposes its redb cache size through filesystem-store options.

The production soak uses a bounded live keyspace of 256 records per peer while
immutable commit history continues to grow normally. Linux telemetry records
anonymous, file-backed, and shared RSS separately. With metrics enabled, the
soak defaults to a fail-closed 256 MiB anonymous-RSS limit.

## Consequences

A normal embedded iroh-db instance has 16 MiB of configured userspace metadata
cache across its two stores instead of a potential 2 GiB. The OS page cache
continues to serve durable files, and advanced callers can explicitly raise
lower-level limits after measuring their workload.

Qualification no longer mistakes intentional record growth for a lifecycle
leak, and it aborts before anonymous-memory exhaustion. Capacity testing with
an expanding dataset remains a separate benchmark from the bounded-state
72-hour lifecycle gate.
