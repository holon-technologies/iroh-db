# ADR 0011: Owned Blob Runtime Shutdown

Status: Accepted
Date: 2026-07-21

## Context

Qualification telemetry showed that every clean same-process database reopen
retained one `iroh-blob-store-*` worker thread and several MiB of resident
memory. Repeated router shutdown and restart did not grow workers; repeated
offline database close and reopen did. The `iroh-blobs` filesystem actor owns
its Tokio runtime and dropped that runtime synchronously from one of its own
workers, leaving the worker blocked during runtime self-join.

This leak was independent of the invalidated soak timeout, which coincided
with host-wide memory pressure, but it would independently violate the final
no-leak qualification gate.

## Decision

`iroh-db` temporarily pins the audited `iroh-blobs` 0.103.0 source commit
`9bc09dc83ab637ba46ae6d7f4f8ad7825b9b0a26`. That fork history uses Tokio's
non-blocking runtime shutdown path after the filesystem actor has drained its
handles and joined its tasks, and exposes an explicit redb cache bound. The
runtime change was proposed in
[iroh-blobs PR #246](https://github.com/n0-computer/iroh-blobs/pull/246).

`IrohBlobStore::shutdown` drains the filesystem actor, and dropping its final
owner then invokes the corrected non-blocking runtime shutdown. `IrohDb::close`
continues to require unique ownership of the database. Linux restart-resource
tests independently cover database reopen, network restart, and the combined
test-cluster peer restart.

## Consequences

Clean same-process reopen cycles no longer accumulate blob runtime workers.
The source exception is exact-commit pinned and explicitly allowlisted by
dependency policy; unrelated Git sources remain denied. Replace the pin with a
released crates.io version containing the upstream fix as soon as one is
available, and remove the Git-source exception in the same change. The release
workflow rejects all Git dependencies before `cargo publish`, so a crates.io
release of `iroh-db` cannot silently fall back to unpatched 0.103.0.
