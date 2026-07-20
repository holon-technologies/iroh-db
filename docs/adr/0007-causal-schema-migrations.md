# ADR 0007: Causal staged schema migrations

- Status: Accepted
- Date: 2026-07-20
- Decision owner: iroh-db protocol

## Context

The accepted architecture requires application-registered deterministic schema
migrations, but the current implementation only rejects a different descriptor
for an already registered `(collection, version)`. Rewriting redb rows in place
would make materialized state authoritative, would not replicate, and could not
be reconstructed from signed commits. Replacing every record in one commit is
atomic but imposes the commit payload limit on collection size and cannot resume
incrementally after a crash.

A migration can also race with offline old-schema writes. Receipt-order
selection would make replicas diverge, while silently decoding old bytes as a
new Rust type is unsafe.

## Decision

1. A schema migration is a domain-local causal protocol represented entirely by
   immutable encrypted signed commits. Mutable migration tables are caches and
   checkpoints only.
2. Applications register an exact adjacent transition `(from descriptor, to
   descriptor, deterministic transform)`. Collection IDs and primary-key types
   must remain equal, the version must increase by one, and either descriptor
   changing without a new version is rejected.
3. The designated domain controller with `Admin` permission coordinates
   migrations in controlled domains. A local-only private domain is coordinated
   by its device. If an application explicitly adds trusted authors to an
   uncontrolled domain, those authors are equivalent administrators; sharing
   that needs a unique coordinator must use a controlled domain. Ordinary
   `Write` permission in a controlled multi-writer domain is never sufficient.
4. Bounded staging commits carry target-schema materializations and the exact
   source record identity they transform. They do not change visible records.
   Each attempt ID commits to the canonical source-state cut. Staging and
   activation are serialized locally; an unchanged restart reuses durable
   stages, while a changed source starts a new immutable attempt. Stages can be
   downloaded in any order.
5. One activation commit names the exact from/to descriptors and migration ID
   and depends on the complete staging frontier selected by the coordinator.
   Activation validates that every source record visible at that causal cut has
   one staged target with the same primary key. It atomically switches the
   collection's visible schema and materialized records.
6. An old-schema commit outside the activation cut remains immutable evidence
   but never becomes visible under the new schema. Acceptance reports a typed
   schema-rebase outcome so an application can explicitly transform the write.
   Receipt order therefore cannot select visible state.
7. Rebuild, snapshot-tail application, repair, and quarantine recovery derive
   staging and activation from the same commit DAG. A mutable checkpoint may
   accelerate resumption but cannot authorize activation.
8. Migration functions never run on untrusted network input. Peers validate
   canonical staged target records with their registered target adapter; the
   signed coordinator commit is responsible for the application-level value
   transformation, just as an ordinary authorized write is responsible for its
   values.
9. Staging and activation opcodes are versioned protocol data. Older peers fail
   closed with an unsupported-schema error and do not acknowledge activation.

## Failure behavior

- A missing registry step, descriptor mismatch, skipped version, changed
  primary key, unauthorized coordinator, incomplete staging set, or malformed
  activation is rejected before visible metadata changes.
- Crashes during staging leave replayable immutable commits. A crash during
  activation leaves either the old or new complete materialization because the
  redb publication is one transaction.
- Concurrent incompatible activations for one predecessor freeze that
  collection and retain both signed candidates. They never choose a winner by
  arrival order or content-hash grinding.
- Ordinary reads continue from the old schema until activation. No query sees a
  partially migrated collection.

## Compatibility

The new opcodes require a sync/object protocol version update before a stable
release. Store tables gain versioned staging and active-schema metadata; the
directory migration must copy into a new format and preserve the prior store
until verification succeeds.

## Verification

Tests must cover multi-batch crash/resume, duplicate and reordered staging,
activation completeness, offline old-schema writes in both receipt orders,
incompatible activation forks, rebuild/repair/reopen equality, snapshot plus
tail, unsupported peers, authorization, and multiple-domain isolation.
