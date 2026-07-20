# ADR 0008: Authenticated Operations and Observable Runtime Boundaries

Status: Accepted
Date: 2026-07-20

## Context

The first production soak candidate exposed two mismatches with the accepted
Milestone 5 contract. Backups used an unsigned text checksum list, so an
attacker able to replace an archive could replace both payloads and checksums.
Operational metrics exposed only durable-state gauges and could not report
apply/query latency, sync outcomes, quarantine, snapshot age, or repair
results. The file key vault was also embedded directly in the facade, despite
the architecture requiring an application-replaceable key-provider boundary.

The standalone CLI has a separate limitation: Rust record merge adapters live
in the application binary. A generic CLI can authenticate immutable objects
and repair secondary indexes from durable per-record index keys, but it cannot
honestly claim a typed replay without those adapters.

## Decision

- Backup format v2 is a strict canonical CBOR catalog containing ordered UTF-8
  relative paths, BLAKE3 hashes, and byte lengths. The complete canonical
  catalog is signed by the database endpoint identity under
  `iroh-db/backup-signature/v1`.
- Restore verifies canonical encoding, signature, format presence, every path,
  hash, and length before publishing a destination. It copies into a random
  sibling staging directory, re-verifies while copying, fsyncs files and
  directories where the platform supports it, and atomically renames without
  overwriting an existing destination.
- `restore_backup` establishes integrity from the signer embedded in the
  catalog. Callers that require provenance use `restore_backup_from` or the
  CLI `--expect-signer` option to pin a previously trusted endpoint ID.
- `KeyProvider` owns endpoint identity and durable current/historical domain
  keys. The owner-only encrypted file vault remains the default. Applications
  with an external provider use `IrohDbBuilder::key_provider` and
  `backup_closed_with_signer`; external provider secrets are not copied into
  the database directory.
- Static structured tracing spans cover apply, query, sync, snapshot,
  verification, repair, backup, and restore without content-bearing fields.
  Lock-free runtime metrics expose latency, index work, quarantine/rebase,
  sync, snapshots, and repair outcomes. The most recent verified snapshot time
  is durable local operational metadata; process counters intentionally reset
  on restart.
- Verification reports whether typed replay actually ran. With registered
  Rust record adapters, `derived_consistent` compares full replay with current
  materialization. A standalone process without adapters still verifies
  hashes, canonical objects, signatures, encryption, dependencies, authority,
  and orphans, but reports `typed_rebuild_performed=false` and never represents
  that result as typed equivalence.

## Consequences

Backup v1 archives are intentionally unsupported pre-release artifacts.
Possession of an unpinned, valid self-signed archive does not prove that it came
from the intended device. External key providers must be supplied again when
opening a restored database whose backup intentionally excluded keys.

Metrics contain no record IDs, collection values, capability bytes, keys, or
plaintext. Runtime counters are observation signals rather than replicated
history. Full typed repair remains an application API because only the
application can register every historical Rust schema adapter.
