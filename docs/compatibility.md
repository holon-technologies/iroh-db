# Compatibility Policy

The current release is pre-1.0 but its durable and wire formats are explicitly versioned.

- Store format: `iroh-db 6.0` in `FORMAT`; unknown formats fail closed. V6 uses
  `meta-v6.redb` and adds active-schema, staged-record, activation, fork, and
  checkpoint tables. Opening format 5 copies its untouched `meta.redb` into a
  separately integrity-checked v6 candidate, fsyncs it, publishes the v6 file,
  and only then atomically advances `FORMAT`. `meta-v5.redb` and the original
  `meta.redb` remain available as rollback evidence. Interrupted candidates
  are discarded and rebuilt from the preserved v5 source. Formats 1 through 4
  remain intentionally unsupported.
- Sync ALPN: `/iroh-db/sync/4`; hello frames advertise an inclusive supported
  object-protocol range and select the highest overlap. This release supports
  range `4..=4`; non-overlap fails before authority or commit exchange. Sync v3
  is intentionally incompatible because it cannot fail closed for schema
  activation operations. Frames use strict canonical CBOR.
- Commit, snapshot, manifest, gossip, authority, invitation, control, key-vault, and backup objects each carry independent versions or magic values.
- Backup catalog v2 is canonical CBOR signed under the endpoint identity's
  backup-specific context. Restore rejects the earlier unsigned development
  manifest. Provenance-sensitive restores additionally pin the expected
  signer; self-signature alone proves archive integrity, not external trust.
- Control transitions use control format v3, which signs both the designated
  successor controller and its exact successor capability ID. Pre-release v1
  and v2 control objects are rejected rather than replayed under mutable active
  capability state.
- Capability certificates use capability format v2, which signs both the
  issuance control sequence and the exact accepted control transition ID.
  Pre-release sequence-only v1 certificates are rejected because future
  sequence claims can be pre-signed before a revocation transition exists.
- Invitations use format v2 and embed a separately signed, target-bound
  authority checkpoint: current control head, controller evidence, exact
  capability allowlist and active-member set, and canonical subject-revocation
  accumulator.
  Pre-release v1 invitations cannot bootstrap rotated domains and are rejected.
- Commit operation codes 14 (`SchemaStage`) and 15 (`SchemaActivate`) carry the
  canonical causal migration protocol. Stage records remain invisible;
  activation verifies exact source-cut coverage and publishes one collection
  atomically. Incompatible activation or stage siblings retain signed evidence
  and freeze the collection independent of receipt order.
- Snapshot format v3 signs active schema activations alongside materialized
  records and causal coverage. Installing a snapshot publishes those cuts in
  the same redb transaction, so delayed pre-activation commits remain durable
  history without becoming visible.
- Canonical golden fixtures and trailing/truncation/malformed tests prevent silent encoder drift.
- Built-in CRDT semantics are permanent for a stored schema. Applications must assign stable collection names, field IDs, and schema versions.
- The greenfield `0.1.0` causal-kernel hardening rejects earlier development commits whose CRDT dots, contexts, or counter authors were supplied by application state. No released database is migrated; development stores created before ADR 0001 must be recreated.

## Supported-version matrix

| Input or peer | Result |
|---|---|
| New v6 directory | Created as `meta-v6.redb` |
| Valid v5 directory | Shadow-copied, integrity-checked, retained, upgraded to v6 |
| Interrupted v5→v6 artifacts | Rebuilt from retained v5 metadata |
| Store formats 1–4 or future unknown | Rejected |
| Sync/object range overlapping `4..=4` | Highest overlap selected |
| Sync/object range without overlap | Rejected before domain exchange |
| Snapshot v3 | Accepted after signature, authority, state, and activation validation |
| Snapshot v1/v2 or future unknown | Rejected |
| Signed backup catalog v2 | Accepted after canonical, signature, path, hash, and size validation |
| Unsigned backup manifest v1 or future unknown | Rejected |

All future durable upgrades must keep the same shadow-copy rule. In-place
reinterpretation of the only good metadata copy is forbidden.

MSRV is Rust 1.91 and is tested alongside stable.
