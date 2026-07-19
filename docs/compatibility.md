# Compatibility Policy

The current release is pre-1.0 but its durable and wire formats are explicitly versioned.

- Store format: `iroh-db 2.0` in `FORMAT`; unknown formats fail closed. The
  pre-release 1.0 development format is intentionally rejected rather than
  reinterpreted in place.
- Sync ALPN: `/iroh-db/sync/2`; authority reconciliation precedes commit-tail
  exchange. It is intentionally incompatible with the pre-release
  `/iroh-db/sync/1` frame sequence, which cannot authenticate a lagging member
  after rotation. Frames carry a protocol version and strict canonical CBOR.
- Commit, snapshot, manifest, gossip, authority, invitation, control, key-vault, and backup objects each carry independent versions or magic values.
- Control transitions use control format v3, which signs both the designated
  successor controller and its exact successor capability ID. Pre-release v1
  and v2 control objects are rejected rather than replayed under mutable active
  capability state.
- Canonical golden fixtures and trailing/truncation/malformed tests prevent silent encoder drift.
- Built-in CRDT semantics are permanent for a stored schema. Applications must assign stable collection names, field IDs, and schema versions.
- The greenfield `0.1.0` causal-kernel hardening rejects earlier development commits whose CRDT dots, contexts, or counter authors were supplied by application state. No released database is migrated; development stores created before ADR 0001 must be recreated.
- A future migration must be crash-resumable and copy into a new format before replacing the prior store. In-place reinterpretation is forbidden.

MSRV is Rust 1.91 and is tested alongside stable.
