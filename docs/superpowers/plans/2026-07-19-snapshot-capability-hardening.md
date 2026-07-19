# Snapshot Capability Hardening Plan

- Status: Complete
- Completed: 2026-07-19

## Goal and boundary

Make snapshot bootstrap a fail-closed, explicit authority operation. Success
means a snapshot is accepted only when its signed content, active capability,
epoch, control head, canonical state, and causal baseline all agree, while every
failure leaves the prior materialized root unchanged.

The accepted design is
`docs/adr/0002-authorized-snapshot-trust-chain.md`. This checkpoint changes the
snapshot wire format and store validation, but does not add M-of-N attestation,
historical control-proof transport, snapshot discovery, or blob-fetch protocol
authorization. Blob-fetch authorization is a separate security boundary and
will receive its own ADR and plan after this checkpoint is green.

Rust, canonical CBOR, redb, iroh-blobs, XChaCha20-Poly1305, and Ed25519 remain
unchanged. Because the repository is greenfield, version-1 snapshot migration is
a non-goal.

### Task 1: Reject unauthorized snapshot creation

**Resources:** `crates/iroh-db/src/{db,snapshot}.rs`,
`crates/iroh-db/tests/snapshot_rebuild.rs`, capability-store APIs

**Depends on:** ADR 0002

**Interfaces and state:** A controlled-domain creator must have the exact active
capability permitting `Snapshot` at the current durable epoch. Private domains
use the domain-derived implicit capability and trusted-device membership.

**Implementation:** Add a RED least-privilege member test, introduce one shared
permission-resolution helper, and call it before reading/exporting state or
writing a snapshot blob. Reject stale domain handles.

**Failure behavior:** Unauthorized or stale creation writes no snapshot blob and
changes no database metadata.

**Validation:** Focused snapshot authorization test and existing private-domain
snapshot tests.

### Task 2: Bind signed snapshots to current authority

**Resources:** `crates/iroh-db/src/snapshot.rs`, snapshot CBOR structs,
`iroh-db-security::ControlTransition`, network bootstrap tests

**Depends on:** Task 1

**Interfaces and state:** Snapshot format version 2 adds `epoch`,
`control_head`, and `capability_id`. The signature covers those fields through
the canonical content bytes. Installation compares all three to durable local
authority before decoding state into the store.

**Implementation:** Add RED unit tests for stale control and mismatched
capability/epoch envelopes. Extend canonical encoding and authorize the envelope
signer against its captured active capability.

**Failure behavior:** Reject unsupported versions and stale or mismatched
authority before the atomic install call; retain the old state root.

**Validation:** Snapshot unit tests, controlled-domain network bootstrap, epoch
rotation, and private-domain bootstrap.

### Task 3: Validate the causal baseline defensively

**Resources:** `crates/iroh-db-store/src/store.rs`, durable store tests,
snapshot encode/decode helpers

**Depends on:** Task 2

**Interfaces and state:** Records, covered commits, frontier commits, and author
sequence entries are strictly ordered and duplicate-free; frontier is a subset
of coverage. Empty history has empty frontier and author sequences.

**Implementation:** Add RED store tests for duplicate/unsorted metadata and a
frontier outside coverage. Validate before opening the replacement transaction;
also reject noncanonical record ordering at the facade boundary.

**Failure behavior:** A malformed baseline returns a typed validation error and
does not clear or replace any existing materialized or causal state.

**Validation:** Focused store tests plus snapshot install/rebuild/tail tests.

### Task 4: Verify and checkpoint the snapshot boundary

**Resources:** workspace tests, rustfmt, Clippy, dependency policy, ADR and plan

**Depends on:** Tasks 1-3

**Interfaces and state:** Format version 2 and its authorization semantics are a
durable protocol decision.

**Implementation:** Refactor only while focused suites remain green. Review all
snapshot call sites for bypasses and commit the completed checkpoint.

**Failure behavior:** Do not claim or commit completion while snapshot,
authority, network bootstrap, formatting, lint, or workspace tests are red.

**Validation:** `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace`, and `cargo deny check`; record any pre-existing
dependency-policy failures separately.

## Completion evidence

- Format check, strict workspace Clippy, and the complete workspace test suite
  passed after the final code change. The extended soak remains explicitly
  ignored by its existing test annotation.
- `cargo deny check` remains red on the pre-existing license allowlist for
  `Unlicense` and `BlueOak-1.0.0`, plus the existing unmaintained transitive
  advisories for `atomic-polyfill`, `paste`, and `proc-macro-error`. This
  checkpoint introduced no dependency or lockfile changes.
