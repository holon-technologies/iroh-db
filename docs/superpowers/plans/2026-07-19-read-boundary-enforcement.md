# Read Boundary Enforcement Plan

- Status: Complete

## Goal and boundary

Require current `Read` at every network path that discloses domain data or
availability metadata. The accepted design is
`docs/adr/0004-read-is-a-data-plane-prerequisite.md`. A write-only sync protocol
and revocation of already downloaded data are non-goals.

### Task 1: Establish authorization regressions

**Resources:** `crates/iroh-db/tests/network_sync.rs`, capability replacement,
sync and snapshot bootstrap APIs

**Depends on:** ADR 0004

**Interfaces and state:** The provider's active endpoint grant is authoritative
even when the receiver still stores an older invitation grant.

**Implementation:** Add tests that replace the receiver with a
`FetchBlobs`-only capability, then attempt sync and snapshot bootstrap.

**Failure behavior:** Both operations fail and leave materialized state empty.

**Validation:** Observe the snapshot bootstrap bypass before implementation.

### Task 2: Gate sync, blob, snapshot, and gossip paths

**Resources:** `crates/iroh-db/src/network.rs`, shared capability resolver,
iroh-blobs request interceptor

**Depends on:** Task 1

**Interfaces and state:** Local and peer permission helpers compare the selected
domain handle to current durable epoch. Blob GET requires `Read` and
`FetchBlobs`; sync and gossip require `Read`.

**Implementation:** Revalidate on each provider GET and each gossip action;
authorize both sync handshake sides; retain generic remote denial behavior.

**Failure behavior:** Missing permission, revoked capability, stale epoch, and
authority lookup failure reject before accepting state or bytes.

**Validation:** Regression tests turn green and existing network suites pass.

### Task 3: Verify and checkpoint

**Resources:** workspace format, lint, tests, dependency policy, ADR and plan

**Depends on:** Task 2

**Implementation:** Audit data-plane entry points, record evidence, and commit.

**Validation:** `cargo fmt --all -- --check`, strict workspace Clippy,
`cargo test --workspace`, and `cargo deny check` with pre-existing policy
failures recorded separately.

## Completion evidence

- `cargo fmt --all -- --check`: passed.
- `cargo clippy --workspace --all-targets -- -D warnings`: passed.
- `cargo test --workspace`: passed; the explicitly opt-in extended soak remains
  ignored.
- `cargo deny check`: the unchanged repository baseline still reports seven
  rejected-license findings and the unmaintained transitive crates
  `atomic-polyfill`, `paste`, and `proc-macro-error`; bans and sources pass.
