# Dependency Policy Hardening Plan

- Status: Complete
- Design: `docs/superpowers/specs/2026-07-19-dependency-policy-design.md`

## Goal and Constraints

Turn the full dependency-policy command used by CI from a known failure into a
fail-closed green gate. Preserve all required iroh networking behavior and do
not globally suppress license families or advisory classes.

### Task 1: Preserve the failing gate as RED evidence

**Resources:** `deny.toml`, `.github/workflows/ci.yml`, `Cargo.lock`
**Depends on:** current committed dependency graph
**Interfaces and state:** cargo-deny's four checks and process exit status
**Implementation:** run the exact CI command and record the rejected packages,
advisory IDs, and dependency paths.
**Failure behavior:** distinguish known reviewed findings from unknown errors;
do not change dependencies merely to silence output.
**Validation:** `cargo deny check` exits 5 because licenses and advisories fail
while bans and sources pass.

### Task 2: Encode narrow reviewed exceptions and notices

**Resources:** `deny.toml`, `THIRD_PARTY_LICENSES.md`
**Depends on:** Task 1 and current upstream/version verification
**Interfaces and state:** exact package specifications, exact advisory IDs,
human-readable reasons, authoritative license links
**Implementation:** add package-version-scoped license exceptions; add
reasoned advisory ignores; publish required third-party notices.
**Failure behavior:** any new package under those licenses or any unlisted
advisory continues to fail. Obsolete ignores remain visible to cargo-deny.
**Validation:** `cargo deny check` passes and reports only explicit ignored
advisories plus warning-level duplicate versions.

### Task 3: Align release evidence and automation

**Resources:** `.github/workflows/release.yml`, `SECURITY.md`,
`docs/milestones/M5.md`, `CHANGELOG.md`
**Depends on:** Task 2
**Interfaces and state:** CI/release command parity and documented exception
review process
**Implementation:** run the full policy gate during release qualification;
document that exceptions must remain exact, reviewed, and removable; pair
local workspace compilation with a no-verify publish dry-run because Cargo
cannot verify mutually unpublished package tarballs against one another; add a
separate extracted-archive verifier that patches those package dependencies
locally and compiles every packaged crate with all targets.
**Failure behavior:** releases stop on any dependency-policy, source-build, or
package-assembly failure.
**Validation:** full cargo-deny passes; ordinary publish dry-run reproduces the
stale-registry API failure; `cargo publish --workspace --dry-run --no-verify`
packages every crate; `bash scripts/verify-packages.sh` compiles the extracted
archives; workflow syntax inspection and diff audit pass.

### Task 4: Verify, review, and checkpoint

**Resources:** workspace and fuzz gates, independent read-only review
**Depends on:** Tasks 1-3
**Interfaces and state:** clean production checkpoint
**Implementation:** run format, strict Clippy, tests, docs, fuzz compilation,
full cargo-deny, and review; commit only with no Critical or Important finding.
**Failure behavior:** any failed gate or broad exception blocks the commit.
**Validation:** record exact final commands/results here and mark complete.

## Completion Evidence

RED evidence from the committed base:

- `cargo deny check` exited 5: advisories and licenses failed while bans and
  sources passed. The complete output identified seven exceptional-license
  packages and three informational unmaintained advisory IDs.
- `cargo publish --workspace --dry-run` exited 101 while verifying
  `iroh-db-store`, because Cargo substituted the stale registry
  `iroh-db-security 0.1.0` API for the mutually unpublished workspace crate.

GREEN evidence from the final policy and release configuration:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo check --manifest-path fuzz/Cargo.toml --all-targets
cargo test --workspace
cargo doc --workspace --no-deps
cargo deny check
bash scripts/verify-packages.sh
cargo publish --workspace --dry-run --no-verify
git diff --check
```

The full workspace suite passed with only the existing opt-in extended soak
ignored. Cargo-deny reported advisories, bans, licenses, and sources all OK.
The artifact-aware package verifier compiled every extracted workspace crate
with all targets. The publish dry-run packaged all ten workspace crates and
reached a client-side dry-run upload for each. Both workflow YAML files parse
successfully. Independent final review found no Critical or Important issues
and returned `Ready: Yes`; it also confirmed that a simulated stale advisory
ignore fails the policy gate.
