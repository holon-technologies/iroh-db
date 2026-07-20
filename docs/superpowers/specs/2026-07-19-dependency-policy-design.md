# Dependency Policy Hardening Design

- Status: Approved by standing user approval
- Date: 2026-07-19

## Outcome

Make the repository's exact CI dependency gate pass while keeping new licenses,
new advisories, vulnerabilities, unsoundness reports, yanked crates, and unknown
sources fail-closed.

## Current Failure

`cargo deny check` fails on the committed tree for two distinct reasons:

- `minicbor`/`minicbor-derive` use `BlueOak-1.0.0`;
  `async_io_stream`/`pharos`/`ws_stream_wasm` use `Unlicense`; and the two
  Mozilla root-certificate data packages use `CDLA-Permissive-2.0`. None has a
  package-scoped exception.
- current upstream `iroh` and `iroh-blobs` transitively retain three
  informational unmaintained advisories with no patched version:
  `RUSTSEC-2023-0089`, `RUSTSEC-2024-0436`, and `RUSTSEC-2024-0370`.

The installed and registry-current versions are `iroh 1.0.2` and
`iroh-blobs 0.103.0`, so a dependency upgrade cannot remove these findings.
Disabling iroh's networking features would weaken the required endpoint,
relay, NAT-traversal, and blob behavior and still would not remove both
iroh-blobs paths.

## Chosen Policy

License acceptance is package-and-version scoped. The seven reviewed packages
receive exact `deny.toml` exceptions rather than globally allowing any of the
three licenses for future dependencies. A third-party notice names the
packages, links the Blue Oak and Unlicense authoritative terms, and reproduces
the complete CDLA-Permissive-2.0 agreement alongside the shared certificate
data as its section 2.1 requires.

Advisory acceptance is ID-scoped with a reason on every entry. Only the three
informational unmaintained notices are ignored. The policy does not lower the
advisory severity threshold or ignore all transitive unmaintained crates.
Consequently a new vulnerability, unsoundness advisory, yanked package, or
newly unmaintained crate still fails CI.

## Maintenance and Failure Behavior

Exact package versions intentionally make dependency updates fail until their
licenses are reviewed again. Cargo-deny also diagnoses ignored advisory IDs
that no longer apply, and `unused-ignored-advisory = "deny"` makes that diagnosis
fatal so obsolete exceptions are removed after upstream migrates. CI and
release qualification both run the same full command.

## Release Dry-Run Semantics

Release qualification compiles and tests the complete local workspace before
assembling and extracting every package archive. The verifier patches each
normalized manifest's internal dependencies to the other extracted archives,
then compiles every packaged crate with all targets. Cargo's ordinary publish
verification cannot model mutually unpublished workspace packages: it resolves
each internal dependency from crates.io and, for this workspace, compiled
`iroh-db-store` against the stale published `iroh-db-security 0.1.0` API. After
artifact-aware compilation, the no-verify publish dry-run performs Cargo's
client-side pre-upload checks. Registry-server validation remains possible only
during actual publication.

## Validation

The existing red `cargo deny check` is the behavioral regression. The final
tree must pass that command, strict workspace quality gates, and a review that
confirms exceptions are no broader than the observed dependency graph.

## Sources

- Open Source Initiative, Blue Oak Model License and Unlicense listings:
  <https://opensource.org/licenses>
- Community Data License Agreement Permissive 2.0:
  <https://cdla.dev/> and
  <https://spdx.org/licenses/CDLA-Permissive-2.0.html>
- Blue Oak Model License notice terms:
  <https://blueoakcouncil.org/license/1.0.0.html>
- RustSec advisory records:
  <https://rustsec.org/advisories/RUSTSEC-2023-0089.html>,
  <https://rustsec.org/advisories/RUSTSEC-2024-0436.html>, and
  <https://rustsec.org/advisories/RUSTSEC-2024-0370.html>
- Cargo-deny package-scoped exceptions and reasoned advisory ignores:
  <https://embarkstudios.github.io/cargo-deny/checks/licenses/cfg.html> and
  <https://embarkstudios.github.io/cargo-deny/checks/advisories/cfg.html>
