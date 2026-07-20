# Fuzz Qualification Plan

- Status: Complete
- Design: `docs/superpowers/specs/2026-07-20-fuzz-qualification-design.md`

## Goal

Make the M5 fuzz gate executable and auditable with broad decoder coverage,
all-family CRDT merge fuzzing, retained corpora, deterministic replay, and
scheduled mutation runs.

### Task 1: Lock corpus and harness requirements as RED tests

**Resources:** `fuzz/tests/corpus.rs`, `fuzz/corpus/`, `fuzz/Cargo.toml`
**Depends on:** accepted design
**Implementation:** require one non-empty bounded corpus per declared target
and replay every seed through shared target functions
**Failure behavior:** missing target functions/corpora fail before automation
can claim qualification
**Validation:** fuzz-package tests initially fail to compile against the absent
shared harness

### Task 2: Implement shared decoder and CRDT invariant harnesses

**Resources:** `fuzz/src/lib.rs`, `fuzz/fuzz_targets/*.rs`, `fuzz/Cargo.toml`
**Depends on:** Task 1 RED evidence
**Implementation:** add strict decode/re-encode checks, security/state decoder
coverage, and valid arbitrary-byte CRDT replica construction with ACI laws
**Failure behavior:** rejected hostile bytes are normal; successful
non-canonical decode or merge-law violation panics with target context
**Validation:** retained-corpus tests and all-target compilation pass

### Task 3: Add retained seeds and recurring fuzz automation

**Resources:** `fuzz/corpus/`, `.github/workflows/fuzz.yml`, release workflow
**Depends on:** Task 2
**Implementation:** check in malformed/boundary and structure-aware valid
seeds, run a weekly/manual bounded per-target cargo-fuzz matrix, retain evolved
corpora/artifacts, replay corpora on release
**Failure behavior:** a target crash fails only its matrix job while every job
still uploads available evidence
**Validation:** every target passes a bounded local smoke run and workflow YAML
parses

### Task 4: Qualify, document, review, and commit

**Resources:** README, SECURITY.md, changelog, M5 evidence
**Depends on:** Tasks 1–3
**Implementation:** document commands and regression-promotion policy, run full
release gates, obtain independent review, and commit a clean checkpoint
**Validation:** full gates and package verification pass with no unresolved
Critical or Important review findings

## Completion Evidence

- The RED corpus test first failed against the absent shared harness and then
  against the absent per-target corpus.
- All five nightly cargo-fuzz targets completed bounded mutation runs against
  isolated copies of the eighteen retained seeds with no crash artifact.
- Stable and Rust 1.91 replay, all-target compilation, formatting, and strict
  Clippy pass for the fuzz package.
- Duration validation accepts the inclusive 1 through 18,000 range and rejects
  empty, zero, negative, non-numeric, over-budget, and oversized digit strings
  before libFuzzer starts; all workflow YAML parses.
- Workspace tests/docs, both cargo-deny graphs, packaged-crate compilation, and
  the workspace publication dry-run pass on the final tree.
- Independent review reports no unresolved Critical or Important finding.
