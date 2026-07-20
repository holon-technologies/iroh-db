# Fuzz Qualification Design

## Problem

Milestone 5 and the threat model require codec/CRDT fuzzing, retained malformed
protocol corpora, and clean-corpus release evidence. The repository currently
only compiles two decoder fuzz targets. It has no corpus, no CRDT target, no
corpus replay test, and no scheduled execution, so the documented production
gate cannot actually be run or audited.

## Decision

Keep the fuzz package outside the release workspace, but turn it into a shared
harness plus five cargo-fuzz entry points:

- commit envelope/body canonical decoding;
- sync-frame/gossip canonical decoding;
- signed authority, checkpoint, invitation, and ticket decoding;
- schema, record-field, and materialized-state decoding;
- deterministic merge-law checks across every built-in CRDT family.

Successful strict decodes must re-encode to the identical input. The CRDT
target constructs only valid replica states from arbitrary bytes and asserts
commutativity, associativity, and idempotence. A panic is therefore always a
decoder or merge invariant failure rather than rejected hostile input.

## Retained Corpus

Each target owns a checked-in `fuzz/corpus/<target>/` directory containing
small malformed, boundary-oriented, and structure-aware valid seeds. Stable
prefixes turn mutable seed suffixes into valid canonical objects so mutation
can cross successful decoder paths, including signed formats that blind byte
mutation is unlikely to construct. A normal Rust integration test discovers
every file, rejects missing/empty target corpora and oversized seeds, and sends
each retained input through the same shared harness used by libFuzzer. This
makes corpus regressions part of ordinary release qualification without
requiring nightly or cargo-fuzz.

Newly discovered crashing inputs remain normal cargo-fuzz artifacts. After a
failure is fixed and minimized, the minimized input is promoted into the
target's checked-in corpus so the stable replay test permanently locks it.

## Automation

A weekly/manual matrix workflow installs nightly cargo-fuzz and runs every
target for a bounded per-target wall time. Jobs upload the evolved corpus and
any crash artifacts even on failure. Release qualification replays retained
corpora with stable Rust; scheduled fuzzing provides mutation depth and does
not masquerade as a deterministic unit test.

The workflow rejects non-integer, zero, and over-budget durations before
libFuzzer starts, and uses a fixed memory cap. Every matrix job is independent,
so one crashing decoder cannot suppress evidence from the other target
families.

## Acceptance

The checkpoint passes retained-corpus replay, compilation of every cargo-fuzz
target, a bounded smoke run of every target, workflow parsing, full workspace
release gates, package checks, and independent review. Documentation records
the exact commands and distinguishes local smoke evidence from the recurring
qualification workflow.
