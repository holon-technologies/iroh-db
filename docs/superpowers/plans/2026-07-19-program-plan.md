# iroh-db Program Plan

## Goal and Success

Implement the accepted `iroh-db` architecture from an empty repository through production Milestone 5. Each milestone must satisfy its documented acceptance gate before the next begins. The final result is a Rust-native local-first database that persists and queries locally, converges between iroh peers, enforces encrypted capability domains, projects sharing safely, streams encrypted blobs from multiple providers, and ships production verification and repair tooling.

## Approach

Implementation proceeds as five vertical, releasable increments. Network inputs always reuse the local validation and apply kernel established in Milestone 1. Durable formats are locked by golden tests before consumers depend on them. Later milestone plans are written only after the preceding gate, so their exact upstream iroh APIs and measured bottlenecks are evidence-based.

## Constraints and Non-Goals

- The accepted architecture spec is normative.
- Rust 1.91 is the MSRV; current stable is also tested.
- iroh owns endpoint identity, QUIC, discovery, routing and relays; iroh-gossip owns dissemination; iroh-blobs owns byte transport and hash verification.
- No SQL, joins, arbitrary merge functions, cross-domain atomicity, or server coordinator.
- No milestone begins with a failing prior gate.
- New behavior follows RED-GREEN-REFACTOR.
- Unsafe Rust is denied unless an ADR documents the exception.
- Security and cryptographic dependencies are audited rather than reimplemented.

## Program Tasks

### Task 0: Architecture Gate

**Resources:** `docs/superpowers/specs/2026-07-19-iroh-db-design.md`, `docs/milestones/M0.md`
**Depends on:** user vision and current official iroh documentation
**Interfaces and state:** accepted protocol, storage, CRDT, security, blob and milestone contracts
**Implementation:** preserve the accepted design; record later consequential changes as ADRs
**Failure behavior:** unresolved format/security decisions prevent Milestone 1
**Validation:** accepted status, no blocking open question, detailed Milestone 1 plan

### Task 1: Embedded Database

**Resources:** `docs/superpowers/plans/2026-07-19-milestone-1.md`, workspace library crates, `docs/milestones/M1.md`
**Depends on:** Task 0
**Interfaces and state:** typed Rust API, local commits, materialized views, queries, subscriptions, encrypted local blobs and snapshots
**Implementation:** execute the detailed Milestone 1 plan test-first
**Failure behavior:** retain the previous green slice; do not start networking
**Validation:** full M1 gate from the architecture spec

### Task 2: Distributed Sync

**Resources:** a gate-time M2 plan, `iroh-db-sync`, integration topology tests, `docs/milestones/M2.md`
**Depends on:** green Milestone 1
**Interfaces and state:** `/iroh-db/sync/1`, gossip hints, iroh-blobs dependency transfer, peer reconciliation and snapshot bootstrap
**Implementation:** write the detailed plan after confirming selected iroh versions against the M1 dependency graph; reuse the identical validation/apply path
**Failure behavior:** network errors cannot mutate or block local accepted state
**Validation:** partition convergence, authorization rejection, malformed input, crash/restart matrix

### Task 3: Sharing and Membership

**Resources:** a gate-time M3 plan, security/control modules, projection API, `docs/milestones/M3.md`
**Depends on:** green Milestone 2 and security review
**Interfaces and state:** invitations, delegated capabilities, epoch rotation, revocation cut, projection and rebase-required recovery
**Implementation:** lock attack-matrix tests before control-plane implementation
**Failure behavior:** rejected/old capabilities never mutate state; private history never crosses domains
**Validation:** capability and revocation attack matrix, multi-device and projection privacy tests

### Task 4: Blob Performance

**Resources:** a gate-time M4 plan, provider scheduler/cache modules, benchmarks, `docs/milestones/M4.md`
**Depends on:** green Milestone 3 and measured single-provider baseline
**Interfaces and state:** provider-independent `BlobStream`, scheduling priorities, caches and telemetry
**Implementation:** optimize only measured paths; delegate native fan-in to iroh-blobs if compatible
**Failure behavior:** provider loss/corruption degrades or retries without returning unauthenticated plaintext
**Validation:** range accounting, provider churn/corruption, fairness and throughput gate

### Task 5: Production Hardening

**Resources:** a gate-time M5 plan, CLI, fuzz targets, compatibility fixtures, CI/release configuration, `docs/milestones/M5.md`
**Depends on:** green Milestone 4 and repeated security review
**Interfaces and state:** verify/repair, backup/restore, migrations, observability and supported format matrix
**Implementation:** add operational tools around immutable blobs and rebuildable metadata; never repair in place without a verified shadow copy
**Failure behavior:** backup/repair/migration failures preserve the only good copy
**Validation:** 72-hour churn, rebuild/restore state-root equality, fuzz corpora, version matrix and regression budgets

## Resolved Decisions

All material architecture decisions are in the accepted specification. The user granted standing approval on 2026-07-19. There are no blocking open decisions.

## Execution

Use `superpowers:executing-plans` in the current checkout. Do not use sub-agents unless the user explicitly requests delegation. Use `superpowers:test-driven-development` for every behavior task, `security-review` before cryptographic/authentication work, and `superpowers:verification-before-completion` at every gate.
