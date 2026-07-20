# Production Testkit and Soak Qualification Plan

- Status: Complete
- Design: `docs/superpowers/specs/2026-07-20-production-testkit-design.md`

## Goal and Success

Turn `iroh-db-testkit` into the production fault-injection harness promised by
Milestone 5 and make the extended churn gate duration-based, restart-aware, and
evidence-producing.

## Constraints

- Exercise real production iroh and database paths; do not build a transport
  simulator.
- Add no durable or wire-format state.
- Keep faults explicit and deterministic.
- Never hide timeout, lifecycle, close, or divergence failures.
- Use RED-GREEN-REFACTOR for the new behavior.

### Task 1: Lock the missing harness behavior as RED tests

**Resources:** `crates/iroh-db-testkit/tests/cluster.rs`,
`crates/iroh-db-testkit/Cargo.toml`
**Depends on:** accepted design
**Interfaces and state:** cluster creation, directed sync, node lifecycle,
durable restart, schedule reports, convergence, shutdown
**Implementation:** add black-box tests against the public testkit contract and
run them before implementation
**Failure behavior:** failures must be behavioral or missing-capability
failures from the placeholder crate, never test setup mistakes
**Validation:** `cargo test -p iroh-db-testkit --test cluster` is RED for the
expected absent harness

### Task 2: Implement the real-iroh cluster and fault kernel

**Resources:** `crates/iroh-db-testkit/src/lib.rs`
**Depends on:** Task 1 RED evidence
**Interfaces and state:** `TestCluster`, `TestkitError`, `FaultStep`,
`FaultReport`, `ConvergenceReport`, rotating schedule
**Implementation:** own temporary roots/databases/nodes, validate all indices
and lifecycle transitions, wrap operations in deadlines, reopen durable peers,
converge full mesh, and clean up best-effort
**Failure behavior:** typed errors preserve stopped slots and never report
partial convergence
**Validation:** focused testkit tests pass under strict Clippy

### Task 3: Move churn and exact-duration soak onto the testkit

**Resources:** `crates/iroh-db-testkit/tests/churn.rs`
**Depends on:** Task 2
**Interfaces and state:** fixed accelerated rounds; duration/round/restart/
timeout environment inputs; final counts and state root
**Implementation:** remove bespoke topology orchestration, create record handles
only for each operation so restart is safe, apply rotating schedules, inject a
normal-lane restart, and print qualification evidence
**Failure behavior:** malformed or zero environment values fail clearly;
timeouts and restart failures fail the soak
**Validation:** ordinary churn plus a short ignored duration-driven soak pass

### Task 4: Qualify and checkpoint

**Resources:** README, SECURITY.md, M5 gate, changelog, release workflow
**Depends on:** Tasks 1–3
**Interfaces and state:** documented exact 72-hour command and reusable harness
**Implementation:** update claims and commands, add a manual/scheduled soak job
that retains logs, and record exact local evidence
**Failure behavior:** CI never labels accelerated rounds as 72-hour evidence
**Validation:** full release gates, independent review, staged diff inspection,
and a clean commit

## Completion Evidence

- The initial black-box cluster suite failed on the placeholder crate's missing
  public harness types, then passed all five tests after implementation.
- The ordinary churn lane completed eight rounds, 22 syncs, two durable
  restarts, convergence, and exact record-count verification.
- A two-second duration qualification completed three rounds, 12 syncs, three
  durable restarts, convergence, and exact record-count verification.
- Workspace formatting, strict Clippy, tests, docs, fuzz compilation,
  dependency policy, package-archive verification, publish dry-run, workflow
  YAML parsing, and diff checks passed.
- Independent review reported no Critical or Important findings.
