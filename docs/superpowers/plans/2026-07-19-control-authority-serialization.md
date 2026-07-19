# Control Authority Serialization Plan

- Status: Complete

## Goal and boundary

Make the domain control chain genuinely single-successor without reorganizing
keys or application history. The accepted design is
`docs/adr/0005-designated-domain-controller.md`. This checkpoint covers durable
controller state and equivocation quarantine; automatic control/key distribution
over the sync protocol is a subsequent checkpoint.

### Task 1: Bind the controller to canonical control objects

**Resources:** `iroh-db-security` authority codec and golden tests

**Interfaces and state:** `ControlTransition` names the controller for the new
state. The field is signed, hashed, bounded by the existing canonical envelope,
and independent of the application `writer`.

**Implementation:** Add RED canonical/tamper tests, add the accessor and wire
field, and update issuance call sites.

**Failure behavior:** Missing, trailing, or modified controller data fails strict
decode or signature verification.

### Task 2: Enforce designated authority and transfer

**Resources:** `iroh-db-store` control metadata and tests, facade rotation API

**Depends on:** Task 1

**Interfaces and state:** Genesis derives its controller from the descriptor;
later state derives it from the canonical head. The next controller must have an
active `Admin` grant covering the new epoch and must survive the transition.

**Implementation:** Add `current_controller`, enforce author and successor
authorization, retain ordinary rotation, and expose an explicit controller
transfer rotation.

**Failure behavior:** A non-controller, unauthorized successor, or self-revoking
successor causes no control-head or credential change.

### Task 3: Quarantine controller equivocation

**Resources:** immutable control-object and fork-evidence tables, epoch lookup,
rotation tests

**Depends on:** Task 2

**Interfaces and state:** Distinct canonical siblings signed by the predecessor
controller are persisted in canonical ID order without consulting state mutated
by either sibling. A forked domain returns a typed error from active
control-state lookup.

**Implementation:** Atomically index observed transitions by control slot before
staging key activation, detect same-slot siblings against retained objects,
persist the first evidence pair, recover an interrupted one-epoch key activation
from the digest-bound archive on open, and make epoch, authorization, invitation,
sync, snapshot, and write paths fail closed through shared active-epoch lookup.

**Failure behavior:** Neither arrival order can continue using its first head;
reopen preserves the frozen state. Already accepted immutable bytes remain
available only to explicit repair/projection tooling.

### Task 4: Verify and checkpoint

**Resources:** focused authority/store/rotation tests, full workspace gate,
dependency policy, ADR and plan

**Depends on:** Tasks 1-3

**Validation:** `cargo fmt --all -- --check`, strict workspace Clippy,
`cargo test --workspace`, and `cargo deny check` with unchanged policy failures
recorded separately.

## Completion evidence

- `cargo fmt --all -- --check` passed.
- `cargo clippy --workspace --all-targets -- -D warnings` passed.
- `cargo test --workspace` passed; the extended partition/reconnect soak remains
  intentionally ignored for opt-in long-running verification.
- `cargo deny check` retained the pre-existing policy baseline: seven rejected
  license findings and the unmaintained `atomic-polyfill`, `paste`, and
  `proc-macro-error` advisories. Bans and sources passed.
- Independent read-only review found no remaining Critical or Important issues
  and marked the checkpoint ready to merge.
