# ADR 0005: Serialize domain control with a designated controller

- Status: Accepted
- Date: 2026-07-19
- Decision owner: iroh-db protocol

## Context

Application commits are CRDT data and may safely have many concurrent writers.
Domain control changes are different: a transition selects a causal cut, rotates
the encryption key, revokes members, and may change the single-writer endpoint.
Choosing a winning sibling after either branch has been used would require
rolling back keys, authorization, and accepted encrypted data. Arrival-order
selection does not converge, while content-hash selection permits disruptive
reorganizations and nonce grinding by an administrator.

## Decision

1. Every controlled domain has exactly one designated controller. The genesis
   controller is the endpoint named as owner by the domain descriptor.
2. Only the current controller may sign the next control transition. The
   endpoint must also hold an active `Admin` or `Revoke` capability for the
   transition's previous epoch; designation never bypasses capabilities.
3. Each transition names the controller for its successor state and signs the
   exact successor capability ID. A transfer is valid only when that capability
   grants the successor `Admin` at the new epoch and is not revoked by the
   transition. Replicated successor evidence and the control head are installed
   in one durable transaction, so validation never depends on receipt order.
4. `MultiWriter`, `SingleWriter`, and `AppendOnly` continue to govern application
   commits independently. The existing `writer` field remains the application
   writer; the new `controller` field governs only the control chain.
5. Canonical control candidates observed before a fork are retained as immutable
   evidence. Two distinct transitions signed by the predecessor's controller for
   the same predecessor and sequence constitute controller equivocation. This is
   intentionally true even when one sibling would fail a later semantic check:
   the controller can already force denial of service by signing two valid
   siblings, and signature-only fork detection avoids arrival-dependent
   historical authorization. The first conflicting pair is retained and the
   domain is durably frozen; later candidates are rejected without mutation.
   Another epoch, authorization decision, network disclosure, or write cannot
   proceed.
6. A future explicit recovery protocol may resolve a frozen domain by projecting
   accepted data into a new domain or by a separately specified threshold
   recovery transition. Silent first-arrival or automatic sibling selection is
   forbidden.

## Consequences

Normal data writes stay local-first and multi-writer. Membership changes require
the designated controller to be available on one of its local devices, and
controller transfer must be performed before that device is retired. An honest
offline administrator may prepare invitations but cannot independently rotate
the group epoch. A compromised controller can deny service or equivocate, but it
cannot make honest replicas silently accept different authority histories.

The controller signer is an iroh endpoint identity. Copying its private key to
multiple devices violates the device-identity boundary and can trigger the same
equivocation freeze as malicious signing.

Epoch keys are archived before the selected control head advances and activated
afterward. Open reconciles a one-epoch catalog/head interruption only when the
archived key's distribution digest matches the durable head. This makes every
crash point recoverable without treating the key catalog as authority.

## Verification

Canonical-codec tests bind the successor controller and capability ID into the
signature and content ID. Store tests prove that a delegated administrator
cannot rotate, controller transfer takes effect exactly at the next transition,
and opposite receipt orders of two controller siblings leave both replicas
durably frozen.
Facade tests prove a frozen domain rejects reads of the active epoch for network
authorization and refuses subsequent local writes.
