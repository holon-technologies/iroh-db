# ADR 0009: Four-MiB Default Blob Chunks

Status: Accepted
Date: 2026-07-20

## Context

The architecture proposed a one-MiB default while allowing 64-KiB through
eight-MiB chunks. Milestone 4's real iroh multi-provider implementation showed
that four-MiB chunks materially reduce per-object scheduling, QUIC, hash, and
AEAD overhead while still providing responsive seeking and enough independent
work for provider fan-in and bounded prefetch.

## Decision

New imports default to four-MiB independently encrypted chunks. The accepted
64-KiB through eight-MiB range remains unchanged. Every manifest signs its
actual chunk size and exact chunk descriptors, so readers never infer this
default and existing objects retain their original layout.

## Consequences

Small random seeks may transfer more ciphertext than under the proposed
one-MiB default, while sequential media throughput and scheduler overhead
improve. Applications that prioritize fine-grained seeking may select a
smaller supported chunk size through lower-level import configuration when
that API is exposed; changing the import default does not change the manifest
format or verification rules.
