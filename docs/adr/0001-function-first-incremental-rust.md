# ADR-0001: Function-first incremental Rust reboot

## Status

Accepted in `MTM-001`.

## Context

Re-CTM 0.3.0 is a functioning Python system with public compatibility, security,
persistence, mathematical workflow, and manual-validation obligations. A one-shot
rewrite would combine language migration, contract interpretation, data migration,
authority cutover, and optimization into one unreviewable risk.

## Decision

MTM-reboot is a separate repository delivered in eight milestones. Python remains the
production reference until each component has passed golden and shadow comparison,
integration/security testing, relevant target acceptance, and rollback review.

The project uses:

- one production authority per component;
- read-only Rust shadow execution before cutover;
- an acyclic target crate dependency graph;
- intentional native-isolation and finalization choke points;
- append-only milestone events, receipts, iteration records, and failed-check evidence;
- performance claims only after A0–A5 and an explicit A6 benchmark.

## Consequences

- Migration is slower than a branch-wide rewrite but every accepted state remains
  usable and reviewable.
- Temporary compatibility adapters are allowed only at coarse, recorded boundaries.
- Python deletion occurs only in `MTM-008`, separately from authority cutover.
- Graph metrics guide investigation but never override functionality or security.
