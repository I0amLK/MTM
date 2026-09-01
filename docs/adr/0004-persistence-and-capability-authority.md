# ADR 0004: Persistence and capability authority

## Status

Accepted for `MTM-004`.

## Context

Re-CTM schema version 2 stores workflow runs, domains, capabilities, branches,
steering, projects, claims, immutable revisions, references, audits, manifests and
promotion state in SQLite. Migration must preserve exact row semantics, transaction
ordering, fail-closed future versions and the single-writer rule. Capability tokens
must agree with both signed claims and persisted registry facts.

## Decision

- `mtm-storage` owns SQLite schema 2 and migrations `0 → 1 → 2`.
- Multi-step writes use `BEGIN IMMEDIATE`; external I/O is forbidden inside a
  transaction.
- The store exposes typed operations rather than a general SQL utility surface.
- Clock and ID sources are explicit. Production uses UTC/system randomness; shadow
  tests use deterministic sources without altering source behavior.
- Capability tokens use the source HMAC-SHA256/base64url format and require exact
  claim shape, registry parity, owner binding, epoch/state/domain validity, permission
  matching and role-resource firewalls.
- Python and Rust never dual-write one production database. Differential tests use
  separate copies, and target acceptance opens the configured source database through
  SQLite URI read-only mode before backing it up.
- Promotion remains one atomic transaction. Missing dependencies, base conflicts or
  insertion failures leave the active revision and project-run promotion state
  unchanged.

## Evidence

- 52 exact state, project, reference, promotion and capability operations.
- v0, v1 and v2 copied database parity plus future-version rejection.
- failed v2 migration rollback and source-runtime restoration from a v1 copy.
- real configured-state read-only backup with Python/Rust digest equality.
- cross-runtime capability issuance/validation and registry-tamper denial.
- serialized `BEGIN IMMEDIATE` writers and transactional Rust tests.

## Consequences

`mtm-storage` is the authoritative persistence/capability implementation for the new
Rust project, but Re-CTM Python remains the deployed production writer. Gateway and
workflow cutovers remain separate milestones. Rollback requires routing the future
composition layer back to Python against an unmodified or restored compatible
database copy; no production database was migrated by this milestone.
