# MTM-016 E2: creation identity and evidenced submission recovery

Base: `ed613d4ef72f0df210226811122d29d07cbea308`. Development only: preserve E1
artifacts/evidence and do not touch production keys, selectors or databases.

## Scope

An optional bounded `creation_key` identifies one intended start within an OAuth
owner. Bind its digest to the canonical workspace and normalized request. Distinct
keys (or absent keys) still create independent runs for identical problems. The
key is not authentication. Store no raw key, problem, request or capability in the
receipt. Reserve a server-chosen run ID before initialization; complete the receipt
in the same transaction as `created -> assess`. Replay returns the same identity,
not a new run, task or authority. Incomplete initialization remains explicitly unknown.

Step checkpoints distinguish prepared, running and commit-ready work. The original
worker must atomically activate before any workflow write. Explicit `recover_only`
on the original request may close a still-prepared reservation as not started;
activation and recovery race through the same transaction boundary. Recovery may
not execute a missing request or clear running/legacy unknown work.

Pair transitioned submission results with the actual workflow transition in one
transaction, bound to a server-issued execution trace, run/owner/domain/epoch/state
and accepted caller-write count. Crashes after that commit no longer leave a false
pending blocker. Record known non-transition/correction outcomes before next-task
construction. No transaction or mutex spans filesystem/network/model/LaTeX work.

Run-only task refresh must not mechanically advance a pending step. Read-only
status exposes its checkpoint without clearing it. Cancellation remains the
existing owner action, not a way to relabel an unknown submission successful.

Schema 4 adds creation receipts and checkpoints. Existing schema-3 receipts keep
their meaning; never invent checkpoints for old pending work. Rollback restores
pre-upgrade copies, never decrements the database version.

## Explicit limitations

There is no transaction across vault files and SQLite. Interruptions during a
write or inside an action before its transition can remain unknown. No timed
takeover, replay of partial writes, blanket pending reset or synthetic mathematical
success is allowed. Legacy unknown work and incomplete creation remain visible;
further recovery requires per-effect evidence. This is not general exactly-once,
complete crash reconciliation, distinct-capability deduplication, or Native/control/
retrieval idempotency. Do not mark E or release complete from this bounded delivery.

## Validation

Schema 3->4 and failed migration rollback; identity/workspace/owner conflicts;
independent intended starts; same-key races/restart; no secret/body persistence;
prepared recovery versus activation; atomic transition/receipt rollback; wrong
execution trace/epoch; legacy/running unknown refusal; real OAuth/MCP response loss
and multi-stage replay. Retain capability, finalizer, full-flow and integrity gates.
