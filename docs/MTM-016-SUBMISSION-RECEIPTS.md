# MTM-016 E1: persistent step submission receipts

Base: `648679f64a889728cf1e9c9794a514c9e04a9581`. This is an approved E-stage
contract/storage change, not a deployment. State schema 3 adds durable receipts;
workflow protocol 3, role ACLs and the single finalizer are unchanged.

## Bounded delivery

Protect `rethlas_step` submissions using the SHA-256 of the original, opaque
server capability as the operation identity. Bind it to the OAuth owner,
canonical workspace digest, run, domain, role, epoch, issued state and a versioned
digest of action/payload/ordered writes. A receipt is NOT an authority token.
No raw capability, next task, proof, context, OAuth token or request body is saved
in the receipt. Existing workflow data keeps its established private storage.

An existing receipt is accessible only after current-signer signature validation,
registered-claims consistency and owner/run/workspace checks. Revoked/expired
capabilities may identify their own existing receipt, never a new write. Missing
receipts retain the normal capability validation/rejection/refresh behavior.

Before any logical write, reserve a receipt in a short SQLite transaction. Check
the live run/domain/capability again in that transaction. Only one pending step
per run may execute, including requests using another capability for that run.
No mutex or SQLite transaction is held across filesystem/network/LaTeX work.

After the existing workflow path returns a structured result, store only a typed
completion summary. Identical replay returns that summary with zero new writes
and NO capability or task context. The caller fetches the current task separately.
Changed content on the same operation identity is an idempotency conflict.

A crash or unclassified error after reservation leaves the receipt pending.
Pending means RESULT_UNKNOWN, not failure, not zero writes and not permission to
retry. Another token does not bypass the pending-run guard. There is deliberately
no TTL eviction or automatic takeover. Recovery/reconciliation is an E2 task.
Bound receipt counts to 4096/run and 100000/database; capacity exhaustion refuses
new work without deleting safety tombstones.

## Non-goals and upgrade boundary

This does not yet deduplicate `rethlas_start`, control/retrieval calls, distinct
capabilities after a completed submission, or arbitrary Native operations. It
does not claim an atomic transaction across SQLite and vault files, exactly-once
shell execution, or automatic crash reconciliation. It never silently recreates
a run after an uncertain start. Those gaps remain visible in E2 acceptance.

The pending guard covers step submission execution, not a global workflow lock:
owner status/control and the existing mechanical current-task path keep their
semantics. A status observation alone does not reconcile or clear a receipt.
Known structured correction results release the reservation by completing a
correction receipt; an unclassified partial failure deliberately does not. This
can leave a run blocked and is a reason not to deploy E1 before E2 acceptance.

Schema 2 is migrated transactionally to 3 and old schema-1/2 rows are preserved.
The historical bootstrap contract remains schema 2. Old schema-2 binaries must
not open schema 3 as if compatible. Rollback of disposable development state is
restoring its pre-upgrade copy, not decrementing PRAGMA user_version or dropping
receipt rows. No installed binary, selector or production database is changed.

## Acceptance

Test schema 2->3, migration rollback, newer-version rejection and preserved copies;
cross-owner/run/workspace, changed request, altered/rotated signing keys, expiry,
concurrent same/different capabilities, durable pending and completed receipts,
counts/capacity and no raw token/body persistence. Exercise actual authenticated
MCP replay before/after restart and check memory/transition counts independently.
Keep the 500 normal-assessment and complete protocol fixtures. Environment-blocked
Native and final target/browser/resource/install gates remain separate observations.
