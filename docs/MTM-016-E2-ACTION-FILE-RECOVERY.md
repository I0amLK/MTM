# MTM-016 E2: restartable action file effects

This checkpoint completes the current-contract E2 recovery matrix for model-driven
workflow actions without introducing a replay runtime or storing action bodies in
submission receipts.

## Scope

The previously atomic database-only actions remain unchanged:

- `assessment_complete`
- `exploration_complete`
- `proof_submitted` (including compact-to-full escalation)
- `repair_submitted`

The following actions are now explicitly enrolled as restartable before their
private internal file effects begin:

- `plans_proposed`
- `direct_proving_complete`
- `branch_complete`
- `join_complete`
- `failures_identified`
- `replan_complete`
- `verification_submitted`

`recover_only=true` on the exact original submission never executes one of these
actions. It only closes an exact enrolled pending receipt as
`SUBMISSION_INTERRUPTED`, preserving the already confirmed caller-write prefix.
The caller fetches the current task and submits a new request without replaying that
prefix.

## Stable private effects

Action-internal private files use a stable action-effect slot derived from the run,
task domain, epoch, action and logical slot. The sidecar stores only:

- a format version;
- the bounded private relative path;
- a content SHA-256;
- append/replace mode;
- the exact bounded before/after file images already used by caller-write recovery.

It never stores the proof, plan, branch result, join synthesis, failure summary,
replan decision or verification report body.

On a corrected resubmission:

- an existing file equal to the recorded after-image is reused byte-for-byte;
- a missing/unapplied effect equal to the recorded before-image may publish the
  exact originally prepared effect;
- changed action content, changed file bytes, changed path or malformed sidecar
  fails closed as `ACTION_EFFECT_CONFLICT`;
- the action is not inferred from workflow state alone.

For an action that appends several records to the same JSONL file, MTM records one
combined final file effect for that action/file pair. This prevents an earlier
record's sidecar from incorrectly treating later records from the same action as
external drift.

## Stable protocol-3 server fields

Protocol-3 records generated inside these actions no longer depend on a fresh
random record id or wall-clock timestamp when the action is corrected after an
interruption. Their server-owned identity and timestamp are deterministically
derived from the current run/domain/epoch/action/slot binding. Direct-screening
attempt ids are likewise stable for the same canonical plan/subgoal within the
same action attempt.

This stability applies only to action-internal retry identity. Ordinary new model
writes and independent later workflow actions retain their normal identities.

## Transition boundary

The restartable marker is consumed in the same SQLite transaction as task-domain
closure and the workflow transition. The completion receipt is written by the
existing transition certificate in that transaction. Therefore a failed transition
does not leave a consumed restartable marker, sealed task domain or completed
receipt behind.

The mechanism reuses schema 7 and the existing caller-write journal. No new table,
schema migration, package, background worker, timeout takeover or generic replay
engine is added.

## Recovery matrix after this checkpoint

Current-schema new work has a defined behavior for each mutation class:

- keyed run creation: durable creation identity and restartable initialization;
- caller file writes: before/after evidence and retained-prefix reconciliation;
- proof manifest/reference audit writes: database write plus acknowledgement in one
  transaction;
- four database-only actions: explicit atomic action transaction;
- seven file-affecting model actions: explicit restartable action plus stable private
  file effects;
- branch preparation, LaTeX state commit and terminal artifact completion:
  restartable mechanical advancement;
- opaque or historical unmarked pending work: remain `RESULT_UNKNOWN`, with no
  automatic replay or state inference.

`RESULT_UNKNOWN` is therefore still a legitimate terminal recovery answer when the
server lacks sufficient evidence. Deterministic behavior does not mean every old or
opaque side effect is reconstructed.

## Acceptance boundary

This checkpoint is protocol/recovery work, not release qualification. It does not
substitute for final real-host Native isolation, compiled LaTeX, browser/OAuth,
resource, install/upgrade/rollback or representative research-corpus acceptance.
Production selectors, production state and production keys are not changed.

