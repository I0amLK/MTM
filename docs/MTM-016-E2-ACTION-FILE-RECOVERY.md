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

## Delivery

Implementation commit `1633ab8221dd9f394a87482923f35d4361e74cd3` keeps
state schema 7 and advances the MTM-owned tool contract to `mtm-tools-v9`.
The independent development artifact
`target/mtm016-e2-action-files/release/mtm` has SHA-256
`1e056a583e03effdbd2366056bf2b8985f929f4e712cf7c4bfa7da720ee673e4`.

Post-commit exact-artifact protocol qualification passed with 500 normal assessment
first hops (250 compact, 250 full), zero normal INVALID/rejections, three scripted
complete workflows, copied-v1 migration/new-run, restart/key checks, five Git tools
and the complete current `capability_runtime` recovery fixture family. The raw
passing report is sealed at
`records/evidence/MTM-016/candidate-protocol-e2-action-files-1633ab8.json`, SHA-256
`3f7592b025017d945746452361fd1727200b93dae598d3c3f9753f706ab4bf21`.

The first post-commit qualifier attempt is also preserved at
`records/evidence/MTM-016/candidate-protocol-e2-action-files-first-env.json`, SHA-256
`1c146c83b3fc76b8ef87745ff9001cdae01c1b95d23205d50dd5ea50ddcbc1d5`.
That attempt never launched the candidate: a recreated command sandbox had not yet
populated the full locked dependency cache needed by the qualifier's deliberately
offline child cargo runner. Running `cargo fetch --locked` in the same command
environment before the unchanged qualifier resolved the environment prerequisite.

The complete connected-sandbox source gate remains false only because the same ten
inherited Bubblewrap/Native Runtime tests fail; Runtime reports 128 passed, 10 failed
and one existing ignored target-only network test. Format, Clippy, the other Rust
targets and diff checks pass, with no new ignore or suppression.

With the successful exact-artifact run, Stage E is complete for the current contract:
new current-schema state-changing paths have either evidenced recovery or an explicit
deterministic no-replay result. Historical opaque/unmarked work remains
`RESULT_UNKNOWN`. This Stage-E completion is not release qualification.

