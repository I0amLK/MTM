# MTM-016 E2: restartable mechanical advancement

Base: `d5aa47937ca7f0aad2f540f7e6c2f03501354b6c`. Development only. This is
round 1 of the operator's final five planned MTM-016 delivery rounds. It does not
authorize production deployment or qualify the installed preview.2 state.

## Scope

Close three mechanical interruption windows that do not require another model
submission or a new recovery daemon:

- `branch_prepare -> branch_run` derives stable snapshot/branch identities from the
  run, round, index and server-normalized plan id. The snapshot and assignment
  payloads are byte-stable on retry. Missing private files are published before the
  database transaction; exact existing files are reused and conflicting bytes fail
  closed. Branch/domain rows, active snapshot metadata, branch-request clearing,
  run transition and epoch change commit in one short SQLite transaction.
- `latex_validate -> verify|repair` still runs the actual LaTeX gate outside SQLite.
  The already-computed gate result, `latex_passed` value and state transition then
  commit together. A database failure can therefore cause LaTeX validation to be
  rerun after reconnect; no exactly-once claim is made for the external compiler.
- Final proof publication is idempotent only when the existing final bytes exactly
  equal the verifier-approved draft. Different existing bytes are never overwritten.
  After the run has reached `done`, reconnect may recreate only the derived,
  non-authorizing manual-validation manifest and may run the existing idempotent
  project-promotion retry. It does not republish different proof bytes.

Schema remains **7**; no table, crate, dependency package, compiler version or
background agent is added. The model-facing tool contract advances to
`mtm-tools-v8` so current clients are told which mechanical states are restartable.
Workflow protocol remains 3 and public tool count remains 24 with zero hidden aliases.

## Failure and legacy rules

The branch-preparation database transaction refuses an already-partial current-round
legacy branch set with `MECHANICAL_LEGACY_PARTIAL_UNKNOWN`; it does not infer that
old rows belong to the deterministic retry and does not delete them. New branch
preparation cannot leave a subset of branch/domain rows if transition insertion or
metadata update fails.

Mechanical snapshot/assignment/final/manifest files use the existing private atomic
writer and exact-byte comparison. They are not enrolled in the caller-write receipt
journal because there is no caller capability authorizing these mechanical effects.
This checkpoint does not claim resistance to a hostile same-UID process changing
private files between checks, nor power-loss durability beyond the existing atomic
writer and SQLite FULL-synchronous boundaries.

The final artifact remains controlled by the existing unforgeable finalization
permit. An exact pre-existing `proof_verified.tex` is reusable only after the same
permit checks the current draft hash. A mismatched final file returns
`FINAL_ARTIFACT_CONFLICT` and is preserved.

## Regression evidence

Tests are added before or with the fixes. The branch-preparation fault initially
left database branch rows after private branch initialization failed; the regression
failed on the expected zero-row assertion. After the fix, the same fault leaves zero
branch/domain rows and retry produces exactly one snapshot and one branch set.

The Done-reconnect fault makes `debug/manual-validation-manifest.json` a directory.
Final proof publication and the `finalize -> done` transition succeed, then manifest
publication fails. Before the reconnect fix the manifest remained missing; after the
fix, a later `next_task` in `done` recreates that derived manifest while the verified
proof bytes remain unchanged.

Storage regressions additionally inject transition failure into branch preparation,
verify all branch rows/metadata/transition roll back together, refuse a legacy
partial current round, and couple LaTeX result metadata to its transition. The vault
test repeats finalization with the same permit/bytes and then verifies a conflicting
final file is refused rather than overwritten.

## Remaining E2 boundary

This delivery does **not** make all workflow actions restartable. Planning,
direct-screening, join and verification still have action-owned file effects that
must be reconciled explicitly, as do branch-result/branch-state files around branch
completion. Those are the planned focus of the next delivery round. Legacy unknown
submission records stay unknown; no timeout, blanket reset or replay is introduced.

Final Native host, real browser, compiled-LaTeX target, resource, install/upgrade/
rollback and research-corpus acceptance remain F-stage work. First-party Python
retirement remains separate and no Python is deleted by this checkpoint.

## Delivery

Implementation `4e08475524b057e367a1bd55febb802dde8d6a30` keeps state schema 7 and
advances the MTM-owned tool contract to `mtm-tools-v8`. The independent release
artifact `target/mtm016-e2-mechanical/release/mtm` has SHA-256
`44eb052244b2a5075a8cc95b8d0c6f496ecd6dbbbf7a8b67bdb863580786b724`.

The complete sandbox source gate remains false only because the same ten inherited
nested-Bubblewrap Runtime tests fail: Runtime reports 128 passed, 10 failed and one
existing ignored real-network test. Format, Clippy, all other Rust targets and diff
checks pass; no test is suppressed. The separately rerun Runtime target confirms the
same ten names. This does not reuse historical host success for the schema-7/v8
candidate.

Post-commit exact-artifact protocol qualification passed with 500 normal assessment
first hops (250 compact, 250 full), zero normal INVALID/rejections, three scripted
complete workflows, copied-v1 migration/new-run, restart/key checks and five Git
tools. The raw report is sealed byte-for-byte at
`records/evidence/MTM-016/candidate-protocol-e2-mechanical-4e08475.json`, SHA-256
`ba13b008ddb04699556881ba686266349ea5f0270dc0d4b3bd29b7eccaaafdb1`.
Those 500 first hops are not 500 independent mathematical proofs, and the protocol
profile has Native disabled and static-only LaTeX.

No package/version/schema migration, Python deletion, production selector, installed
binary, production database or key changed. The next planned final-five round is the
remaining model-action file-effect recovery and E-stage closure.
