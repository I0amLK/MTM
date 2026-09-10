# MTM-reboot engineering rules

Read `docs/CODE_STANDARD.md`, `docs/COMMIT_STANDARD.md`,
`docs/ACCEPTANCE.md`, and `records/governance/migration-graph.json` before changing code.

## Priority

1. Functionality, compatibility, mathematical finalization, and security boundaries.
2. Recorded, tested, reviewable, and reversible implementation.
3. Measured performance and structural optimization.

No lower-priority goal may weaken a higher-priority goal.

## Authority rules

- Every migrated component has exactly one production authority.
- Rust shadow implementations are read-only and side-effect-free.
- Python and Rust never write the same production state concurrently.
- There is one workflow transition authority and one finalizer authority.
- Native `dangerous` authority never grants workflow or project authority.
- No migration may change the 24-tool contract, hidden aliases, state schema,
  workflow protocol, OAuth behavior, or artifact semantics without a separate,
  explicitly approved contract-change milestone.

## Change rules

- Every commit references one `MTM-NNN` milestone.
- Every status change appends a migration event.
- Every completed, rejected, or cutover milestone appends a receipt.
- Do not add a new crate before its milestone is approved.
- Do not mix functional migration, unrelated cleanup, formatting, and optimization.
- Do not claim performance without A6 evidence.
- Preserve the source baseline and all failed/rollback evidence.

## MTM-016 approved contract-change work

Read `docs/MTM-016-NATIVE-PLAN.md` and `records/iterations/ITER-016.json`.
The operator approved independent MTM contracts, legacy alias retirement and one
maintenance-only `xtask` crate. This does not authorize production deployment,
historical evidence rewrites, weaker isolation or changed workflow authority.
Use the Rust source checks as delivered; unported Python/target suites remain
explicitly pending rather than being silently counted as passed.

Current commands: `cargo xtask audit`, `cargo xtask records`,
`cargo xtask retirement`, and `cargo xtask check`.
`cargo xtask capability --record` runs the Rust current-binary OAuth/socket and
500-assessment regression; it does not qualify browser, Native or compiled LaTeX.
`cargo xtask qualify --profile <protocol|target> --binary <artifact> --sha256
<digest> --record` selects an explicit artifact for the current Rust qualification
fixtures. `target` additionally requires a capable Native host and compiled LaTeX.
`--profile resource` additionally requires an explicit `--baseline` and
`--baseline-sha256` and compares bounded resource metrics without selecting either
artifact for production.
Read `docs/MTM-016-CANDIDATE-GATE.md`; neither profile can authorize release or
substitute for browser/resource/install/rollback responsibilities.
`cargo xtask native-preflight --record` measures the current Linux environment;
`check` embeds a fresh probe without skipping any tests. Read
`docs/MTM-016-NATIVE-PREFLIGHT.md`: namespace limits/errno are not proof of
host resource exhaustion, candidate correctness or full Native acceptance.
Commit messages are validated by `cargo xtask commit-message <FILE|--stdin>`.
The Git hook must remain executable; atomic patch updates preserve ordinary modes.
Every Python deletion must match `records/governance/python-retirement.json`,
including the baseline source hash and Rust replacement/coverage explanation.

The approved E-stage durable step-receipt implementation introduces state schema 3
and tool contract mtm-tools-v2. Read `docs/MTM-016-SUBMISSION-RECEIPTS.md`: a receipt
grants no authority, contains no raw capability or task context, and never licenses
replay of an unresolved submission. Keep start deduplication, crash reconciliation
and final host qualification explicitly pending. This development schema change
does not authorize opening production data or modifying an installed selector.
E2 follows with schema 4 and mtm-tools-v3; read `docs/MTM-016-E2-RECOVERY.md`.
Optional creation keys distinguish intended starts. recover_only never executes
missing requests or resets running/legacy pending work. Transition certificates
are committed atomically with their step result. This bounded recovery does not
qualify arbitrary mid-write crash replay or permit production deployment.
The next E2 checkpoint uses schema 5 and mtm-tools-v4 for restartable keyed
initialization; read `docs/MTM-016-E2-CREATION-RESUME.md`. Keep the permanent
private lock inode, no-clobber file publication, transactional database setup and
legacy enrollment distinction. Never call external commands, model/network/LaTeX
work or observers while holding the initialization lock. The existing pinned nix
filesystem binding is reused; no new package or compiler version is required.
Do not treat deletion provenance as runtime parity or real-client qualification.
Schema-6 caller-write reconciliation is documented in
`docs/MTM-016-E2-WRITE-RECOVERY.md`. Keep one journal per step, resource/role/domain
binding, strict acknowledgement validation and shared permanent file locks.
Recovery must never regenerate normalized records, execute missing writes or
promote an unknown action to success. No file lock spans observers or external I/O.
Legacy journals are not backfilled; restore pre-upgrade copies for rollback.
The next E2 database-write checkpoint retains schema 6 and introduces mtm-tools-v6.
Read `docs/MTM-016-E2-DATABASE-WRITES.md`: manifest/audit SQL and accepted-write
counts share one short transaction, normalizers remain in workflow, and no public
transaction callback is exposed. Summary counts must match durable counts. This
does not authorize replay of old opaque journals or arbitrary action effects.
Schema 7 records explicit enrollment for four database-only actions; read
`docs/MTM-016-E2-ACTION-TRANSACTIONS.md`. Metadata, project mode, domain seal,
revocation, transition and receipt commit together. Branch database sealing does
not certify its earlier file effects. Never backfill atomic enrollment for old
commit-ready work or run callbacks/observers/file I/O under a SQLite transaction.
The E2 action-file checkpoint keeps schema 7 and advances the MTM-owned tool
contract to mtm-tools-v9; read `docs/MTM-016-E2-ACTION-FILE-RECOVERY.md`.
Plans/direct proving/branch/join/failure/replan/verification actions must enroll
before internal private effects. Corrected resubmission may reuse only exact
sidecar-bound before/after bytes; sidecars store hashes/effect evidence, never
model or proof bodies. Multiple records appended by one action to one JSONL file
must be represented as one combined final effect. Do not infer or adopt legacy
unmarked pending work, and do not execute actions from recover_only.
The following mechanical checkpoint keeps schema 7 and advances the model-facing
contract to mtm-tools-v8; read `docs/MTM-016-E2-MECHANICAL-RECOVERY.md`. Branch
preparation uses deterministic identities and exact private files before committing
all branch/domain rows and the transition together. LaTeX execution stays outside
SQLite while its result and transition commit together. Exact final proof bytes may
be reused after the same finalization permit checks; conflicting bytes are never
overwritten. Done reconnect may repair only the derived manual validation manifest
and the existing promotion retry. Do not infer legacy partial branch rows, claim
external compiler exactly-once behavior, or extend this rule to model-action file
effects that remain pending.
The checker retains inherited host integration tests; in a nested Native sandbox
Bubblewrap tests can fail. Report those failures and compare with the frozen
baseline; never make the gate green by silently ignoring them. `audit --strict`
must remain nonzero while first-party Python or legacy Rust references remain.

## D8 local deployment and historical boundaries

D8 consolidates target/release/install machinery; read
`docs/MTM-016-D8-FAMILY-RETIREMENT.md`. `cargo xtask dist` stages exact bytes without
executing them or validating its version label. The reviewed candidate's own
`mtm install` selects only byte-identical self artifacts under an explicit state
root and selectors. `mtm status --state-root` and `mtm rollback --state-root`
verify local installation mechanics, never release qualification or database
rollback. A retirement family with pending forward acceptance must retain that
classification and list its gaps. Do not promote immutable historical target,
browser, resource or release receipts into current acceptance.

## F1 installed-upgrade fixture

Read `docs/MTM-016-F1-UPGRADE-QUALIFICATION.md`. The explicit `qualify --profile
upgrade` requires both reviewed artifacts and hashes. It tests real old/current
endpoints using only baseline-created disposable state, including stopped-copy
private-mode preparation and exact pre-upgrade restoration. It is not an in-place
production migration, browser/Native/compiled-LaTeX test, or release verdict.
Current source/protocol gates must clear the upgrade profile flag. Keep all failed
Native/resource and unprepared-legacy-mode observations; never widen scope from
the later successful prepared-copy rehearsal.

## F2 protected-patch permission fixture

F2 adds `qualify --profile permissions` for scripted real-MCP consent and protected
patch writes on disposable files. Read `docs/MTM-016-F2-PERMISSION-QUALIFICATION.md`.
Keep its 100-cycle/60-90-second bounds and explicit disabled-command/no-human scope.
Never infer full Native command/grant soak or browser acceptance from it. Other
source/qualification entries must clear `MTM_TEST_PERMISSION_PROFILE`.

## F3 interrupted deployment recovery

Read `docs/MTM-016-F3-INSTALL-INTERRUPTION-RECOVERY.md`. A `pending-v2.json`
journal must be durable before any install/rollback selector mutation. The next
locked `status`, `install` or `rollback` conservatively restores the pre-operation
state before continuing. Never delete the journal before the final postcheck or
describe persisted-prefix tests as a physical power-loss qualification.

## F4/F5 release blockers and corpus

Read `docs/MTM-016-F4-F5-RELEASE-CHECK.md`. `release-check` is read-only and
fail-closed; partial evidence may be structurally valid while its gate remains
blocked. `qualify --profile install_sigkill` is the exact-artifact external-process
SIGKILL drill on disposable selectors. It is not physical power-loss evidence.
Ordinary source/capability gates must clear all SIGKILL/deployment candidate test
environment variables. The fixed 30 x 3 corpus never promotes blocked Native,
research, browser/human or operator-state rows into passes.

## F4/F5 release blockers and task matrix

Read `docs/MTM-016-F4-F5-RELEASE-CHECK.md`. `release-check --binary <artifact>
--manifest records/governance/mtm016-release-inputs.json` is read-only readiness,
not release authorization. Missing or unsupported evidence adapters block it;
hash-bound observations are not authenticated human witnesses. The explicit
`qualify --profile corpus` emits all 30 x 3 task outcomes; initially only the 15
portable scenarios execute, with a new disposable server for each repeat.
Never count blocked rows, inert profile functions or protocol fixtures as research
or independent browser/consent acceptance. Clear `MTM_TEST_CORPUS_PROFILE` in
ordinary checks. An incomplete corpus and blocked release checklist exit nonzero.

## Historical local gate (before MTM-016)

```bash
python3 scripts/run_checks.py
```

Local success is not target/browser/CAS/LaTeX acceptance.
