# MTM-017 development-to-release handoff

## Current release-readiness acceptance, 2026-09-30

The exact `0.6.0-preview.2` candidate
`13d7890c5c763199ed39295e134ff6cc735ceaa04eaddf6c556431a7a56254f4`
is now release-qualified under the explicit
`technical_evidence_plus_scoped_operator_waivers` basis. The active governance
pointer is `records/governance/mtm017-release-inputs.json`; its immutable accepted
record is `records/evidence/MTM-017/release-readiness-accepted-20260930.json`.
The independent schema-8 adapter, input review, successful read-only evaluation,
and separate result review are documented in `docs/MTM-017-FORMAL-READINESS.md`.
The final maintenance source gate passed 712 tests, with zero failures and one
existing ignored test; it binds source
`39f42266b1dafc323b525130ba00cb11aac6f06f6a4448a132cdad6ac2add8f0`.

Technical corpus acceptance remains **87 of 90**, with the three U26 cells
explicitly waived under DECISION-006. DECISION-001 covers only the missing
historical `0.5.0-preview.2` binary; DECISION-003 covers only exact-candidate
clean-build provenance, which remains technically unreproduced. The separate
DECISION-007 accepts the prior source regression risk; its original failure is
still failed, its root cause remains indeterminate, and no runtime fix is claimed.
The three genuine U29 repetitions verify exact restoration before the approved
permissions preparation and same-old-run continuation. All original failures,
sealed observations and earlier corpus pointers remain unchanged.

Whole-project implementation completeness remains unknown; the accepted research
subset is the previously reviewed fifteen trials, with no new mathematical
acceptance here. Technical qualification completeness remains false.
Deployment is **not authorized** and no live state or installed selector changed.
The governance pointer is not itself a CLI input: its `evaluation_inputs` and
`input_review` references identify the separately reviewed evaluation inputs.
Re-evaluation requires the bound local artifacts and public chain; it does not
replay historical private or target archives.

## Historical versioned checkpoint before readiness acceptance

`0.6.0-preview.2` now has its own artifact identity and has passed the dedicated
schema-7 upgrade profile plus seven reexecuted machine profiles. See
`docs/MTM-017-PREVIEW2-QUALIFICATION.md` and the appended ITER-017 receipt.
The earlier development and same-label snapshot identities below are historical.
At this earlier checkpoint, real operator-state-copy compatibility, independent
client/mathematical trials, remaining corpus and complete schema-8 release
readiness were pending. The current scoped disposition is recorded above.

## Checkpoint boundary

MTM-017 delivers dangerous-only Native execution and schema-8 project fact
memory. Its development acceptance is A0, A1 and A3 as defined in
`docs/ACCEPTANCE.md`. The current lifecycle decision and sealed validation
identities are recorded in `records/iterations/ITER-017.json`.

The reviewed Rust source identity is
`61922484c1f969365660b052ab878250738542bf25bd870f40b3b6851ef1930d`
under `mtm-rust-source-v1`. The four implementation commits end at
`2cb49234014a4007ca7838837ebdab8f708ee2c9`; a separate records-only commit
seals development delivery without changing this source identity.

Development completion is not an installed upgrade, a release-qualified
artifact, or completion of MTM-016's remaining release work. Historical
MTM-016/MTM-015 receipts retain their original artifact and acceptance scopes.

Update, 2026-09-26: the earlier MTM-016 remaining-work summary was stale. Its
September 15 release is now lifecycle-reconciled, with the current missing older
rollback artifact recorded separately in `docs/MTM-016-LIFECYCLE-RECONCILIATION.md`.
Forward schema-8 machine qualification is recorded in
`docs/MTM-017-ARTIFACT-QUALIFICATION.md`; neither reconciliation nor those partial
profile passes authorize a new deployment.

## Forward acceptance remains explicit

| Work | Required evidence before the corresponding release claim |
|---|---|
| Exact artifact | Build and retain a reviewed candidate with its own SHA-256, source identity and configuration. Source tests and a different frozen candidate's receipts cannot qualify it. |
| Native commands | Run current dangerous-only command, isolation, TTY, timeout, process-cleanup and available CAS qualification on that candidate. A positive Bubblewrap prerequisite probe is not this qualification. |
| Real client and mathematics | Exercise the current OAuth/MCP path in a real client. Use separate reviewing sessions for mathematical trials; inspect actual statements, proofs and dependency material rather than treating fact IDs or scripted verdicts as mathematical evidence. |
| LaTeX | Compile full, compact and repair workflows with the required compiler policy on the candidate. Static-only capability tests and mocked gates do not establish this result. |
| Operator-state compatibility | Obtain separate operator authorization for a stopped or consistently backed-up state copy. Test schema-7 to schema-8 migration, existing-run resume and restoration of the original copy without touching live state. |
| Resources and installation | Measure equivalent baseline/candidate workloads and perform install/rollback qualification using explicitly selected disposable paths. Keep unexplained regressions and failed attempts visible. |
| Release decision | Evaluate complete current-artifact evidence and obtain a separate deployment decision. No source or capability pass changes installed selectors. |

Release acceptance must resolve any mismatch between a qualification harness's
frozen schema/artifact assumptions and schema 8 explicitly. Do not edit a sealed
receipt's hash, remove a required check or relabel blocked rows to make an older
release manifest accept the new development checkpoint.

## Rollback and data boundaries

Reverting development source does not downgrade a schema-8 database. Database
rollback restores an untouched pre-upgrade copy together with the compatible
binary; deleting fact rows or lowering `PRAGMA user_version` is not rollback.
Existing facts, IDs, proof artifacts and historical failures are not rewritten
by the target-dependency correction or the closing review.

No production state copy, installed-selector mutation, production schema
upgrade, public push, release tag or live-session restart is included in this
development closeout. These require their own reviewed operation and authority.
