# MTM-016 F1: exact installed-runtime upgrade and state rollback

Round 4/5 starts at `188da23fbb33e47d0d329d8845b9eb26d1706aa3`.
This is a bounded part of F, not completion of all target/release acceptance.

## Test contract

Extend the existing `cargo xtask qualify` entry with an explicit `upgrade` profile.
It requires distinct reviewed candidate/baseline artifacts and their SHA-256
digests, and reuses private executable snapshots and bounded child capture.
No production data path or selector can be supplied to this fixture.

The real baseline runtime creates a disposable OAuth identity and active run.
After graceful shutdown, copy its complete owned data/workspace trees into a
bounded private snapshot. Check exact contents, paths and ordinary modes. Launch
the candidate through its own self-install command on two disposable selectors,
then run the installed artifact against the baseline-created data. Require old-run
resume, a new run, same-key restart and the current schema. Stop the candidate,
restore the pre-upgrade state, roll selectors back, and require the real baseline
runtime to serve and advance the restored old run again. Recheck both artifacts
and the frozen state copy. Selector rollback alone is never data rollback.

All client requests use the actual loopback OAuth/MCP boundary. This profile is
deliberately Native-disabled and LaTeX static-only; unlike target/resource it has
no Native prerequisite. That is a separate scope, never a fallback that turns
failed target/resource tests green. The initial supported old-runtime fixture is
0.5.0-preview.2/schema 2; current schema/version must match this source contract.

## Negative tests and acceptance

Reject incomplete/equal/incorrect artifact pairs, wrong or duplicate summaries,
missing checks, widened browser/Native/production claims, fractional counts,
snapshot symlinks/non-regular files, size overflow, state drift and foreign snapshot
ownership. Ordinary source/protocol gates clear the upgrade selector flag.
Artifacts, source identity and summary counts are rechecked independently of a
successful runner exit. Errors and receipts contain fixed stage labels and hashes,
not OAuth credentials, private database contents or raw MCP/log output.

## Remaining F requirements

Fresh target/resource commands on the unchanged D8 artifact currently stop at
Native preflight with ENOSPC and no candidate launch. Preserve these failures.
Real Native safe/trusted/dangerous, TTY/CAS, compiled-LaTeX full/compact/repair,
retrieval/browser/human consent, resource bounds and permission soak remain open.
The fixture-created state is not a copy of the operator's production databases;
production-data rehearsal requires separate explicit approval and evidence.
This work does not prove multi-selector SIGKILL/power-loss recovery, complete
Python retirement, the 30-task x3 corpus or a new release qualification decision.

## Observed legacy-permission prerequisite

The first actual upgrade attempt opened schema-2 state and retrieved the old run,
but its first submitted write returned `FILE_EFFECT_CONFLICT` with zero accepted
writes. The baseline-created private tree contained five group/other-writable
entries in this environment. Current cooperative file effects intentionally
reject those modes; neither schema migration nor a selector switch fixes them.
That first failed qualification is retained, not overwritten by the later pass.

The fixture now explicitly prepares only its **stopped owned private-state copy**:
directories become 0700 and files 0600. It verifies that no names/content or
unrelated modes change, records the number of changed/shared-write entries, and
does not alter the frozen pre-upgrade snapshot. The real candidate can then
resume the old run, create a new one and restart. Rollback restores the original
snapshot's bytes **and modes** before launching the real old binary again.
This is conditional copied-state upgrade evidence, not a claim that arbitrary
unprepared legacy installations can be upgraded in place. No product mode check
is relaxed and no production path gains an automatic chmod operation.

## Operator entry

From the checkout, after the locked dependency cache is available:

```sh
cargo xtask qualify --profile upgrade \
  --binary target/mtm016-d8/release/mtm \
  --sha256 955b097c8fdbb781a5ae5d7da9797c1b57d5a84bf755502c25a856016439025f \
  --baseline /home/lk/.local/share/mtm/releases/0.5.0-preview.2/mtm \
  --baseline-sha256 2164c84701b191b06a66a5d28ba595697d355f9a3bdc78ca31ea455d49793d6a \
  --record
```

Only the two reviewed binary paths are read; their parent production state is not
opened. `candidate-upgrade.json` is a regenerable report. Seal its exact bytes
under `records/evidence/MTM-016/` and bind the hash in the iteration receipt.
`selector_changed=true` in this profile names **disposable fixture selectors**;
`production_selectors_changed=false` remains separate and mandatory. Failure
after possible execution leaves launch/selector outcomes unknown, not false.

Only maintenance/test code is changed; the D8 product artifact is retained rather
than silently rebuilt/replaced. Revert the dedicated F1 commit(s) to remove this
profile without changing any live installation, key or database.

## Build isolation during verification

Run source checks and qualification sequentially when they share a Cargo target
directory, or use separate target directories. The first composed source run
overlapped an upgrade qualifier and additionally failed the existing repeat-install
test (five deployment tests passed, one failed). That test copies the Cargo-built
artifact and subsequently invokes the shared Cargo binary path, so concurrent
rebuilds can invalidate its self-identity requirement. This is a plausible
interference mechanism, not a proven attribution from the failure alone. Preserve
that observation and run the same full gate again without concurrent builds.

The unchanged sequential rerun passed all six deployment tests, all 42 CLI
capability/recovery functions (three profile entries inert), and 63 maintenance
unit plus 11 maintenance CLI tests. Format, Clippy and diff checks passed. The
full gate remains nonzero only for the same ten inherited Native/Bubblewrap tests
(Runtime: 128 passed, 10 failed, one existing ignored test). No test was waived.

An independent clean checkout and restricted compiler/tool PATH are supplemental
checks. Absence of Python from that PATH is not proof that no interpreter exists
anywhere on the host, and does not retire the 67 remaining first-party Python files.

## Post-commit observations

Implementation commit: `d9129f05a14228f218f7a8beb7de733217c45db9`.
A separate `git clone --local --no-hardlinks` of that commit was clean before
execution. Locked offline release build and all 63 maintenance unit / 11 CLI tests
passed with the pinned compiler and an explicit C/Git/curl/Bubblewrap tool PATH,
without a Python executable on that PATH. Build output used a separate target
directory. This is scoped build/test evidence, not full-host Python removal.

The clean build produced SHA-256
`496f83ba59578a61833d2bef40085bc6e5771a0d5edb0a30d5aeca7bbccc6183`
(13,580,984 bytes), distinct from the retained D8 SHA-256
`955b097c8fdbb781a5ae5d7da9797c1b57d5a84bf755502c25a856016439025f`.
Both report version 0.6.0-preview.1, schema 7 and mtm-tools-v9. Product source,
Cargo manifests/lockfile and toolchain pin were unchanged between D8 and F1.
The byte difference is retained as an observation, not attributed without further
investigation; no byte-reproducible-build or interchangeable-artifact claim is made.

The original D8 artifact passed post-commit protocol qualification (500 normal
assessments, no normal INVALID/rejection, full/compact/repair fixtures) and the
clean-checkout upgrade profile against the exact preview.2 baseline. Upgrade
passed all 15 declared checks after stopped-copy mode preparation, with an exact
25-entry / 221,439-byte original snapshot restored before the old runtime resumed.
The standalone clean-build artifact is assessed separately and never overwrites
D8 or the production installation. Exact sealed report paths and remaining scope
are recorded in the F1 delivery receipt.

The clean-build artifact also passed its own 15-check upgrade profile, its own
500-assessment full/compact/repair protocol qualification, and exact-byte `dist`.
Both successful upgrade reports bind schema 2 -> 7 -> 2 and original snapshot
restoration; neither report claims browser, Native execution or compiled LaTeX.
All four post-commit qualification reports, the byte-identical copied dist report
and the explicitly labelled clean-build observation are sealed in
`MTM016-F1-UPGRADE-DELIVERY`. F1 is complete for that conditional fixture scope;
the overall F stage, production migration and release remain incomplete.
