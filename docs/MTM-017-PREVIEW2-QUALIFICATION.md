# MTM-017: versioned preview.2 qualification checkpoint

## Identities

The independently versioned `0.6.0-preview.2` candidate uses schema 8,
`mtm-tools-v10`, workflow protocol 3 and the same 24 public tools. The implementation
commit is `7b4afe2359e688263557f62154e4bc1e640c12c0` and the tested Rust source hash
is `0adec4b02a8b54fd20fb30c796c9959ccc346cc0f9336517fc47eafcb6951e02`.

The optimized candidate SHA-256 is
`13d7890c5c763199ed39295e134ff6cc735ceaa04eaddf6c556431a7a56254f4`.
Its immutable workspace snapshot is:

```text
target/mtm017-preview2/mtm-0.6.0-preview.2-13d7890c5c763199ed39295e134ff6cc735ceaa04eaddf6c556431a7a56254f4/mtm
```

The paired baseline is the archived, previously released schema-7 preview.1 at
`f59cbddaebb8b9944d1365d6d4f1c072e2cc78e76dbbce8d870308c470c88034`.
Neither snapshot is selected for production by qualification.

## Observed results

The complete source gate passed 633 tests with zero failures and one inherited
target-only ignored test. Format, warnings-denied all-target Clippy, record,
architecture, retirement and diff checks passed, with positive Native prerequisites
and unchanged before/after source and commit identities.

| Exact-candidate profile | Result and boundary |
|---|---|
| `upgrade_schema8` | 21 checks passed: 7-to-8 migration, legacy revisions/proofs retained without fact backfill, zero-write completed-receipt replay, new fact promotion, old/new run progression, same-key restart, two disposable selectors and exact snapshot restoration to schema 7. |
| `protocol` | 500 independent assessments, split 250 compact / 250 full, zero normal INVALID/rejections; all eight adversarial checks, lifecycle and workspace checks passed. |
| `native_commands` | Dangerous-only isolation, seven risk classes, 32 command cycles, TTY/stdin, timeout/kill, descendant cleanup and functional Sage/Magma checks passed. |
| `compiled_latex` | Required `latexmk`/`pdflatex` compact, full and repair flows passed, final artifacts matched, and unsafe shell escape was rejected. |
| `resource` | Three starts and 180 measured requests per artifact passed the unchanged non-regression thresholds against schema 7. No performance improvement is claimed. |
| `corpus_native` | U16-U20 repeated three times each: 15 passed, zero failed. This is not the full 90-trial corpus. |
| `install_sigkill` | Actual external-process SIGKILL and journal-based recovery passed on eight disposable selectors. This is not physical power-loss or production cutover evidence. |
| `retrieval` | Actual HTTPS retrieval and cross-domain redirect denial passed; no credentials or returned bodies were archived. |

The qualifier validates reports before publishing them. All eight generated
reports are archived byte-for-byte under `records/evidence/MTM-017/preview2-*`.
The complete source-report JSON is compacted only in whitespace; reconstructing
its two-space pretty encoding reproduces the original stdout report SHA-256
`98b86a4dbe23e9f8b0e20c84f4a14aebb5ca1895b2f4f0b725d05d2bc501daf0`.
The inherited runner label remains MTM-016, but exact source, candidate and profile
identities bind these new observations. No old receipt or release input is replaced.

## Failure retained and corrected

The first source run failed five deployment fixtures because they passed a
hard-coded preview.1 label to preview.2. The installer correctly rejected the
mismatch. Current fixture arguments and recovery paths now use the compiled package
version, and the negative test explicitly rejects the old label before writing.
All eight deployment tests and the subsequent complete source gate passed.
The original failure is sealed separately, not relabelled as a pass.

## Remaining release conditions

The upgrade test explicitly prepares private modes in stopped, generated fixture
state. It proves this conditional migration and exact restoration, not an
unprepared in-place operator upgrade. Separately authorized operator-state-copy
compatibility, real-client and independent cross-run mathematical trials, remaining
current-artifact corpus coverage, reproducible clean-build provenance and a complete
schema-8 readiness/deployment decision remain required. Scripted verifier fixtures
are never independent mathematical review.

The historical missing 0.5.0-preview.2 rollback binary is not recovered by this
checkpoint. The schema-8-to-schema-7 fixture instead uses the exact archived
0.6.0-preview.1 baseline. Both production selectors and the deployment manifest
were rechecked unchanged; no live session, production database or remote branch
was modified. `release_qualified` remains false.
