# MTM-016: U25 dangerous-Native acceptance v2

## Approved scope

The operator selected the real daily research path: U25 uses dangerous Native.
It must execute both Sage and Magma on three fresh sessions, retain exact input,
output, version and exit-status evidence, prove the general theorem independently
of finite computation, compile with required LaTeX, and obtain a separate reviewer
on the same live OAuth connection before finalization and collection.

Do not add a safe-permission release gate. The existing permission tests and
U28 observations remain unchanged; U25 no longer duplicates their responsibility.
There is no new runtime mode, public tool, workflow authority, state schema or
licensing mechanism. Dangerous Native does not grant verifier/finalizer authority.

## Version boundary

| Evidence | U21-U24 | New U25 |
| --- | --- | --- |
| session | mtm-research-session-v1 / safe | mtm-research-session-v2 / dangerous |
| CAS observation | not applicable | mtm-research-cas-observation-v2 |
| public research trial | mtm-research-trial-evidence-v1 | mtm-research-trial-evidence-v2 |

The new complete research batch is `mtm-research-corpus-batch-v2`. Its aggregate
wrapper remains v3 with the exact 78/0/12 boundary. External aggregation remains
v4 with the exact 90/0/0 boundary. No partial or fabricated batch is published.

U25 v2 CAS tool records contain only name, version, input_sha256, output_sha256
and exit_code. The surrounding observation contains schema, run_id, native_mode,
general_proof_independent, raw_credentials_recorded and tools. Unknown fields,
including the old permission fields, fail closed. Missing material stays a
reported blocker; contradictory present material fails. Hashes establish byte
correspondence, not authenticity of execution or mathematical correctness.

## Frozen evidence and requalification

This amendment changes acceptance-only Rust code, launcher, tests and documents.
It does not change crates/, Cargo.lock, the frozen corpus, the case registry, the
f59cbdda candidate bytes or c674843 candidate-source identity. No product rebuild
is necessary for this scoped amendment. Do not copy old receipts onto a newly
rebuilt product identity if a future change does affect the product.

U21-U24 and U26-U29 evidence stays byte-immutable. The new tests check version
separation; review must also compare the exact existing receipt hashes. The old
safe U25 attempts remain diagnostic history and cannot become v2 passes by editing
metadata. The previous safe r1 must not be resumed as a dangerous trial. Preserve
it and use the newly committed launcher for each fresh v2 session.

Because xtask source changes, the previous source qualification is stale. Run
and seal a fresh capable-host source check; do not edit the old source receipt or
weaken release-check. Then complete U25 x3, build the complete research batch,
aggregate v3 then v4, and run the unchanged full release checklist. A passing
readiness checklist still is not deployment authorization.

## Execution and validation

After review, tests and a dedicated commit, the ordinary-host entry remains:

```sh
bash scripts/mtm016-research-session.sh --task U25 --repeat 1
```

Use repeats 2 and 3 for the other sessions. Do not reuse the earlier wrapper that
pins HEAD to 114b23f. The main launcher derives schema and mode from the task;
there is no arbitrary --native-mode override. Its environment and CLI both use
the same selected mode for preflight and TUI. It never creates workflow runs or
submits approvals, verifier reports, trial passes or release authorization.

Use literal CAS argv without artificial permission-trigger strings. Preserve
actual command responses and their exact input/output bytes for collection. Do
not claim previously run outer diagnostics as execution inside the new trial.

Required checks: shell syntax and session conformance, all mtm-xtask tests,
formatting and clippy, the complete capable-host source gate, immutable-receipt
integrity, retirement and strict audit. The source gate must not skip Native
failures in a nested sandbox. Real U25 computation and independent review are
separate from these synthetic contract tests.

Rollback: revert the dedicated acceptance-amendment commit. Do not modify an
installed selector, production state, old receipts or either generation of
private trial history. V2 trial receipts cannot be imported by the old v1 batch.
