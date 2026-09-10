# MTM-016 F4/F5: release blockers and measured task coverage

Starting point: `3a13720b0576b21f428280f9a64e3caf2c16af8d`.
This work must not relabel incomplete round 4 as complete. F1/F2/F3 receipts
prove only their declared scopes. In particular, constructed interrupted-prefix
fixtures are not an externally killed installation process, scripted form
responses are not human consent, and static LaTeX is not compiler acceptance.

## F4: a read-only, fail-closed release checklist

Add `cargo xtask release-check --binary <artifact> --manifest <repo-relative-json>
[--record]` in the existing maintenance crate. Require explicit candidate hash,
candidate source commit, evidence-harness hash, baseline hash and individually
hash-pinned evidence paths. Reuse existing qualification summary validators;
never trust a report's top-level `passed` without rechecking its counts and scope.
Reject unknown/duplicate JSON fields, wrong artifact/source identities, unsafe
paths, oversized input, duplicated evidence and cross-profile substitutions.
Recheck current record integrity, retirement and Rust-only inventory separately.

The output is a readiness checklist, not a deployment permission. It never
installs, invokes an evidence-supplied command, opens operator state or produces a
release certificate. Required gates with no reviewed evidence adapter stay blocked,
even when someone supplies a JSON file saying `passed=true`. File hashes establish
integrity, not an independent witness or authenticity of a human observation.

## F5: declare all 30 tasks before running the three-repeat matrix

Use one versioned static corpus with 30 distinct tasks and three repeats each.
Initially execute the 15 portable public-MCP workspace/Git/workflow tasks, each in
its own newly created disposable server. The other 15 explicitly require Native,
research/compiled-LaTeX, external-client/human or operator-state/process-kill
evidence. Emit all 90 rows. Blocked, failed and passed are distinct outcomes;
an incomplete matrix exits nonzero and cannot satisfy the release checklist.

This is a usability corpus, not 90 independently verified mathematical proofs.
Do not repurpose a previous 500-assessment protocol fixture as the corpus, copy a
single result into three rows, or fabricate completion for unsupported tasks.
Candidate bytes and corpus bytes are hash-bound before and after execution.
No new crate, runtime dependency, workflow schema or product tool is introduced.

## Verification and record discipline

Add negative tests for nested duplicate JSON keys, report identity/scope drift,
missing evidence, false top-level success, missing/duplicate/relabelled matrix
rows, incomplete repeat coverage and protected-path input. Run formatting,
warnings-denied Clippy, maintenance tests, the real explicit corpus and the full
source gate sequentially in a persistent locked/offline toolchain environment.
Preserve failed reports; seal new observations in ITER-016 with exact hashes.
Implementation and delivery evidence are separate commits. No push or production
cutover is included. Revert these dedicated commits to remove the maintenance
entries without altering production state.

## Current implemented boundary

The release checklist has 14 required evidence categories plus current record
integrity, retirement provenance and Rust-only inventory. All 14 evidence
categories now have explicit reviewed adapters. Source/protocol/permissions/
upgrade/target/resource reuse their existing qualification validators; clean-build,
install-SIGKILL, corpus, Native commands, compiled LaTeX, retrieval, browser/human
consent and copied operator-state use strict dedicated schemas. Missing evidence
stays `required_evidence_missing`, and clean-build/corpus can validate honest
partial evidence without making their gates pass. This still is not a deployment
authorization mechanism. Install and dist remain explicit local mechanics, not
tools that confer release qualification.

The initial matrix yielded 42 successful portable trials, three U15 failures and
45 blocked trials. U15 used a malformed handle that the public JSON schema
rejected before capability validation. Its fixed negative input uses the existing
catalog test's syntax-only shape and has no valid signature. A separate regression
then confirmed capability rejection, zero accepted writes and no state advance.
The original failed run and direct diagnostic observations are preserved.

The corrected matrix executed all 15 portable cases three times on the exact F3
artifact: 45 passed, zero failed, 45 blocked. The runner exited zero, but the
qualification command exited one at `corpus_coverage`. It retained all 90 rows;
no task count, repeat requirement or real-client requirement was relaxed.
Candidate, harness and corpus hashes were unchanged throughout that run.

Use the following from the checkout with the pinned toolchain/cache available:

```sh
cargo xtask release-check --binary target/mtm016-f3/release/mtm \
  --manifest records/governance/mtm016-release-inputs.json --record
cargo xtask qualify --profile corpus --binary target/mtm016-f3/release/mtm \
  --sha256 589db2a1e639a3a5ba7c10e39a04c0a6a68440b2e2319bc05d5e45f59aa3b2a8 --record
```

Both currently return nonzero for incomplete acceptance. These invocations use
neither production-state paths nor installation selectors. Round 4 remains
blocked; round 5 is in progress rather than declared complete.

The full composed source check passed format, warnings-denied workspace Clippy,
six deployment unit tests, seven deployment CLI tests, 46 capability/recovery
test functions (five explicit profile functions inert), 72 maintenance unit and
13 maintenance CLI tests. Its only failed target remained `mtm-runtime --lib`:
128 passed, ten existing Native/Bubblewrap failures, one existing ignored test.
That failed full check is sealed separately and is a release blocker, not a
portable-test waiver. Current records and retirement provenance checks passed.

Post-commit implementation identity is
`d59e7f9dcf9376c345e41d1773e0b77e9db28f2e`. Its separately rerun exact-artifact
corpus again returned 45 passed / zero failed / 45 blocked, with all 90 rows and
unchanged source/corpus/candidate hashes. This is one 90-row partial matrix,
not 90 passes obtained by adding together two runs of the portable half.
The readiness input manifest may reference that partial observation, but the
complete-corpus release adapter remains deliberately unavailable until reviewed
real-world task execution and complete evidence ingestion are implemented.

The same exact F3 artifact also completed post-commit protocol qualification:
500 normal assessments with zero normal rejection/INVALID, and full, compact
and repair routes. The finalized report binds implementation commit `d59e7f9`
and unchanged harness hash `6f00e648b0a67102d0bc7bf30189e2010e38d9d45d277bed0a4bafb6a7ad4269`.
Its owned runner exited zero, reaped children and closed pipes. One command-status
poll was blocked by the tool platform; acceptance is based on the subsequently
read and hash-verified finalized report, not an inferred outer-command exit.
No Native, compiler, browser, human or release claim is inferred from that pass.

Final release readiness has five validated conditions and twelve blockers out of
seventeen. Protocol, permissions and prepared-copy upgrade retain their exact
scopes; current record integrity and retirement provenance also pass. This does
not discharge the incomplete source/Native/full-corpus/retirement gates. Eight
forward evidence adapters remain unfinished. The delivery receipt is
`MTM016-F4-F5-DELIVERY` in `records/iterations/ITER-016.json`. No push, installation
selector switch, production database read/write or secret change occurred.

Subsequent F4 work adds an exact-artifact `install_sigkill` qualification profile.
It starts the selected candidate as an external process, installs eight disposable
regular-file selectors, starts a real rollback, waits until the durable recovery
journal and a strict partial selector prefix are simultaneously observable, then
sends SIGKILL from the parent test process. The next separately started `status`
must reconstruct the active candidate on every selector and remove the journal;
a final rollback must then reproduce every original selector byte hash and mode.
This is process-kill evidence, not physical power-loss, controller-cache or shared
filesystem evidence. The profile environment is explicitly cleared from ordinary
source/capability gates so it cannot alter unrelated tests.

A detached clean worktree at source commit `cc17b16` was also built with the
locked dependency graph in offline mode. The build succeeded, but its artifact
SHA-256 was `512f0e1ba4d90c476b1e44141cc832eb3d3a1093d11b385f96b86bbae5fa3a05`,
not the selected F3 candidate SHA-256 `589db2a1e639a3a5ba7c10e39a04c0a6a68440b2e2319bc05d5e45f59aa3b2a8`.
The clean-build gate therefore remains blocked; no reproducible-build claim is
made and Python-free PATH was not proven by that observation.
