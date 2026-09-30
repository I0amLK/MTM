# MTM-017 fixed-inventory schema-8 readiness draft

## Scope and invocation

`cargo xtask release-readiness-schema8` is a separate, read-only maintenance
command. It emits `mtm017-readiness-draft-v1` to stdout and exits **1** because
complete schema-8 criteria and mandatory evidence are not implemented/available
in this reviewed inventory. This is a useful blocked draft, not an unexpected
success and not `mtm017-release-inputs.json`. It has no options, output writer,
record mode, manifest override, force, authorization or deployment action.

From the ordinary host checkout, respecting the existing tool-cache ownership:

```sh
CARGO_TARGET_DIR="$PWD/target/mtm-tool" cargo xtask release-readiness-schema8
```

Run a real draft only after independent implementation/input review. A separately
authorized coordinator may preserve stdout under a new, explicitly draft evidence
filename after checking exit status and complete JSON. Do not overwrite an older
receipt or final release-input pointer. The command itself creates no files.

The frozen MTM-016 release checker, cutover driver, manifest and all runtime code
remain unchanged. No candidate is executed; no operator database, OAuth storage,
private research bundle, installed selector or production state is opened. This
adds no crate/dependency, model tool or workflow authority. Future operator-state
capture/rehearsal implementation and its synthetic fixtures cannot satisfy a real
operator-state evidence gate; authorization and actual copy evidence remain separate.

## Closed fixed inventory, not a general evidence format

V1 compiles six reviewed path/SHA-256 roots: the preview.2 qualification snapshot,
research acceptance state, clean-build state, operator decision ledger, frozen
MTM-016 manifest and historical missing-binary record. Their existing exact seals
are in the implementation. It follows only sealed public path/hash references
within MTM-017 evidence or another exact compiled root. It also reads the two
fixed reviewed candidate/baseline artifacts. There is no caller-selected root
manifest, discovery of the latest run, new seal, or self-approved evidence input.
The old importer implementation-validation record is retained by its exact seal;
its historical `source_files`/`documentation` locators are deliberately not read
as current input bytes. Its old maintenance hash stays historical, while this
command reports a separate current source hash. Other outside-namespace references
are rejected rather than silently followed.

The accepted JSON byte language is closed to these exact reviewed hashes:
unknown fields, changed values, removed fields and even changed whitespace fail
the seal check. Duplicate keys at any depth, trailing data, excessive nesting
and oversized JSON also fail the existing bounded JSON decoder. Path/hash
references use a closed `deny_unknown_fields` type. Qualification reports use
the existing closed profile-specific validators. This is **not** a general
unknown-field schema validator or a format for newly supplied evidence. Adding
or superseding evidence requires a separately reviewed inventory/code revision.

Descriptor-relative `openat` reads prohibit traversal and symlinks on every
directory/leaf, non-regular files, multiple hard links, wrong ownership, other
write or special permission bits. Fixed public JSON already includes mode 0664;
V1 accepts that public archived-data mode, never executes it and never chmods
evidence. This does not relax the research importer's private bundle/catalog
rules. Executable artifacts must retain owner execute and cannot be group- or
other-writable. JSON is bounded to 1 MiB per file, artifacts to 32 MiB, inventory
to 128 files and reference traversal to 16 levels. Open file identity, size,
mode, ownership, link count, mtime and ctime are checked before/after reading.
Every input is reopened and compared by both bytes and metadata before output.

## Observations and release gate dispositions

Each of the eighteen rows explicitly identifies `scope`, `gate_disposition`,
`technical_pass`, `governance_disposition`, `observation_validation` and remaining
work. The disposition is one of `technical_pass`, `waived_by_operator`,
`missing_evidence`, `criteria_not_implemented`.

These are proposed gap-accounting rows, **not an approved complete release gate
registry**:

1. Exact selected candidate and schema-7 baseline bytes
2. Frozen source checkpoint versus changed maintenance source
3. Protocol fixtures
4. Generated-state schema-7/8/7 upgrade fixture
5. Dangerous-only Native command fixtures
6. Compiled-LaTeX fixtures
7. Paired resource workload
8. U16-U20 fifteen-row Native subset
9. Disposable process-SIGKILL recovery
10. Real external retrieval
11. Previously accepted U21-U25 fifteen-row research subset's public chain
12. Genuine schema-7 operator-state copy, old-run continuation and exact restoration
13. Real-browser OAuth/reconnect adapter
14. Complete current-candidate corpus
15. Current static records/retirement/Rust-only inventory
16. Complete schema-8 criteria/adapters
17. Clean-build single-gate human override
18. Historical 0.5.0-preview.2 missing-binary scoped waiver

The eight profile reports retain their original runner milestone and scope. V1
rechecks report seals, candidate/baseline bindings, all existing profile summary
validators, exact harness source and product commit. It recomputes the historical
source hash from Git, checks ancestry and checks tracked/untracked product-code
drift. These observations are displayed as scoped recorded passes while their
full schema-8 release gate adapters remain `criteria_not_implemented`, with
`technical_pass=false`. Generated upgrade data is not operator data, fixed proofs
are not independent mathematics, Native fifteen rows are not a full corpus and
one broad SIGKILL profile does not become three U30 trials.

Research revalidation binds the public inputs, separate input review, exact
proposal, independent result review, governance acceptance and fifteen distinct
original receipt seals/rows. It establishes `previously_accepted_subset=15` and
`public_chain_verified=true`, with `newly_accepted_trials=0`,
`private_bundle_artifacts_rehashed_now=false` and
`private_math_review_reexecuted=false`. The earlier independent review remains
an observation, not cryptographic authentication or newly proved mathematics.
Its row's technical pass is only this explicitly named public-chain validation.
The checker neither reopens private bundles nor repeats their mathematical review.

The corpus does not inherit historical 90/0, 78/12 or 63/27 totals, and does not
sum Native15 and research15 into a new 30/90 claim. Approved retirement of the
F2 consent/grant ledger is respected; it is neither a new waiver nor a pass.
The old U27/U28 consent/decline cases need an explicit schema-8 mapping and remain
`u27_u28_schema8_mapping_pending=true` rather than being silently removed or
mechanically required under the retired contract.

## Implementation, waivers and fail-closed output

Top-level `implementation_complete="unknown"` applies to the current whole tree.
`product_checkpoint.source_checkpoint_verified=true` identifies only the frozen
source observation. The changed maintenance source gets its own fresh hash and
`whole_source_gate_verified=false`; old source counts are never current counts.
Current read-only record, retirement and inventory checks are not a new workspace
test gate. `research_accepted=true` is scoped to the fifteen previously accepted
research rows. `requirements_complete=false`, `release_qualified=false` and
`deployment_authorized=false` are explicit. No observation can override them.

DECISION-001 only excludes the old missing 0.5.0-preview.2 binary for this exact
schema-8 candidate. It leaves the actual schema-7 baseline/copy/rollback
requirements intact and never claims the historical binary was recovered.
DECISION-003 only governs this candidate's clean-build provenance. The checker
cross-binds its active state, immutable decision, ledger entry, original failure,
prior gate, comparison and both build reports. It retains `passed=false`,
`exact_candidate_reproduced=false`, `technical_status="not_reproduced"` and the
distinct human governance allowance. Neither waiver becomes a technical pass,
new test result, cross-gate waiver or deployment authority.

Unexpected drift/malformed evidence fails before any draft is emitted. Valid
fixed observations still produce a blocked draft and nonzero exit. Completing
the actual release criteria requires reviewed future adapters and real evidence;
the permanent false flags in this deliberately bounded draft are not a proposed
substitute for such a completed checker. Real final inputs are assembled only
after the necessary operator-state and other prerequisites are genuinely closed.

## Verification and rollback

Maintenance tests cover option/authority rejection, seal/duplicate/unknown-field
failure, path/permission/link/file bounds, file replacement and mode drift,
candidate/harness/profile mutation, research approval/matrix mutation, waiver
scope and failure retention, eighteen unique rows and non-authorizing output.
Sealed public records used by parser tests are fixtures for validation behavior;
tests do not execute a real draft, count new trials or qualify a release.

Run maintenance tests, formatting, Clippy and applicable static aggregate checks.
Report passed/failed/never-run separately; maintenance verification is not a full
workspace source gate. Rollback removes the additive command/module/tests/doc
and preserves all existing evidence. There is no runtime/database rollback or
production deployment to reverse.
