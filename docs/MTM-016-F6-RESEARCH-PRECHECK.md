# MTM-016 F6: read-only research evidence precheck

## Scope and exit status

From this checkout on Linux, run:

```sh
cargo xtask research-precheck --bundle /absolute/private/evidence-bundle
```

This is an evidence preparation tool, not the research collector, mathematical
verifier or corpus importer. It never starts a server, runs a compiler/CAS,
submits a workflow action, changes an owner, updates a release manifest or adds a
passed trial. It has no `--record`, `--accept`, binary override or automatic
approval option. Use the Cargo-cache ownership rules in
`docs/MTM-016-F6-CARGO-CACHE-OWNERSHIP.md`; a Native tool invocation must not write
the operator's default Cargo target directories.

Exit 0 means the selected material is present, its bytes match the bundle's
digests, and the implemented common-fact checks find no inconsistency. It is NOT
research acceptance. Missing material produces a bounded JSON checklist and
exit 1. Invalid schemas, contradictory facts, changed bytes and unsafe files
produce a fixed diagnostic and exit 1. Neither outcome modifies the inputs.

Every successful inventory, including a fully populated synthetic fixture,
explicitly keeps `research_trial_passed=false`, `accepted_trials_delta=0`,
`release_qualified=false` and `manual_validation_required=true`.

The normal producer for a sealed real run is the host-side Rust collector in
`docs/MTM-016-F6-RESEARCH-COLLECTOR.md`. Precheck remains independently callable
for synthetic/negative fixtures, but a release-bound real trial must not be
assembled by hand from guessed server facts. The collector invokes this same
precheck before publishing its private bundle and still receives no acceptance or
release authority.

## Private bundle boundary

Select one explicit directory with mode 0700. Keep real research bundles outside
the repository. The command does not discover sessions, read a workflow database,
scan an operator HOME, or use the development connection's identity to adopt a
disposable research run. No directory component may be a symbolic link. Files
must be regular, singly linked, owned by the bundle-directory owner, and neither
group/other writable nor set-id/sticky. Use mode 0600 for evidence files.

The Linux reader holds directory descriptors and opens fixed leaf names with
`openat`, no-follow and nonblocking flags. It rejects links, FIFOs and other
special files, and checks descriptor metadata before/after bounded reads.
Directory replacement cannot redirect an already-open descriptor to another
tree. JSON inputs are limited to 1 MiB each, other text to 4 MiB each, and total
bundle input to 32 MiB. Duplicate JSON keys at every depth are rejected.

Do not put OAuth keys, tokens, capabilities, tunnel URLs, private databases or
`operator.log` in the bundle. A fixed filename is not permission to copy a secret
into it. The report never prints proof/review/compiler bodies, run IDs, owner
fingerprints, private paths or conversation markers. It reports fixed filenames,
byte counts and digests. Hashes bind supplied bytes; they do not authenticate
their origin or establish who reviewed them.

## Manifest contract

`bundle.json` has exactly these fields:

| Field | Meaning |
| --- | --- |
| `schema` | Literal `mtm-research-bundle-v1`. |
| `task_id` | `U21` through `U25`. |
| `repeat` | Integer 1, 2 or 3; selects the existing frozen TSV case. |
| `trial_id` | Actual 32-character lowercase hexadecimal preparation identity. |
| `run_id` | Actual run identity, at most 256 ASCII letters/digits/underscores/hyphens. |
| `artifacts` | Array of objects containing exactly `kind` and lowercase `sha256`. |

The digest is SHA-256 of the complete corresponding file bytes. Paths and
commands are not accepted as artifact selectors. Duplicate or task-inapplicable
kinds are rejected before any artifact file is opened. Unlisted files are not
read and cannot satisfy a requirement. An empty artifacts array is a valid
incomplete inventory, not evidence of a completed trial.

The original corpus and the 15-case registry are hash-pinned. The selected frozen
candidate is also hash-checked without execution. This checks the local artifact,
not whether a running process actually used it; the report explicitly leaves
`running_candidate_attested_by_precheck=false`.

## Common material and normalization

Obtain workflow material only using the original disposable connection's lawful
owner/artifact interfaces. Before accessing its run, confirm OAuth owner
continuity locally. A different development connection is not a substitute.
Retain the original observations privately; normalization must not invent,
rewrite or remove findings. These file formats deliberately exclude capability
envelopes and raw transport logs.

| Kind | Fixed file | Material expected |
| --- | --- | --- |
| `session` | `session.json` | Exact immutable launcher preparation JSON, all 20 fields. Do not change its false execution/acceptance flags after completion. |
| `status` | `status.json` | Owner-scoped status response with actual case/run, done/sealed/correct/compiled state and no pending submission. |
| `transitions` | `transitions.json` | The `content` array from the `transition_log` artifact, preserving row order and sequence. |
| `proof_manifest` | `proof_manifest.json` | The inner manifest object, not the transport wrapper; retain its target and all four dependency/reference/hypothesis/computation arrays. |
| `verification_report` | `verification_report.json` | The logical report object with `verification_report.summary`, `critical_errors`, `gaps`, and any `repair_hints`. |
| `compiler` | `compiler.json` | Actual compiler observation in the format below. |
| `compiler_output` | `compiler_output.txt` | Retained output of the corresponding required compilation, not a constructed success label. |
| `final_tex` | `final.tex` | Exact finalizer-published TeX bytes. |
| `reviewed_tex` | `reviewed.tex` | Exact draft bytes actually examined in the final independent review. |
| `review` | `review.json` | Actual procedural handoff and substantive statement-check observations, described below. |

Do not manufacture `reviewed.tex` by copying the final artifact after the fact
and asserting someone reviewed it. Final and reviewed bytes must agree, but their
provenance remains independently inspectable evidence. Similarly, `latex_passed`
alone cannot fill in a missing original compiler observation or output file.
Keep unavailable material missing and retain the resulting blocker.

The compiler observation contains `schema` equal to
`mtm-research-compiler-observation-v1`, the actual `run_id`, `policy="required"`,
`program="latexmk"` or `"pdflatex"`, integer `exit_code`, and `source_sha256` /
`output_sha256` binding the final TeX and retained compiler-output bytes. Only an
observed zero exit can satisfy this check. This command does not rerun or
authenticate the compilation.

The review observation is a closed object containing:

```text
schema: mtm-research-review-observation-v1
trial_id, run_id: actual identities of this trial
generator_session, reviewer_session: distinct locally recorded session markers
generator_owner_fingerprint, reviewer_owner_fingerprint: local SHA-256
    fingerprints of the same OAuth client ID observed at the two handoff stages
reviewed_sha256: digest of the exact reviewed.tex bytes
verification_report_sha256: digest of the exact verification_report.json bytes
same_live_connection_observed: true only when the same live OAuth client was
    observed on both sides of the handoff
reviewed_before_finalization: true only when the review was completed before
    the finalizer published final.tex
statement_checks: array of {location, summary} from the actual independent review
```

Use bounded ASCII letters/digits/underscores/hyphens for session markers, never
credentials or conversation URLs. Record actual observations rather than inventing
different names for a single reviewing context. Each statement check must contain
nonblank location and summary text. Matching owner fingerprints and distinct
session markers are consistency checks, NOT authenticated proof of independence.
The observer, session boundary and exact reviewed draft must still be audited.

## Route-specific mechanical consistency

| Task | Additional required kinds / files |
| --- | --- |
| U21 | No additional files beyond the common material. |
| U22 | `retrieval` / `retrieval.json`, `reference_audit` / `reference_audit.json`, `sources` / `sources.json`. |
| U23 | `seeded_draft` / `seeded_draft.tex`, `first_findings` / `first_findings.json`, `repair_history` / `repair_history.json`. |
| U24 | `branches` / `branches.json`. |
| U25 | `sage_input`, `sage_output`, `magma_input`, `magma_output` with corresponding `.txt` filenames; `cas_observation` / `cas_observation.json`. |

U23 additionally requires a declared `seeded_challenge=true` repair history with
the actual `run_id`, `initial_draft_sha256`, `first_findings_sha256` and
`final_sha256`. The first findings must contain a located error/gap and repair
guidance, the final report must have no unresolved findings, and the transition
observations must include repair plus repeated compilation and verification.
The initial and final drafts must differ. These are structural checks, not a
claim that the planted mathematical defect was independently understood.

When all U22 route files are present, the precheck now also requires the material
proof references to be covered by recorded `rethlas_retrieve` calls, by an actual
original/authoritative-source inspection observation, by the run's registered
reference set and by exactly one successful `SOURCE_VERIFIED` audit bound to the
reviewed proof bytes. `retrieval.json` uses
`mtm-research-retrieval-observation-v1`: it records the run id, one or more bounded
calls with method `rethlas_retrieve`, returned reference ids, a result digest and
`external_network_observed=true`, plus false raw-credential/body-retention flags.
`sources.json` uses `mtm-research-source-observation-v1`: each source records its
reference id, `source_kind` (`original` or `authoritative`), locator/content hashes
and `original_or_authoritative_source_inspected=true`. These records bind what was
reported; they do not make a fabricated record authentic or substitute for reading
the source during review.

When U24's branch and transition material is present, `branches.json` uses
`mtm-research-branch-observation-v1`. It requires at least two distinct sealed
branch ids, domains, reviewer/session markers and order indices, a recorded denial
of sibling-private reads for each route, and a join that occurs only after all
required branches are sealed and considers exactly those branch ids. The workflow
transition log must contain `branch_prepare`, then `branch_run`, then `branch_join`.
This validates the branch topology and isolation observations, not the mathematical
quality of the alternative proofs.

When all U25 CAS material is present, `cas_observation.json` uses
`mtm-research-cas-observation-v2`. It must record `native_mode="dangerous"`,
`general_proof_independent=true`, `raw_credentials_recorded=false`, and exactly
one Sage plus one Magma execution. Each tool needs a bounded nonempty version,
exact input/output hashes and integer zero exit. Permission-challenge and grant
fields are no longer part of this closed schema, and are rejected as unknown.
The U25 session must be a fresh `mtm-research-session-v2`; U21-U24 keep their
existing v1 safe-session contract. The proof manifest must retain at least two
computational-evidence entries. These checks establish file correspondence, not
authentication of execution or proof of mathematics. Self-consistent invented
observations are not made authentic by hashes. Independent review remains required.

All route-specific semantic checks are deliberately conditional on the complete
set of files needed for that check. A missing file remains a readable
`missing_material` blocker rather than turning evidence preparation into a false
trial failure. Present but contradictory route evidence fails closed.

Even after all of these mechanical relationships pass, source authenticity,
reviewer/session provenance and mathematical correctness still require substantive
independent inspection. Synthetic regressions exercise the same shapes while
explicitly disclaiming real retrieval, review and CAS execution.

## Remaining release work

The accepted corpus remains 63 passed / 0 failed / 27 blocked. A completed U21
workflow or a green inventory does not change those counts. All three repetitions,
authenticated observations, actual review and route evidence, U26-U29, and a
separately reviewed corpus importer remain necessary.

This delivery changes Rust maintenance source. Unlike the earlier shell-only
launcher repairs, it needs a fresh whole-source gate on the capable host before
release readiness can be claimed. Local `mtm-xtask` unit tests and Clippy are not
a substitute for that gate. The frozen runtime, launcher, case registry, existing
accepted evidence and release-input manifest are not replaced by this command.
