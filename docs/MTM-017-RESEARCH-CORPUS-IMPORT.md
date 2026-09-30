# MTM-017: separately reviewed research-subset import

## Boundary

`research-import-check` prepares a read-only proposal for exactly U21-U25,
three repeats each, on MTM-017 schema 8 and the frozen 0.6.0-preview.2 candidate.
It does not import by itself. Every output keeps `accepted_trials_delta=0`,
`corpus_count_incremented=false`, `production_selector_changed=false`,
`production_state_modified=false` and `release_qualified=false`.

Machine output separately states `implementation_complete="unknown"` for the
whole project, `research_accepted=false`, `release_qualified=false` and
`deployment_authorized=false`. A proposal does not decide the project's distinct
implementation-completion gate. Later subset acceptance may establish only
`research_accepted=true` within these fifteen rows, without changing release or
deployment authority.

The command does not write any file, open a workflow/OAuth database, execute the
candidate, mutate a trial, repair a bundle, select a release, install or deploy.
It has no record, accept, release or latest-session option. It adds no crate,
dependency, public tool, workflow authority or state schema.

The historical MTM-016 release driver and parser remain unchanged. In particular,
its existing 90/0 aggregate does not become MTM-017 evidence. No historical 63/27
base is inherited and this subset never implies 78/12, a complete 90/0 corpus,
browser acceptance or release qualification.

## Three separate steps

1. Prepare the closed public inputs, private explicit bundle catalog and supporting
   audit. A separate reviewer inspects the implementation, negative tests, all
   fifteen original bundles and their route/review observations. Its input-review
   record binds the complete input bytes, catalog bytes, current maintenance source
   hash and exact maintenance executable hash. Input review does not add a count.
2. Run the command below. It reopens all receipts and bundles and emits a proposal
   containing fifteen eligible rows and zero accepted rows. Preserve its complete
   output bytes under a new evidence filename, without overwriting old evidence.
3. Independently review that exact proposal and retain a separate result-review
   record bound to its full SHA-256. Only after that review may an explicit,
   separately recorded governance acceptance activate these fifteen research rows.
   The command cannot write or activate that acceptance. Preserve the original
   standalone receipts and their historical non-counting records unchanged.

A structured review record is a procedural observation, not cryptographic
authentication of its author. Hashes, a `correct` verdict and green prechecks do
not prove source authenticity, reviewer identity or mathematics. The output says
this explicitly. An invented review remains an evidence-integrity violation;
there is no self-certification route from a JSON approval string to a corpus count.

## Invocation and inputs

From this ordinary host checkout, respecting Cargo cache ownership:

```sh
CARGO_TARGET_DIR="$PWD/target/mtm-tool" cargo xtask research-import-check \
  --inputs records/evidence/MTM-017/corpus-import-inputs-20260930.json \
  --bundle-catalog /absolute/private/bundle-catalog.json \
  --input-review records/evidence/MTM-017/corpus-import-input-review-20260930.json
```

`mtm017-research-import-inputs-v1` is a closed object containing milestone,
state_schema_version, candidate_sha256, candidate_source_commit, corpus_sha256,
case_registry_sha256, prepared_by, bundle_catalog_sha256, audit and prechecks
path/hash references, fifteen task_id/repeat/receipt path/hash references and the
four false corpus/production/release flags. The identities are pinned to preview.2
SHA `13d7890c5c763199ed39295e134ff6cc735ceaa04eaddf6c556431a7a56254f4`,
source `7b4afe2359e688263557f62154e4bc1e640c12c0` and the unchanged frozen corpus
and fifteen-case registry. All public references remain within
`records/evidence/MTM-017/`.

The private catalog has schema `mtm017-research-bundle-catalog-v1`, milestone and
exactly fifteen task_id/repeat/bundle entries. Every bundle is an explicit absolute
path ending in `.mtm-acceptance/MTM-017/research/U2x-ry.XXXXXXXX/` followed by
`evidence-bundle.<trial_id>`. It is not discovered by scanning for the latest run.
Keep its parent mode 0700 and its leaf mode 0600. The bounded reader accepts only
owned, single-link regular leaves without group/other write or special mode bits;
the parent remains private even if a non-writable leaf uses mode 0644. Private
paths and catalog contents are never emitted into the proposal.

The input-review schema is `mtm017-research-import-input-review-v1`. It contains
milestone, inputs_sha256, bundle_catalog_sha256, implementation_source_sha256,
maintenance_binary_sha256, prepared_by, a distinct reviewer_session, a nonzero
recorded_unix_seconds, the same four false flags and decision
`approved_for_read_only_proposal`. Its ordered checks are exactly:

- implementation_and_negative_tests_reviewed
- all_fifteen_original_bundles_inspected
- receipt_and_exact_artifact_bindings_checked
- route_observations_and_review_provenance_inspected
- no_historical_base_or_release_authority_inherited
- proposal_only_zero_accepted_delta

Do not fabricate this record while preparing inputs. The separate review must
actually occur. Any later input, catalog, source or executable change requires a
new matching review rather than editing an already sealed review identity.

## Byte checks and failure behavior

JSON is bounded and rejects duplicate keys at every depth, unknown fields and
trailing data. Descriptor-relative readers reject links, traversal, special files,
oversized files, unsafe modes and changed file metadata. Repository evidence is
bounded to 1 MiB per file; the private catalog to 64 KiB. Existing precheck limits
apply separately to each private bundle.

Only the fixed historical MTM-016 driver has a specialized bounded JSON reader
that accepts its existing public mode 0664. It is hashed as data, not passed to
the executable-candidate validator. The fixed driver reader still rejects links,
other-write, executable/special mode bits, oversized or changed files and hash
drift. All MTM-017 evidence and private bundle/catalog readers retain their
stricter no-group/other-write rule. No original receipt or driver is chmodded.

Every receipt keeps its original closed trial schema: v1 for U21-U24, v2 for U25.
The importer verifies all task/repeat cells and unique case, trial, receipt path,
receipt digest, bundle/final/report/review digest and recording timestamp. It
checks the exact ordered route flags and MTM-017 dangerous/session-v2 policy.
Existing `research-precheck` rehashes every artifact and checks compiled final
bytes, exact reviewed bytes and route consistency. The importer additionally
cross-binds the receipt to the bundle manifest, session, review observation,
verification report and precheck artifact digests, including same-owner markers,
separate generator/reviewer sessions and review-before-finalization.

The maintenance source, public inputs, private catalog, input review, supporting
audit and all receipt bytes are checked again before output. The old driver hash
is checked before and after. Any mismatch fails without a partial proposal or
count increment. The schema-8 identity comes from the exact selected candidate
and MTM-017 collector contract; this checker does not reopen a workflow database.

## Verification and rollback

Run maintenance unit/CLI tests, Clippy, formatting and records checks. Preserve
failed diagnostic attempts instead of relabeling them. Synthetic tests establish
fail-closed parser and file behavior only, never real research trials. A fresh
whole-source capable-host gate remains separate from this maintenance test run.

Rollback before governance acceptance means retaining or withdrawing the new
non-authorizing proposal; no runtime or production rollback is involved. After
acceptance, use a new append-only governance supersession, never edit the fifteen
original trial receipts or their sealed evidence.
