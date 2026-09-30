# MTM-017 current-candidate partial corpus

`corpus-aggregate-check` is a new read-only maintenance adapter for the exact
schema-8 preview.2 candidate. It does not change the frozen MTM-016 release
driver, parser, manifest, runtime or historical corpus counts.

## Four reviewed batches, counted by cell

- U01-U15: 45 portable passes from the new exact-candidate 90-row observation.
  The original outer report remains `passed=false`, `failed_stage=corpus_coverage`
  and qualifier exit 1. Its inner runner exits 0, with 45 pass / 0 fail / 45
  blocked. Only the actual U01-U15 passed rows contribute coverage.
- U16-U20: 15 sealed exact-candidate Native rows. The Native validator remains
  unchanged; this adapter additionally requires all U20 rows to have the precise
  dangerous-only checks, never legacy safe/trusted/grant checks. The raw
  `scripted_consent_only` label is preserved and grants no human-consent claim.
- U21-U25: the already accepted 15 research rows and their original public
  input-review/proposal/result-review/acceptance chain. The fixed research pointer
  and original receipts stay byte-identical. No private bundle or mathematics is
  re-executed or re-reviewed by this aggregate, and these rows are not accepted
  again.
- U30: three newly recorded, separately reviewed process-SIGKILL trials. Raw
  seals, observation IDs, recording times, CTM invocation IDs and TMPDIR parents
  must be distinct. Identical command templates, stderr hashes and empty lineage
  diffs are normal and are not treated as repeated trials. These observations do
  not establish physical power-loss, shared-filesystem or production recovery.

The adapter derives 78 covered cells from validated rows: 63 newly eligible plus
15 previously accepted research cells. U26-U29 are always twelve pending cells.
No waiver, future operator-state rehearsal, unapproved U27/U28 mapping or broad
machine-profile pass can fill these cells. Full corpus, release and deployment
remain false.

## Separate review and activation

1. A closed `mtm017-partial-corpus-inputs-v1` selects exactly four typed batches:
   portable raw/observation/review, Native raw/snapshot, original research state,
   and U30 observation/review plus repeats 1-3. The selected paths and hashes must
   equal the separately reviewed fixed byte anchors in this adapter. There is no
   caller-provided passed count or arbitrary list of passed cells.
2. An independent input review binds the complete inputs SHA, current maintenance
   source SHA and exact maintenance binary SHA. Its distinct reviewer marker and
   six ordered checks are procedural observations, not cryptographic identity.
3. The command emits a proposal with `accepted_delta=0` and
   `corpus_count_incremented=false`. A separate result review must bind the exact
   output bytes. Only then may an explicitly authorized governance activation add
   the 63 newly reviewed rows and reference the existing 15, yielding a new 78/90
   partial-corpus pointer. It must not rewrite the original research pointer.

```sh
CARGO_TARGET_DIR="$PWD/target/mtm-tool" cargo xtask corpus-aggregate-check \
  --inputs records/evidence/MTM-017/partial-corpus-inputs-20260930.json \
  --input-review records/evidence/MTM-017/partial-corpus-input-review-20260930.json
```

There are no record, accept, release, deployment, arbitrary-candidate or base
options. Output always distinguishes whole-tree `implementation_complete=unknown`,
`research_accepted=true` only for the prior fifteen rows, `release_qualified=false`
and `deployment_authorized=false`. It also keeps `full_corpus_accepted=false`.

## Validation boundary

New envelopes and receipt schemas reject duplicate and unknown JSON fields.
Supporting wrapper/snapshot/review bytes must match fixed reviewed anchors, so
adding an unknown field or updating a reference hash cannot silently replace them.
Semantic validation still rechecks raw results and is directly covered by
mutation tests rather than relying only on those anchor hashes.

Portable inner rows use the existing closed corpus validator plus an independent
closed partial-outer adapter; the outer result is never changed to reuse a success
validator. Native and U30 use the original closed qualification validators, then
the narrower schema-8 conditions. Native snapshot identity, its exact eight-profile
set and nine unique seals are verified. Its old source identity remains
`0adec4...` / `7b4afe...`, distinct from portable/U30 harness identity
`10066ff...` / `b8ca577...`; neither is relabelled as current maintenance source.

U30 requires equal nonempty nine-entry before/after maps with exact candidate,
baseline and old-driver hashes, distinct and serial observed invocation windows,
valid UTC times on the fixed reviewed observation date, and recorded time equal
to the observed finish time. Freshness assertions remain bound to archived
environment/source observations and independent review; they are not generated
by this checker.

All files are reopened through bounded descriptor-relative no-follow reads.
Only flat MTM-017 JSON, the two fixed governance anchors, the exact artifact
paths and the two reviewed target archive namespaces are eligible. Symlinks,
hardlinks, unexpected ownership, other-write and special modes fail closed.
Public archived files may retain mode 0664; private research bundles are not
opened. Data logs may be empty, but JSON must decode and artifacts must be
nonempty bounded executables. Maximum inventory is 256 files / 64 MiB, with
1 MiB per data file and 32 MiB per artifact. Metadata and bytes are rechecked
before output.

Archived maintenance-binary observations remain historical claims inside their
sealed wrappers. This new build is not compared to the old mutable cache binary.
Current implementation and executable identity instead come from the independent
input review. All new logs go under `target/mtm017-corpus-aggregate-20260930/`;
only flat regular JSON evidence is published under `records/evidence/MTM-017/`.

## Tests and remaining gates

Run maintenance tests, CLI tests, Clippy, formatting, record and diff checks plus
a fresh whole-source gate for this changed implementation. The earlier
`10066ff...` source pass belongs to the previous tree and cannot satisfy this
gate. Synthetic fixtures never add corpus credit. Preserve any failed attempts
and all historical observations. No passing trial needs to be rerun for this
read-only aggregation.

Rollback is an append-only superseding governance decision; do not delete or
rewrite the original trials, research acceptance chain, failed observations or
MTM-016 evidence. No production action is part of this procedure.
