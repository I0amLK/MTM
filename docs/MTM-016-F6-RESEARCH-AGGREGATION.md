# MTM-016 F6: research corpus evidence aggregation

## Purpose

This adapter advances only the fixed U21-U25 portion of the already declared
30-task x 3 corpus. It does not run research, choose a proof, authenticate a human
witness, copy private databases, or turn a verifier `correct` string into a proof
certificate. Private evidence remains outside the repository and is first checked
with `cargo xtask research-precheck`.

The accepted corpus before research ingestion is exactly 63 passed / 0 failed /
27 blocked. A research batch is admissible only after all fifteen U21-U25 cells
have separately completed their prescribed case and have a reviewed, sanitized
trial receipt. There is no partial 64/89, 70/20 or best-effort research aggregate.
The closed v3 aggregate is exactly 78 passed / 0 failed / 12 blocked and therefore
still leaves the release corpus gate blocked for U26-U29.

## Per-trial evidence

U21-U24 sanitized receipts retain schema `mtm-research-trial-evidence-v1`.
New U25 receipts use `mtm-research-trial-evidence-v2`; old U25 v1 receipts cannot
be relabelled or imported into the active batch. Each receipt is stored under
`records/evidence/MTM-016/`. It binds the frozen candidate/source,
corpus and research-case registry plus one task/repeat/case/trial. It records only
hashes and bounded procedural facts, never a run id, OAuth client id, capability,
operator key, proof body, source body, CAS body, database or transport log.

Required common facts are:

- required LaTeX passed and the final artifact is sealed;
- the final reviewed TeX, verification report and review observation have exact
  SHA-256 identities;
- generator and reviewer session markers are distinct while the locally observed
  OAuth owner fingerprint is continuous;
- the independent review has at least one substantive statement check and was
  observed before finalization;
- the read-only private precheck passed and the mathematical reviewer explicitly
  accepted the reviewed statement/proof;
- no raw private state is recorded and neither the trial nor the receipt claims
  release authority.

The receipt contains an exact ordered `route_checks` vector. U21 has only the
common checks. U22 additionally requires retrieval, original/authoritative-source
inspection and bound reference audits. U23 requires preservation of the seeded
gap, a specific independent finding, repaired recompilation and re-verification.
U24 requires at least two branch routes with distinct domains, observed sibling
privacy denial and sealing before join. U25 requires actual Sage and Magma use
under dangerous Native, exact I/O binding and a proof independent of finite
computation. Its route includes `dangerous_native_observed`, not a safe-mode
permission observation. Reviewer and finalizer requirements are unchanged.

These fields are evidence claims that must be produced from the retained private
trial. The release adapter validates their closed shape and cross-trial identity;
it cannot cryptographically establish that a person/model really performed the
review. Fabricated receipts remain an evidence-integrity violation even when they
are structurally valid.

## Research batch

`mtm-research-corpus-batch-v2` contains exactly fifteen references: twelve
unchanged U21-U24 v1 receipts and three fresh U25 v2 receipts. It requires each
U21-U25 x repeat 1-3 cell exactly once, fifteen
distinct evidence paths/hashes, fifteen distinct trial ids and fifteen distinct
recording timestamps. Every referenced receipt is reopened and revalidated; a
caller cannot supply only aggregate counts.

The batch is complete only for the research subset. Its fixed totals are 15 passed
and 0 failed. A failed or infrastructure-invalid attempt is retained outside this
batch and does not silently consume the fixed repeat. The first invalid historical
U21-r1 owner-recovery attempt therefore remains non-counting.

## Partial corpus v3

`mtm-usability-corpus-aggregate-v3` has one exact v2 base and one research batch:

```text
validated immutable v1 U01-U15 + U30  = 48 passed / 42 blocked
validated U16-U20 Native batch        = 15 passed / 27 blocked
validated U21-U25 research batch      = 15 passed / 12 blocked
---------------------------------------------------------------
v3 partial corpus                     = 78 passed / 12 blocked
```

The release checker reopens the v2 base, recursively revalidates its Native batch,
then opens every research trial. `complete`, `production_changed` and
`release_qualified` must all remain false. The adapter returns a blocked corpus
gate even when all research trials pass because U26-U29 are not supplied by this
scope.

No current release input should point to a v3 aggregate until real fifteen-trial
evidence exists. Unit/synthetic fixtures prove only fail-closed parsing and count
boundaries; they never create corpus passes.
