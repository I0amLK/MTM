# MTM-016 F6: U26-U29 external corpus and final aggregation

## Boundary

The existing browser/human and copied-operator-state release gates prove their
declared broad scopes once. They do not supply the fixed three corpus repetitions
for U26-U29. This adapter accepts only twelve separately observed corpus trials:
U26, U27, U28 and U29, repeats 1 through 3.

No existing broad receipt may be referenced directly as one of those twelve
trials. Each new trial has its own trial identity, observation timestamp and
sanitized witness-observation digest. The release checker reopens all twelve trial
files instead of trusting aggregate counters.

## Trial schema

Each file uses `mtm-external-corpus-trial-evidence-v1`, is stored under
`records/evidence/MTM-016/`, and binds the frozen candidate/source and frozen corpus
identity. Common requirements are exact-candidate observation, zero normal
capability-invalid events, zero rejected normal submissions, no raw private state,
no production modification and no release-authority claim.

Route-specific requirements are closed and ordered:

- **U26 browser OAuth reconnect:** real browser, DCR/PKCE, protected-resource path,
  reconnect against the exact candidate, zero normal invalid capability events and
  zero normal submission rejections.
- **U27 decline/cancel:** real browser and an independently observed human decline
  and cancel. `protected_effect_count` must be exactly zero.
- **U28 consent scopes:** real browser plus independently observed human consent;
  once use, session reuse, expiry and restart invalidation are all required.
- **U29 copied operator state:** explicit operator authorization, production
  original observed read-only, candidate upgrade/resume, restoration of the exact
  original copy and resumed old runtime. Browser/human flags are false for this
  state-copy scope.

The structural validator cannot cryptographically authenticate a witness. A false
witness report remains evidence fraud even when its JSON shape is valid. Raw
browser logs, OAuth material, copied databases and operator-state archives remain
private and are never valid public corpus receipt fields.

## Twelve-trial batch

`mtm-external-corpus-batch-v1` contains exactly twelve receipt references and must
cover every U26-U29 x repeat 1-3 cell once. Receipt paths, hashes, trial ids and
recording timestamps must all be distinct. It has fixed totals 12 passed / 0
failed and is complete only for this external subset.

An infrastructure-invalid, cancelled or failed attempt is retained separately; it
is not relabelled as a passed repeat. The batch cannot omit a fixed cell or reuse a
successful broad gate observation three times.

## Complete corpus v4

`mtm-usability-corpus-aggregate-v4` has exactly one v3 base plus exactly one
`corpus_external` batch. The release checker recursively reopens the v3 78/12
aggregate, which itself recursively reopens the v2 63/27 aggregate and all U16-U25
evidence. Only then can the final counts be:

```text
v3 U01-U25 plus U30       78 passed / 12 blocked
U26-U29 external batch   12 passed /  0 blocked
------------------------------------------------
v4 complete corpus       90 passed /  0 blocked
```

For v4 only, `complete=true` is required. The corpus evidence itself still keeps
`release_qualified=false`: a complete corpus is one input to read-only
`release-check`, not deployment authorization. All other release gates must remain
valid against the exact selected candidate before release readiness can become
true.

Synthetic unit tests exercise shape, count, repeat, witness-scope and fail-closed
mutations only. They never create current release evidence and must never be added
to the release-input manifest as real trials.
