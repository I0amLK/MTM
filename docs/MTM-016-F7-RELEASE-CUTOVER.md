# MTM-016 F7: governed Rust release cutover

## Boundary

`cargo xtask release-check` remains read-only. It may prove that the selected
candidate is ready for release review, but it never installs a binary, changes a
selector or claims deployment authorization.

The only MTM-016 repository path that may change the live MTM selectors is:

```text
cargo xtask release-cutover \
  --binary target/mtm016-f6-frozen/mtm-0.6.0-preview.1-f59cbddaebb8b9944d1365d6d4f1c072e2cc78e76dbbce8d870308c470c88034/mtm \
  --manifest records/governance/mtm016-release-inputs.json \
  --authorize MTM-016
```

The command is intentionally specific to MTM-016. There is no arbitrary binary,
manifest, version, state-root, selector, skip-readiness or force override.

## Preconditions

Before any live write, the driver requires all of the following:

- a clean Git worktree;
- the exact frozen candidate SHA-256
  `f59cbddaebb8b9944d1365d6d4f1c072e2cc78e76dbbce8d870308c470c88034`;
- the exact `mtm 0.6.0-preview.1` version identity;
- the governed MTM-016 release-input manifest;
- a fresh in-process execution of the unchanged release checker with all 17
  gates validated, zero blockers, unchanged inputs and no production mutation;
- the current deployment manifest in `rust_active` state;
- both `/home/lk/.local/bin/mtm` and `/home/lk/.cargo/bin/mtm` selecting the
  exact current release named by that deployment manifest.

The driver creates an exclusive MTM-016 rollout lock and a byte-for-byte rollback
copy of the pre-cutover deployment manifest. A conflicting backup or lock fails
closed.

## Rollout

The candidate is copied into the immutable versioned release directory and
hash/version checked again. The live drill is then:

1. atomically switch both selectors to `0.6.0-preview.1` and run version/help smoke;
2. atomically roll both selectors back to the previously active release and smoke it;
3. recut over to `0.6.0-preview.1`, recheck both selector hashes, and persist the
   final deployment manifest.

Existing MTM sessions are not restarted. The selector affects new launches only.
The driver does not rewrite research/workflow databases, OAuth state, proofs or
other production data.

Any error after the pre-cutover snapshot attempts to restore both selectors and
the exact original deployment manifest before returning failure. A copied but
unselected candidate may remain as an immutable side-by-side artifact after a
failed drill.

## Receipt

Success creates `records/evidence/MTM-016/preview-release.json` exactly once. The
receipt binds the release commit, candidate/source identities, release-input
manifest digest, 17/17 readiness result, previous-release identity, real
rollback/recutover result and evidence-hygiene assertions. It records that the
production selector changed while production data was not rewritten.

The release driver itself is Rust and is part of the MTM source hash. Therefore
this implementation must be committed, receive a fresh capable-host source
qualification, and pass the complete read-only release checklist again before the
cutover command is allowed to run.
