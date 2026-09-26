# MTM-016 lifecycle reconciliation

## The release happened before the lifecycle closeout

The sealed `records/evidence/MTM-016/preview-release.json` records the authorized
0.6.0-preview.1 release on 2026-09-15 at 07:01:38 UTC. The release driver was
already committed, its capable-host source check passed, all seventeen readiness
gates were revalidated, and the real rollback/recutover drill passed. Commit
`54a11f2` sealed that receipt, but did not update the iteration or migration graph.
Their old `in_progress` and release-driver TODOs were stale summaries, not proof
that deployment was still required.

On 2026-09-26 the release receipt, all fourteen referenced evidence hashes and
Git ancestry were checked without rerunning deployment. The historical source
hash was recomputed from its committed Git bytes. Both installed command entries
resolve to the released artifact and report its exact version. The deployment
manifest and rollback manifest agree with the release receipt. Detailed read-only
observations are in `records/evidence/MTM-016/lifecycle-reconciliation-20260926.json`.

`MREC-016` and `MEVT-067` close the historical preview-release milestone on that
basis. Existing receipts and previous failed observations remain unchanged.
The acceptance scope is the exact schema-7 binary with SHA-256
`f59cbddaebb8b9944d1365d6d4f1c072e2cc78e76dbbce8d870308c470c88034`,
not the later schema-8 development source.

## Current operational risk: previous rollback binary is missing

The recorded previous 0.5.0-preview.2 binary no longer exists at its recorded
release path. The rollback metadata remains, but metadata cannot restore missing
executable bytes. The time and cause of removal are unknown. The successful
September 15 drill remains a historical fact; current rollback readiness is false.
Recover the exact `2164c84701b191b06a66a5d28ba595697d355f9a3bdc78ca31ea455d49793d6a`
artifact before claiming that fallback works now. Do not substitute a same-version
rebuild with a different hash or run the old cutover again to conceal the gap.

## Schema-8 next steps

MTM-017 development remains complete, but its separate artifact qualification is
not discharged by this reconciliation. The older frozen release driver must not
be repointed at a schema-8 binary. New snapshots may be staged and tested only at
disposable locations until current-artifact, client, mathematical, migration and
release-decision gates are satisfied. No live database, selector or running session
was changed by this records-only reconciliation. Reversing a governance decision
requires a new event/receipt, not deletion of sealed evidence.
