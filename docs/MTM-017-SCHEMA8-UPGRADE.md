# MTM-017: distinct preview.2 and schema-7 upgrade qualification

## Scope

The schema-8 development candidate is versioned `0.6.0-preview.2`; the installed
schema-7 `0.6.0-preview.1` and every sealed report remain unchanged. Only the eight
workspace package versions and their exact local dependency pins change. No
third-party dependency, compiler pin, public tool, schema or workflow protocol
changes. Earlier `20e5178` snapshot passes are historical, not passes for new bytes.

The additive `cargo xtask qualify --profile upgrade_schema8` requires two explicit
artifacts and distinct hashes. It uses the reviewed schema-7 baseline at
`f59cbddaebb8b9944d1365d6d4f1c072e2cc78e76dbbce8d870308c470c88034` and requires
the candidate to identify as preview.2/schema 8. The existing `upgrade` profile
and schema-2 to schema-7 receipt validator remain separate historical contracts.
No baseline-schema, state-root, selector, skip or force argument is accepted.

## Fixture and checks

The baseline creates all state through its disposable OAuth/MCP server. A stopped
snapshot records owned files, paths and modes, and stays immutable. The candidate
is self-installed into two disposable selectors, then must resume and advance
old work, preserve a completed submission receipt without duplicate writes,
retain legacy revisions without inventing fact IDs, create new work and preserve
the same key across restart. Schema-8 tables must initially be empty.

Rollback restores the original snapshot before the baseline is relaunched; both
the executable selectors and the exact data bytes/modes must match. The restored
old runtime must advance the original old run again. Fixed field types, exact
transition versions, check sets and hashes are revalidated outside the fixture.
Legacy/new-profile substitution and missing, duplicate or widened reports fail.

## Authority and rollback

These tests use only generated temporary state: no operator database is copied,
opened or upgraded and no production selector is modified. Native is disabled and
LaTeX is static-only for this upgrade fixture. Real client, independent mathematics,
compiled LaTeX, copied-operator-state compatibility and complete release acceptance
are distinct gates. This adds no schema-8 deployment authority.

Revert this implementation checkpoint to remove version/profile changes; preserve
sealed observations and append a governance correction. Database rollback always
restores the untouched pre-upgrade copy with its matching binary, never a lowered
schema version or deletion of schema-8 rows.

## Invocation

Use the immutable candidate and baseline paths recorded in the new artifact
receipt, not an installed selector or an arbitrary same-version executable:

```sh
cargo xtask qualify --profile upgrade_schema8 \
  --binary "$CANDIDATE" --sha256 "$CANDIDATE_SHA256" \
  --baseline "$SCHEMA7_BASELINE" \
  --baseline-sha256 f59cbddaebb8b9944d1365d6d4f1c072e2cc78e76dbbce8d870308c470c88034 \
  --record
```

The runner retains `candidate-upgrade-schema8.json`; the sealed report must bind
both executable hashes and the unchanged committed harness. Its 21 required checks
include the original 15 install/snapshot/lifecycle checks plus six schema-8 checks.
The fixture explicitly prepares permissions only in its stopped owned state tree;
the untouched original snapshot is restored with its original modes on rollback.
Passing this conditional fixture is not approval for an unprepared in-place upgrade.
