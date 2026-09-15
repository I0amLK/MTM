# MTM-016: Rust record integrity and host evidence ownership

`cargo xtask records` is the single current integrity entry. It uses Rust plus
Git metadata, not a sibling Re-CTM checkout, Python interpreter, installed selector
or live database. This is static evidence validation, never a release qualifier.

## Scope being replaced

The former `validate_record_layout.py` responsibilities are now handled by
`xtask/src/record_layout.rs`: required governance files, ITER-NNN.json naming,
flat MTM-NNN evidence directories, canonical validation records, root-JSON
prohibition, one-to-one relocation paths, kinds and preserved evidence hashes.
The existing records/README.md remains valid documentation.

The former `validate_historical_mtm_release_evidence.py` responsibilities are
also consolidated here. Six immutable MTM-003 through MTM-008 receipts retain
their historical project identities, accepted verdicts and exact check counts.
Their hashes are checked against the unchanged baseline-bound relocation index.
No historical implementation is executed and no historical deployment is required.
These six records are a subset of the 26 historical hashes, not six new test runs.

Record paths are bounded and canonical, reject symlink components, and remain
within the checkout. Tree enumeration and input reads have fixed limits. Tests
cover absent/malformed namespaces, wrong versions and kinds, duplicate mappings,
path escapes, symlinks, oversized records, changed hashes and verdict/count types.
These checks do not claim race-free access against a hostile concurrently mutated
filesystem or authenticity against an attacker controlling the entire Git history.

## New observations do not overwrite old ones

Operator host reports for source 61e6bf7 were moved byte-for-byte to
`records/evidence/MTM-016/host-native-preflight-61e6bf7.json` and
`records/evidence/MTM-016/host-source-check-61e6bf7.json` in commit 739d60b.
The ITER-016 review contains their hashes and the observation's limitations.
`records` validates these seals in addition to the 26 historical hashes.
Committed iteration receipt arrays must remain prefixes of their working-copy
versions: changing a seal's expected hash or deleting the entire review is not
accepted as an ordinary update. New observations are appended as new receipts.

Regenerable files under records/validation describe only their own run. A new
sandbox failure cannot overwrite the archived host success; a prior host success
cannot authorize a later failing check. Failed sandbox reports remain retrievable
from commit 61e6bf7 and their earlier receipts are retained.

The new check report separates `native_environment` from
`product_test_evaluation`. Only consistent outcomes for the four required commands,
a ready environment and unchanged Rust source/HEAD can pass the aggregate.
Neither a standalone preflight nor a static historical check claims that product
tests were executed. Individual host test counts and an exact product binary hash
were not captured by the original host reports and are not invented afterwards.

## Verification

```sh
cargo test -p mtm-xtask --locked
cargo xtask records
cargo xtask check --record
```

The actual record CLI is tested with a Git-only child PATH and cleared inherited
environment. No Python is exposed there. Remaining Python governance callers may
temporarily delegate to this Rust result while their other responsibilities are
being retired; that transitional outer test suite is not yet Rust-only.
Full Native/browser/LaTeX/resource/upgrade acceptance remains separate.
