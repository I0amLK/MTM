# Python retirement: reviewed responsibilities, not a line-count target

## Current D8 grouped-retirement checkpoint

Round 3/5 removes 49 target/release/install-family files, including the now-orphaned
external-binary capability checker. **60 of the original 127 Python files are
retired; 67 remain.** The ledger now distinguishes 8 direct Rust replacements,
4 historical comparisons and 48 consolidated family files whose forward
acceptance remains explicitly pending. This corrects the provisional broader
"replaced_by_rust" classification; deletion provenance is not runtime parity.
See `docs/MTM-016-D8-FAMILY-RETIREMENT.md` and the D8 iteration receipts for the
complete responsibility map, installation safety tests and unchanged F gates.

## Historical third-batch checkpoint

Nine baseline Python files have now been retired; 118 remain. After `df6660c`
fixed inherited numeric validation and `3f0fb44` introduced independent Rust policy
tests, the pure-policy Python reference chain was retired as one dependency family.
All 135 original inputs and 14 operation groups remain tested, with the fractional
lower-bound bug intentionally rejected instead of copied. The actual CLI tests
run with an empty inherited environment and PATH. See
`docs/MTM-016-POLICY-REGRESSION.md` for exact coverage and limitations.

This does not complete target/release migration or justify a new performance claim.
The old cross-language golden hash and measurements remain immutable history.

The Rust replacements are introduced before a separate deletion commit. The
retirement ledger is `records/governance/python-retirement.json`; each deleted
Python file is bound to its bytes at the MTM-015 baseline, a disposition, Rust
replacement locations and verification commands. `cargo xtask retirement` checks
this provenance and is part of `cargo xtask check`. It does not execute commands
from the ledger and does not equate a coverage declaration with runtime parity.

## First reviewed batch

The first batch is now removed from the working source tree: three Python files,
leaving 124 of the initial 127. `cargo xtask retirement` verifies all three original
content hashes and replacement locations. The strict whole-repository retirement
check still fails, as required; this is not a completed Rust-only release.

| Python responsibility | Rust responsibility / decision |
|---|---|
| `scripts/validate_commit_message.py` | `xtask/src/commit_message.rs`, unit tests and actual CLI tests; Git hook delegates directly to Rust. |
| `scripts/run_mtm005_conformance.py` | The exact Re-CTM directory/shadow parity requirement is intentionally retired with MTM-owned contracts. Current gateway behavior is checked by Rust catalog, OAuth/MCP and HTTP integration tests. |
| `conformance/python_gateway_shadow.py` | Historical Python gateway shadow runner is no longer a current product authority; paired Rust shadow and public fixture constructor were already retired. |

The two legacy commit-message assertions in `tests/test_governance.py` move to
Rust with their behavior preserved; unrelated Python tests remain until their
responsibilities are addressed. The residual historical `run_checks.py` now
schedules current Rust gateway tests rather than a deleted shadow driver. This
does not promote that legacy aggregate into the current qualification authority.

The old 44-record cross-language hash and measurements remain historical facts,
not claims about the new contract. Existing golden data and accepted/rejected
evidence remain unchanged. Old scripts are recoverable from Git at the frozen
baseline; no adjacent Re-CTM checkout is needed for current Rust gateway checks.

## What is not replaced by the HTTP suite

`crates/mtm-gateway/tests/http_contract.rs` uses the real Rust router, OAuth stores
and dispatcher in process. Authentication goes through DCR, password authorization
and PKCE; no synthetic principal constructor or production credential is used.
The backend only counts dispatches. These tests do not prove browser rendering,
socket/process shutdown, Native sandbox behavior, full workflow, CAS or LaTeX.
The old target/browser harness is not deleted in this batch. Its target coverage
must be re-established on the exact new candidate before release.

Rust-only readiness remains false while any other first-party Python responsibility
or live legacy dependency remains. Unexplained capability failures stay open; a
clean later test is not a root-cause explanation. Production installs, selectors,
keys, research files and run databases are untouched by this retirement.

## Regression discovered while replacing the hook

The installed patch tool changed the commit hook from executable to non-executable
when updating its content. Git ignored it for checkpoint `92bdd05`; that result
is recorded, not relabelled as a successful automatic hook invocation. Its message
was subsequently validated by the Rust entry, and the checkout's executable bit
was restored without changing file content or installing a new runtime.

The development runtime now preserves ordinary Unix rwx bits on updates and moves.
Restrictive source permissions are applied when the staging file is created,
before writing content. New files continue to honor umask. Changed content does
not inherit special permission bits; this does not promise owner/ACL/xattr
preservation. Seven regressions cover executable/private modes, moves, metadata
races, rollback and new-file behavior. The source gate also checks that the Git
hook is actually executable on Unix.

## Second batch: Rust current-binary capability regression

Replacement commit `cf553c5` adds `cargo xtask capability --record` and the actual
CLI integration suite before deleting `scripts/capability_recovery.py` and
`tests/test_capability_recovery.py`. Their rules now live in Rust test-only code;
no product SDK or second capability authority is introduced. Five Python files
have been retired in total; 122 of the original 127 remain.

The current-source check now uses Rust and passes 500 independent assessment first
hops (250 compact, 250 full), zero normal INVALID/rejections, negative capability
tests, persisted-key restart and simulated response-loss recovery. See
`MTM-016-CAPABILITY-REGRESSION.md` for the exact scope and exclusions. The complete
source check still fails its ten inherited nested-Bubblewrap tests; no new tests
are suppressed and this is not release qualification.

The old `check_capability_current.py` remains because target/installed-binary
harnesses still depend on its external-binary and report interfaces. Those callers
must migrate together before deletion; switching the ordinary source gate does
not prove target or release-path retirement. Historical evidence stays immutable.

## Fourth batch: consolidated record integrity

Replacement commit `841bfe1` moves canonical record-layout validation and the six
historical release-summary checks into the existing Rust `records` command. It
also validates sealed host observations and append-only committed receipt prefixes.
The two Python validators are deleted only after the Rust filesystem regressions
and actual Git-only-PATH CLI test pass. Eleven Python files are retired in total;
116 remain. The three earlier batches and their results above are historical.

Residual `run_checks.py` calls this Rust check once rather than executing separate
Python validators. Remaining governance test callers consume its JSON result;
they do not implement a second validation policy. That outer legacy test suite,
target drivers and release tooling are not yet fully retired. See
`MTM-016-RECORD-INTEGRITY.md` for exact responsibilities and limitations.
