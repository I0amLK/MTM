# Python retirement: reviewed responsibilities, not a line-count target

The Rust replacements are introduced before a separate deletion commit. The
retirement ledger is `records/governance/python-retirement.json`; each deleted
Python file is bound to its bytes at the MTM-015 baseline, a disposition, Rust
replacement locations and verification commands. `cargo xtask retirement` checks
this provenance and is part of `cargo xtask check`. It does not execute commands
from the ledger and does not equate a coverage declaration with runtime parity.

## First reviewed batch

| Python responsibility | Rust responsibility / decision |
|---|---|
| `scripts/validate_commit_message.py` | `xtask/src/commit_message.rs`, unit tests and actual CLI tests; Git hook delegates directly to Rust. |
| `scripts/run_mtm005_conformance.py` | The exact Re-CTM directory/shadow parity requirement is intentionally retired with MTM-owned contracts. Current gateway behavior is checked by Rust catalog, OAuth/MCP and HTTP integration tests. |
| `conformance/python_gateway_shadow.py` | Historical Python gateway shadow runner is no longer a current product authority; paired Rust shadow and public fixture constructor were already retired. |

The two legacy commit-message assertions in `tests/test_governance.py` move to
Rust with their behavior preserved; unrelated Python tests remain until their
responsibilities are addressed. The residual historical `run_checks.py` should
schedule current Rust gateway tests rather than a deleted shadow driver. This
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
