# MTM-016: Rust-native maintenance and usable tools

## Approved objective and baseline

The operator approved this work in the project conversation on 2026-09-07.
Baseline: `b3ab147b72d72aa546c9c41bdbe71924aa5ebb97` (MTM-015 completion).
Implementation branch: `work/mtm016-native-usability`.

CTM is unavailable in this session. Development therefore uses a fresh clone at
`~/桌面/MTM/mtm-native-016` in the connected MTM workspace, not the old `.mtm-a4-source`
snapshot and not the inaccessible `~/桌面/tempcoding/MTM-reboot` checkout. The remote
main commit was checked before cloning. No selector, installed binary, live secret,
research document or production database is to be changed by this work.

Success means usable native tools and an independent first-party Rust maintenance
chain, not a mechanical line-for-line translation of Python. User programs may
still use Python/Sage/LaTeX/Git. Rust-only refers to MTM's own implementation,
build orchestration, tests and release control; it does not ban external tools.

## Non-negotiable boundaries

- Retain one workflow writer, role/domain authorization and the existing finalizer.
- Never authorize a rejected capability or turn a run id into workflow authority.
- Preserve MTM projects, runs, proof artifacts and existing data formats until a
  separately tested/versioned MTM data migration is necessary.
- Preserve historical receipts and LICENSE/NOTICE byte-for-byte. Historical code
  can remain in Git history, not as a requirement of the current installation.
- Do not replace unknown shell semantics with permissive execution. Native checks
  and the actual executor must agree about command interpretation and environment.
- No new model API, daemon, general agent runtime, scheduler or graph framework.
- No production cutover, push, or release declaration during partial implementation.

## Delivery sequence

| ID | Delivery | Required evidence |
|---|---|---|
| A | Inventory first-party Python and live Re-CTM couplings; record deletion/replacement ownership | Rust-generated tracked-file inventory; unchanged historical receipts |
| B | Fix ordinary command parsing and Workspace/Git usability | Positive and adversarial Rust regressions, exact-binary native smoke where possible |
| C | MTM-owned typed contracts/catalog; remove 11 legacy public dispatch aliases | Schema/description fixtures, unknown-alias rejection, complete Rethlas regressions |
| D | Consolidate maintenance into a small Rust `xtask`; retire Python/shadow execution only after coverage replacement | Python-free clean-clone build/test, Rust historical evidence validation, equivalent security/target suites |
| E | Task-domain lifecycle, explicit uncertain-result recovery, bounded workflow idempotency | Concurrent/restart/response-loss tests; no shell exactly-once claim; no authority from receipt lookup |
| F | New release identity, complete task corpus and reversible upgrade | 30 representative tasks x 3 runs, full LaTeX/retrieval/branch flows, resource bounds and rollback |

The single `xtask` maintenance crate is approved here. Product crates may not depend
on it. It shares the pinned toolchain/lockfile but does not become a runtime
dependency. Its initial `check` command runs Rust **source** checks and the inherited
workspace tests. Some inherited tests require a real Bubblewrap-capable host, so
the test suite is not yet fully portable to nested sandboxes. This command is not
a substitute for the unported capability, target, browser or release suites.
Missing coverage remains listed as pending, never converted to a green check.

## Retirement map

The C-stage registry/alias checkpoint is documented in
`docs/MTM-016-TOOL-CONTRACT.md`. It uses the separate `0.6.0-preview.1` development
identity, not the installed preview.2 release identity. No deployment is implied.

| Existing responsibility | Replacement / disposition |
|---|---|
| Re-CTM imports and Python shadows | Extract useful static cases, independently validate expected values, then delete executables |
| Python build/check wrappers | Cargo and `cargo xtask check` |
| Historical receipt validators | Rust integrity/commit binding; no demand for historical live selectors |
| Milestone-specific release scripts | Consolidated Rust CLI install/status/rollback and `xtask qualify/dist` |
| Python unit tests | Rust tests in the responsible crate; no copied milestone-specific framework |
| Shared tool descriptions/catalog hashes | MTM-owned typed registry and contract-change fixtures |
| Co-installation requirement and old aliases | Remove from current contract; preserve historical facts only |
| ReCtmError, old sandbox HOME and response keys | Separate reviewed naming/API changes under C; do not silently mutate persisted data |

## Error/uncertainty policy

A 502 without a response proves neither execution nor non-execution. Signed-token
failure is an observation, not proof of client fault or server fault. A later clean
session does not explain an earlier mismatch. Keep that diagnosis open until
request-correlated evidence supports attribution. Count business submissions and
state transitions separately from repeated internal capability checks.

## Coding and recording rules

Use existing crate boundaries; forbid unsafe, reachable unwrap/expect/panic and
unbounded diagnostic output. Add no production dependency just for test convenience.
Only apply_patch performs source/document edits. Cargo/Git may create their normal
build/metadata artifacts. Do not modify previously accepted evidence to match new
code. Run negative tests beside the fix and record command, exit status, limitations
and file scope in `records/iterations/ITER-016.json`.

Each coherent commit references MTM-016 with the existing trailers. Stages remain
in_progress until their own evidence is present. Product protocol/alias changes
will get a new release identity (planned 0.6.0-preview.1), never an overwrite of
the installed 0.5.0-preview.2. Rollback before deployment is reverting the dedicated
branch commits; no live data or key rollback is required.

## Initial delivery, 2026-09-07

The Rust inventory enumerates 127 existing Python files and assigns a provisional
retirement owner to each. None has been deleted: independent behavioral coverage
must replace each retained responsibility first. Textual Re-CTM markers are not
automatically classified as live dependencies. The current product graph is eight
crates and 17 normal dependency edges; the earlier storage-to-core edge was already
absent from the baseline Cargo manifest and was stale architecture documentation.

Implemented and tested locally:

- Quote/escape-aware boundaries for literal shell command lists (`;`, `|`, `&`
  and their pairs), shared by executable fact collection and command-risk checks.
  Regressions cover previously missed destructive/inline-script commands after an
  adjacent separator. Quoted operators remain data. Heredocs, redirections, expansions,
  compound syntax and builtin/environment semantics are not claimed as fixed.
- `search_text` accepts a regular file without searching siblings, preserves path
  and private-root guards, applies filters, and rejects out-of-contract bounds.
- Rust `xtask audit`, `records`, and `check`, with negative tests for graph/history
  corruption and a guard against product-to-maintenance dependencies.

`cargo xtask check` deliberately remains failed inside the connected Native sandbox:
ten inherited Bubblewrap tests fail there. The untouched b3ab147 baseline fails the
same ten tests; a direct namespace probe reports ENOSPC. No assertion was removed or
new test ignored to manufacture a pass. Core, storage, workflow and targeted new
tests passed; actual host Native and complete release qualification remain pending.

Run from this clone on the host for the same checks:

```sh
cargo xtask audit --strict
cargo xtask records
cargo xtask check --record
```

`audit --strict` is expected to fail while retirement is incomplete. Neither this
failure nor the nested-sandbox test failures authorize an installation or cutover.
