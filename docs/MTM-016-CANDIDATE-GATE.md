# MTM-016 D5/D6: exact-candidate protocol and target qualification

D5 is a bounded delivery within MTM-016, not completion of stages D/E/F and not
a new production release. Starting source: `69b5fd35b7bed2c359ee9d499abd874706616805`.

## Completion contract

Provide one Rust maintenance entry accepting an explicit executable and SHA-256.
Run the existing independent OAuth/capability and workspace regressions against
those exact bytes, plus persisted-secret and complete protocol workflow fixtures.
Never silently substitute the Cargo-built product for the supplied candidate.
Use a private disposable executable snapshot, workspace, database and credentials;
do not change a selector, production state, existing secret or installed artifact.

The gate must reject missing/conflicting selection, wrong hashes, unsupported
artifacts, changed input, missing/duplicate/foreign summary records, process
failure and source drift. Normal source tests must continue to exercise their
Cargo-built binary. Summary counts and artifact identity are validated separately
from a successful test-runner exit code. Test output is bounded and raw protocol
data is not retained in records.

Complete compact, full and repair fixtures exercise actual runtime transitions
and mechanical finalization. They do not claim independent mathematical research
evaluation. Native stays disabled and LaTeX stays explicitly static-only in this
profile: real isolation, compiled LaTeX, browser, resource, upgrade and rollback
remain mandatory separate qualifications. D5 cannot set release_qualified=true.

## Retirement boundary

This replaces the missing external-binary responsibility of the source-only Rust
gate. Do not delete `check_capability_current.py` in isolation: the old MTM-015
target caller also binds historical harness hashes and has required-LaTeX,
resource and deployment responsibilities. Retire that family only after its
remaining responsibilities are replaced or explicitly made historical. Do not
translate every historical script into a separate Rust executable.

## Validation and rollback

Use unit tests for selection/summary failures and actual CLI negative cases that
prove rejected artifacts are never launched. Run the ordinary workspace gate,
the current-source capability gate and the exact-candidate gate. Keep the earlier
host acceptance sealed and do not use it to relabel this environment's failures.
Rollback is reverting the dedicated D5 commits; no live data migration is involved.

## Operator entry

From this checkout, with the locked dependencies already available:

```sh
cargo build --release --locked --offline -p mtm-cli --bin mtm
sha256sum target/release/mtm
cargo xtask qualify --profile protocol --binary target/release/mtm \
  --sha256 <the-reviewed-artifact-sha256> --record
```

Use an ordinary immutable artifact file rather than a mutable selector symlink.
The path can be absolute or checkout-relative. The gate requires Linux, Cargo,
the locked Rust dependencies, and actual curl/Git for the disposable fixtures.
It builds the current test harness but launches a private byte-identical snapshot
of the selected product; the candidate is not silently replaced by that build.
The original and snapshot are checked before/after, and each server restart
rechecks its executable. All three independently validated summaries must match
the selected SHA. The report is `records/validation/candidate-protocol.json`.

Only use reviewed MTM artifacts. A hash proves byte identity, not trustworthiness;
this maintenance harness is not a sandbox for hostile executable input. Temporary
state protects ordinary qualification from touching production configuration; it
does not confer isolation guarantees on arbitrary candidate code.

The fixture-only `MTM_TEST_CANDIDATE` and `MTM_TEST_CANDIDATE_SHA256` variables are
consumed only by the Rust integration tests, never the runtime. The ordinary
`cargo xtask capability` and `cargo xtask check` remove both before spawning tests,
so an inherited candidate selection cannot substitute for current-source checks.
Partial selection fails rather than falling back. No new public MCP tool,
workflow authority or finalizer is added.

## Scope of the protocol profile

The three complete fixture paths are compact, full direct-route, and one
verifier-gap/repair cycle. They use current server-issued plans, subgoal IDs and
capabilities, restart at assembly, require the final run to be sealed, and compare
the exported TeX bytes. Verifier context/memory boundaries and absence of a final
artifact before completion are checked. A correct label alongside a reported gap
must route to repair. This is scripted state-machine testing, not independent
mathematical evaluation or branch-barrier coverage.

The persisted-key fixture checks owner-only storage, same-key restart, old bearer
rejection after changing a disposable key, same registered client identity after
reauthentication, and zero-write old-capability rejection followed by one fresh
submission. No production key path can be supplied to that helper.

Captured test output has a two-MiB per-stream bound and a fixed ten-minute runner
deadline. A timed-out/oversized/incomplete runner can never pass; managed process
groups are terminated while still owned. This is not a guarantee against a
hostile daemon escaping a process group. Raw test protocol/credential/log data
is not written to repository reports. On incomplete execution, whether a
candidate launched remains unknown unless validated evidence establishes it.

## D5 completion

Implementation `9bcf435` passed the protocol profile again after commit, using a
release-profile `0.6.0-preview.1` artifact. The byte-bound report is sealed as
`records/evidence/MTM-016/candidate-protocol-d5-9bcf435.json`; the iteration receipt
binds its hash. All 500 normal first hops, three complete scripted flows and five
Git-tool checks passed on the same selected artifact. Wrong-SHA execution was
separately rejected before candidate launch.

The source suite now has 16 passing protocol tests and 61 passing maintenance
unit/CLI tests. The complete workspace command in the connected nested sandbox
still reports its ten known Native failures. The previous host pass is kept as
its own sealed observation, not used to turn this later environment green.
D5 is complete only within the declared protocol scope; MTM-016, full target
qualification, persistent workflow idempotency and Python retirement are pending.

## D6 target profile

D6 extends the same exact-artifact entry rather than introducing another release
script:

```sh
cargo xtask qualify --profile target --binary target/release/mtm \
  --sha256 <the-reviewed-artifact-sha256> --record
```

The target profile first runs the Rust Native preflight. If the current environment
cannot create the required user/Bubblewrap namespaces, qualification stops at
`native_preflight` and reports `candidate_launched=false`. It never weakens
Bubblewrap, changes sysctls, skips the target test or falls back to protocol-only
success.

On a capable Linux host it launches the same private SHA-bound candidate snapshot
through a fixed target server profile: Bubblewrap backend, dangerous Native mode
and `LatexPolicy::Required`. Dangerous mode is intentional for this qualification
lane because permission elicitation is not the object under test; the public
`exec_command` still traverses OAuth/MCP, the production Native authority and the
production Bubblewrap executor. The test requires hard-isolation attestation,
private-vault exclusion and a real command result.

The target profile also runs a complete compact workflow with the required LaTeX
policy. A sealed `done` result with `latex_passed=true` in that fixed profile
requires the isolated `latexmk` compile path; static-only fallback cannot satisfy
the test. The exported TeX bytes, restart-at-assemble behavior and verifier memory
firewall remain checked. The verifier result is a scripted fixture, so this proves
runtime/finalizer mechanics and compiled-LaTeX compatibility, not independent
mathematical correctness.

The target profile intentionally does **not** claim browser use, resource
non-regression, installation, selector cutover, upgrade/rollback or release
qualification. Those remain later D/F responsibilities. It also does not authorize
deletion of the old target Python family until copied-state/resource and remaining
target responsibilities have explicit Rust coverage.

During D6 development, the connected nested Native environment returned the same
namespace-limit preflight classification already recorded for source tests. The
target command therefore stopped before candidate launch, as required. The protocol
profile was rerun against the exact release artifact and remained green. D6 cannot
be marked target-qualified until the target command is rerun on the ordinary Linux
host and its report is reviewed/sealed.
