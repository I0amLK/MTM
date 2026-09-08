# Current-binary capability regression in Rust

Run `cargo xtask capability --record` from the development checkout. It builds and
tests the current CLI via Cargo and writes the regenerable, redacted summary to
`records/validation/capability-current.json`. `cargo test --workspace` also includes
the test automatically; it is not an ignored or optional success-path-only suite.

The test is `crates/mtm-cli/tests/capability_runtime.rs`, using test-only helpers in
`tests/support/`. Those helpers are not linked into the product, do not construct
authenticated server principals, and are not an SDK that the web model automatically
uses. No Python interpreter or historical harness is executed by the Rust gate.

## Actual test boundary

The executable is Cargo's `CARGO_BIN_EXE_mtm`, not an installed selector. Its SHA-256
is checked before and after the test. The server uses disposable workspace/data
directories and real SQLite, HTTP sockets, DCR/password/PKCE authorization, MCP
dispatch, capability validation and workflow writes. A first startup binds port zero
and reports the owned loopback endpoint; no reserve-and-release free-port race is
used. Graceful shutdown is bounded and a test failure kills its owned child.

The child inherits no host environment. Its PATH contains only a link to the actual
installed curl because the existing research adapter resolves curl during startup.
No fake executable replaces curl and Python is not exposed on that PATH. Native is
explicitly disabled and LaTeX is `static_only`, as in the old loopback gate. No
external provider is queried. This is not a claim that the entire host lacks Python,
or that Native isolation, compiled LaTeX, browser rendering or Quick Tunnel passed.

The small test HTTP client only accepts bounded, length-framed responses from its
owned loopback address; it is not a general HTTP client or production dependency.
Credentials are opaque and never included in returned test errors or reports. Raw
child logs are drained and discarded; the maintenance report retains only typed
summary fields and digests of the test runner's redacted output.

## What must pass

Five hundred independent normal runs alternate compact/full, 250 each. Each uses
the current server-issued task's minimal submission, advances the same run, confirms
the logical write count and cancels its disposable run. Zero normal INVALID,
rejections or refreshes are required. These are assessment first hops, not 500
complete proofs, and logical submissions are counted separately from internal
capability-validation events.

Separate adversarial cases cover altered and shortened signatures, zero logical
memory changes before authorization, successful fresh submission, used-token
revocation, cross-run mismatch and cross-owner refresh denial. Invalid and revoked
inspect/retrieve requests must remain denied and return no replacement authority.

A real process restart preserves the disposable data/key files and the same OAuth
principal: the previously issued task capability is submitted without reconstruction
or refresh. Another test intentionally discards a successful tool outcome at the
client callback boundary and proves that the recovery helper does not replay it;
public status observes the completed transition. This is simulated response loss,
not an actual Cloudflare 502 experiment or server-side exactly-once guarantee.

The pure recovery tests preserve the Python helper's one-retry and cursor-binding
rules, and add explicit missing-contract, float/boolean count and transport-uncertainty
checks. Role/domain fields are required; an optional epoch must remain identical.
The maintained Rust helper is test-only and does not create a new production authority.

## Recording and migration boundaries

The maintenance command fingerprints Rust source, tests, embedded assets, lockfile
and toolchain/configuration before and after execution. A passing subprocess alone
is insufficient: a strict typed summary must contain all expected adversarial
checks, 500 independent successes, both modes and successful clean shutdown. Missing,
duplicate, extra-field, reduced-count or false-scope reports are rejected.

Only `scripts/capability_recovery.py` and its Python unit-test module are removed
in this reviewed deletion batch. `scripts/check_capability_current.py` still supplies
the historical target harness's external `--binary` interface and old report shape;
it remains until that target/release dependency family is replaced or explicitly
retired. The normal source-check entry can use Rust now without pretending the old
target path has already migrated. Existing MTM-013/015 evidence is not rewritten.

A clean run does not explain the earlier web-client signature mismatch. That
diagnosis, real-host/web/LaTeX qualification, persistent operation idempotency and
the rest of the Python retirement remain open. Nothing here installs a binary,
changes a production selector, rotates production keys or rewrites production runs.
