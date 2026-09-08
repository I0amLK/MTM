# Independent Rust policy regression

This MTM-016 checkpoint replaces the pure-policy comparison against a sibling
Re-CTM checkout. It does not replace host, workflow, browser or release qualification.
The previous MTM-002 output hash and resource measurements remain historical records;
they are neither regenerated nor asserted as measurements of this development build.

## Coverage preserved

`crates/mtm-cli/tests/support/policy_cases.rs` contains the 135 named input cases
previously assembled by `conformance/mtm002_cases.py`. Their 14 operation groups
remain explicit: schema validation, redaction, fingerprints, byte redaction, OAuth
origin validation, redirects, tunnel parsing, workspace paths, environment filtering,
inline-script detection, command policy, patch parsing, hunk application and terminal
states. The serialized input batch retains the recorded 13,719-byte size.

Expected results are authored as test data rather than generated from either current
implementation. Success results are compared exactly. Errors must have nonempty
messages and the expected code, category, retryability and structured details. Exact
Python diagnostic spelling is deliberately not a new MTM contract requirement.
The separate numeric tests still assert the location and message of a range error.

The old `schema-float-number` case is an intentional correction: `1.5` with a minimum
of `3` must be rejected. Five new regressions first reproduced the inherited failure,
then passed after the implementation was repaired. They include 4,556 comparisons
against exact quarter-unit expectations and boundaries beyond f64's integer precision.
Only inclusive minimum/maximum on serde_json i64/u64/f64 values is implemented here;
this is not a complete JSON Schema or arbitrary-precision decimal implementation.

## Two independent execution paths

`policy_corpus.rs` calls the public Rust evaluator and checks unique case names,
all operation counts, expected results and determinism. `policy_cli.rs` runs the
actual built `mtm evaluate` / `evaluate-batch` executable with its environment cleared,
an empty PATH and a disposable empty working directory. It checks the entire batch,
single/batch consistency across all 14 operations, 1000/1001-item and 1 MiB boundaries,
malformed JSON/UTF-8, per-item errors, bounded output and process deadlines.

All command-looking strings in this corpus are inputs to pure policy functions,
never commands to execute. No Python process or reference checkout is used. The
test fixtures remain inside the CLI crate so they do not introduce a cross-package
file dependency into its tests. No production dependency or authority is added.

Run with ordinary Cargo; no additional milestone-specific runner is needed:

```sh
cargo test -p mtm-core --test numeric_schema --locked
cargo test -p mtm-cli --test policy_corpus --test policy_cli --locked
```

Both targets also run under `cargo test --workspace` and `cargo xtask check`.

## Retirement decision and limits

After these replacements are committed, retire the old four-file chain together:
`scripts/run_mtm002_conformance.py`, `conformance/mtm002_cases.py`,
`conformance/python_reference.py`, and `conformance/python_batch_cli.py`.
The reviewed deletion ledger binds their baseline bytes and replacement locations.
The residual Python aggregate must call the Rust tests rather than the removed driver.

Cross-language output equality and cross-language performance comparison cease to
be current acceptance conditions. No new performance claim follows from their
retirement. Full resource non-regression remains required before release.
No prior accepted/rejected evidence or golden hash is changed. Pure policy tests
do not exercise Native execution, real OAuth clients, live tunnels, compiled LaTeX,
workflow idempotency, or the earlier unexplained capability signature mismatch.
