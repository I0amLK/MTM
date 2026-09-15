# MTM-016 Rust-reference audit after Python retirement

The first-party Python retirement is complete at implementation commit
`14bbd961822fd3b6217e53def4e545402189d914`: all 127 Python files from the
frozen MTM-015 baseline are absent and baseline-hash accounted for. The old
inventory nevertheless reported 81 `legacy_rust_reference_files` because it
classified any Rust file containing `ReCtm`, `re_ctm`, `re-ctm` or `Re-CTM` as
a live legacy dependency. That rule mixed runtime authority with compatibility
spelling and therefore could not be used as a sound Rust-only release gate.

## Blocking definition

`cargo xtask audit` now separates three concerns. `rust_only_ready` is blocked
by a first-party `.py` source, a Rust source that can launch a first-party
repository Python entrypoint, or an unreadable/unbounded source file. User
commands such as `python3 -c ...`, Python filenames used only as command-policy
fixtures, and Sage/Python invoked by the user through Native tooling remain
supported and are not first-party runtime authority.

Rust files containing historical or wire-compatible Re-CTM spellings remain
reported as `compatibility_rust_reference_files`. They include the current
`ReCtmError` type name, legacy MCP diagnostic keys, the frozen Native helper
protocol string, sandbox HOME/hostname strings and historical test URLs. These
strings are not hidden or counted as removed. Renaming them would change source
or wire identity and belongs to a separately qualified future candidate.

Four Rust-only development binaries are also reported separately as
`legacy_shadow_binary_files`:

- `crates/mtm-native/src/bin/shadow.rs`
- `crates/mtm-storage/src/bin/shadow.rs`
- `crates/mtm-workflow/src/bin/mtm_workflow_shadow.rs`
- `crates/mtm-workflow/src/bin/target_validation.rs`

No current source caller for these binaries was found. They are not Python
authority and therefore do not block Rust-only readiness. Deleting them now
would change the `crates/` source identity bound to the already frozen candidate
and would require a new candidate plus requalification; that cleanup is deferred
rather than silently invalidating current evidence.

## Fail-closed checks

The inventory tests require compatibility names and user Python examples to stay
non-authoritative, while an actual Rust `Command::new("python3")` or a shell
wrapper launching a repository `scripts/`, `conformance/` or `tests/` Python
entrypoint is classified as a first-party Python launcher. The detector scans
both product crates and `xtask`; it does not exempt its own source file.

The expected current audit boundary is therefore:

```text
python_file_count                       = 0
legacy_rust_reference_file_count        = 0
compatibility_rust_reference_file_count = 81
legacy_shadow_binary_file_count          = 4
rust_only_ready                          = true
```

This is a semantic correction to the audit, not a claim that 81 Rust files were
deleted. Release qualification remains false until the independent Native,
target/resource, compiled-LaTeX, browser/human, copied-operator-state and full
corpus gates pass.
