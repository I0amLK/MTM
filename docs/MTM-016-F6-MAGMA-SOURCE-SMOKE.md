# F6: quiet Magma batch output in the source smoke

The operator's complete source run at `77629807dfc6f01f14d76c69e54bb3baca216328`
has one failing test target (`mtm-runtime --lib`), with 137 passed, one failed and
one existing ignored real-network test. The only failing assertion is in
`native_authority::tests::exec_candidate_preserves_git_latex_sage_and_exposes_magma`.
The raw source-check receipt is preserved byte-for-byte as
`records/evidence/MTM-016/source-check-f6-7762980-failed.json`.

## Reproduction and correction

The source fixture called `magma -b` with only `quit;` on stdin but demanded a
banner or authorization text. The installed real launcher was exercised in the
existing MTM exec environment with a cleared environment and system-only PATH:
the original input exited zero without output; adding `print 6*7;` exited zero
and printed `42`. These are launcher diagnostics, not a new candidate qualification.

The inline test now sends the arithmetic fixture and bounds execution to 30
seconds. Functional success needs a completed, non-timed-out, unsignalled process,
integer exit code zero, and exactly one stdout line equal to `42`. Empty output,
a banner alone, a wrong result, duplicate result lines, and process failure cannot
pass. The historical optional source-smoke allowance for an unavailable host
license is separately classified and narrowed to exit 1 with an explicit Magma
`not authorised`/`not authorized` diagnostic. It never becomes a functional pass;
the F6 Native qualification still requires actual Magma execution.

Two pure regression tests failed with the old output rule and passed after the
repair. The original integration test remains present and must be rerun on the
capable host. No ignore attribute, compiler setting, license, Native isolation,
grant rule, product runtime code, or frozen binary is changed.

## Exact source identity boundary

The repair is wholly inside the existing top-level `#[cfg(test)] mod tests` in
`crates/mtm-runtime/src/native_authority.rs`. The production prefix preceding
that guard is byte-identical. The old release-check treated any edit under
`crates/*/src/` as a product edit; it could not represent this inline test fix.

Release-check therefore recognizes exactly one reviewed whole-file byte pair:

```text
before: be4022a71733974860b806484e390c5ecac03bf0442cb3eb5b9ad53e695be2e5
after:  d4979559e8094ac9ce4bdcd91d2654162621b702e179e7ca5100a620de57515c
```

This is not a generic test-stripper, regex-based Rust parser, ignored source path,
or user-supplied override. Both full files (including the guard and all production
bytes) are SHA-bound in the checker. Any other edit, an altered guard, another
path, changed old bytes or reversal of the pair is rejected. The reader rejects
symlinks. A regression verifies the production prefix and adverse byte changes.
Reports explicitly list `reviewed_inline_test_edits` when the pair is used.

The source/harness hash continues to cover the full raw files. Consequently new
source tests require a new source hash and committed receipt; old successful
Native/LaTeX observations retain their original harness hashes and are not
rewritten or promoted to source-test success. Frozen candidate selection and SHA
remain unchanged. No new reproducible-build or release claim follows from this
test-only source equivalence.

An additional local comparison rebuilt the non-test executable before and after
the amendment in the same checkout and target directory. Both locked, offline
release builds returned SHA-256
`c6ec7a5712a159371fb3290fd389a8ea3b840a6d795211945b97b8a9914bf155`.
This is equality between the two local builds, not reproduction or replacement of
the selected `46c1441b...` artifact. The observation is preserved in
`records/evidence/MTM-016/magma-source-build-comparison-7762980.json`.
The reviewed pair cannot exempt an untracked source file or executable/special
permission bits; a disposable Git regression exercises those refusal paths.

## Operator validation

First rerun the formerly failing test without any dedicated qualification flags:

```bash
env -u MTM_TEST_NATIVE_COMMAND_PROFILE -u MTM_TEST_COMPILED_LATEX_PROFILE \
  cargo test --locked -p mtm-runtime --lib \
  native_authority::tests::exec_candidate_preserves_git_latex_sage_and_exposes_magma \
  -- --exact --nocapture --test-threads=1
```

Then run the complete `cargo xtask check --record` on the same committed checkout.
The previous failure remains immutable, and source stays blocked until the new
full source receipt passes. The already sealed Native and compiled-LaTeX gates
remain separate from source, target, resource, browser, operator-state and corpus.
