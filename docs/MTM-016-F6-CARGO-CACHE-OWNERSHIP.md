# MTM-016 F6: host and tool Cargo cache ownership

## Observed failure, not a resource regression

The operator's source run at `e8e665911a54dedb6ee4a0b8607ce48aec679215`
completed capability_runtime (55 function results), Runtime (140 passed, one
existing ignored), and maintenance unit tests (83 passed). Eleven CLI integration
targets instead reported 27 `NotFound` errors. Resource qualification did not run
because it followed the unsuccessful source gate with `&&`.

All eleven failing cached test executables contain their child program path under
`/workspace/mtm-native-016/target/debug/`. The operator runs the same checkout as
`/home/lk/桌面/MTM/mtm-native-016`. The changed capability_runtime executable was
rebuilt with the latter path; the unchanged CLI test executables retained the former.
Their test sources use `env!("CARGO_BIN_EXE_mtm")` or the corresponding maintenance
variable. This identifies cross-mount reuse of path-bound build products, rather
than a new Magma, Native permission, policy or deployment assertion defect.

The contamination works in both directions: the host-built `mtm-xtask` embeds the
host `CARGO_MANIFEST_DIR`, and its root canonicalization fails inside the MTM mount.
An identity-test replay under its original `/workspace` path passed both tests;
the cached maintenance-test replay had one success and one assertion failure,
with direct maintenance startup reporting the missing compiled checkout root.
These diagnostics are not a replacement for the failed host source gate.

## Ownership and bounded recovery

The operator owns the default `target/debug` and `target/release` build caches.
MTM tooling owns exactly one separate cache, `target/mtm-tool`, addressed as
`/workspace/mtm-native-016/target/mtm-tool` inside the tool environment. Cargo
invoked indirectly by the commit hook must inherit the same explicit setting.
Do not share the compiled caches across the two absolute checkout roots. Do not
copy or symlink a compiled maintenance binary across roots and call that recovery.

No runtime, test, validator, manifest-format or resource-threshold change is needed.
No path fallback, widened filesystem authority or fresh full build tree is needed
on the host. Clear only the affected packages' development products, then rebuild
them at the host root. Dependencies and frozen candidate staging directories are
outside that package-scoped recovery. A local Cargo dry-run reported 7,142 files,
approximately 2.3 GiB; it did not delete anything. This is cache regeneration, not
deletion of test source or accepted evidence.

From the reviewed host checkout, without another concurrent Cargo workload:

```sh
(
  export CARGO_TARGET_DIR="$PWD/target"
  unset MTM_TEST_NATIVE_COMMAND_PROFILE MTM_TEST_COMPILED_LATEX_PROFILE
  cargo clean --locked --offline --profile dev -p mtm-cli -p mtm-xtask &&
  cargo test --locked -p mtm-cli --test identity --test policy_cli &&
  cargo xtask check --record
)
```

Only after source passes, run the existing exact-candidate resource command with
the same candidate and baseline hashes. Never use an unrestricted `cargo clean`,
remove the target tree, touch source to force recompilation, override binary
selection, or replace an old receipt's source hash. The subshell does not exit or
reconfigure the user's interactive shell. Subsequent tool-side builds must stay
in their own cache, including during review of newly produced host reports.

## Evidence and limits

The original host failure is preserved byte-for-byte as
`records/evidence/MTM-016/source-check-f6-e8e6659-path-failed.json` and remains
failed. The earlier successful source receipt also remains immutable. A separate
diagnostic records the path observations and package-clean dry-run. Neither makes
source or resource pass. Native, compiled-LaTeX and target keep their existing
independent evidence; no performance or release claim follows from this repair.
