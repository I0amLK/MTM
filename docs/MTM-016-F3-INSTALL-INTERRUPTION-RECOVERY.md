# MTM-016 F3: interrupted installation recovery

This is a bounded continuation of round **4/5**. It closes the durable
process-interruption gap in D8/F1 selector mechanics; it does not claim host power
loss, production cutover, real Native, browser, compiled-LaTeX or release
qualification.

## Failure being repaired

D8 made each selector replacement and manifest publication atomic and compensated
ordinary returned errors. A process killed after one or more selectors were
durable but before `current-v2.json` was committed could nevertheless leave a
mixed visible installation. The next `status`, `install` or `rollback` could only
report selector drift because no durable record said whether the interrupted
operation had been an install or a rollback.

F3 adds one cooperative transaction journal under the explicit state root:

```text
deployment/pending-v2.json
deployment/pending-v2.manifest.backup   # only when a prior manifest exists
```

The journal is written and directory-synced **before the first selector mutation**.
It binds the complete validated active manifest, operation direction and exact
pre-operation manifest bytes. The optional manifest backup and journal are 0600.
The same permanent installation lock serializes creation, recovery and normal
installation commands.

## Recovery rule

Recovery is conservative and deterministic:

- interrupted `install` restores every selector to the recorded previous state and
  restores the exact prior manifest, or removes the manifest when there was none;
- interrupted `rollback` reselects the recorded active release everywhere and
  restores the exact active manifest;
- malformed, symlinked, oversized, wrong-mode or hash-drifted recovery material
  fails closed before recovery is accepted;
- a manifest backup without a journal is inert and may be removed because no
  selector mutation starts before the journal itself is durable;
- the journal is removed only after the final manifest/status postcheck succeeds.
  The journal is removed before its auxiliary manifest backup, so interruption
  during cleanup cannot destroy the only recovery authority.

If returned-error compensation itself cannot verify the recovered state, the
command remains failed and the recovery material is retained for review. A
successful recovery never creates release qualification.

## Validation scope

Unit fixtures materialize exact persistent prefixes corresponding to termination
after the first selector of an install and after the first selector of a rollback.
They require restoration of symlink targets, regular-file bytes and modes, exact
manifest bytes and removal of the completed recovery journal. Negative fixtures
prove malformed journals do not mutate unrelated selectors and orphan backups are
inert.

Public CLI integration constructs the same durable prefixes and then invokes real
`mtm status` / `mtm install`. This proves the next ordinary command performs the
recovery under the production deployment code rather than requiring a private test
repair function.

These are exact crash-state prefix fixtures, not a claim that a physical machine
was power-cycled. Filesystem/device write-cache behavior, hostile same-UID changes,
cross-host shared filesystems and arbitrary corruption remain outside this scope.
An actual external SIGKILL/power-loss drill may supplement the prefix proof but is
not inferred from it.

All test state and selectors remain in disposable directories. No installed MTM
selector, production database, key or research artifact is read or changed.

## Composed-source validation

The implementation adds six deployment unit tests in total; the two F3 tests cover
the durable install/rollback prefixes, malformed-journal refusal and inert orphan
backup cleanup. All six passed. The public deployment integration suite now has
seven tests; all seven passed, including automatic recovery through real `status`
and retrying `install`. Targeted `mtm-cli` Clippy passed with warnings denied.

The complete `cargo xtask check --record` source gate also passed format, Clippy and
diff checks. All 44 CLI capability/recovery functions and all seven deployment CLI
tests passed. The workspace gate remains nonzero only because the same ten inherited
Native/Bubblewrap runtime cases fail in this nested environment (128 runtime passes,
10 failures and one pre-existing ignored target-only test). Native preflight again
reported `namespace_limit_or_depth` / ENOSPC. No test was skipped or weakened to
make F3 green. The composed failed source observation is sealed separately as
`records/evidence/MTM-016/source-check-f3-composed.json`.
