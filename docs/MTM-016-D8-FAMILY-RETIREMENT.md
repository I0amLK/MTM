# MTM-016 D8: target/release/install family retirement

This is round **3/5**, not completion of all stage D or a release decision.
Starting commit: `671135560816e0884d2334d328805d5822cb1a4c`.
The initial Rust install/status/rollback/dist replacement was committed separately
as `1097188a6cd65d145bd8e3e367fc36bcb43363a2`. Review exposed additional installation
faults; their fixes and tests precede the final Python deletion commit as well.

## Exact retirement boundary

This round removes 49 Python files: 14 historical/MTM-015 target files, 32
release/install/cutover/staging files, two release-helper test modules, and the
now-unreferenced `check_capability_current.py`. The baseline had 127 Python files;
60 are now retired and 67 remain. There is no repository-wide Rust-only claim.

The ledger distinguishes **8 direct Rust replacements**, **4 intentionally retired
historical comparisons**, and **48 consolidated family files with pending forward
acceptance**. The earlier provisional count of 55 replacements conflated direct
replacement with family consolidation. Every removed file still has its own
baseline SHA-256; no family entry may hide an undeclared deletion or omit its
pending acceptance. `retirement` checks provenance, not runtime equivalence, and
never executes the command strings stored in the ledger.

| Responsibility | Current owner | Boundary still requiring acceptance |
|---|---|---|
| Current-source and external-binary capability checks | `xtask capability`, `xtask qualify --profile protocol`; independent Rust OAuth/MCP fixtures | Fixed 500 assessments, not the old configurable sample-count interface; no independent web-model claim |
| Historical target/release/staging records | `xtask records`; original bytes, identities, counts and baseline binding | History is not a current candidate pass; no live selector or historical executable is queried |
| Native and compiled-LaTeX target qualification | Existing Rust `qualify --profile target` | Exact candidate on a capable host; remaining full permission/TTY/CAS/retrieval/browser paths are not implied by this profile |
| Resource comparison | Existing Rust `qualify --profile resource` | Equivalent baseline/candidate samples; permission-grant soak is separate and still pending |
| Immutable distribution staging | `xtask dist` | Byte identity only; caller-supplied version label is explicitly unverified |
| Explicit local install/status/rollback | Candidate's own Rust CLI | Selector mechanics and ordinary-error compensation only; not live upgrade, old-runtime health or state-schema rollback |
| Historical browser adapter | Retained Python bridge delegates receipt policy to `xtask records` and checks the selected frozen artifact | Still Python; still the historical MTM-015 candidate, not MTM-016 browser acceptance |

The original 60-90 second permission soak, minimum 100 iterations, resource growth
bounds, real human-consent requirements and clean-install/old-run recovery duties
are not deleted as requirements. They are explicitly retained in the family
ledger's `pending_acceptance`. In particular the old Python release-parser tests
are not described as an already ported forward release validator. Frozen-byte
integrity protects their historical evidence; F must validate the new release
schema and mandatory gates independently.

## Installation contract

There is no default home directory, production selector, automatic process stop,
or production database path. Install accepts one to eight explicit normalized
absolute selectors named `mtm`, outside its state root and source artifact.
Existing ancestor symlinks are rejected, including in-root symlinks.

Run `install` **through the intended reviewed candidate itself**. `--binary` must
have that process's exact SHA-256, and `--version` must match its compiled version.
This rejects arbitrary executable bytes or a misleading version label without
starting another unchecked identity subprocess. `dist` intentionally does not
execute its input; it reports `version_label_verified=false`.

The installation stores artifacts at `releases/<version>/<full-sha256>/mtm` and
distribution uses `mtm-<version>-<full-sha256>/mtm`. Publication refuses conflicting
existing bytes, dangling artifact links and unexpected metadata. Files are
bounded while being read/copied, not only by an initial stat. Artifact modes must
be ordinary executable modes. Manifest and regular-file backups start owner-only.

A permanent nonblocking lock serializes cooperating commands using the same state
root. Repeat installation of an already selected identical artifact preserves the
original rollback baseline. Existing selector sets cannot be changed implicitly.
Status rejects empty/duplicate selector arrays, unknown manifest fields/states,
wrong content addresses, escaped backups, invalid modes and drift. Rollback checks
all regular-file backups before mutating any selector and preserves ordinary rwx
bits. A repeated completed rollback only verifies the restored state.

Ordinary failures compensate every touched selector, including the current one
when rename may have succeeded before sync failed. They also restore and verify
the previous manifest. `compensation_verified=false` is never reported as a
successful restoration. Immutable staged artifacts/backups may remain after a
failed installation; they are not automatically deleted.

These are cooperative local filesystem mechanics, not a hostile same-UID security
boundary. Multiple roots selecting the same paths are unsupported. There is no
claim of simultaneous visibility across several selectors, SIGKILL/power-loss
recovery, ACL/xattr/owner preservation, or semantic health of the previous symlink
target. F must use reviewed previous artifacts and pre-upgrade state copies;
selecting an older binary does not undo the workflow schema 7 migration.

## Validation and rollback

Four new CLI regression tests first failed on the draft implementation: lost
rollback baseline after repeat install, false success for empty selector arrays,
ancestor-symlink acceptance, and unbound runtime/version labels. The six CLI
integration tests then passed with the repairs. Further Rust unit/CLI tests cover
lock contention, partial compensation failure, malformed manifests, no-clobber
publication, dangling links and special modes. All test writes use disposable
paths; none selects an installed production command.

The residual Python suite has three pre-existing failures. They were reproduced
in a detached checkout of the round's starting commit: the hard-coded 15-milestone
assertion and two validators that predate the approved maintenance crate. They
remain failed, not skipped or relabelled. Historical helper imports and the
remaining forward coverage must be handled in later D work.

The exact command outcomes and final artifact hashes belong in `ITER-016.json` and
its sealed D8 reports. `cargo xtask check` continues to run inherited host tests;
Native preflight never waives a failed test. `audit --strict` must remain nonzero
while the 67 Python files and remaining legacy Rust references exist.

Revert the deletion commit to restore the frozen helpers, then the separate Rust
replacement/fix commits as needed. No installed selector, production key, run
database or research artifact is changed by this delivery. No push or release
qualification is implied.
