# MTM-017: two clean builds without changing the selected candidate

## Scope and execution boundary

The operator requested two clean checkout/build observations for the exact
schema-8 `0.6.0-preview.2` candidate. This document and
`scripts/mtm017-clean-build-provenance.sh` prepare that work only. Do not run the
build entry until the corpus phase is finished and execution is explicitly
authorized. A successful plan, shell syntax check or prepared script is not build
evidence, reproducible provenance, release qualification or deployment authority.

Use only the CTM connector from the ordinary host checkout. Its exec `workdir`
parameter is `.`; an absolute workdir is rejected by that connector. The script
derives the actual repository from its own location and verifies the Git root.
It never invokes Codex, Work, a cloud executor, a production MTM command, an
installed selector, or an old release driver.

## Frozen identities

- Source commit: `7b4afe2359e688263557f62154e4bc1e640c12c0`
- Sealed `mtm-rust-source-v1` identity at that commit:
  `0adec4b02a8b54fd20fb30c796c9959ccc346cc0f9336517fc47eafcb6951e02`
- Candidate SHA-256:
  `13d7890c5c763199ed39295e134ff6cc735ceaa04eaddf6c556431a7a56254f4`
- Candidate path:
  `target/mtm017-preview2/mtm-0.6.0-preview.2-13d7890c5c763199ed39295e134ff6cc735ceaa04eaddf6c556431a7a56254f4/mtm`
- Cargo.lock SHA-256:
  `cd7c8da83a0750ebfca58512470bd35ee4a6c66c3b68404662d822cf5bc42a8c`
- Existing compiler pin: `1.98.0`, target `x86_64-unknown-linux-gnu`
- Build command:
  `cargo build --release --locked --offline -p mtm-cli --bin mtm`

`records/evidence/MTM-017/preview2-qualification-snapshot.json` is the existing
binding. Do not edit its hashes or the candidate. Later collector/precheck changes
alter the current complete harness source identity even when product crates are
unchanged. Both new builds therefore clone the frozen commit, not a dirty/current
HEAD; the runner's own HEAD, status and file hash are separately retained.

## Authorized bounded qualification-cache exception

The normal ownership rules in `AGENTS.md` and
`docs/MTM-016-F6-CARGO-CACHE-OWNERSHIP.md` remain in force for ordinary work.
This requested two-clean-build qualification requires an empty compiled-product
cache twice, which a repeated warm-cache build cannot prove. Its sole scoped
approved exception is a new owner-private session below
`target/mtm017-clean-build-provenance/`, with one `checkout` and one `build-cache`
path reused serially. It does not repurpose, clean or write `target/debug`,
`target/release`, `target/mtm-tool`, frozen candidate directories or any operator
cache. It does not create a `/workspace` alias or run a path-bound maintenance
executable from a different checkout. The operator approved this narrow
cache/private-dependency/cleanup arrangement on 2026-09-30; the exact question and
answer are retained in `MTM017-READINESS-DECISION-002` in
`records/governance/mtm017-readiness-decisions.json`, with the matching narrow
entry in `AGENTS.md`. Actual builds still wait for the corpus phase and independent
pre-execution review. This changes no general Cargo rule.

For each round, the script makes a fresh no-hardlink detached local clone, verifies
the exact commit, tree, lockfile and clean source, and builds into its empty cache.
It copies only the selected crates.io compressed archives and sparse index into
a private Cargo home; the pinned lockfile contains no git dependency. Existing
dependency caches are read for copying and hash comparison only, never linked
into the writable private Cargo home. Each tree rejects symlinks, regular-file
hardlinks, special files, files above 64 MiB and more than 100,000 entries; combined
file bytes must not exceed 512 MiB. Source and copy shape/content hashes must match,
and original inputs are rechecked after each build. Copying has a 120-second bound
per tree. Private Cargo unpacking and compilation remain inside the session.

The same private Cargo home is retained between the two rounds, including its
first-round unpacked sources and metadata. The compiled-product cache and source
checkout are fresh each round; this does not claim a second empty Cargo home.

The dependency input is explicitly selected with `--dependency-cache`; it never
defaults to the connector's temporary HOME. The reviewed host input
`/home/lk/.cargo` contains 1,243 archive/index entries and 109,054,353 file bytes,
about 104 MiB. Its archive cache contains 120 of 124 locked registry packages;
the four missing packages are r-efi, wasi, windows-link and windows-sys. Whether
the Linux build needs any missing archive is left to the real offline build,
not silently counted as complete dependency qualification. The connector's
temporary HOME contains only 31 archives and is not the selected input.
Each run requires free disk space for the selected inputs plus a conservative
12 GiB build reserve. This is a preflight capacity check, not a guarantee that a
build cannot run out of space. The private dependency copy and all failed scratch
remain available for inspection; they are never included in recursive cleanup.
Offline availability is only established by the actual build. Existing compiled
caches are never consumed, and existing Cargo configuration or credentials are
not copied. A minimal build
environment removes inherited Rust flags, wrappers, credentials and arbitrary
environment settings. PATH includes only the
pinned Rust toolchain and explicitly recorded system compiler tools. The absence
of Python from this PATH does not claim Python is absent from the host or that
arbitrary subprocess behavior was traced. Cargo offline mode is not an OS-level
network-isolation claim.

Cargo configuration inherited from checkout ancestors is checked separately:
only the exact pinned alias-only `.cargo/config.toml` in the clone and source
repository is accepted and hash-recorded. Any other ancestor Cargo configuration
fails closed before compilation rather than silently affecting the artifact.
Git ignores inherited Git environment variables and global/system configuration,
disables hooks and automatic line-ending conversion, and verifies both clones'
raw source bytes against the committed `mtm-rust-source-v1` SHA before and after
compilation. The complete build environment allowlist is stored as a NUL-separated
manifest and hash-bound by each receipt. Compiler/toolchain manifests are measured
from the actual fixed tool-bin targets before and after each build and compared
with the initial session manifest; any drift blocks acceptance and scratch cleanup.

The executable, receipt, logs and input hashes are retained separately for each
round before deleting that round's scratch. Deletion accepts only the literal
`checkout` and `build-cache` children of this invocation's marked session. It
checks canonical paths, private session ownership/mode, child ownership, and
marker-bound device/inode identity. Checkout markers live inside `.git` to keep
the tested source tree clean. No recursive cleanup of `target` or the session's
`evidence` directory exists. Failures and interruptions preserve their remaining
scratch and evidence; there is no automatic resume, cleanup or retry. The guards
do not claim protection against a hostile concurrent same-UID process.

## Absolute-path caveat and acceptance

The frozen artifact was built at `/home/lk/桌面/MTM2/MTM` using
`target/mtm-tool`; the qualification clones have a different absolute path.
Both new rounds use the same clone/cache path within one session. Rust macros,
compiler/linker settings or other path-sensitive inputs can still make both new
binaries equal to each other while differing from the selected artifact.

No remap-path-prefix, SOURCE_DATE_EPOCH or Rust flag is invented to hide that
difference. Every round records its actual checkout/cache path, Git commit/tree,
manifest/lock/toolchain input hashes, compiler tool hashes, compiler/Cargo versions,
command, timestamps, exit code, source cleanliness, output hash and the unchanged
selected-candidate hash. The comparison binds both receipt hashes.

Only two successful clean builds whose SHA-256 values both equal the frozen
candidate can support that candidate's clean-build provenance. Any mismatch exits
nonzero, preserves both results, and requires an explicit diagnosis of original
build inputs. A same-version different-hash rebuild cannot inherit prior candidate
qualification. The comparison is a new input for the still-separate schema-8
readiness adapter, not an acceptance receipt from the frozen MTM-016 validator.

## Commands

Preparation, no cloning or Cargo build and no output files:

```sh
bash -n scripts/mtm017-clean-build-provenance.sh
bash scripts/mtm017-clean-build-provenance.sh --plan \
  --dependency-cache /home/lk/.cargo
```

Only after separate execution authorization and the corpus phase:

```sh
bash scripts/mtm017-clean-build-provenance.sh \
  --run --authorize MTM-017-CLEAN-BUILD --dependency-cache /home/lk/.cargo
```

Each Cargo invocation is bounded to 30 minutes with TERM/KILL escalation and a
per-file size limit applying to logs and generated build files. A failed first
build stops before round two.
Reports and build logs remain in the private qualification session; publish only
reviewed metadata under a new MTM-017 record. Do not expose raw logs automatically.
No report grants release or deployment authority; production selector/state flags
remain false throughout.
