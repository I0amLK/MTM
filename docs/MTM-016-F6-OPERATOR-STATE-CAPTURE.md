# MTM-016 F6: authorized operator-state capture, not acceptance

The operator explicitly authorized copying current production MTM state for the
MTM-016 copied_operator_state rehearsal, without modifying the production original.
The current MTM connection reports preview.2 / state schema 2, but its Native
namespace deliberately hides the runtime's data/private roots. Authorization does
not remove that filesystem boundary. Do not bypass it with another process root,
mount alias, permission downgrade, or secret-bearing process environment dump.

The existing `qualify --profile upgrade` generates its own baseline fixture. It
cannot consume an operator data path and cannot satisfy copied_operator_state.
The existing strict release adapter remains unchanged and blocked until an actual
copy migration, old-owner run continuation and old-runtime rollback are observed.

## First host action

Use the production data root from the original production launch configuration,
not a browser acceptance session. The documented default is `$HOME/.mtm`; an
explicit `MTM_DATA_ROOT` overrides it. The capture command intentionally has no
default and does not consult an inherited `MTM_DATA_ROOT` or shell test variables.
Its current supported layout is `oauth.sqlite3` plus `private/state.sqlite3` below
one root. A separately configured private root requires separate reviewed capture
planning, not a guessed fallback. Missing source files cause an error.

Pause requests from all production clients while the command runs. The flag below
confirms the selected source and absence of intentional concurrent writes. The
helper does not stop the production server, checkpoint a database, delete WAL/SHM,
change original permissions, invoke sudo or change installation selectors.

```sh
bash scripts/mtm016-capture-operator-state.sh \
  --source "$HOME/.mtm" --operator-confirmed-quiescent
```

The helper uses an explicitly read-only Bubblewrap source bind and a private
writable destination, with no network and no inherited credentials. It checks
read-only mount flags before reading state, captures one normalized PAX archive,
then independently streams the entire source again and compares SHA-256 digests.
No filenames or private file bodies are printed. Symlinks, regular hardlinks,
special files/modes, nested devices, depth >=33, >20,000 entries, >128 MiB files or
>256 MiB total file data fail closed. An archive is also file-size-limited, and
the host command has a 180-second timeout with bounded termination. No failure
automatically retries, falls back to writable access or raises a limit.

The first real host attempt reached the isolated helper but stopped at its initial
read-only mount check before any archive was created. The original check parsed one
raw `/proc/self/mountinfo` field directly. The follow-up keeps the same fail-closed
requirement but asks util-linux `findmnt` for the exact mountpoint's VFS options and
requires a standalone `ro` option. It also separates `readonly_mount_options` from
`readonly_mount_layout`, so a later failure distinguishes mount semantics from
database visibility without probing the production source by writing to it.

All files, including SQLite journals/WAL/SHM and private keys, remain in a private
archive under `$HOME/.mtm-acceptance/MTM-016/`, outside the repository. Do not upload
the archive, extracted databases, keys, raw logs, or original run/proof contents.
Failed partial captures remain there for operator-controlled cleanup and are not
usable acceptance inputs. A successful archive is made owner-read-only.

Bound failures publish only one fixed metadata category plus aggregate entry/byte
counts, never the rejected path or private content. Current categories are
`entry_limit`, `depth_limit`, `cross_device`, `special_mode`,
`unsupported_file_type`, `regular_file_hardlink`, `single_file_size`, and
`total_file_size`. These diagnostics do not relax the bound or trigger a retry.

Two identical source streams show observed byte stability, not a transactional
multi-database snapshot or proof that a live writer was stopped. Before use, verify
SQLite recovery/integrity on a separate extracted working copy, retain the original
archive, and compare source identity again under read-only access as appropriate.
If writers cannot remain quiescent, obtain a coordinated offline/filesystem
snapshot rather than treating this capture as a live-database backup protocol.

## Remaining rehearsal

After a verified capture, inspect only the working copy's schema, run-state counts,
ownership and copied OAuth client authentication methods. Keep proof bodies and
credentials out of reports. A new DCR identity is not the old run owner: do not
rewrite owner IDs, weaken OAuth, mint a capability directly or substitute a newly
created run for old-run continuation. If a copied confidential client requires a
credential unavailable to the rehearsal, preserve that blocker.

Use only the pinned baseline and frozen candidate in isolated, non-public,
Native-disabled/static-LaTeX rehearsal instances. Preserve the pre-upgrade archive;
prepare private permissions only on a working copy; migrate to schema 7; authenticate
normally as the preserved old owner; resume an eligible existing run; then restore
an independent copy of the original bytes/modes and resume with the old binary.
Only after those observations may the existing Rust release adapter ingest a
`mtm-copied-operator-state-evidence-v1` report. Capture-summary JSON is a different
schema and cannot turn the release gate green. No source/resource rerun or candidate
rebuild follows from adding this operator transport helper and documentation.

## Transport verification

`bash conformance/mtm016-operator-capture-tests.sh` exercises the actual archive and
tree-bound primitives on temporary synthetic files. It checks deterministic
streams, content drift, round-trip archive bytes/modes, Unicode/newline filenames,
WAL/SHM/key inclusion, link/FIFO/special-mode/size/depth refusals, the exact 20,000
entry boundary, missing source/arguments, and refusal without the required read-only
mount. These tests neither open SQLite nor access production state.

The separate full helper launch on synthetic state in the current MTM Native
environment stopped at Bubblewrap with ENOSPC before capture. No writable fallback
was used. The primitive tests pass, but successful host namespace setup and an
actual production capture remain unobserved until the operator executes the host
entry above. The earlier real-host Native preflight does not substitute for this
specific capture run.
