# MTM-016 F6: inspect the captured working copy, not production

This is the next checkpoint after the operator-reported capture at `4989327`.
The selected archive SHA-256 is
`2d448c5ba1a6f61f8139775c254ad85316b05bf82c0ff6c9d8a0f98805893d8e`.
The capture report records 4,523 entries and 26,126,712 file bytes. Neither these
reported counts nor a passing inspection qualify migration or release.

## Inputs and authority

`scripts/mtm016-inspect-operator-copy.sh` accepts an archive digest and an explicit
SQLite executable, never a production data root. It searches only the owner's
private `HOME/.mtm-acceptance/MTM-016/copied-state.*` captures (at most 128), rejects
missing or ambiguous matches, and requires the original complete capture receipt,
ordinary single-link input files, owner-private parent directories, the pinned
capture-helper hash, and an owner-read-only archive with the selected digest.
The 16 capture fields and their types/identities are required; missing, duplicate,
unknown and malformed fields are rejected. The newest directory is never guessed.

The archive and capture receipt are bound read-only. Only a newly created private
`inspection.*` working directory is durably writable. The production tree and the
rest of the private session are not mounted. No network, MTM runtime, selector,
OAuth login, client registration, capability minting, or owner-ID rewrite occurs.
SQLite and its installation's `lib` directory are mounted read-only at a fixed
prefix to preserve its relative shared-library lookup. The selected system awk
executable is bound directly, reusing the reviewed capture helper rather than
depending on `/etc/alternatives` inside the minimal namespace.

Inputs must remain unchanged while inspection runs. This is an operator-controlled
local rehearsal, not protection against a hostile same-UID process changing the
archive's ancestors. No permission or ownership change is made to the source or
original archive. Prior captures and failed inspections are retained privately.

## Checks and report interpretation

The bounded, network-free namespace verifies the input SHA and receipt before
extracting into a new empty directory. It requests original ordinary modes but
does not restore foreign ownership. It rejects unsafe extracted file types, links,
oversized trees and count mismatches before opening either database. Archive,
helper and SQLite identities are rechecked at their relevant boundaries. Limits
remain 180 seconds for the isolated process, 1 GiB virtual memory, 512 MiB per
output file, and the existing capture tree bounds. There is no automatic retry.

Only the extraction's `oauth.sqlite3` and `private/state.sqlite3` are opened.
Connections disable trusted schema and enable query-only SQL. Opening them may
perform SQLite recovery and update copied WAL/SHM; this is why the databases are
not opened in the original archive or production directory. WAL/SHM are never
discarded, and `immutable=1` is not used. Both full `integrity_check` and separate
`foreign_key_check` must pass. Schema versions outside 1 through 6 are rejected.

The report contains counts only: total, active/unsealed and done runs; OAuth client
count; missing-owner count; and active runs whose preserved owner is a public or
confidential client. `assess_public_client_runs` is a potential rehearsal route,
not proof of available credentials or a resumable task. Missing-owner counts are
observations, not silently repaired. No run ID, owner ID, proof, password, token,
client secret, or arbitrary database error is emitted to the terminal.

`inspection_complete=true` means these preinspection checks passed. It still sets
`migration_executed`, `old_run_resumed`, `rollback_executed`, and
`release_qualified` to false. This report is not an input for the release adapter.
The complete copied-state gate additionally requires normal authentication as a
preserved old owner, candidate migration to schema 7, an eligible old-run
continuation, restoration from the original archive, and old-runtime continuation.
No synthetic/new run can replace that evidence.

## Ordered host entry

Production clients need not be paused: neither command reads production. Run the
complete synthetic namespace test first. Its failure exits nonzero and must stop
the second command. The successful earlier capture test does not substitute for
this new SQLite/extraction path.

```sh
bash conformance/mtm016-operator-copy-inspection-tests.sh --host-isolation --sqlite /home/lk/miniconda3/bin/sqlite3 &&
bash scripts/mtm016-inspect-operator-copy.sh --archive-sha256 2d448c5ba1a6f61f8139775c254ad85316b05bf82c0ff6c9d8a0f98805893d8e --sqlite /home/lk/miniconda3/bin/sqlite3
```

The host test creates its own SQLite files, committed WAL, reports, and archives.
It checks successful extraction and inspection, wrong-digest rejection before
extraction, bad-receipt rejection, count-mismatch rejection before database open,
and unsafe-link rejection. Ordinary tests also cover corrupt databases, foreign
keys, schema mismatch, failed directory changes, all missing capture fields,
unknown/duplicate/type errors, quoted paths, input links/sizes and private parent
modes. Temporary synthetic fixtures are removed; real private inspections are not.

Return only `inspection-summary.json` as printed, or the fixed
`COPY_INSPECT_TEST` / `MTM_COPY_INSPECT_ERROR` / `MTM_COPY_INSPECT_DIAGNOSTIC`
failure lines. Do not upload a session, archive, database, raw log, key or proof.
Do not rerun capture, raise bounds, strip WAL, change permissions, or start an MTM
binary on production to resolve an inspection failure.

## External semantics checked during review

- SQLite PRAGMA documentation: `integrity_check` does not cover foreign-key errors;
  query-only SQL is not an assertion that opening a connection performs no disk I/O.
  https://www.sqlite.org/pragma.html
- GNU tar extraction guidance: use a new empty directory and keep its parent
  inaccessible to untrusted users; preserve archive protection during extraction.
  https://www.gnu.org/software/tar/manual/html_section/Security.html

These references explain the inspection design, not acceptance of the actual
operator archive. Runtime observations and remaining host boundaries are recorded
separately in `records/iterations/ITER-016.json`.
