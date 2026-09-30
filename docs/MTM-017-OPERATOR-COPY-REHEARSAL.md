# MTM-017 schema-7 copy preparation and 7 → 8 → 7 rehearsal

## Authorization advancement on 2026-09-30

The operator subsequently explicitly authorized one read-only capture of the
confirmed `/home/lk/.mtm` source and attested that MTM writers would remain stopped.
That single capture and its separate copied schema-7 inspection passed, as recorded
in the new capture and copy-inspection evidence. The archive remains private and
owner-read-only. No further production capture or modification is authorized by
those receipts. Three uninspectable non-MTM system processes remain an explicit
writer-visibility limitation; the capture claims observed byte stability only.

The original strict attempt prepared only the candidate copy. It reached exact
restoration, then the baseline refused a write because the old run's memory parent
retained mode 0775. That failed observation remains immutable and counts as zero
successful real repetitions.

The operator subsequently approved DECISION-005, recorded in
`records/evidence/MTM-017/operator-copy-prepared-continuation-authorization-20260930.json`.
Its bounded meaning is exact_restore_then_prepared_continuation: first prove and
durably record exact original bytes/modes on a fresh baseline copy; only then
prepare that disposable copy's private modes and verify the same old run. Never
change the production source, original archive, runtime artifacts or selectors.
This approval does not make unprepared-original-mode continuation a success.

## Initial preparation-only authorization

Only implementation and source-free synthetic/preflight validation are authorized
at this checkpoint. Do not read production state, launch configuration, OAuth
clients or credentials; do not stop a service, capture real state, change selectors,
commit or push. Production quiescence and capture require a separate operator
decision. A later data root must come from the actual startup configuration, never
the connector's HOME or an inherited MTM_DATA_ROOT. A separately configured private
root requires separate planning; this helper supports one root containing
oauth.sqlite3 and private/state.sqlite3.

## Reviewed historical mechanisms and deliberate differences

The new scripts are independent MTM-017 files. The frozen MTM-016 scripts and
receipts are unchanged. Their actual implementation was inspected: the old capture
pinned older artifacts, old inspection accepted schemas 1–6, and the old rehearsal
expected 2 → 7 → 2 with safe Native. Merely changing its milestone or receipt labels
would not prove schema-8 compatibility.

This runner pins both exact executables, without building or installing either:

- Baseline preview.1/schema 7:
  f59cbddaebb8b9944d1365d6d4f1c072e2cc78e76dbbce8d870308c470c88034
- Candidate preview.2/schema 8:
  13d7890c5c763199ed39295e134ff6cc735ceaa04eaddf6c556431a7a56254f4

The candidate uses dangerous as its required mode label, with Native execution
disabled; the baseline uses safe with Native disabled. Both use static-only LaTeX,
two Tokio workers, loopback inside an unshared network namespace, and no production
mount or selector. No external redirect is followed. Runtime children are owned,
tracked and reaped; the outer namespace has a 240-second TERM/KILL bound.

## Source-free validation order

Run only after independent pre-execution review, via the authorized CTM connector
with workdir `.`. No Cargo cache or runtime source is changed.

```sh
bash conformance/mtm017-operator-capture-tests.sh --host-isolation
bash conformance/mtm017-operator-copy-inspection-tests.sh --host-isolation \
  --sqlite /home/lk/miniconda3/bin/sqlite3
bash conformance/mtm017-copy-rehearsal-tests.sh \
  --sqlite /home/lk/miniconda3/bin/sqlite3
bash scripts/mtm017-run-copy-rehearsal.sh --synthetic \
  --sqlite /home/lk/miniconda3/bin/sqlite3
```

Each command must pass before proceeding. The first uses self-created files and
the actual read-only Bubblewrap capture path. The second opens only new extractions
of self-created SQLite fixtures, including committed WAL/SHM. The third checks
restoration, strict reports, old-owner selection, PKCE callback binding and negative
boundaries. The fourth creates a disposable schema-7 baseline client and assess run
through real endpoints, then exercises the exact 7/8/7 continuation path.

Synthetic capture, preinspection and rehearsal summaries all explicitly identify
synthetic-only evidence. They set copied_operator_state_gate_passed=false and
release_qualified=false. The rehearsal also records evidence_kind=synthetic_fixture.
These reports test machinery and cannot satisfy the real copied-state gate.
Capture and inspection do not assert old-run continuation. Runtime rehearsal work
and failure sessions stay private; fixture test cleanup checks an ownership marker,
UID, mode and the original device/inode. Identity mismatch retains the directory.

## Capture transport, for later authorization only

The future capture command requires an explicit canonical source and an existing
owner-private acceptance parent whose final component is MTM-017, outside the repo.
Its parent must also be owner-private. No directory is guessed or scanned. Source
and destination must be disjoint, including checked device/inode ancestry and the
same containing mount; separate mount aliases are conservatively refused.

```sh
bash scripts/mtm017-capture-operator-state.sh \
  --source "$CONFIRMED_PRODUCTION_DATA_ROOT" \
  --destination-parent "$PRIVATE_ACCEPTANCE_PARENT/MTM-017" \
  --operator-confirmed-quiescent
```

The flag attests a separately coordinated quiescent window. The helper cannot
stop writers and must not be run before that authorization. It uses a read-only
source bind, verifies exact ro mount options, generates two normalized PAX streams
and requires matching SHA-256 plus matching aggregate tree bounds. It retains
WAL, SHM, journals, keys, names, modes, timestamps and numeric archive ownership.
Two matching streams mean observed byte stability, not a transactional snapshot.
It never opens a source database or performs a SQLite checkpoint.

Limits: 20,000 entries, depth below 33, 128 MiB per file, 256 MiB total file data,
512 MiB output archive and a 180-second namespace timeout. Links, hardlinks,
special files/modes and cross-device entries fail closed. A complete archive is
owner-read-only (0400), outside the repository. Failed captures are retained.
Public capture output is only the sanitized typed receipt, counts, SHA and fixed
diagnostic categories. Do not upload any archive, database, key or raw log.

## Explicit captured-copy runner, for a later approved archive

```sh
bash scripts/mtm017-run-copy-rehearsal.sh --captured \
  --session "$PRIVATE_CAPTURE_SESSION" --archive-sha256 "$ARCHIVE_SHA256" \
  --sqlite /home/lk/miniconda3/bin/sqlite3
```

The runner performs a fresh complete synthetic prerequisite before reading the
explicit capture session. It rejects noncanonical/symlink paths, hardlinked inputs,
incorrect private modes, incorrect archive SHA or capture-helper provenance, and
synthetic receipts presented as real captures. There is no newest-directory guess.
All selected executables, helpers, libraries and archive inputs must remain
unchanged throughout a run. Private paths, read-only namespace binds, mode 0400,
and before/after hashes detect ordinary drift; they are not a system-level seal
against malicious concurrent replacement by another process with the same UID.
The standalone inspector has no public host entry; the reviewed wrapper composes
its primitives, and conformance exercises its namespace-only entry.

GNU tar members are checked before extraction for types, ordinary modes, paths,
duplicates, depth/count and apparent-size bounds. Extraction is into a nonexistent
destination with no-clobber children. A nonrecursive second pass restores only the
archive's exact `.` directory metadata. Re-archiving must reproduce the exact SHA
before any SQLite open, including on rollback. Foreign ownership is not restored;
an ownership mismatch therefore fails the exact comparison. Query-only SQLite may
recover copied WAL/SHM, which is why only disposable extractions are opened.

The selected run must already satisfy assess/active/sealed=0 and join its preserved
owner to a public OAuth client using token_endpoint_auth_method=none. Selection is
deterministic by created_at/run_id. No match is a blocker; captured mode cannot
register a new client, create a run, rewrite ownership or mint a capability directly.

Authentication uses the existing copied client and registered redirect with normal
authorization-code/PKCE endpoints. A new namespace-only password authenticates the
disposable server; no production credential is requested, read or retained. The
reviewed OAuth implementation consumes authorization codes and returns short-lived
signed bearer tokens, with no refresh-token or persistent grant creation. Tokens,
capabilities, owner/client identifiers and raw wire bodies remain in private
namespace tmpfs; they never enter logs or repository evidence. The explicitly
authorized selected run ID is the sole identifier exception in the final receipt.
If another authentication flow would
create or expand persistent access, stop for separate authorization.

The runner verifies schema 7, database integrity/foreign keys, ownership/client
fingerprints and persisted signing-key SHA, then starts the exact candidate.
Schema 8 must have empty new fact/finding tables and no backfilled legacy fact IDs.
The old run advances assess → explore once, restarts on the candidate and resumes
the same run without another transition. It then restores a fresh archive copy,
proves original bytes/modes and saves a new owner-read-only
baseline-exact-restoration.json before opening either restored database. The
baseline preparation entry rechecks the exact archive SHA and the proof's archive
and device/inode binding immediately before changing modes. It then prepares only
that disposable baseline copy, checks schema 7, same-run state, owner/client sets
and key identity, launches the baseline, authenticates and advances the same run.
Schema checks cannot be skipped; SQLite recovery cannot be mistaken for the exact
original bytes/modes observation. Never downgrade user_version, change production
state or publish a final proof.

Both copy-preparation entries require no running child, a safe owned tree and an
unchanged original archive digest. They change only private directories to 0700
and private files to 0600. A normalized-mode archive digest proves all other
bytes/metadata unchanged. Baseline preparation additionally requires the durable
exact-original proof and rejects a missing, stale, duplicate or misleading proof.
Run `bash conformance/mtm017-copy-mode-preparation-tests.sh --sqlite /home/lk/miniconda3/bin/sqlite3`
for source-free denial tests and exact original-mode restoration after preparation.

The strict v2 40-field final receipt includes schema_before=7, schema_candidate=8,
schema_restored=7; old_owner_authenticated; old_run_advanced_on_candidate;
candidate_restart_resumed; restored_old_runtime_advanced;
restored_archive_bytes_and_modes_match; production_modified=false and
selectors_modified=false. It also requires rollback_validation_mode=
exact_restore_then_prepared_continuation, an exact-before-preparation assertion,
baseline_disposable_copy_mode_prepared=true, a preparation content-preservation
assertion and unprepared_baseline_continuation_claimed=false. It binds the operator
decision SHA and the retained strict failure SHA; the wrapper rechecks both input
records before and after execution. Old v1 reports cannot substitute for v2.
Only the selected run ID may be published, as explicitly
authorized; owner/client/token/key/database contents remain private. Even a real
observed rehearsal does not independently grant release/deployment approval or
replace other release gates. No receipt can claim success until every assertion
and all owned runtime shutdowns have completed.
