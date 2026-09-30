#!/usr/bin/env bash
# Self-created SQLite fixtures only; never accepts an archive or production root.
set -euo pipefail
umask 077
host_isolation=false
if [[ ${1-} == --host-isolation ]]; then host_isolation=true; shift; fi
[[ $# == 2 && $1 == --sqlite && $2 == /* ]] || exit 2
sqlite=$(/usr/bin/readlink -e -- "$2")
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
helper=$repo/scripts/mtm017-inspect-operator-copy.sh
transport=$repo/scripts/mtm017-capture-operator-state.sh
source "$transport"
source "$helper"
copy_sqlite=$sqlite
root=$(/usr/bin/mktemp -d /tmp/mtm-copy-inspection-test.XXXXXXXX)
mtm_fixture_mark
wal_pid=
cleanup() {
  if [[ -n $wal_pid && $'\n'$(jobs -pr)$'\n' == *$'\n'"$wal_pid"$'\n'* ]]; then kill "$wal_pid" 2>/dev/null || true; wait "$wal_pid" 2>/dev/null || true; fi
  mtm_fixture_cleanup
}
trap cleanup EXIT
mkdir -m 700 "$root/tree" "$root/tree/private"
"$sqlite" -batch -bail -init /dev/null "$root/tree/oauth.sqlite3" "CREATE TABLE oauth_clients(client_id TEXT PRIMARY KEY,token_endpoint_auth_method TEXT NOT NULL); INSERT INTO oauth_clients VALUES('public-fixture','none'),('confidential-fixture','client_secret_post');"
"$sqlite" -batch -bail -init /dev/null "$root/tree/private/state.sqlite3" "PRAGMA user_version=7; CREATE TABLE runs(run_id TEXT PRIMARY KEY,owner_id TEXT NOT NULL,state TEXT NOT NULL,status TEXT NOT NULL,sealed INTEGER NOT NULL); CREATE TABLE domains(domain_id TEXT PRIMARY KEY,run_id TEXT REFERENCES runs(run_id)); INSERT INTO runs VALUES('one','public-fixture','assess','active',0),('two','confidential-fixture','assemble','active',0),('three','missing-owner','done','done',1);"
printf 'private fixture sentinel never echoed\n' > "$root/tree/private/proof.txt"
copy_check_databases "$root/tree" > "$root/database.json"
[[ $(copy_sql :memory: "SELECT json_extract(CAST(readfile('$root/database.json') AS TEXT),'$.run_count')=3 AND json_extract(CAST(readfile('$root/database.json') AS TEXT),'$.runs_with_missing_owner')=1 AND json_extract(CAST(readfile('$root/database.json') AS TEXT),'$.active_public_client_runs')=1 AND json_extract(CAST(readfile('$root/database.json') AS TEXT),'$.active_confidential_client_runs')=1;") == 1 ]]
if grep -Eq 'public-fixture|confidential-fixture|missing-owner|private fixture sentinel' "$root/database.json"; then exit 1; fi
printf 'COPY_INSPECT_TEST integrity_counts_and_no_private_identifiers=passed\n'

# A failed chdir must not let conditional invocation inspect the caller's tree.
if (cd "$root/tree"; copy_check_databases "$root/absent-copy") > "$root/missing-copy-out" 2> "$root/missing-copy-error"; then
  printf 'COPY_INSPECT_TEST missing_copy_fell_back_to_caller_directory\n' >&2; exit 1
fi
[[ ! -s $root/missing-copy-out ]]
printf 'COPY_INSPECT_TEST missing_copy_no_current_directory_fallback=passed\n'

"$sqlite" -batch -bail -init /dev/null "$root/tree/private/state.sqlite3" "INSERT INTO domains VALUES('orphan','absent-run');"
if copy_check_databases "$root/tree" > "$root/rejected-out" 2> "$root/rejected-error"; then exit 1; fi
[[ ! -s $root/rejected-out ]]
"$sqlite" -batch -bail -init /dev/null "$root/tree/private/state.sqlite3" "DELETE FROM domains; PRAGMA user_version=8;"
if copy_check_databases "$root/tree" > "$root/rejected-out" 2> "$root/rejected-error"; then exit 1; fi
[[ ! -s $root/rejected-out ]]
"$sqlite" -batch -bail -init /dev/null "$root/tree/private/state.sqlite3" 'PRAGMA user_version=7;'
cp "$root/tree/oauth.sqlite3" "$root/oauth-saved"
printf 'not a database\n' > "$root/tree/oauth.sqlite3"
if copy_check_databases "$root/tree" > "$root/rejected-out" 2> "$root/rejected-error"; then exit 1; fi
[[ ! -s $root/rejected-out ]]
cp "$root/oauth-saved" "$root/tree/oauth.sqlite3"
printf 'COPY_INSPECT_TEST corrupt_foreign_key_and_wrong_schema_rejected=passed\n'

# Keep one real SQLite writer idle while copying its committed WAL. There are
# no concurrent writes/checkpoints; the inspector subsequently opens only copies.
mkdir -m 700 "$root/wal-live"
coproc WAL_KEEP { "$sqlite" -batch -bail -init /dev/null "$root/wal-live/state.sqlite3"; }
wal_pid=$WAL_KEEP_PID
wal_in=${WAL_KEEP[1]}; wal_out=${WAL_KEEP[0]}
printf '%s\n' 'PRAGMA journal_mode=WAL;' 'CREATE TABLE marker(n INTEGER);' 'INSERT INTO marker VALUES(42);' '.print WAL_READY' >&"$wal_in"
while IFS= read -r -t 5 -u "$wal_out" line; do [[ $line == WAL_READY ]] && break; done
[[ ${line-} == WAL_READY && -s $root/wal-live/state.sqlite3-wal ]]
mkdir -m 700 "$root/wal-copy"
cp "$root/wal-live/state.sqlite3" "$root/wal-live/state.sqlite3-wal" "$root/wal-live/state.sqlite3-shm" "$root/wal-copy/"
[[ $(copy_sql "$root/wal-copy/state.sqlite3" 'SELECT n FROM marker;') == 42 ]]
exec {wal_in}>&-
wait "$wal_pid"; wal_pid=
printf 'COPY_INSPECT_TEST committed_wal_retained_and_read_on_copy=passed\n'

fixture_digest=1111111111111111111111111111111111111111111111111111111111111111
"$sqlite" -batch -bail -init /dev/null :memory: "SELECT json_object('schema','mtm017-schema7-state-capture-v1','milestone','MTM-017','capture_complete',json('true'),'source_selection','explicitly_supplied','source_readonly_mount_observed',json('true'),'two_source_streams_identical',json('true'),'archive_sha256','$fixture_digest','entries',3,'source_file_bytes',123,'database_opened',json('false'),'transactional_snapshot_claimed',json('false'),'migration_executed',json('false'),'old_run_resumed',json('false'),'rollback_executed',json('false'),'raw_private_state_published',json('false'),'release_qualified',json('false'),'synthetic_only',json('true'),'copied_operator_state_gate_passed',json('false'),'production_modified',json('false'),'selectors_modified',json('false'));" > "$root/receipt-good.json"
copy_validate_receipt "$root/receipt-good.json" "$fixture_digest"
for mutation in "json_remove(j,'$.capture_complete')" "json_set(j,'$.capture_complete',1)" "json_set(j,'$.release_qualified',json('true'))" "json_set(j,'$.entries',3.5)" "json_set(j,'$.entries',20001)" "json_set(j,'$.database_opened',json('true'))" "json_set(j,'$.archive_sha256','wrong')" "substr(j,1,length(j)-1)||',\"entries\":3}'" "json_set(j,'$.unreviewed_field',json('true'))"; do
  copy_sql :memory: "WITH r(j) AS (SELECT CAST(readfile('$root/receipt-good.json') AS TEXT)) SELECT $mutation FROM r;" > "$root/receipt-bad.json"
  if copy_validate_receipt "$root/receipt-bad.json" "$fixture_digest" > /dev/null 2>&1; then
    printf 'COPY_INSPECT_TEST malformed_receipt_unexpectedly_accepted\n' >&2; exit 1
  fi
done
cp "$root/receipt-good.json" "$root/quoted'path.json"
copy_validate_receipt "$root/quoted'path.json" "$fixture_digest"
printf 'COPY_INSPECT_TEST receipt_types_missing_duplicate_identity_and_quoted_path=passed\n'

# Every required field is independently mandatory. No partial JSON or future
# field set can be presented as the reviewed capture receipt.
for field in schema milestone capture_complete source_selection source_readonly_mount_observed two_source_streams_identical archive_sha256 entries source_file_bytes database_opened transactional_snapshot_claimed migration_executed old_run_resumed rollback_executed raw_private_state_published release_qualified synthetic_only copied_operator_state_gate_passed production_modified selectors_modified; do
  copy_sql :memory: "SELECT json_remove(CAST(readfile('$root/receipt-good.json') AS TEXT),'$.$field');" > "$root/receipt-bad.json"
  if copy_validate_receipt "$root/receipt-bad.json" "$fixture_digest" > /dev/null 2>&1; then exit 1; fi
done
for malformed in '{' '[]' 'null' 'true' '"not a receipt"'; do
  printf '%s\n' "$malformed" > "$root/receipt-bad.json"
  if copy_validate_receipt "$root/receipt-bad.json" "$fixture_digest" > /dev/null 2>&1; then exit 1; fi
done
printf 'COPY_INSPECT_TEST all_twenty_fields_and_malformed_receipts=passed\n'

# Exercise the host selection guards only against disposable files. Missing
# input must not manufacture a digest or permit another inode type/owner mode.
if copy_digest "$root/missing-archive" > "$root/no-digest" 2>/dev/null; then exit 1; fi
[[ ! -s $root/no-digest ]]
copy_regular_input "$root/receipt-good.json" 16384
ln -s "$root/receipt-good.json" "$root/receipt-link"
if copy_regular_input "$root/receipt-link" 16384; then exit 1; fi
ln "$root/receipt-good.json" "$root/receipt-hardlink"
if copy_regular_input "$root/receipt-good.json" 16384; then exit 1; fi
rm "$root/receipt-hardlink"
if copy_regular_input "$root/receipt-good.json" 1; then exit 1; fi
mkdir -m 700 "$root/input-private"
copy_private_directory "$root/input-private"
chmod 755 "$root/input-private"
if copy_private_directory "$root/input-private"; then exit 1; fi
chmod 700 "$root/input-private"
ln -s "$root/input-private" "$root/input-private-link"
if copy_private_directory "$root/input-private-link"; then exit 1; fi
printf 'COPY_INSPECT_TEST input_hash_link_size_and_private_directory_guards=passed\n'

if [[ $host_isolation == true ]]; then
  mkdir -m 700 "$root/good" "$root/bad-hash" "$root/bad-link" "$root/bad-receipt" "$root/bad-counts"
  mtm_copy_archive "$root/tree" > "$root/preupgrade.tar"
  chmod 400 "$root/preupgrade.tar"
  digest=$(copy_digest "$root/preupgrade.tar")
  read -r entries bytes < <(mtm_copy_tree_bounds "$root/tree")
  make_receipt() {
    "$sqlite" -batch -bail -init /dev/null :memory: "SELECT json_object('schema','mtm017-schema7-state-capture-v1','milestone','MTM-017','capture_complete',json('true'),'source_selection','explicitly_supplied','source_readonly_mount_observed',json('true'),'two_source_streams_identical',json('true'),'archive_sha256','$1','entries',$entries,'source_file_bytes',$bytes,'database_opened',json('false'),'transactional_snapshot_claimed',json('false'),'migration_executed',json('false'),'old_run_resumed',json('false'),'rollback_executed',json('false'),'raw_private_state_published',json('false'),'release_qualified',json('false'),'synthetic_only',json('true'),'copied_operator_state_gate_passed',json('false'),'production_modified',json('false'),'selectors_modified',json('false'));" > "$root/receipt.json"
  }
  make_receipt "$digest"
  rc=0
  copy_inspect_namespace "$root/preupgrade.tar" "$root/receipt.json" "$root/good" "$helper" "$transport" "$sqlite" "$digest" > "$root/namespace-out" 2> "$root/namespace-error" || rc=$?
  if (( rc != 0 )); then
    printf 'COPY_INSPECT_TEST namespace_inspection=failed exit_code=%s production_source_accessed=false\n' "$rc" >&2
    if grep -Fq 'bwrap: Creating new namespace failed:' "$root/namespace-error"; then printf 'COPY_INSPECT_TEST namespace_setup=failed\n' >&2; fi
    grep -E '^MTM017_COPY_(INSPECT_(ERROR reason|DIAGNOSTIC stage)=[a-z_]+|BOUND_FAIL reason=[a-z_]+ entries=[0-9]+ bytes=[0-9]+)$' "$root/namespace-error" >&2 || true
    exit 1
  fi
  [[ $(copy_digest "$root/preupgrade.tar") == "$digest" ]]
  [[ $(copy_sql :memory: "SELECT json_extract(CAST(readfile('$root/good/inspection-summary.json') AS TEXT),'$.inspection_complete')=1 AND json_extract(CAST(readfile('$root/good/inspection-summary.json') AS TEXT),'$.database_summary.run_count')=3;") == 1 ]]
  wrong=0000000000000000000000000000000000000000000000000000000000000000
  if copy_inspect_namespace "$root/preupgrade.tar" "$root/receipt.json" "$root/bad-hash" "$helper" "$transport" "$sqlite" "$wrong" > "$root/bad-out" 2> "$root/bad-error"; then exit 1; fi
  grep -qx 'MTM017_COPY_INSPECT_ERROR reason=archive_hash' "$root/bad-error"
  [[ ! -e $root/bad-hash/tree ]]
  # Invalid receipts stop before extraction; wrong but well-typed counts stop
  # before SQLite opens. The original digest-pinned archive stays unchanged.
  cp "$root/receipt.json" "$root/original-receipt.json"
  copy_sql :memory: "SELECT json_set(CAST(readfile('$root/original-receipt.json') AS TEXT),'$.release_qualified',json('true'));" > "$root/receipt.json"
  if copy_inspect_namespace "$root/preupgrade.tar" "$root/receipt.json" "$root/bad-receipt" "$helper" "$transport" "$sqlite" "$digest" > "$root/bad-out" 2> "$root/bad-error"; then exit 1; fi
  grep -qx 'MTM017_COPY_INSPECT_ERROR reason=capture_receipt_invalid' "$root/bad-error"
  [[ ! -e $root/bad-receipt/tree ]]
  copy_sql :memory: "SELECT json_set(CAST(readfile('$root/original-receipt.json') AS TEXT),'$.entries',1);" > "$root/receipt.json"
  if copy_inspect_namespace "$root/preupgrade.tar" "$root/receipt.json" "$root/bad-counts" "$helper" "$transport" "$sqlite" "$digest" > "$root/bad-out" 2> "$root/bad-error"; then exit 1; fi
  grep -qx 'MTM017_COPY_INSPECT_ERROR reason=extracted_counts_mismatch' "$root/bad-error"
  [[ ! -e $root/bad-counts/database-summary.json && ! -e $root/bad-counts/inspection-summary.json ]]
  [[ $(copy_digest "$root/preupgrade.tar") == "$digest" ]]
  ln -s /input/preupgrade.tar "$root/tree/unsafe-link"
  mtm_copy_archive "$root/tree" > "$root/link.tar"
  link_digest=$(copy_digest "$root/link.tar")
  make_receipt "$link_digest"
  if copy_inspect_namespace "$root/link.tar" "$root/receipt.json" "$root/bad-link" "$helper" "$transport" "$sqlite" "$link_digest" > "$root/bad-out" 2> "$root/bad-error"; then exit 1; fi
  grep -qx 'MTM017_COPY_INSPECT_ERROR reason=unsafe_archive_members' "$root/bad-error"
  [[ ! -e $root/bad-link/database-summary.json ]]
  printf 'COPY_INSPECT_TEST isolated_extract_integrity_identity_and_link_denial=passed\n'
  printf 'COPY_INSPECT_TEST isolated_receipt_and_count_denial_before_database=passed\n'
fi
printf 'COPY_INSPECT_TEST production_source_accessed=false synthetic_only=true host_isolation=%s\n' "$host_isolation"
