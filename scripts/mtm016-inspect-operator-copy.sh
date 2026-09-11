#!/usr/bin/env bash
# Host-only preinspection. Never accepts or mounts a production data directory.
# Opens SQLite only in a new private extraction; never starts an MTM runtime.
set -euo pipefail
umask 077
export LC_ALL=C

copy_fail() { printf 'MTM_COPY_INSPECT_ERROR reason=%s\n' "$1" >&2; exit 1; }

copy_digest() {
  local output digest rest
  output=$(/usr/bin/sha256sum -- "$1") || return 1
  read -r digest rest <<< "$output"
  [[ $digest =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "$digest"
}

copy_private_directory() {
  [[ -d $1 && ! -L $1 && $(/usr/bin/stat -c %u -- "$1") == "$UID" && $(/usr/bin/stat -c %a -- "$1") == 700 ]]
}

copy_regular_input() {
  [[ -f $1 && ! -L $1 && $(/usr/bin/stat -c %h -- "$1") == 1 && $(/usr/bin/stat -c %u -- "$1") == "$UID" && $(/usr/bin/stat -c %s -- "$1") -le $2 ]]
}

copy_sql() {
  "$copy_sqlite" -batch -bail -noheader -init /dev/null "$1" "PRAGMA trusted_schema=OFF; PRAGMA query_only=ON; $2"
}

copy_validate_receipt() {
  local summary=${1//\'/\'\'} expected=$2 valid
  [[ $expected =~ ^[0-9a-f]{64}$ ]] || return 1
  valid=$(copy_sql :memory: "WITH receipt(j) AS (SELECT CAST(readfile('$summary') AS TEXT))
    SELECT json_valid(j) AND json_type(j)='object'
      AND json_extract(j,'$.schema')='mtm-operator-state-capture-v1'
      AND json_extract(j,'$.milestone')='MTM-016'
      AND json_extract(j,'$.source_selection')='operator_supplied'
      AND json_type(j,'$.capture_complete')='true'
      AND json_type(j,'$.source_readonly_mount_observed')='true'
      AND json_type(j,'$.two_source_streams_identical')='true'
      AND json_extract(j,'$.archive_sha256')='$expected'
      AND json_type(j,'$.entries')='integer' AND json_extract(j,'$.entries') BETWEEN 1 AND 20000
      AND json_type(j,'$.source_file_bytes')='integer' AND json_extract(j,'$.source_file_bytes') BETWEEN 0 AND 268435456
      AND json_type(j,'$.database_opened')='false' AND json_type(j,'$.transactional_snapshot_claimed')='false'
      AND json_type(j,'$.migration_executed')='false' AND json_type(j,'$.old_run_resumed')='false'
      AND json_type(j,'$.rollback_executed')='false' AND json_type(j,'$.raw_private_state_published')='false'
      AND json_type(j,'$.release_qualified')='false'
      AND (SELECT count(*) FROM json_each(j))=16
      AND NOT EXISTS (SELECT 1 FROM json_each(j) GROUP BY key HAVING count(*)>1)
    FROM receipt;") || return 1
  [[ $valid == 1 ]]
}

copy_check_databases() (
  # Only this caller-owned extraction may be supplied. No SQL error text or
  # table/row contents leave the outer private process log.
  cd -- "$1" || copy_fail working_directory_unavailable
  local database result schema
  for database in oauth.sqlite3 private/state.sqlite3; do
    [[ -f $database && ! -L $database ]] || copy_fail database_layout
    result=$(copy_sql "$database" "SELECT (SELECT count(*)=1 AND min(integrity_check)='ok' FROM pragma_integrity_check) AND (SELECT count(*)=0 FROM pragma_foreign_key_check);") || copy_fail database_check_execution
    [[ $result == 1 ]] || copy_fail database_integrity_or_foreign_key
  done
  schema=$(copy_sql private/state.sqlite3 'SELECT user_version FROM pragma_user_version;') || copy_fail schema_read
  [[ $schema =~ ^[1-6]$ ]] || copy_fail unsupported_state_schema
  # Unknown schemas, views in place of authoritative tables, and absent columns
  # fail rather than silently generating an empty eligibility report.
  [[ $(copy_sql private/state.sqlite3 "SELECT count(*)=2 FROM sqlite_schema WHERE type='table' AND name IN ('runs','domains');") == 1 ]] || copy_fail state_table_contract
  [[ $(copy_sql oauth.sqlite3 "SELECT count(*)=1 FROM sqlite_schema WHERE type='table' AND name='oauth_clients';") == 1 ]] || copy_fail oauth_table_contract
  copy_sql private/state.sqlite3 "
    ATTACH DATABASE 'oauth.sqlite3' AS copied_oauth;
    SELECT json_object(
      'sqlite_version',sqlite_version(),
      'schema_before',$schema,
      'state_integrity_passed',json('true'),
      'oauth_integrity_passed',json('true'),
      'foreign_key_checks_passed',json('true'),
      'run_count',(SELECT count(*) FROM runs),
      'active_unsealed_runs',(SELECT count(*) FROM runs WHERE status='active' AND sealed=0),
      'done_runs',(SELECT count(*) FROM runs WHERE state='done' AND sealed=1),
      'oauth_client_count',(SELECT count(*) FROM copied_oauth.oauth_clients),
      'runs_with_missing_owner',(SELECT count(*) FROM runs r WHERE NOT EXISTS (SELECT 1 FROM copied_oauth.oauth_clients c WHERE c.client_id=r.owner_id)),
      'active_public_client_runs',(SELECT count(*) FROM runs r JOIN copied_oauth.oauth_clients c ON c.client_id=r.owner_id WHERE r.status='active' AND r.sealed=0 AND c.token_endpoint_auth_method='none'),
      'active_confidential_client_runs',(SELECT count(*) FROM runs r JOIN copied_oauth.oauth_clients c ON c.client_id=r.owner_id WHERE r.status='active' AND r.sealed=0 AND c.token_endpoint_auth_method IN ('client_secret_basic','client_secret_post')),
      'assess_public_client_runs',(SELECT count(*) FROM runs r JOIN copied_oauth.oauth_clients c ON c.client_id=r.owner_id WHERE r.status='active' AND r.sealed=0 AND r.state='assess' AND c.token_endpoint_auth_method='none'),
      'owner_credentials_examined',json('false'),
      'old_owner_authentication_tested',json('false')
    );" || copy_fail database_summary_query
)

copy_inspect_namespace() {
  local archive=$1 summary=$2 destination=$3 helper=$4 transport=$5 sqlite=$6 digest=$7
  local awk_executable prefix
  awk_executable=$(/usr/bin/readlink -e /usr/bin/awk) || return 1
  [[ $awk_executable == /usr/bin/* && -f $awk_executable && -x $awk_executable ]] || return 1
  prefix=${sqlite%/bin/sqlite3}
  [[ $prefix != "$sqlite" && -d $prefix/lib ]] || return 1
  # Preserve SQLite's $ORIGIN/../lib linkage without exposing its whole home.
  # /work is the only durable writable host directory; production is not mounted.
  /usr/bin/timeout --signal=TERM --kill-after=5s 180s \
    /usr/bin/bwrap --unshare-all --new-session --die-with-parent --cap-drop ALL \
      --ro-bind /usr /usr --ro-bind /bin /bin --ro-bind /lib /lib \
      --ro-bind-try /lib64 /lib64 --dir /etc --ro-bind-try /etc/ld.so.cache /etc/ld.so.cache \
      --ro-bind "$awk_executable" /capture-awk \
      --ro-bind "$sqlite" /opt/copy-sqlite/bin/sqlite3 --ro-bind "$prefix/lib" /opt/copy-sqlite/lib \
      --ro-bind "$archive" /input/preupgrade.tar --ro-bind "$summary" /input/capture-summary.json \
      --ro-bind "$helper" /inspect-script --ro-bind "$transport" /capture-script \
      --bind "$destination" /work --tmpfs /tmp --proc /proc --dev /dev \
      --chdir /work --clearenv --setenv PATH /usr/bin:/bin --setenv LC_ALL C --setenv HOME /tmp \
      /bin/bash --noprofile --norc /inspect-script --internal "$digest"
}

if [[ ${BASH_SOURCE[0]} != "$0" ]]; then return 0; fi

if [[ ${1-} == --internal ]]; then
  [[ $# == 2 && $2 =~ ^[0-9a-f]{64}$ ]] || copy_fail invalid_internal_arguments
  expected=$2
  stage=toolchain
  trap 'rc=$?; if (( rc != 0 )); then printf "MTM_COPY_INSPECT_DIAGNOSTIC stage=%s\n" "$stage" >&2; fi' EXIT
  ulimit -f 524288
  ulimit -v 1048576
  copy_sqlite=/opt/copy-sqlite/bin/sqlite3
  [[ $(copy_sql :memory: "SELECT json_valid('{}');") == 1 ]] || copy_fail sqlite_probe
  source /capture-script
  mtm_capture_awk=/capture-awk
  mtm_mount_is_readonly /input/preupgrade.tar || copy_fail archive_not_readonly
  mtm_mount_is_readonly /input/capture-summary.json || copy_fail summary_not_readonly
  [[ $(copy_digest /input/preupgrade.tar) == "$expected" ]] || copy_fail archive_hash
  stage=capture_receipt
  copy_validate_receipt /input/capture-summary.json "$expected" || copy_fail capture_receipt_invalid
  stage=extract
  /usr/bin/mkdir -m 700 /work/tree
  # New, empty tree only. Keep archive modes; never restore foreign ownership.
  # No archive path is evaluated as a shell command or SQL input.
  /usr/bin/tar --extract --file=/input/preupgrade.tar --directory=/work/tree \
    --no-same-owner --same-permissions --keep-old-files --delay-directory-restore
  stage=extracted_bounds
  mtm_copy_tree_bounds /work/tree > /work/extracted-bounds.txt
  read -r entries bytes < /work/extracted-bounds.txt
  counts=$(copy_sql :memory: "SELECT json_extract(CAST(readfile('/input/capture-summary.json') AS TEXT),'$.entries') || ' ' || json_extract(CAST(readfile('/input/capture-summary.json') AS TEXT),'$.source_file_bytes');")
  [[ "$entries $bytes" == "$counts" ]] || copy_fail extracted_counts_mismatch
  # A recovery checkpoint may alter/delete copied WAL/SHM. The original archive
  # remains RO; do not strip WAL, use immutable=1, or repair either database.
  stage=databases
  copy_check_databases /work/tree > /work/database-summary.json
  [[ -s /work/database-summary.json && $(/usr/bin/stat -c %s /work/database-summary.json) -le 16384 ]] || copy_fail database_summary_invalid
  stage=archive_recheck
  [[ $(copy_digest /input/preupgrade.tar) == "$expected" ]] || copy_fail archive_changed
  copy_sql :memory: "SELECT json_object('schema','mtm-operator-copy-preinspection-v1','milestone','MTM-016','inspection_complete',json('true'),'archive_sha256','$expected','archive_unchanged',json('true'),'extracted_entries',$entries,'extracted_file_bytes',$bytes,'original_modes_requested',json('true'),'foreign_ownership_restored',json('false'),'production_source_mounted',json('false'),'production_modified',json('false'),'database_opened_on_working_copy_only',json('true'),'database_summary',json(CAST(readfile('/work/database-summary.json') AS TEXT)),'transactional_snapshot_claimed',json('false'),'migration_executed',json('false'),'old_run_resumed',json('false'),'rollback_executed',json('false'),'raw_private_state_published',json('false'),'release_qualified',json('false'));" > /work/inspection-summary.json
  /usr/bin/sync /work/inspection-summary.json /work
  exit 0
fi

[[ $# == 4 && $1 == --archive-sha256 && $3 == --sqlite && $2 =~ ^[0-9a-f]{64}$ && $4 == /* && ${HOME-} == /* ]] ||
  copy_fail usage_archive_sha256_and_explicit_sqlite_required
expected=$2
sqlite=$(/usr/bin/readlink -e -- "$4") || copy_fail sqlite_unavailable
[[ $sqlite == */bin/sqlite3 && -f $sqlite && -x $sqlite && ! -L $sqlite ]] || copy_fail sqlite_path_invalid
[[ $(/usr/bin/stat -c %a -- "$sqlite") =~ ^[0-7]{1,3}$ ]] || copy_fail sqlite_special_mode
script=$(/usr/bin/readlink -e -- "${BASH_SOURCE[0]}")
repo=${script%/scripts/mtm016-inspect-operator-copy.sh}
[[ $repo != "$script" && -f $repo/Cargo.toml ]] || copy_fail repository_not_found
transport=$repo/scripts/mtm016-capture-operator-state.sh
[[ $(copy_digest "$transport") == 0072b4126bf5f55495863e35c0b501ad42e95222068222843da5cd81c9eb9e82 ]] || copy_fail capture_helper_changed
home=$(/usr/bin/readlink -e -- "$HOME") || copy_fail home_unavailable
parent=$home/.mtm-acceptance/MTM-016
copy_private_directory "$home/.mtm-acceptance" && copy_private_directory "$parent" || copy_fail capture_parent_not_private
# Locate only a matching completed receipt, never guess the newest directory.
shopt -s nullglob
sessions=("$parent"/copied-state.*)
(( ${#sessions[@]} > 0 && ${#sessions[@]} <= 128 )) || copy_fail capture_session_count
selected= matches=0
for session in "${sessions[@]}"; do
  copy_private_directory "$session" || copy_fail capture_session_not_private
  [[ -f $session/archive.sha256 && -f $session/capture-summary.json ]] || continue
  copy_regular_input "$session/archive.sha256" 256 || copy_fail digest_file_invalid
  read -r digest name < "$session/archive.sha256" || copy_fail digest_file_invalid
  [[ $digest == "$expected" && $name == preupgrade.tar ]] || continue
  matches=$((matches+1)); selected=$session
done
(( matches == 1 )) || copy_fail matching_capture_missing_or_ambiguous
copy_regular_input "$selected/capture-summary.json" 16384 || copy_fail capture_summary_invalid
copy_regular_input "$selected/preupgrade.tar" 536870912 || copy_fail archive_file_invalid
[[ $(/usr/bin/stat -c %a "$selected/preupgrade.tar") == 400 && $(copy_digest "$selected/preupgrade.tar") == "$expected" ]] || copy_fail archive_identity_or_mode
copy_regular_input "$selected/capture-script.sha256" 128 || copy_fail capture_helper_receipt_missing
read -r capture_hash < "$selected/capture-script.sha256"
[[ $capture_hash == 0072b4126bf5f55495863e35c0b501ad42e95222068222843da5cd81c9eb9e82 ]] || copy_fail capture_helper_receipt_mismatch
sqlite_hash=$(copy_digest "$sqlite")
helper_hash=$(copy_digest "$script")
summary_hash=$(copy_digest "$selected/capture-summary.json")
destination=$(/usr/bin/mktemp -d -- "$selected/inspection.XXXXXXXX")
if ! copy_inspect_namespace "$selected/preupgrade.tar" "$selected/capture-summary.json" "$destination" "$script" "$transport" "$sqlite" "$expected" > "$destination/process.stdout" 2> "$destination/process.stderr"; then
  printf 'inspection_complete=false\n'
  /usr/bin/grep -E '^MTM_COPY_(INSPECT_(ERROR reason|DIAGNOSTIC stage)=[a-z_]+|BOUND_FAIL reason=[a-z_]+ entries=[0-9]+ bytes=[0-9]+)$' "$destination/process.stderr" || true
  copy_fail inspection_failed_private_diagnostics_retained
fi
[[ $(copy_digest "$selected/preupgrade.tar") == "$expected" && $(copy_digest "$sqlite") == "$sqlite_hash" && $(copy_digest "$script") == "$helper_hash" && $(copy_digest "$selected/capture-summary.json") == "$summary_hash" && $(copy_digest "$transport") == 0072b4126bf5f55495863e35c0b501ad42e95222068222843da5cd81c9eb9e82 ]] || copy_fail input_changed
printf '%s\n' "$sqlite_hash" > "$destination/sqlite.sha256"
printf '%s\n' "$helper_hash" > "$destination/inspection-script.sha256"
printf '%s\n' "$summary_hash" > "$destination/capture-summary.sha256"
/usr/bin/cat "$destination/inspection-summary.json"
printf 'NEXT: retain the archive and private inspection copy; this is not migration or release acceptance.\n'
