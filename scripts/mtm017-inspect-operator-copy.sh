#!/usr/bin/env bash
# Host-only preinspection. Never accepts or mounts a production data directory.
# Opens SQLite only in a new private extraction; never starts an MTM runtime.
set -euo pipefail
umask 077
export LC_ALL=C

copy_fail() { printf 'MTM017_COPY_INSPECT_ERROR reason=%s\n' "$1" >&2; exit 1; }

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
  local summary=${1//\'/\'\'} expected=$2 mode=${3:-synthetic} valid synthetic=false
  [[ $mode == synthetic || $mode == captured ]] || return 1
  [[ $mode != synthetic ]] || synthetic=true
  [[ $expected =~ ^[0-9a-f]{64}$ ]] || return 1
  valid=$(copy_sql :memory: "WITH receipt(j) AS (SELECT CAST(readfile('$summary') AS TEXT))
    SELECT json_valid(j) AND json_type(j)='object'
      AND json_extract(j,'$.schema')='mtm017-schema7-state-capture-v1'
      AND json_extract(j,'$.milestone')='MTM-017'
      AND json_extract(j,'$.source_selection')='explicitly_supplied'
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
      AND json_type(j,'$.synthetic_only')='$synthetic'
      AND json_type(j,'$.copied_operator_state_gate_passed')='false'
      AND json_type(j,'$.production_modified')='false' AND json_type(j,'$.selectors_modified')='false'
      AND (SELECT count(*) FROM json_each(j))=20
      AND NOT EXISTS (SELECT 1 FROM json_each(j) GROUP BY key HAVING count(*)>1)
    FROM receipt;") || return 1
  [[ $valid == 1 ]]
}

copy_check_databases() (
  # Only this caller-owned extraction may be supplied. No SQL error text or
  # table/row contents leave the outer private process log.
  cd -- "$1" || copy_fail working_directory_unavailable
  local database result schema mode=${2:-synthetic} synthetic=false
  [[ $mode == synthetic || $mode == captured ]] || copy_fail inspection_mode
  [[ $mode != synthetic ]] || synthetic=true
  for database in oauth.sqlite3 private/state.sqlite3; do
    [[ -f $database && ! -L $database ]] || copy_fail database_layout
    result=$(copy_sql "$database" "SELECT (SELECT count(*)=1 AND min(integrity_check)='ok' FROM pragma_integrity_check) AND (SELECT count(*)=0 FROM pragma_foreign_key_check);") || copy_fail database_check_execution
    [[ $result == 1 ]] || copy_fail database_integrity_or_foreign_key
  done
  schema=$(copy_sql private/state.sqlite3 'SELECT user_version FROM pragma_user_version;') || copy_fail schema_read
  [[ $schema == 7 ]] || copy_fail unsupported_state_schema
  # Unknown schemas, views in place of authoritative tables, and absent columns
  # fail rather than silently generating an empty eligibility report.
  [[ $(copy_sql private/state.sqlite3 "SELECT count(*)=2 FROM sqlite_schema WHERE type='table' AND name IN ('runs','domains');") == 1 ]] || copy_fail state_table_contract
  [[ $(copy_sql oauth.sqlite3 "SELECT count(*)=1 FROM sqlite_schema WHERE type='table' AND name='oauth_clients';") == 1 ]] || copy_fail oauth_table_contract
  copy_sql private/state.sqlite3 "
    ATTACH DATABASE 'oauth.sqlite3' AS copied_oauth;
    SELECT json_object(
      'sqlite_version',sqlite_version(),
      'schema_before',$schema,
      'synthetic_only',json('$synthetic'),
      'copied_operator_state_gate_passed',json('false'),
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
  local archive=$1 summary=$2 destination=$3 helper=$4 transport=$5 sqlite=$6 digest=$7 mode=${8:-synthetic}
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
      /bin/bash --noprofile --norc /inspect-script --internal "$digest" "$mode"
}

if [[ ${BASH_SOURCE[0]} != "$0" ]]; then return 0; fi

if [[ ${1-} == --internal ]]; then
  [[ $# == 3 && $2 =~ ^[0-9a-f]{64}$ && ( $3 == synthetic || $3 == captured ) ]] || copy_fail invalid_internal_arguments
  expected=$2
  mode=$3; synthetic=false; [[ $mode != synthetic ]] || synthetic=true
  stage=toolchain
  trap 'rc=$?; if (( rc != 0 )); then printf "MTM017_COPY_INSPECT_DIAGNOSTIC stage=%s\n" "$stage" >&2; fi' EXIT
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
  copy_validate_receipt /input/capture-summary.json "$expected" "$mode" || copy_fail capture_receipt_invalid
  stage=extract
  mtm_copy_archive_members_safe /input/preupgrade.tar || copy_fail unsafe_archive_members
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
  /usr/bin/tar -xf /input/preupgrade.tar -C /work/tree --no-same-owner --same-permissions \
    --no-recursion --overwrite-dir --delay-directory-restore -- . || copy_fail extract_root_metadata
  restored=$(mtm_copy_archive /work/tree | /usr/bin/sha256sum) || copy_fail archive_roundtrip_read
  [[ ${restored%% *} == "$expected" ]] || copy_fail archive_roundtrip_identity
  # A recovery checkpoint may alter/delete copied WAL/SHM. The original archive
  # remains RO; do not strip WAL, use immutable=1, or repair either database.
  stage=databases
  copy_check_databases /work/tree "$mode" > /work/database-summary.json
  [[ -s /work/database-summary.json && $(/usr/bin/stat -c %s /work/database-summary.json) -le 16384 ]] || copy_fail database_summary_invalid
  stage=archive_recheck
  [[ $(copy_digest /input/preupgrade.tar) == "$expected" ]] || copy_fail archive_changed
  copy_sql :memory: "SELECT json_object('schema','mtm017-schema7-copy-preinspection-v1','milestone','MTM-017','inspection_complete',json('true'),'synthetic_only',json('$synthetic'),'copied_operator_state_gate_passed',json('false'),'archive_sha256','$expected','archive_unchanged',json('true'),'extracted_entries',$entries,'extracted_file_bytes',$bytes,'original_modes_requested',json('true'),'foreign_ownership_restored',json('false'),'production_source_mounted',json('false'),'production_modified',json('false'),'database_opened_on_working_copy_only',json('true'),'database_summary',json(CAST(readfile('/work/database-summary.json') AS TEXT)),'transactional_snapshot_claimed',json('false'),'migration_executed',json('false'),'old_run_resumed',json('false'),'rollback_executed',json('false'),'raw_private_state_published',json('false'),'release_qualified',json('false'));" > /work/inspection-summary.json
  /usr/bin/sync /work/inspection-summary.json /work
  exit 0
fi

copy_fail host_entry_requires_mtm017_run_copy_rehearsal_wrapper
