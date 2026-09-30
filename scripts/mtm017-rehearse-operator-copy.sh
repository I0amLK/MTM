#!/usr/bin/env bash
# Exact-artifact rehearsal on a fresh extraction, never a production path.
# Private wire replies live on namespace tmpfs, not in durable evidence.
set -euo pipefail
umask 077
export LC_ALL=C
r_candidate_sha=13d7890c5c763199ed39295e134ff6cc735ceaa04eaddf6c556431a7a56254f4
r_baseline_sha=f59cbddaebb8b9944d1365d6d4f1c072e2cc78e76dbbce8d870308c470c88034
r_pid=
r_wire=/tmp/mtm-copy-wire
r_data=/work/runtime/data
r_mode=unselected
r_fail() { printf 'MTM017_COPY_REHEARSAL_ERROR reason=%s\n' "$1" >&2; exit 1; }
r_require() { [[ $1 == 1 ]] || r_fail "$2"; }
r_doc() {
  local file=${1//\'/\'\'}
  copy_sql :memory: "WITH d(j) AS (SELECT CAST(readfile('$file') AS TEXT)) SELECT $2 FROM d;"
}
r_check_json() {
  local valid
  [[ -s $1 && -f $1 && ! -L $1 && $(/usr/bin/stat -c %s "$1") -le 2097152 ]] || return 1
  valid=$(r_doc "$1" "CASE WHEN json_valid(j) THEN json_type(j)='object' AND NOT EXISTS (SELECT 1 FROM json_tree(j) t JOIN json_tree(j) p ON p.id=t.parent WHERE p.type='object' GROUP BY t.parent,t.key HAVING count(*)>1) ELSE 0 END") || return 1
  [[ $valid == 1 ]]
}
r_json() {
  r_doc "$r_wire/reply.json" "$1"
}
r_identity() {
  r_doc "$r_wire/identity.json" "$1"
}
r_child_running() {
  local running
  [[ $r_pid =~ ^[0-9]+$ ]] || return 1
  running=$(jobs -pr)
  [[ $'\n'$running$'\n' == *$'\n'"$r_pid"$'\n'* ]]
}
r_cleanup() {
  if [[ -n $r_pid ]]; then
    if r_child_running; then
      kill -TERM "$r_pid" 2>/dev/null || true
      /usr/bin/sleep 0.2
      if r_child_running; then kill -KILL "$r_pid" 2>/dev/null || true; fi
    fi
    wait "$r_pid" 2>/dev/null || true
    r_pid=
  fi
}
r_http() {
  local path=$1 expected_status=$2 status
  shift 2
  [[ $r_origin =~ ^http://127\.0\.0\.1:([0-9]{1,5})$ ]] || r_fail request_origin
  (( 10#${BASH_REMATCH[1]} > 0 && 10#${BASH_REMATCH[1]} < 65536 )) || r_fail request_port
  [[ $path == /health || $path == /oauth/register || $path == /oauth/authorize || $path == /oauth/token || $path == /mcp ]] || r_fail request_path
  [[ $path != /oauth/register || $r_mode == synthetic ]] || r_fail registration_not_allowed
  # No redirects, proxies, retries, TLS callbacks or inherited curl configuration.
  : > "$r_wire/headers"
  : > "$r_wire/reply.json"
  status=$(/usr/bin/curl -q --silent --show-error --noproxy '*' --proto '=http' --http1.1 \
    --connect-timeout 3 --max-time 10 --max-filesize 2097152 --retry 0 \
    --dump-header "$r_wire/headers" --output "$r_wire/reply.json" --write-out '%{http_code}' \
    "$r_origin$path" "$@") || r_fail transport_outcome_unknown_no_replay
  [[ $status == "$expected_status" ]] || r_fail http_status
  r_validate_headers "$r_wire/headers" "$r_wire/reply.json" "$expected_status" || r_fail response_framing
  if [[ $path != /oauth/authorize ]]; then r_check_json "$r_wire/reply.json" || r_fail response_json; fi
}
r_validate_headers() {
  local headers=$1 body=$2 expected=$3 bytes
  [[ $(/usr/bin/stat -c %s "$headers") -le 16384 ]] || return 1
  bytes=$(/usr/bin/stat -c %s "$body") || return 1
  (( bytes <= 2097152 )) || return 1
  "$mtm_capture_awk" -v expected="$expected" -v bytes="$bytes" '
    BEGIN { good=1 }
    { sub(/\r$/, "") }
    NR==1 { if ($1!="HTTP/1.1" || $2!=expected) good=0; next }
    /^$/ { if (ended) good=0; ended=1; next }
    {
      if (ended || $0 !~ /^[A-Za-z0-9-]+: /) { good=0; next }
      name=tolower(substr($0,1,index($0,":")-1))
      value=substr($0,index($0,":")+2)
      if (++seen[name]>1) good=0
      if (name=="transfer-encoding") good=0
      if (name=="content-length" && (value !~ /^[0-9]+$/ || value+0!=bytes)) good=0
    }
    END { exit !(good && ended && seen["content-length"]==1) }
  ' "$headers"
}
r_start() {
  local binary=$1 expected=$2 port attempt native_mode=safe
  [[ $expected != "$r_candidate_sha" ]] || native_mode=dangerous
  [[ -z $r_pid && $(copy_digest "$binary") == "$expected" ]] || r_fail start_identity
  : > "$r_wire/runtime-start.log"
  /usr/bin/env --default-signal=INT,QUIT,TERM -i HOME=/work/runtime PATH=/usr/bin:/bin TMPDIR=/tmp \
    MTM_WORKSPACE=/work/runtime/workspace MTM_DATA_ROOT=/work/runtime/data \
    MTM_PRIVATE_ROOT=/work/runtime/data/private MTM_DEBUG_ROOT=/work/runtime/data/debug \
    MTM_OAUTH_PASSWORD="$r_password" MTM_NATIVE_EXEC_BACKEND=disabled MTM_NATIVE_MODE="$native_mode" \
    MTM_LATEX_POLICY=static_only MTM_WORKFLOW_PROTOCOL_VERSION=3 MTM_DEBUG=0 MTM_TRACE_PAYLOADS=0 TOKIO_WORKER_THREADS=2 \
    "$binary" serve --host 127.0.0.1 --port 0 --workspace /work/runtime/workspace \
      --native-mode "$native_mode" --latex-policy static_only > /dev/null 2> "$r_wire/runtime-start.log" &
  r_pid=$!
  port=
  for ((attempt=0; attempt<300; attempt++)); do
    [[ $(/usr/bin/stat -c %s "$r_wire/runtime-start.log") -le 65536 ]] || r_fail startup_output_bound
    port=$("$mtm_capture_awk" '/^local MCP: http:\/\/127\.0\.0\.1:[0-9]+\/mcp$/ { sub(/^.*:/, ""); sub(/\/mcp$/, ""); print }' "$r_wire/runtime-start.log")
    [[ -n $port ]] && break
    r_child_running || r_fail runtime_start
    /usr/bin/sleep 0.05
  done
  [[ $port =~ ^[0-9]{1,5}$ ]] && (( port > 0 && port < 65536 )) || r_fail startup_endpoint
  r_origin=http://127.0.0.1:$port
  r_http /health 200
  r_require "$(r_json "json_type(j,'$.ok')='true'")" health
}
r_stop() {
  local attempt
  [[ -n $r_pid ]] || r_fail missing_owned_process
  kill -INT "$r_pid" || r_fail interrupt
  for ((attempt=0; attempt<160; attempt++)); do
    if ! r_child_running; then
      local rc=0
      wait "$r_pid" || rc=$?
      r_pid=
      (( rc == 0 )) || r_fail unclean_shutdown
      return 0
    fi
    /usr/bin/sleep 0.05
  done
  r_fail shutdown_timeout
}
r_login() {
  local verifier challenge nonce location suffix code line locations=0
  r_check_json "$r_wire/identity.json" || r_fail identity_json
  printf '%s' "$(r_identity "json_extract(j,'$.owner_id')")" > "$r_wire/client-id"
  printf '%s' "$(r_identity "json_extract(j,'$.redirect')")" > "$r_wire/redirect"
  r_require "$(r_identity "json_type(j,'$.owner_id')='text' AND length(json_extract(j,'$.owner_id')) BETWEEN 1 AND 256 AND json_type(j,'$.redirect')='text' AND length(json_extract(j,'$.redirect')) BETWEEN 1 AND 2048")" owner_shape
  verifier=$(/usr/bin/openssl rand -hex 32)
  nonce=$(/usr/bin/openssl rand -hex 16)
  printf '%s' "$verifier" > "$r_wire/verifier"
  challenge=$(/usr/bin/openssl dgst -sha256 -binary "$r_wire/verifier" | /usr/bin/base64 -w0 | /usr/bin/tr '+/' '-_' | /usr/bin/tr -d '=')
  [[ $challenge =~ ^[A-Za-z0-9_-]{43}$ && $nonce =~ ^[0-9a-f]{32}$ ]] || r_fail pkce_randomness
  printf '%s' "$challenge" > "$r_wire/challenge"
  printf '%s' "$r_password" > "$r_wire/password"
  r_http /oauth/authorize 302 --data-urlencode "client_id@$r_wire/client-id" \
    --data-urlencode "redirect_uri@$r_wire/redirect" --data-urlencode "password@$r_wire/password" \
    --data-urlencode "code_challenge@$r_wire/challenge" --data-urlencode code_challenge_method=S256 \
    --data-urlencode response_type=code --data-urlencode "state=$nonce" --data-urlencode "resource=$r_origin/mcp"
  location=
  while IFS= read -r line; do
    line=${line%$'\r'}
    if [[ ${line,,} == location:\ * ]]; then location=${line#*: }; locations=$((locations+1)); fi
  done < "$r_wire/headers"
  [[ $locations == 1 ]] || r_fail callback_header
  local redirect
  redirect=$(< "$r_wire/redirect")
  code=$(r_callback_code "$location" "$redirect" "$nonce") || r_fail callback_binding_or_state
  printf '%s' "$code" > "$r_wire/code"
  r_http /oauth/token 200 --data-urlencode "client_id@$r_wire/client-id" \
    --data-urlencode "redirect_uri@$r_wire/redirect" --data-urlencode "code@$r_wire/code" \
    --data-urlencode "code_verifier@$r_wire/verifier" --data-urlencode grant_type=authorization_code \
    --data-urlencode "resource=$r_origin/mcp"
  r_require "$(r_json "json_extract(j,'$.token_type')='Bearer' AND json_type(j,'$.access_token')='text' AND length(json_extract(j,'$.access_token')) BETWEEN 1 AND 16384 AND instr(json_extract(j,'$.access_token'),char(10))=0 AND instr(json_extract(j,'$.access_token'),char(13))=0")" token_shape
  printf 'Authorization: Bearer %s\n' "$(r_json "json_extract(j,'$.access_token')")" > "$r_wire/auth-header"
}
r_callback_code() {
  local location=$1 redirect=$2 nonce=$3 prefix suffix
  [[ $nonce =~ ^[0-9a-f]{32}$ && $redirect =~ ^https?://[^[:space:]#]+$ && ${#redirect} -le 2048 ]] || return 1
  if [[ $redirect == *\?* ]]; then prefix=$redirect\&; else prefix=$redirect\?; fi
  [[ $location == "$prefix"* ]] || return 1
  suffix=${location#"$prefix"}
  [[ $suffix =~ ^code=([A-Za-z0-9_-]{1,256})\&state=([0-9a-f]{32})$ && ${BASH_REMATCH[2]} == "$nonce" ]] || return 1
  # The callback is never contacted: only this header from owned loopback is read.
  printf '%s' "${BASH_REMATCH[1]}"
}
r_call() {
  r_http /mcp 200 --header "@$r_wire/auth-header" --header 'Content-Type: application/json' --data-binary "@$r_wire/request.json"
  r_require "$(r_json "json_extract(j,'$.jsonrpc')='2.0' AND json_extract(j,'$.id')='copy-rehearsal' AND json_type(j,'$.error') IS NULL AND json_type(j,'$.result.isError')='false' AND json_type(j,'$.result.structuredContent.ok')='true'")" mcp_outcome
  r_json "json_extract(j,'$.result.structuredContent')" > "$r_wire/result.json"
}
r_make_request() {
  case $1 in
    server_info|rethlas_step) ;;
    rethlas_start) [[ $r_mode == synthetic ]] || r_fail new_run_not_allowed ;;
    *) r_fail tool_not_allowed ;;
  esac
  r_identity "json_object('jsonrpc','2.0','id','copy-rehearsal','method','tools/call','params',json_object('name','$1','arguments',json($2)))" > "$r_wire/request.json"
}
r_info() {
  local native_mode=safe
  [[ $1 != 0.6.0-preview.2 ]] || native_mode=dangerous
  r_make_request server_info "'{}'"
  r_call
  r_require "$(r_json "json_extract(j,'$.result.structuredContent.server')='mtm' AND json_extract(j,'$.result.structuredContent.version')='$1' AND json_extract(j,'$.result.structuredContent.oauth_client_id')=json_extract(CAST(readfile('$r_wire/identity.json') AS TEXT),'$.owner_id')")" endpoint_owner_identity
  r_require "$(r_json "json_extract(j,'$.result.structuredContent.native.native_exec_backend')='DisabledExecBackend' AND json_extract(j,'$.result.structuredContent.native.native_mode')='$native_mode' AND json_type(j,'$.result.structuredContent.native.workflow_authority_inherited')='false'")" endpoint_native_policy
}
r_task() {
  r_make_request rethlas_step "json_object('run_id',json_extract(j,'$.run_id'))"
  r_call
  r_run_binding "$1" || r_fail old_run_task_state
}
r_run_binding() {
  local valid
  [[ $1 == assess || $1 == explore ]] || return 1
  valid=$(r_json "json_extract(j,'$.result.structuredContent.state')='$1' AND json_extract(j,'$.result.structuredContent.run_id')=json_extract(CAST(readfile('$r_wire/identity.json') AS TEXT),'$.run_id')") || return 1
  [[ $valid == 1 ]]
}
r_advance() {
  r_task assess
  r_require "$(r_json "coalesce(json_extract(j,'$.result.structuredContent.task.minimal_submission.action'),json_extract(j,'$.result.structuredContent.task.minimal_submission_template.action'))='assessment_complete' AND json_type(j,'$.result.structuredContent.capability')='text' AND length(json_extract(j,'$.result.structuredContent.capability'))>0")" assessment_contract
  r_doc "$r_wire/result.json" "json_object('jsonrpc','2.0','id','copy-rehearsal','method','tools/call','params',json_object('name','rethlas_step','arguments',json_object(
      'run_id',json_extract(j,'$.run_id'),'capability',json_extract(j,'$.capability'),'action','assessment_complete',
      'payload',json_object('route','full','requires_external_retrieval',json('false'),'requires_multiple_plans',json('true'),'route_reason','Copied-state lifecycle rehearsal only; mathematical assessment is deferred.'),
      'writes',json_array(json_object('resource','memory:generation:immediate_conclusions','content',json_object('summary','Copied-state compatibility rehearsal only. No mathematical claim has been assessed or proved; continue through full exploration.'))))))" > "$r_wire/request.json"
  r_call
  r_run_binding explore || r_fail old_run_not_advanced
  r_require "$(r_json "json_type(j,'$.result.structuredContent.submission.error') IS NULL")" submission_error
}
r_state() {
  copy_sql "$r_data/private/state.sqlite3" "WITH d(j) AS (SELECT CAST(readfile('$r_wire/identity.json') AS TEXT)) SELECT count(*)=1 AND min(r.owner_id=json_extract(j,'$.owner_id') AND r.state='$1' AND r.status='active' AND r.sealed=0 AND r.transition_seq=json_extract(j,'$.transition_seq')+$2) FROM runs r,d WHERE r.run_id=json_extract(j,'$.run_id');"
}
r_check_schema() {
  r_require "$(copy_sql /work/runtime/data/private/state.sqlite3 "SELECT user_version=$1 FROM pragma_user_version;")" schema_mismatch
  local db
  for db in /work/runtime/data/oauth.sqlite3 /work/runtime/data/private/state.sqlite3; do
    r_require "$(copy_sql "$db" "SELECT (SELECT count(*)=1 AND min(integrity_check)='ok' FROM pragma_integrity_check) AND NOT EXISTS(SELECT 1 FROM pragma_foreign_key_check);")" database_check
  done
}
r_extract() {
  [[ -z $r_pid ]] || r_fail extraction_while_runtime_running
  [[ $r_data == /* && ! -e $r_data && ! -L $r_data ]] || r_fail restoration_destination_not_new
  [[ $r_archive_sha =~ ^[0-9a-f]{64}$ && $(copy_digest "$r_archive") == "$r_archive_sha" ]] || r_fail restore_input_identity
  mtm_copy_archive_members_safe "$r_archive" || r_fail unsafe_archive_members
  /usr/bin/mkdir -m 700 -- "$r_data" || r_fail restoration_destination_create
  /usr/bin/tar -xf "$r_archive" -C "$r_data" --no-same-owner --same-permissions --keep-old-files --delay-directory-restore || r_fail restore_extraction
  mtm_copy_tree_bounds "$r_data" > "$r_wire/restored-bounds" || r_fail restored_tree_bounds
  # --keep-old-files preserves the already-created extraction root, including
  # its new mtime/mode. Restore ONLY the archived '.' directory metadata after
  # the no-clobber extraction. --no-recursion and the exact member prevent this
  # second pass from visiting or replacing children. Never use --overwrite.
  /usr/bin/tar -xf "$r_archive" -C "$r_data" --no-same-owner --same-permissions \
    --no-recursion --overwrite-dir --delay-directory-restore -- . || r_fail restore_root_metadata
  mtm_copy_tree_bounds "$r_data" > "$r_wire/restored-bounds" || r_fail restored_tree_bounds
  r_check_restored_archive
  r_restored_identity=$(/usr/bin/stat -c %d:%i "$r_data") || r_fail restored_identity
}
r_check_restored_archive() {
  local restored
  restored=$(mtm_copy_archive "$r_data" | /usr/bin/sha256sum) || r_fail restored_archive_read
  [[ ${restored%% *} == "$r_archive_sha" ]] || r_fail restored_archive_bytes_or_modes
  r_last_restored_sha=${restored%% *}
}
r_select_old() {
  copy_sql "$r_data/private/state.sqlite3" "ATTACH DATABASE '$r_data/oauth.sqlite3' AS o;
    SELECT json_object('run_id',r.run_id,'owner_id',r.owner_id,'transition_seq',r.transition_seq,'redirect',json_extract(c.redirect_uris_json,'\$[0]'))
    FROM runs r JOIN o.oauth_clients c ON c.client_id=r.owner_id
    WHERE r.state='assess' AND r.status='active' AND r.sealed=0 AND c.token_endpoint_auth_method='none'
    ORDER BY r.created_at,r.run_id LIMIT 1;" > "$r_wire/identity.json"
  [[ -s $r_wire/identity.json && $(/usr/bin/stat -c %s "$r_wire/identity.json") -le 8192 ]] || r_fail no_eligible_preserved_owner
  r_check_json "$r_wire/identity.json" || r_fail old_identity_invalid
  r_require "$(r_identity "json_type(j,'$.transition_seq')='integer' AND json_extract(j,'$.transition_seq') BETWEEN 0 AND 9007199254740990")" original_transition_sequence
}
r_owner_digest() {
  copy_sql "$r_data/private/state.sqlite3" 'SELECT json_group_array(json_array(run_id,owner_id)) FROM (SELECT run_id,owner_id FROM runs ORDER BY run_id);' | /usr/bin/sha256sum
}
r_client_digest() {
  copy_sql "$r_data/oauth.sqlite3" 'SELECT json_group_array(json_array(client_id,redirect_uris_json,token_endpoint_auth_method,client_name,secret_digest,issued_at)) FROM (SELECT * FROM oauth_clients ORDER BY client_id);' | /usr/bin/sha256sum
}
r_preserved() {
  local owners clients key artifacts
  owners=$(r_owner_digest) && clients=$(r_client_digest) && key=$(copy_digest /work/runtime/data/oauth-token-secret.hex) || r_fail preservation_read
  [[ $owners == "$owners_before" && $clients == "$clients_before" && $key == "$key_before" ]] || r_fail preservation_mismatch
  artifacts=$(/usr/bin/find /work/runtime/workspace -name proof_verified.tex -print -quit) || r_fail workspace_scan
  [[ -z $artifacts ]] || r_fail unexpected_final_artifact
}
r_content_digest() {
  # Normalize archive metadata for comparison only; never chmod input here.
  /usr/bin/tar --sort=name --format=posix --mode=0700 \
    --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
    --numeric-owner --atime-preserve=system -C /work/runtime/data -cf - . | /usr/bin/sha256sum
}
r_copy_identity_digest() {
  printf '%s' "$r_restored_identity" | /usr/bin/sha256sum | "$mtm_capture_awk" '{print $1}'
}
r_write_baseline_restore_proof() {
  [[ -z $r_pid && $r_data == /work/runtime/data && ! -e /work/baseline-exact-restoration.json && ! -L /work/baseline-exact-restoration.json ]] || r_fail baseline_restore_proof_scope
  [[ $r_mode == synthetic || $r_mode == captured ]] || r_fail baseline_restore_proof_mode
  [[ ${r_restored_identity-} == "$(/usr/bin/stat -c %d:%i "$r_data")" && ${r_last_restored_sha-} == "$r_archive_sha" && $(copy_digest "$r_archive") == "$r_archive_sha" ]] || r_fail baseline_restore_proof_identity
  # Written and synced immediately after exact extraction, before SQLite opens
  # this copy or any ordinary modes are prepared. No private identifiers enter it.
  printf '{"schema":"mtm017-baseline-exact-restoration-v1","archive_sha256":"%s","restored_archive_sha256":"%s","working_copy_identity_sha256":"%s","bytes_and_modes_match":true,"before_baseline_mode_preparation":true,"prepared_modes_used_for_exact_check":false,"synthetic_only":%s}\n' \
    "$r_archive_sha" "$r_last_restored_sha" "$(r_copy_identity_digest)" "$([[ $r_mode == synthetic ]] && printf true || printf false)" > /work/baseline-exact-restoration.json
  /usr/bin/chmod 400 /work/baseline-exact-restoration.json
  /usr/bin/sync /work/baseline-exact-restoration.json /work
}
r_validate_baseline_restore_proof() {
  local identity synthetic=false valid
  [[ $r_mode == synthetic || $r_mode == captured ]] || return 1
  [[ $r_mode != synthetic ]] || synthetic=true
  identity=$(r_copy_identity_digest) || return 1
  copy_regular_input /work/baseline-exact-restoration.json 4096 || return 1
  [[ $(/usr/bin/stat -c %a /work/baseline-exact-restoration.json) == 400 ]] || return 1
  r_check_json /work/baseline-exact-restoration.json || return 1
  valid=$(r_doc /work/baseline-exact-restoration.json "(SELECT count(*) FROM json_each(j))=8
    AND json_extract(j,'$.schema')='mtm017-baseline-exact-restoration-v1'
    AND json_extract(j,'$.archive_sha256')='$r_archive_sha'
    AND json_extract(j,'$.restored_archive_sha256')='$r_archive_sha'
    AND json_extract(j,'$.working_copy_identity_sha256')='$identity'
    AND json_type(j,'$.bytes_and_modes_match')='true'
    AND json_type(j,'$.before_baseline_mode_preparation')='true'
    AND json_type(j,'$.prepared_modes_used_for_exact_check')='false'
    AND json_type(j,'$.synthetic_only')='$synthetic'") || return 1
  [[ $valid == 1 ]]
}
r_prepare_private_modes() {
  # Only new disposable copies. The baseline leg additionally requires the
  # durable exact-original proof authorized by the two-stage operator decision.
  local leg=${1:-candidate}
  [[ $leg == candidate || $leg == restored_baseline ]] || r_fail mode_preparation_leg
  [[ -z $r_pid && $r_data == /work/runtime/data && ! -L $r_data && ! -L $r_data/private && -d $r_data/private ]] || r_fail mode_preparation_scope
  [[ ${r_restored_identity-} == "$(/usr/bin/stat -c %d:%i "$r_data")" && $(/usr/bin/stat -c %u "$r_data") == "$UID" ]] || r_fail mode_preparation_identity
  if [[ $leg == restored_baseline ]]; then
    [[ ${r_baseline_prepared-false} == false ]] || r_fail baseline_mode_preparation_repeated
    r_check_restored_archive
    r_validate_baseline_restore_proof || r_fail baseline_restore_proof_invalid
  fi
  mtm_copy_tree_bounds "$r_data" > "$r_wire/mode-preparation-bounds" || r_fail mode_preparation_bounds
  [[ $(copy_digest "$r_archive") == "$r_archive_sha" ]] || r_fail mode_preparation_archive_identity
  local before
  before=$(r_content_digest) || r_fail mode_preparation_content_read
  /usr/bin/find "$r_data/private" -type d -exec /usr/bin/chmod 700 '{}' + || r_fail mode_preparation_directories
  /usr/bin/find "$r_data/private" -type f -exec /usr/bin/chmod 600 '{}' + || r_fail mode_preparation_files
  [[ $(r_content_digest) == "$before" && $(copy_digest "$r_archive") == "$r_archive_sha" ]] || r_fail mode_preparation_changed_content
  [[ $leg != restored_baseline ]] || r_baseline_prepared=true
}
r_validate_summary() {
  local file=$1 mode=$2 archive=$3 synthetic=false valid
  [[ $mode == synthetic || $mode == captured ]] || return 1
  [[ $archive =~ ^[0-9a-f]{64}$ ]] || return 1
  [[ $mode != synthetic ]] || synthetic=true
  r_check_json "$file" || return 1
  valid=$(r_doc "$file" "(SELECT count(*) FROM json_each(j))=40
    AND json_extract(j,'$.schema')='mtm017-schema8-copy-rehearsal-v2'
    AND json_extract(j,'$.milestone')='MTM-017'
    AND json_type(j,'$.synthetic_only')='$synthetic'
    AND json_extract(j,'$.archive_sha256')='$archive'
    AND json_extract(j,'$.candidate_sha256')='$r_candidate_sha'
    AND json_extract(j,'$.baseline_sha256')='$r_baseline_sha'
    AND json_type(j,'$.schema_before')='integer' AND json_extract(j,'$.schema_before')=7
    AND json_type(j,'$.schema_candidate')='integer' AND json_extract(j,'$.schema_candidate')=8
    AND json_type(j,'$.schema_restored')='integer' AND json_extract(j,'$.schema_restored')=7
    AND json_extract(j,'$.native_backend')='disabled' AND json_extract(j,'$.latex_policy')='static_only'
    AND json_type(j,'$.rehearsal_complete')='true'
    AND json_type(j,'$.original_archive_unchanged')='true'
    AND json_type(j,'$.restored_archive_bytes_and_modes_match')='true'
    AND json_type(j,'$.old_owner_authenticated')='true'
    AND json_type(j,'$.owner_and_client_sets_unchanged_on_candidate')='true'
    AND json_type(j,'$.owner_and_client_sets_unchanged_on_baseline')='true'
    AND json_type(j,'$.old_run_advanced_on_candidate')='true'
    AND json_type(j,'$.candidate_restart_resumed')='true'
    AND json_type(j,'$.restored_old_runtime_advanced')='true'
    AND json_type(j,'$.exactly_one_transition_per_leg')='true'
    AND json_type(j,'$.persisted_signing_key_preserved')='true'
    AND json_type(j,'$.no_final_artifact_published')='true'
    AND json_type(j,'$.clean_shutdown')='true'
    AND json_type(j,'$.mathematical_verification_claimed')='false'
    AND json_type(j,'$.production_source_mounted')='false'
    AND json_type(j,'$.production_modified')='false'
    AND json_type(j,'$.selectors_modified')='false'
    AND json_type(j,'$.raw_private_state_published')='false'
    AND json_type(j,'$.release_qualified')='false'
    AND json_type(j,'$.copied_operator_state_gate_passed')='false'
    AND json_extract(j,'$.evidence_kind')=CASE WHEN '$synthetic'='true' THEN 'synthetic_fixture' ELSE 'operator_copy_observation' END
    AND json_type(j,'$.run_id')='text' AND length(json_extract(j,'$.run_id')) BETWEEN 1 AND 256
    AND json_extract(j,'$.rollback_validation_mode')='exact_restore_then_prepared_continuation'
    AND json_type(j,'$.original_bytes_modes_exact_before_baseline_preparation')='true'
    AND json_type(j,'$.baseline_disposable_copy_mode_prepared')='true'
    AND json_type(j,'$.baseline_mode_preparation_content_unchanged')='true'
    AND json_type(j,'$.unprepared_baseline_continuation_claimed')='false'
    AND json_extract(j,'$.preserved_strict_failure_sha256')='2fbc819765e920a8ce89ad4f94317a26275b3701c785fe2fa9e2ffee4fbd67d0'
    AND json_extract(j,'$.operator_decision_sha256')='953be5aa5bfa3632408f66264e129b184219ce09c8ecd5de91ee93e608ee0933'") || return 1
  [[ $valid == 1 ]]
}

if [[ ${BASH_SOURCE[0]} != "$0" ]]; then return 0; fi
[[ $# == 2 && $1 == --internal && ( $2 == synthetic || $2 == captured ) ]] || r_fail internal_entry_requires_reviewed_host_wrapper
r_mode=$2
stage=setup
trap 'rc=$?; r_cleanup; if ((rc!=0)); then printf "MTM017_COPY_REHEARSAL_DIAGNOSTIC stage=%s\n" "$stage" >&2; fi' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
source /capture-script
source /inspect-script
copy_sqlite=/opt/copy-sqlite/bin/sqlite3
mtm_capture_awk=/capture-awk
export OPENSSL_CONF=/dev/null
ulimit -f 524288
ulimit -v 1048576
[[ $(copy_digest /candidate) == "$r_candidate_sha" && $(copy_digest /baseline) == "$r_baseline_sha" ]] || r_fail artifact_identity
for item in /candidate /baseline /capture-script /inspect-script /rehearsal-script /opt/copy-sqlite/bin/sqlite3 /capture-awk; do mtm_mount_is_readonly "$item" || r_fail input_not_readonly; done
/usr/bin/mkdir -m 700 "$r_wire" /work/runtime /work/runtime/workspace
r_require "$(copy_sql :memory: "SELECT json_valid('{}');")" sqlite_probe
[[ $(/capture-awk 'BEGIN { print 6*7 }') == 42 ]] || r_fail classifier_probe
r_password=$(/usr/bin/openssl rand -hex 32)
[[ $r_password =~ ^[0-9a-f]{64}$ ]] || r_fail randomness
if [[ $r_mode == synthetic ]]; then
  stage=synthetic_baseline_seed
  /usr/bin/mkdir -m 700 /work/runtime/data
  r_start /baseline "$r_baseline_sha"
  r_http /oauth/register 201 --header 'Content-Type: application/json' --data-binary '{"redirect_uris":["http://127.0.0.1/rehearsal-callback"],"token_endpoint_auth_method":"none","client_name":"Disposable copied-state rehearsal"}'
  r_json "json_object('owner_id',json_extract(j,'$.client_id'),'redirect','http://127.0.0.1/rehearsal-callback')" > "$r_wire/identity.json"
  r_login
  r_make_request rethlas_start "json_object('problem_tex','Synthetic lifecycle fixture, not a mathematical evaluation.','problem_id','copied-state-synthetic','workflow_mode','full','register_result',json('false'))"
  r_call
  r_require "$(r_json "json_extract(j,'$.result.structuredContent.state')='assess'")" synthetic_assess
  r_stop
  r_archive=/work/synthetic-preupgrade.tar
  mtm_copy_archive /work/runtime/data > "$r_archive"
  r_archive_sha=$(copy_digest "$r_archive")
  /usr/bin/chmod 400 "$r_archive"
  /usr/bin/mv /work/runtime/data /work/synthetic-seed-data
else
  stage=captured_input
  r_archive=/input/preupgrade.tar
  mtm_mount_is_readonly /input/archive-digest || r_fail archive_digest_not_readonly
  read -r r_archive_sha < /input/archive-digest
  mtm_mount_is_readonly "$r_archive" && mtm_mount_is_readonly /input/capture-summary.json || r_fail archive_not_readonly
  [[ $(copy_digest "$r_archive") == "$r_archive_sha" ]] || r_fail archive_hash
  copy_validate_receipt /input/capture-summary.json "$r_archive_sha" captured || r_fail capture_receipt
fi
stage=preupgrade_extraction
r_extract
copy_check_databases /work/runtime/data "$r_mode" > "$r_wire/database-counts.json"
r_doc "$r_wire/database-counts.json" "json_set(j,'$.synthetic_only',json('$([[ $r_mode == synthetic ]] && printf true || printf false)'),'$.copied_operator_state_gate_passed',json('false'))" > /work/preinspection.json
r_check_schema 7
r_select_old
r_require "$(r_state assess 0)" original_run_state
key_before=$(copy_digest /work/runtime/data/oauth-token-secret.hex)
owners_before=$(r_owner_digest)
clients_before=$(r_client_digest)
# The original archive and exact restoration remain unchanged. The operator
# explicitly authorized private-mode preparation on this candidate copy.
stage=candidate_private_mode_preparation
r_prepare_private_modes
legacy_revisions=$(copy_sql "$r_data/private/state.sqlite3" 'SELECT json_group_array(json_array(revision_id,claim_id)) FROM (SELECT revision_id,claim_id FROM claim_revisions ORDER BY revision_id);' | /usr/bin/sha256sum)
stage=candidate_migration
r_start /candidate "$r_candidate_sha"
r_check_schema 8
r_require "$(copy_sql "$r_data/private/state.sqlite3" "SELECT (SELECT count(*) FROM facts)=0 AND (SELECT count(*) FROM fact_edges)=0 AND (SELECT count(*) FROM fact_revocations)=0 AND (SELECT count(*) FROM memory_findings)=0 AND (SELECT count(*) FROM memory_finding_status)=0 AND NOT EXISTS(SELECT 1 FROM claim_revisions WHERE fact_id IS NOT NULL);")" schema8_no_legacy_backfill
[[ $(copy_sql "$r_data/private/state.sqlite3" 'SELECT json_group_array(json_array(revision_id,claim_id)) FROM (SELECT revision_id,claim_id FROM claim_revisions ORDER BY revision_id);' | /usr/bin/sha256sum) == "$legacy_revisions" ]] || r_fail legacy_revision_identity
r_login
r_info 0.6.0-preview.2
stage=candidate_old_run_continuation
r_advance
r_require "$(r_state explore 1)" candidate_transition
r_stop
stage=candidate_restart
r_start /candidate "$r_candidate_sha"
r_login
r_info 0.6.0-preview.2
r_task explore
r_require "$(r_state explore 1)" restart_transition
r_stop
r_check_schema 8
r_preserved
stage=restore_original_archive
/usr/bin/mv /work/runtime/data /work/upgraded-data
r_extract
r_write_baseline_restore_proof
stage=restored_baseline_private_mode_preparation
r_prepare_private_modes restored_baseline
r_check_schema 7
r_require "$(r_state assess 0)" restore_run_state
r_preserved
stage=restored_baseline_continuation
r_start /baseline "$r_baseline_sha"
r_login
r_info 0.6.0-preview.1
r_advance
r_require "$(r_state explore 1)" restored_baseline_transition
r_stop
r_check_schema 7
r_preserved
stage=final_identity
[[ -z $r_pid ]] || r_fail owned_process_not_reaped
[[ $(copy_digest "$r_archive") == "$r_archive_sha" && $(copy_digest /candidate) == "$r_candidate_sha" && $(copy_digest /baseline) == "$r_baseline_sha" ]] || r_fail final_input_drift
copy_sql :memory: "SELECT json_object('schema','mtm017-schema8-copy-rehearsal-v2','milestone','MTM-017','rehearsal_complete',json('true'),'synthetic_only',json('$([[ $r_mode == synthetic ]] && printf true || printf false)'),'archive_sha256','$r_archive_sha','candidate_sha256','$r_candidate_sha','baseline_sha256','$r_baseline_sha','schema_before',7,'schema_candidate',8,'schema_restored',7,'original_archive_unchanged',json('true'),'restored_archive_bytes_and_modes_match',json('true'),'old_owner_authenticated',json('true'),'owner_and_client_sets_unchanged_on_candidate',json('true'),'owner_and_client_sets_unchanged_on_baseline',json('true'),'old_run_advanced_on_candidate',json('true'),'candidate_restart_resumed',json('true'),'restored_old_runtime_advanced',json('true'),'exactly_one_transition_per_leg',json('true'),'persisted_signing_key_preserved',json('true'),'no_final_artifact_published',json('true'),'native_backend','disabled','latex_policy','static_only','mathematical_verification_claimed',json('false'),'production_source_mounted',json('false'),'production_modified',json('false'),'selectors_modified',json('false'),'clean_shutdown',json('true'),'raw_private_state_published',json('false'),'release_qualified',json('false'),'copied_operator_state_gate_passed',json('false'),'evidence_kind','$([[ $r_mode == synthetic ]] && printf synthetic_fixture || printf operator_copy_observation)','run_id',json_extract(CAST(readfile('$r_wire/identity.json') AS TEXT),'$.run_id'),'rollback_validation_mode','exact_restore_then_prepared_continuation','original_bytes_modes_exact_before_baseline_preparation',json('true'),'baseline_disposable_copy_mode_prepared',json('true'),'baseline_mode_preparation_content_unchanged',json('true'),'unprepared_baseline_continuation_claimed',json('false'),'preserved_strict_failure_sha256','2fbc819765e920a8ce89ad4f94317a26275b3701c785fe2fa9e2ffee4fbd67d0','operator_decision_sha256','953be5aa5bfa3632408f66264e129b184219ce09c8ecd5de91ee93e608ee0933');" > /work/rehearsal-summary.json
r_validate_summary /work/rehearsal-summary.json "$r_mode" "$r_archive_sha" || r_fail summary_contract
/usr/bin/sync /work/rehearsal-summary.json /work
