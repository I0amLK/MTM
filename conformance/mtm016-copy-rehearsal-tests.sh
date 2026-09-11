#!/usr/bin/env bash
# No operator archive, production root, real credentials or network accepted.
set -euo pipefail
umask 077
[[ $# == 2 && $1 == --sqlite && $2 == /* ]] || exit 2
sqlite=$(/usr/bin/readlink -e -- "$2")
repo=$(cd -- "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
source "$repo/scripts/mtm016-capture-operator-state.sh"
source "$repo/scripts/mtm016-inspect-operator-copy.sh"
source "$repo/scripts/mtm016-rehearse-operator-copy.sh"
copy_sqlite=$sqlite
root=$(/usr/bin/mktemp -d /tmp/mtm-rehearsal-unit.XXXXXXXX)
trap 'r_cleanup; /usr/bin/rm -rf -- "$root"' EXIT
r_wire=$root/wire
r_data=$root/data
mkdir -m 700 "$r_wire" "$r_data" "$r_data/private"
negative=0
reject() {
  if ("$@") > "$root/rejected.stdout" 2> "$root/rejected.stderr"; then
    printf 'COPY_REHEARSAL_TEST unexpected_acceptance=%s\n' "$1" >&2; exit 1
  fi
  negative=$((negative+1))
}

for payload in '{}' '{"a":[{"x":1},{"x":2}],"b":true}'; do
  printf '%s' "$payload" > "$root/json"
  r_check_json "$root/json"
done
for payload in '' '[]' 'null' '{' '{"a":1,"a":2}' '{"a":{"x":1,"x":2}}' '{"a":1,"\u0061":2}'; do
  printf '%s' "$payload" > "$root/json"
  reject r_check_json "$root/json"
done
printf 'COPY_REHEARSAL_TEST duplicate_nested_and_malformed_json=passed\n'

printf '{}' > "$root/body"
printf 'HTTP/1.1 200 OK\r\ncontent-length: 2\r\ncontent-type: application/json\r\n\r\n' > "$root/headers"
r_validate_headers "$root/headers" "$root/body" 200
for header in \
  $'HTTP/1.1 200 OK\r\ncontent-length: 1\r\n\r\n' \
  $'HTTP/1.1 200 OK\r\ncontent-length: 2\r\nContent-Length: 2\r\n\r\n' \
  $'HTTP/1.1 200 OK\r\ncontent-length: 2\r\ntransfer-encoding: chunked\r\n\r\n' \
  $'HTTP/1.1 302 Found\r\ncontent-length: 2\r\n\r\n' \
  $'HTTP/1.0 200 OK\r\ncontent-length: 2\r\n\r\n' \
  $'HTTP/1.1 200 OK\r\ncontent-length: 2\r\n' \
  $'HTTP/1.1 200 OK\r\n\r\n' \
  $'HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nHTTP/1.1 200 OK\r\n\r\n'; do
  printf '%s' "$header" > "$root/headers"
  reject r_validate_headers "$root/headers" "$root/body" 200
done
printf 'COPY_REHEARSAL_TEST http_framing_status_and_length=passed\n'

check_fixture_rpc() (
  r_http() { cp "$root/rpc.json" "$r_wire/reply.json"; r_check_json "$r_wire/reply.json" || r_fail response_json; }
  r_call
)
printf '%s' '{"jsonrpc":"2.0","id":"copy-rehearsal","result":{"isError":false,"structuredContent":{"ok":true,"run_id":"old-run","state":"explore"}}}' > "$root/rpc-good.json"
cp "$root/rpc-good.json" "$root/rpc.json"
check_fixture_rpc
for mutation in \
  "json_set(j,'\$.id','other-request')" \
  "json_set(j,'\$.jsonrpc','1.0')" \
  "json_set(j,'\$.error',json('{}'))" \
  "json_set(j,'\$.result.isError',json('true'))" \
  "json_set(j,'\$.result.structuredContent.ok',1)" \
  "json_remove(j,'\$.result.isError')" \
  "json_remove(j,'\$.result.structuredContent.ok')"; do
  r_doc "$root/rpc-good.json" "$mutation" > "$root/rpc.json"
  reject check_fixture_rpc
done
printf 'COPY_REHEARSAL_TEST mcp_response_id_error_and_boolean_contract=passed\n'

nonce=0123456789abcdef0123456789abcdef
redirect=https://example.invalid/callback
[[ $(r_callback_code "$redirect?code=fixture_Code-42&state=$nonce" "$redirect" "$nonce") == fixture_Code-42 ]]
[[ $(r_callback_code "$redirect?existing=1&code=fixture_Code-42&state=$nonce" "$redirect?existing=1" "$nonce") == fixture_Code-42 ]]
for location in \
  "$redirect?code=fixture&state=ffffffffffffffffffffffffffffffff" \
  "$redirect.extra?code=fixture&state=$nonce" \
  "$redirect?code=fixture&state=$nonce&extra=1" \
  "$redirect?code=fixture&code=other&state=$nonce" \
  "$redirect?code=fixture%0A&state=$nonce" \
  "$redirect?state=$nonce&code=fixture" \
  "$redirect?code=fixture&state=$nonce"$'\r\n'; do
  reject r_callback_code "$location" "$redirect" "$nonce"
done
reject r_callback_code 'file:///tmp?code=fixture' file:///tmp "$nonce"
printf 'COPY_REHEARSAL_TEST callback_prefix_nonce_and_no_redirect=passed\n'

# Only self-created SQLite fixtures are mutated in these tests.
"$sqlite" -batch -bail -init /dev/null "$r_data/oauth.sqlite3" "CREATE TABLE oauth_clients(client_id TEXT PRIMARY KEY,redirect_uris_json TEXT,token_endpoint_auth_method TEXT,client_name TEXT,secret_digest TEXT,issued_at INTEGER); INSERT INTO oauth_clients VALUES('owner','[\"https://example.invalid/callback\"]','none','fixture',NULL,1),('secret-owner','[\"https://example.invalid/callback\"]','client_secret_post','fixture-secret','not-a-credential',2);"
"$sqlite" -batch -bail -init /dev/null "$r_data/private/state.sqlite3" "CREATE TABLE runs(run_id TEXT PRIMARY KEY,owner_id TEXT,state TEXT,status TEXT,sealed INTEGER,transition_seq INTEGER,created_at TEXT); INSERT INTO runs VALUES('old-run','owner','assess','active',0,4,'2020-01-02'),('secret-run','secret-owner','assess','active',0,0,'2020-01-01'),('done-run','owner','done','done',1,8,'2020-01-01');"
r_select_old
[[ $(r_identity "json_extract(j,'$.run_id')") == old-run ]]
[[ $(r_state assess 0) == 1 ]]
owners=$(r_owner_digest); clients=$(r_client_digest)
"$sqlite" -batch -bail -init /dev/null "$r_data/private/state.sqlite3" "UPDATE runs SET state='explore',transition_seq=5 WHERE run_id='old-run';"
[[ $(r_state explore 1) == 1 && $(r_owner_digest) == "$owners" ]]
"$sqlite" -batch -bail -init /dev/null "$r_data/private/state.sqlite3" "UPDATE runs SET owner_id='secret-owner' WHERE run_id='old-run';"
[[ $(r_state explore 1) == 0 && $(r_owner_digest) != "$owners" ]]
"$sqlite" -batch -bail -init /dev/null "$r_data/private/state.sqlite3" "UPDATE runs SET owner_id='owner',transition_seq=6 WHERE run_id='old-run';"
[[ $(r_state explore 1) == 0 ]]
"$sqlite" -batch -bail -init /dev/null "$r_data/private/state.sqlite3" "UPDATE runs SET transition_seq=5,sealed=1 WHERE run_id='old-run';"
[[ $(r_state explore 1) == 0 ]]
"$sqlite" -batch -bail -init /dev/null "$r_data/oauth.sqlite3" "UPDATE oauth_clients SET client_name='changed' WHERE client_id='owner';"
[[ $(r_client_digest) != "$clients" ]]
reject r_select_old
[[ ! -s $r_wire/identity.json ]]
printf '{"run_id":"old-run","owner_id":"owner","transition_seq":4}' > "$r_wire/identity.json"
printf '{"result":{"structuredContent":{"run_id":"old-run","state":"explore"}}}' > "$r_wire/reply.json"
r_run_binding explore
printf '{"result":{"structuredContent":{"run_id":"other-run","state":"explore"}}}' > "$r_wire/reply.json"
reject r_run_binding explore
printf '{"result":{"structuredContent":{"run_id":"old-run","state":"done"}}}' > "$r_wire/reply.json"
reject r_run_binding explore
printf 'COPY_REHEARSAL_TEST old_owner_task_binding_transition_and_registration=passed\n'

digest=1111111111111111111111111111111111111111111111111111111111111111
copy_sql :memory: "SELECT json_object('schema','mtm-operator-copy-rehearsal-v1','milestone','MTM-016','rehearsal_complete',json('true'),'synthetic_only',json('true'),'archive_sha256','$digest','candidate_sha256','$r_candidate_sha','baseline_sha256','$r_baseline_sha','schema_before',2,'schema_candidate',7,'schema_restored',2,'original_archive_unchanged',json('true'),'restored_archive_bytes_and_modes_match',json('true'),'old_owner_authenticated',json('true'),'owner_and_client_sets_unchanged_on_candidate',json('true'),'owner_and_client_sets_unchanged_on_baseline',json('true'),'old_run_advanced_on_candidate',json('true'),'candidate_restart_resumed',json('true'),'restored_old_runtime_advanced',json('true'),'exactly_one_transition_per_leg',json('true'),'persisted_signing_key_preserved',json('true'),'no_final_artifact_published',json('true'),'native_backend','disabled','latex_policy','static_only','mathematical_verification_claimed',json('false'),'production_source_mounted',json('false'),'production_modified',json('false'),'selectors_modified',json('false'),'clean_shutdown',json('true'),'raw_private_state_published',json('false'),'release_qualified',json('false'));" > "$root/good.json"
r_validate_summary "$root/good.json" synthetic "$digest"
reject r_validate_summary "$root/good.json" captured "$digest"
fields=$(r_doc "$root/good.json" '(SELECT group_concat(key,char(10)) FROM json_each(j))')
while IFS= read -r field; do
  r_doc "$root/good.json" "json_remove(j,'\$.$field')" > "$root/bad.json"
  reject r_validate_summary "$root/bad.json" synthetic "$digest"
done <<< "$fields"
for mutation in \
  "json_set(j,'\$.production_modified',json('true'))" \
  "json_set(j,'\$.rehearsal_complete',1)" \
  "json_set(j,'\$.schema_candidate',7.0)" \
  "json_set(j,'\$.release_qualified',json('true'))" \
  "json_set(j,'\$.token','synthetic-secret-must-not-be-emitted')" \
  "json_set(j,'\$.candidate_sha256','$digest')"; do
  r_doc "$root/good.json" "$mutation" > "$root/bad.json"
  reject r_validate_summary "$root/bad.json" synthetic "$digest"
done
printf 'COPY_REHEARSAL_TEST summary_all_thirty_fields_types_scope_and_identity=passed\n'

# Invalid origins are rejected before curl, so these are source-free/no-network.
r_origin=https://example.invalid
reject r_http /health 200
r_origin=http://127.0.0.1:0
reject r_http /health 200
r_origin=http://127.0.0.1:65536
reject r_http /health 200
r_origin=http://127.0.0.1:1
r_mode=captured
reject r_http /oauth/register 201
reject r_make_request rethlas_start "'{}'"
reject r_make_request exec_command "'{}'"
printf 'COPY_REHEARSAL_TEST non_loopback_and_invalid_ports=passed\n'
printf 'COPY_REHEARSAL_TEST captured_mode_no_new_owner_run_or_native_tool=passed\n'

# The signal reset is part of the real launch path, not a test bypass.
/usr/bin/env --default-signal=INT,QUIT,TERM -i PATH=/usr/bin:/bin /bin/bash -c 'trap "exit 0" INT; printf ready; while :; do sleep 0.02; done' > "$root/ready" &
r_pid=$!
for ((attempt=0; attempt<100; attempt++)); do [[ -s $root/ready ]] && break; sleep 0.02; done
[[ -s $root/ready ]]
r_child_running
r_stop
[[ -z $r_pid ]]
/usr/bin/sleep 60 &
r_pid=$!; owned=$r_pid
r_cleanup
[[ -z $r_pid && ! -d /proc/$owned ]]
printf 'COPY_REHEARSAL_TEST owned_child_graceful_stop_and_failure_cleanup=passed\n'
printf 'COPY_REHEARSAL_TEST negative_cases=%s production_source_accessed=false network_used=false runtime_artifact_executed=false\n' "$negative"
