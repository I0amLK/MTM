#!/usr/bin/env bash
# No operator archive, production root, real credentials or network accepted.
set -euo pipefail
umask 077
[[ $# == 2 && $1 == --sqlite && $2 == /* ]] || exit 2
sqlite=$(/usr/bin/readlink -e -- "$2")
repo=$(cd -- "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
source "$repo/scripts/mtm017-capture-operator-state.sh"
source "$repo/scripts/mtm017-inspect-operator-copy.sh"
source "$repo/scripts/mtm017-rehearse-operator-copy.sh"
copy_sqlite=$sqlite
root=$(/usr/bin/mktemp -d /tmp/mtm-rehearsal-unit.XXXXXXXX)
mtm_fixture_mark
trap 'r_cleanup; mtm_fixture_cleanup' EXIT
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

# Exercise the actual restoration function without a runtime or a namespace.
# A deliberately old nanosecond timestamp prevents a fast test from hiding a
# failure to restore the archive's existing root-directory metadata.
mkdir -m 700 "$root/restore-source" "$root/restore-source/private"
printf 'synthetic database\n' > "$root/restore-source/private/state.sqlite3"
printf 'synthetic wal\n' > "$root/restore-source/private/state.sqlite3-wal"
printf 'synthetic shm\n' > "$root/restore-source/private/state.sqlite3-shm"
printf 'synthetic key\n' > "$root/restore-source/oauth-token-secret.hex"
printf 'synthetic unicode name\n' > "$root/restore-source/含 空格"$'\n'"name"
long_name=$(printf '%0180d' 1)
printf 'synthetic long name\n' > "$root/restore-source/private/$long_name"
chmod 750 "$root/restore-source"
touch -m -d @1700000000.123456789 "$root/restore-source" "$root/restore-source/private"
mtm_copy_archive "$root/restore-source" > "$root/restore-original.tar"
restore_digest=$(copy_digest "$root/restore-original.tar")
chmod 400 "$root/restore-original.tar"
(
  r_archive=$root/restore-original.tar
  r_archive_sha=$restore_digest
  r_data=$root/restore-result
  r_extract
)
mtm_copy_archive "$root/restore-result" > "$root/restore-result.tar"
cmp -s "$root/restore-original.tar" "$root/restore-result.tar"
[[ $(copy_digest "$root/restore-original.tar") == "$restore_digest" ]]
printf 'COPY_REHEARSAL_TEST exact_archive_root_metadata_roundtrip=passed\n'

fixture_restore() (
  r_data=$1
  r_archive=${2:-$root/restore-original.tar}
  r_archive_sha=${3:-$restore_digest}
  r_pid=${4-}
  r_extract
)
fixture_compare_restored() (
  r_data=$root/restore-result
  r_archive_sha=$restore_digest
  r_check_restored_archive
)
fixture_compare_restored
reject fixture_restore "$root/restore-result"
mkdir -m 700 "$root/existing-empty"
reject fixture_restore "$root/existing-empty"
ln -s "$root/restore-result" "$root/destination-link"
reject fixture_restore "$root/destination-link"
ln -s "$root/absent-target" "$root/dangling-destination"
reject fixture_restore "$root/dangling-destination"
reject fixture_restore "$root/active-restore" "$root/restore-original.tar" "$restore_digest" 1
[[ ! -e $root/active-restore ]]
reject fixture_restore "$root/wrong-hash-restore" "$root/restore-original.tar" 0000000000000000000000000000000000000000000000000000000000000000
[[ ! -e $root/wrong-hash-restore ]]
fixture_compare_restored
printf 'COPY_REHEARSAL_TEST restore_existing_paths_active_child_and_identity_denied=passed\n'

# Every mutation is followed by a positive comparison after exact repair of
# this synthetic fixture, so one stale earlier mismatch cannot mask another.
printf 'synthetic databasf\n' > "$root/restore-result/private/state.sqlite3"
touch -r "$root/restore-source/private/state.sqlite3" "$root/restore-result/private/state.sqlite3"
[[ $(stat -c %s "$root/restore-result/private/state.sqlite3") == $(stat -c %s "$root/restore-source/private/state.sqlite3") ]]
reject fixture_compare_restored
cp -p "$root/restore-source/private/state.sqlite3" "$root/restore-result/private/state.sqlite3"
fixture_compare_restored
chmod 640 "$root/restore-result/private/state.sqlite3"
reject fixture_compare_restored
chmod 600 "$root/restore-result/private/state.sqlite3"
fixture_compare_restored
chmod 700 "$root/restore-result"
reject fixture_compare_restored
chmod 750 "$root/restore-result"
fixture_compare_restored
touch -m -d @1700000000.123456790 "$root/restore-result"
reject fixture_compare_restored
touch -r "$root/restore-source" "$root/restore-result"
fixture_compare_restored
printf 'extra synthetic entry\n' > "$root/restore-result/extra"
reject fixture_compare_restored
rm "$root/restore-result/extra"
touch -r "$root/restore-source" "$root/restore-result"
fixture_compare_restored
mv "$root/restore-result/private/state.sqlite3-wal" "$root/moved-wal"
reject fixture_compare_restored
mv "$root/moved-wal" "$root/restore-result/private/state.sqlite3-wal"
touch -r "$root/restore-source/private" "$root/restore-result/private"
fixture_compare_restored
printf 'COPY_REHEARSAL_TEST exact_comparison_rejects_content_modes_time_and_entries=passed\n'

# Repeated members must fail pre-extraction before a destination even exists.
cp "$root/restore-original.tar" "$root/duplicate.tar"
chmod 600 "$root/duplicate.tar"
mkdir -m 700 "$root/duplicate-source" "$root/duplicate-source/private"
printf 'duplicate must not overwrite\n' > "$root/duplicate-source/private/state.sqlite3"
tar --append -f "$root/duplicate.tar" -C "$root/duplicate-source" ./private/state.sqlite3
duplicate_digest=$(copy_digest "$root/duplicate.tar")
reject fixture_restore "$root/duplicate-result" "$root/duplicate.tar" "$duplicate_digest"
[[ ! -e $root/duplicate-result ]]
grep -qx 'MTM017_COPY_REHEARSAL_ERROR reason=unsafe_archive_members' "$root/rejected.stderr"
[[ $(copy_digest "$root/restore-original.tar") == "$restore_digest" ]]
printf 'COPY_REHEARSAL_TEST duplicate_archive_member_no_clobber=passed\n'

mkdir -m 700 "$root/unsafe-source"
ln -s /etc/passwd "$root/unsafe-source/link"
mtm_copy_archive "$root/unsafe-source" > "$root/link.tar"
reject fixture_restore "$root/link-result" "$root/link.tar" "$(copy_digest "$root/link.tar")"
[[ ! -e $root/link-result ]]
rm "$root/unsafe-source/link"
truncate -s 134217729 "$root/unsafe-source/oversized"
tar --sparse --format=posix -cf "$root/sparse.tar" -C "$root/unsafe-source" .
reject fixture_restore "$root/sparse-result" "$root/sparse.tar" "$(copy_digest "$root/sparse.tar")"
[[ ! -e $root/sparse-result ]]
rm "$root/unsafe-source/oversized"
printf fixture > "$root/unsafe-source/file"
tar -cf "$root/traversal.tar" --transform='s,^,../,' -C "$root/unsafe-source" .
reject fixture_restore "$root/traversal-result" "$root/traversal.tar" "$(copy_digest "$root/traversal.tar")"
[[ ! -e $root/traversal-result ]]
printf 'COPY_REHEARSAL_TEST preextraction_links_sparse_bounds_and_traversal_denied=passed\n'

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
copy_sql :memory: "SELECT json_object('schema','mtm017-schema8-copy-rehearsal-v2','milestone','MTM-017','rehearsal_complete',json('true'),'synthetic_only',json('true'),'archive_sha256','$digest','candidate_sha256','$r_candidate_sha','baseline_sha256','$r_baseline_sha','schema_before',7,'schema_candidate',8,'schema_restored',7,'original_archive_unchanged',json('true'),'restored_archive_bytes_and_modes_match',json('true'),'old_owner_authenticated',json('true'),'owner_and_client_sets_unchanged_on_candidate',json('true'),'owner_and_client_sets_unchanged_on_baseline',json('true'),'old_run_advanced_on_candidate',json('true'),'candidate_restart_resumed',json('true'),'restored_old_runtime_advanced',json('true'),'exactly_one_transition_per_leg',json('true'),'persisted_signing_key_preserved',json('true'),'no_final_artifact_published',json('true'),'native_backend','disabled','latex_policy','static_only','mathematical_verification_claimed',json('false'),'production_source_mounted',json('false'),'production_modified',json('false'),'selectors_modified',json('false'),'clean_shutdown',json('true'),'raw_private_state_published',json('false'),'release_qualified',json('false'),'copied_operator_state_gate_passed',json('false'),'evidence_kind','synthetic_fixture','run_id','fixture-old-run','rollback_validation_mode','exact_restore_then_prepared_continuation','original_bytes_modes_exact_before_baseline_preparation',json('true'),'baseline_disposable_copy_mode_prepared',json('true'),'baseline_mode_preparation_content_unchanged',json('true'),'unprepared_baseline_continuation_claimed',json('false'),'preserved_strict_failure_sha256','2fbc819765e920a8ce89ad4f94317a26275b3701c785fe2fa9e2ffee4fbd67d0','operator_decision_sha256','953be5aa5bfa3632408f66264e129b184219ce09c8ecd5de91ee93e608ee0933');" > "$root/good.json"
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
  "json_set(j,'\$.schema','mtm017-schema8-copy-rehearsal-v1')" \
  "json_set(j,'\$.rollback_validation_mode','original_modes_continuation')" \
  "json_set(j,'\$.unprepared_baseline_continuation_claimed',json('true'))" \
  "json_set(j,'\$.operator_decision_sha256','$digest')" \
  "json_set(j,'\$.token','synthetic-secret-must-not-be-emitted')" \
  "json_set(j,'\$.candidate_sha256','$digest')"; do
  r_doc "$root/good.json" "$mutation" > "$root/bad.json"
  reject r_validate_summary "$root/bad.json" synthetic "$digest"
done
printf 'COPY_REHEARSAL_TEST summary_all_forty_fields_types_scope_and_identity=passed\n'

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
