#!/usr/bin/env bash
# Bounded preparation-contract tests; no public service or production writes.
set -euo pipefail
umask 077
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
source "$repo/scripts/mtm017-web-session.sh"
ws_init
ws_args prepare
for op in check start up attach stop; do ws_args "$op" /absolute/session; done
if ws_args; then exit 1; fi
if ws_args prepare extra; then exit 1; fi
if ws_args start relative; then exit 1; fi
if ws_args start /absolute/session --native-mode safe; then exit 1; fi
if ws_args prepare --binary /tmp/other; then exit 1; fi
if ws_args --state-root /operator/data; then exit 1; fi
if ws_session /tmp; then exit 1; fi

testroot=$(/usr/bin/mktemp -d)
trap '/usr/bin/rm -rf -- "$testroot"' EXIT
/usr/bin/mkdir -m 700 "$testroot/private"
rs_private_dir "$testroot/private"
/usr/bin/chmod 755 "$testroot/private"
if rs_private_dir "$testroot/private"; then exit 1; fi
/usr/bin/chmod 700 "$testroot/private"
/usr/bin/ln -s "$testroot/private" "$testroot/linked"
if rs_private_dir "$testroot/linked"; then exit 1; fi
printf 'inert fixture\n' > "$testroot/file"
/usr/bin/chmod 500 "$testroot/file"
if rs_snapshot "$testroot/file" "$testroot/output" "$WS_CANDIDATE_SHA"; then exit 1; fi
[[ ! -e $testroot/output ]]

# An inherited root/key/debug override cannot enter the clean runtime command.
rs_task=U25
MTM_DATA_ROOT=/operator/data MTM_TRACE_PAYLOADS=1 MTM_OAUTH_PASSWORD=not-a-real-key rs_environment "$testroot/private"
[[ ${rs_env[0]} == /usr/bin/env && ${rs_env[1]} == -i ]]
joined=$(printf '%s\n' "${rs_env[@]}")
[[ $joined == *"MTM_DATA_ROOT=$testroot/private/data"* ]]
[[ $joined == *MTM_NATIVE_MODE=dangerous* && $joined == *MTM_LATEX_POLICY=required* ]]
[[ $joined == *MTM_TRACE_PAYLOADS=0* && $joined != *not-a-real-key* && $joined != */operator/data* ]]
printf 'web_session_contract_tests=passed; public_service_started=false; production_changed=false\n'
