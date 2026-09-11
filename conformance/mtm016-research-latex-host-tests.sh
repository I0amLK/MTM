#!/usr/bin/env bash
# Exact frozen helper, synthetic TeX only. No server, OAuth, run or tunnel.
set -euo pipefail
umask 077
export LC_ALL=C
repo=$(cd -- "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")/.." && /usr/bin/pwd -P)
[[ $# == 2 && $1 == --sqlite && $2 == /* ]] || exit 1
sqlite=$(/usr/bin/readlink -e -- "$2")
[[ -f $sqlite && -x $sqlite ]] || exit 1
source "$repo/scripts/mtm016-research-session.sh"
tmp=$(/usr/bin/mktemp -d /tmp/mtm-research-latex.XXXXXXXX)
trap '/usr/bin/rm -rf -- "$tmp"' EXIT
trap 'printf "RESEARCH_LATEX_TEST failed_stage=%s synthetic_only=true\n" "$stage" >&2' ERR
stage=fixture_setup
session="$tmp/session with 'quotes'"
/usr/bin/mkdir -m 700 -- "$session" "$session/tool-bin" "$session/home" "$session/data" "$session/tmp" "$session/workspace"
for name in bwrap latexmk pdflatex sh cat printf sleep; do
  target=$(rs_tool "$name" "${PATH:-}")
  /usr/bin/ln -s -- "$target" "$session/tool-bin/$name"
done
candidate=$repo/target/mtm016-f5-frozen/mtm-0.6.0-preview.1-$RS_CANDIDATE_SHA/mtm
rs_snapshot "$candidate" "$session/candidate" "$RS_CANDIDATE_SHA"
rs_environment "$session"
printf '%s\n' '\documentclass{article}' '\begin{document}Compiler transport fixture only.\end{document}' > "$session/workspace/proof.tex"
escaped=${session//\'/\'\'}
sql() { "$sqlite" -batch -init /dev/null -noheader ':memory:' "$1"; }
request() {
  local roots=$1
  sql "SELECT json_object('protocol','re-ctm-native-helper-v1','operation','execute',
    'request_id','research-compiler-fixture','workspace','$escaped/workspace',
    'forbidden_paths',json_array('$escaped/data','$escaped/home'), 'mode','safe',
    'argv',json_array('$escaped/tool-bin/latexmk','-pdf','-interaction=nonstopmode','-halt-on-error','-no-shell-escape','proof.tex'),
    'workdir','.','timeout_ms',60000,'host_path','$escaped/tool-bin','extra_read_roots',json($roots));"
}
helper() {
  /usr/bin/timeout --signal=TERM --kill-after=3s 70s /usr/bin/env -i PATH=/usr/bin:/bin \
    "$session/candidate" __native-helper < "$1" > "$2" 2> "$tmp/helper.stderr"
}
stage=request_serialization
request "'[]'" > "$tmp/legacy-request.json"
request "json_array('$escaped/tool-bin')" > "$tmp/fixed-request.json"
[[ $(sql "SELECT json_array_length(j,'\$.extra_read_roots')=1
    AND json_extract(j,'\$.extra_read_roots[0]')='$escaped/tool-bin'
    AND json_extract(j,'\$.argv[0]')='$escaped/tool-bin/latexmk'
    AND json_extract(j,'\$.mode')='safe'
    FROM (SELECT CAST(readfile('$tmp/fixed-request.json') AS TEXT) j);") == 1 ]]
printf 'RESEARCH_LATEX_TEST exact_request_and_quoted_tool_root=passed\n'
stage=native_preflight
if ! /usr/bin/timeout --signal=TERM --kill-after=3s 20s "${rs_env[@]}" "$session/candidate" attest-native \
  --workspace "$session/workspace" --native-mode safe --latex-policy required > "$tmp/native.json" 2> "$tmp/native.stderr"; then
  printf 'RESEARCH_LATEX_TEST failed_stage=native_preflight synthetic_only=true\n' >&2
  if /usr/bin/grep -Eq 'ENOSPC|No space left on device|Creating new namespace failed' "$tmp/native.json" "$tmp/native.stderr"; then
    printf 'RESEARCH_LATEX_TEST diagnostic=namespace_creation_unavailable\n' >&2
  else
    printf 'RESEARCH_LATEX_TEST diagnostic=unclassified_preflight_failure\n' >&2
  fi
  exit 1
fi
printf 'RESEARCH_LATEX_TEST native_preflight=passed\n'
stage=legacy_missing_mount
legacy_rc=0
helper "$tmp/legacy-request.json" "$tmp/legacy.json" || legacy_rc=$?
[[ $legacy_rc == 0 || $legacy_rc == 1 ]]
[[ $(sql "SELECT CASE WHEN json_valid(j) THEN
    (json_extract(j,'$.ok')=0 OR (json_extract(j,'$.ok')=1 AND json_extract(j,'$.exit_code')<>0)) ELSE 0 END
    FROM (SELECT CAST(readfile('$tmp/legacy.json') AS TEXT) j);") == 1 ]]
[[ ! -e $session/workspace/proof.pdf ]]
printf 'RESEARCH_LATEX_TEST old_unmounted_alias_reproduced=passed\n'
stage=explicit_tool_directory
helper "$tmp/fixed-request.json" "$tmp/fixed.json"
[[ $(sql "SELECT json_extract(j,'$.ok')=1 AND json_extract(j,'$.exit_code')=0
    AND json_extract(j,'$.timed_out')=0 AND json_extract(j,'$.attestation.network_isolated')=1
    AND json_extract(j,'$.attestation.private_vault_mounted')=0
    FROM (SELECT CAST(readfile('$tmp/fixed.json') AS TEXT) j);") == 1 ]]
[[ -s $session/workspace/proof.pdf ]]
[[ $(rs_hash "$candidate") == "$RS_CANDIDATE_SHA" && $(rs_hash "$session/candidate") == "$RS_CANDIDATE_SHA" ]]
printf 'RESEARCH_LATEX_TEST fixed_helper_compiled_with_narrow_readonly_root=passed\n'
printf 'RESEARCH_LATEX_TEST synthetic_only=true research_trials_executed=0 server_started=false production_source_accessed=false\n'
