#!/usr/bin/env bash
# Bounded recovery of the stopped U21-r1 session made by the original launcher.
# Preserves state/keys/logs; never submits a task, replaces an owner or makes a run.

rr_metadata() {
  local file=$1 sqlite=$2 escaped
  rs_regular "$file" 16384 || return 1
  escaped=${file//\'/\'\'}
  [[ $("$sqlite" -batch -init /dev/null -noheader ':memory:' "
    WITH d(j) AS (SELECT CAST(readfile('$escaped') AS TEXT))
    SELECT coalesce(
      json_type(j)='object' AND (SELECT count(*) FROM json_each(j))=20
      AND (SELECT count(DISTINCT key) FROM json_each(j))=20
      AND NOT EXISTS (SELECT 1 FROM json_each(j) WHERE type IN ('array','object','null','real'))
      AND json_extract(j,'$.schema')='mtm-research-session-v1'
      AND json_extract(j,'$.milestone')='MTM-016'
      AND json_extract(j,'$.task_id')='U21' AND json_type(j,'$.repeat')='integer' AND json_extract(j,'$.repeat')=1
      AND json_extract(j,'$.case_id')='u21-r1-subspace-dimension' AND json_extract(j,'$.workflow_mode')='compact'
      AND json_type(j,'$.trial_id')='text' AND length(json_extract(j,'$.trial_id'))=32
      AND json_extract(j,'$.trial_id') NOT GLOB '*[^0-9a-f]*'
      AND json_extract(j,'$.candidate_sha256')='$RS_CANDIDATE_SHA'
      AND json_extract(j,'$.candidate_source_commit')='$RS_CANDIDATE_SOURCE'
      AND json_extract(j,'$.launcher_source_commit')='1d1fcb737039b10ae0dea1683a8ccaf90c296941'
      AND json_extract(j,'$.launcher_sha256')='e4e2a30175976c7bd1db7874db12699d5589203b381248036829c488db7a2b91'
      AND json_extract(j,'$.case_registry_sha256')='$RS_CASES_SHA' AND json_extract(j,'$.corpus_sha256')='$RS_CORPUS_SHA'
      AND json_extract(j,'$.native_mode')='safe' AND json_extract(j,'$.latex_policy')='required'
      AND json_type(j,'$.session_prepared')='true' AND json_type(j,'$.runtime_executed')='false'
      AND json_type(j,'$.independent_review_recorded')='false' AND json_type(j,'$.research_trial_passed')='false'
      AND json_type(j,'$.release_qualified')='false',0) FROM d;" 2>/dev/null) == 1 ]]
}

rr_main() {
  [[ $# == 5 || ( $# == 6 && $6 == --check-only ) ]] || { rs_fail resume_usage; return 1; }
  [[ $1 == --session && $2 == /* && $3 == --sqlite && $4 == /* && $5 == --operator-confirmed-stopped ]] || { rs_fail resume_usage; return 1; }
  local session=$2 sqlite home parent tail repo entry registry trial escaped key recovery before after rc lock process executable path name
  local check=false
  [[ $# == 5 ]] || check=true
  sqlite=$(/usr/bin/readlink -e -- "$4") || return 1
  [[ -f $sqlite && -x $sqlite ]] || return 1
  repo=$(cd -- "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")/.." && /usr/bin/pwd -P) || return 1
  entry=$repo/scripts/mtm016-research-session.sh
  registry=$repo/conformance/mtm016-research-cases.tsv
  home=$(/usr/bin/readlink -e -- "${HOME:-}") || return 1
  parent=$home/.mtm-acceptance/MTM-016/research
  tail=${session#"$parent/"}
  [[ $session == "$parent/"* && $tail =~ ^U21-r1\.[a-zA-Z0-9]{8}$ && $session != *:* && $session != *$'\n'* ]] || { rs_fail resume_scope; return 1; }
  for path in "$home/.mtm-acceptance" "$home/.mtm-acceptance/MTM-016" "$parent" "$session" "$session/home" "$session/tmp" "$session/tool-bin" "$session/workspace" "$session/data" "$session/data/private" "$session/data/debug"; do
    rs_private_dir "$path" || { rs_fail resume_private_layout; return 1; }
  done
  [[ $(/usr/bin/readlink -e -- "$session") == "$session" ]] || { rs_fail resume_canonical_path; return 1; }
  rr_metadata "$session/session.json" "$sqlite" || { rs_fail resume_metadata; return 1; }
  rs_regular "$session/candidate" 268435456 && [[ $(/usr/bin/stat -c %a -- "$session/candidate") == 500 && $(rs_hash "$session/candidate") == "$RS_CANDIDATE_SHA" ]] || { rs_fail resume_candidate; return 1; }
  rs_regular "$session/operator-key.txt" 65 && [[ $(/usr/bin/stat -c %a -- "$session/operator-key.txt") == 600 && $(/usr/bin/stat -c %s -- "$session/operator-key.txt") == 65 ]] || { rs_fail resume_key; return 1; }
  IFS= read -r key < "$session/operator-key.txt" || return 1
  [[ $key =~ ^[0-9a-f]{64}$ ]] || { rs_fail resume_key; return 1; }
  rs_regular "$session/task.md" 32768 && rs_regular "$session/operator.log" 67108864 || { rs_fail resume_original_inputs; return 1; }
  [[ $(rs_hash "$registry") == "$RS_CASES_SHA" && $(rs_hash "$repo/conformance/mtm016-usability-corpus.json") == "$RS_CORPUS_SHA" ]] || { rs_fail resume_case_registry; return 1; }
  rs_args --task U21 --repeat 1
  rs_registry "$registry" U21 1 || return 1
  escaped=${session//\'/\'\'}
  trial=$("$sqlite" -batch -init /dev/null -noheader ':memory:' "SELECT json_extract(CAST(readfile('$escaped/session.json') AS TEXT),'$.trial_id');") || return 1
  [[ $trial =~ ^[0-9a-f]{32}$ ]] || return 1
  for name in latexmk pdflatex; do
    [[ -L $session/tool-bin/$name ]] || { rs_fail resume_compiler_link; return 1; }
    executable=$(/usr/bin/readlink -e -- "$session/tool-bin/$name") || return 1
    [[ $executable == /usr/* && -f $executable && -x $executable ]] || { rs_fail resume_non_system_compiler_unsupported; return 1; }
  done
  # Additional best-effort guard. The operator's stopped-service confirmation
  # remains required; this scan is not a general process/host quiescence proof.
  for process in /proc/[0-9]*/exe; do
    executable=$(/usr/bin/readlink -- "$process" 2>/dev/null) || continue
    [[ $executable != "$session/candidate" ]] || { rs_fail resume_runtime_still_running; return 1; }
  done
  if [[ $check == true ]]; then
    printf 'RESEARCH_RESUME_CHECK metadata_valid=true session_modified=false runtime_started=false\n'
    return 0
  fi
  [[ -t 0 && -t 1 && -t 2 ]] || { rs_fail interactive_terminal_required; return 1; }
  /usr/bin/git -C "$repo" ls-files --error-unmatch -- scripts/mtm016-resume-research-session.sh > /dev/null || return 1
  /usr/bin/git -C "$repo" diff --quiet HEAD -- scripts/mtm016-resume-research-session.sh scripts/mtm016-research-session.sh conformance/mtm016-research-cases.tsv || { rs_fail changed_session_inputs; return 1; }
  lock=$session/research-resume.lock
  [[ ! -L $lock && ( ! -e $lock || ( -f $lock && $(/usr/bin/stat -c %h -- "$lock") == 1 ) ) ]] || { rs_fail resume_lock; return 1; }
  exec 9>> "$lock"
  /usr/bin/flock -n 9 || { rs_fail resume_already_active; return 1; }
  recovery=$(/usr/bin/mktemp -d -- "$session/compiler-recovery.XXXXXXXX") || return 1
  rs_taskcard "$recovery/expected-task.md" "$trial" || return 1
  /usr/bin/cmp -- "$session/task.md" "$recovery/expected-task.md" || { rs_fail resume_task_drift; return 1; }
  if [[ -e $session/workspace/task.md || -L $session/workspace/task.md ]]; then
    rs_regular "$session/workspace/task.md" 32768 && /usr/bin/cmp -- "$session/task.md" "$session/workspace/task.md" || { rs_fail resume_visible_task_conflict; return 1; }
  else
    rs_visible_taskcard "$session" || return 1
  fi
  before=$(/usr/bin/sha256sum -- "$entry" "${BASH_SOURCE[0]}" "$registry" "$session/candidate" "$session/session.json" "$session/operator-key.txt" "$session/operator.log" "$session/task.md" "$session/workspace/task.md") || return 1
  rs_environment "$session" || return 1
  /usr/bin/timeout --signal=TERM --kill-after=3s 20s "${rs_env[@]}" "$session/candidate" attest-native --workspace "$session/workspace" --native-mode safe --latex-policy required > "$recovery/native-preflight.json" 2> "$recovery/native-preflight.stderr" || { rs_fail resume_native_preflight; return 1; }
  printf 'private_recovery=%s\n保留原 run；不新建或改写 owner。task.md 现可在 workspace 中读取。\n' "$recovery"
  printf '本地 OAuth key：cat %q\n' "$session/operator-key.txt"
  printf '{"schema":"mtm-research-session-recovery-v1","trial_id":"%s","state_roots_reused":true,"tool_root_only":true,"workflow_submission_performed":false,"research_trial_passed":false,"release_qualified":false}\n' "$trial" > "$recovery/recovery.json"
  local -a statuses
  set +e
  (cd -- "$session" && exec "${rs_env[@]}" "MTM_OAUTH_PASSWORD=$key" "$session/candidate" tui --quick-tunnel --verbose --host 127.0.0.1 --port 0 --workspace "$session/workspace" --native-mode safe --latex-policy required) 2>&1 | /usr/bin/tee -- "$recovery/operator.log"
  statuses=("${PIPESTATUS[@]}")
  set -e
  key=
  after=$(/usr/bin/sha256sum -- "$entry" "${BASH_SOURCE[0]}" "$registry" "$session/candidate" "$session/session.json" "$session/operator-key.txt" "$session/operator.log" "$session/task.md" "$session/workspace/task.md") || return 1
  [[ $before == "$after" && ${#statuses[@]} == 2 && ${statuses[1]} == 0 ]] || { rs_fail resume_input_or_log_changed; return 1; }
  rc=${statuses[0]}
  printf '{"schema":"mtm-research-recovery-close-v1","trial_id":"%s","runtime_exit_code":%s,"original_inputs_unchanged":true,"research_trial_passed":false,"release_qualified":false}\n' "$trial" "$rc" > "$recovery/close.json"
  /usr/bin/cat -- "$recovery/close.json"
  return "$rc"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  set +x
  set -euo pipefail
  umask 077
  export LC_ALL=C
  entry_root=$(cd -- "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")/.." && /usr/bin/pwd -P)
  source "$entry_root/scripts/mtm016-research-session.sh"
  rr_main "$@"
fi
