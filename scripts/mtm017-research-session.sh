#!/usr/bin/env bash
# Fresh MTM-017 U21-U24 research sessions for the exact preview.2 candidate.
# No production selector/state import, release authority, or corpus acceptance.

readonly R17_CANDIDATE_SHA=13d7890c5c763199ed39295e134ff6cc735ceaa04eaddf6c556431a7a56254f4
readonly R17_CANDIDATE_SOURCE=7b4afe2359e688263557f62154e4bc1e640c12c0
readonly R17_CORPUS_SHA=9227aa6e199887860d88091467aa53fe45eee55cd337eac0587059f8ec434861
readonly R17_CASES_SHA=cd6d6a758e667fca21d2a04d2eba9a015c1d156350b34438660dd8bd16ae1bb9

r17_fail() { printf 'MTM017_RESEARCH_ERROR reason=%s\n' "$1" >&2; return 1; }
r17_hash() { local value; value=$(/usr/bin/sha256sum -- "$1") || return 1; printf '%s' "${value%% *}"; }

r17_regular() {
  local file=$1 bound=$2 size mode
  [[ -f $file && ! -L $file ]] || return 1
  [[ $(/usr/bin/stat -c %h -- "$file") == 1 ]] || return 1
  mode=$(/usr/bin/stat -c %a -- "$file") || return 1
  [[ $mode =~ ^[0-7]{1,4}$ ]] || return 1
  size=$(/usr/bin/stat -c %s -- "$file") || return 1
  [[ $size =~ ^[0-9]+$ ]] && ((size > 0 && size <= bound))
}

r17_private_dir() {
  [[ -d $1 && ! -L $1 ]] &&
    [[ $(/usr/bin/stat -c %u -- "$1") == "$(/usr/bin/id -u)" ]] &&
    [[ $(/usr/bin/stat -c %a -- "$1") == 700 ]]
}

r17_tool() {
  local name=$1 path=$2 part resolved
  local -a parts=()
  IFS=: read -r -a parts <<< "$path"
  for part in "${parts[@]}"; do
    [[ $part == /* && -f $part/$name && -x $part/$name ]] || continue
    resolved=$(/usr/bin/readlink -e -- "$part/$name") || return 1
    [[ $resolved == /* && -f $resolved && ! -L $resolved && -x $resolved ]] || return 1
    printf '%s' "$resolved"
    return 0
  done
  return 1
}

r17_init() {
  r17_script=$(/usr/bin/readlink -e -- "${BASH_SOURCE[0]}") || return 1
  r17_repo=$(/usr/bin/readlink -e -- "${r17_script%/*}/..") || return 1
  r17_registry=$r17_repo/conformance/mtm016-research-cases.tsv
  r17_corpus=$r17_repo/conformance/mtm016-usability-corpus.json
  r17_candidate=$r17_repo/target/mtm017-preview2/mtm-0.6.0-preview.2-$R17_CANDIDATE_SHA/mtm
  r17_base=$HOME/.mtm-acceptance/MTM-017/research
  [[ $r17_repo != *:* && $r17_repo != *$'\n'* && $r17_repo != *$'\t'* ]] || return 1
}

r17_select_case() {
  local task=$1 repeat=$2 line id rep case_id mode problem requirement count=0
  [[ $task =~ ^U2[1-4]$ && $repeat =~ ^[1-3]$ ]] || return 1
  line=$(/usr/bin/awk -F '\t' -v task="$task" -v repeat="$repeat" '
    $1 == task && $2 == repeat { print; found += 1 }
    END { if (found != 1) exit 1 }
  ' "$r17_registry") || return 1
  IFS=$'\t' read -r id rep case_id mode problem requirement <<< "$line"
  [[ $id == "$task" && $rep == "$repeat" ]] || return 1
  [[ $case_id == "${task,,}-r$repeat-"* ]] || return 1
  if [[ $task == U21 || $task == U23 ]]; then
    [[ $mode == compact ]] || return 1
  else
    [[ $mode == full ]] || return 1
  fi
  [[ -n $problem && -n $requirement ]] || return 1
  r17_task=$task
  r17_repeat=$repeat
  r17_case=$case_id
  r17_mode=$mode
  r17_problem=$problem
  r17_requirement=$requirement
}

r17_session() {
  local supplied=$1 canonical leaf task repeat
  canonical=$(/usr/bin/readlink -e -- "$supplied") || return 1
  [[ $canonical == "$supplied" && ${canonical%/*} == "$r17_base" ]] || return 1
  leaf=${canonical##*/}
  [[ $leaf =~ ^(U2[1-4])-r([1-3])\.[A-Za-z0-9]{8}$ ]] || return 1
  task=${BASH_REMATCH[1]}
  repeat=${BASH_REMATCH[2]}
  r17_select_case "$task" "$repeat" || return 1
  r17_session_root=$canonical
  for directory in home tmp tool-bin workspace workspace/research-evidence workspace/research-evidence-input data data/private data/debug control logs; do
    r17_private_dir "$canonical/$directory" || return 1
  done
}

r17_environment() {
  local session=$1
  r17_env=(/usr/bin/env -i
    "HOME=$session/home" "PATH=$session/tool-bin" LC_ALL=C LANG=C.UTF-8
    "TMPDIR=$session/tmp" "XDG_CACHE_HOME=$session/home/.cache"
    "MTM_WORKSPACE=$session/workspace" "MTM_DATA_ROOT=$session/data"
    "MTM_PRIVATE_ROOT=$session/data/private" "MTM_DEBUG_ROOT=$session/data/debug"
    MTM_DEBUG=1 MTM_TRACE_PAYLOADS=0 MTM_NATIVE_EXEC_BACKEND=bubblewrap
    "MTM_NATIVE_EXEC_ALLOW_ROOTS=$session/tool-bin"
    MTM_NATIVE_MODE=dangerous MTM_LATEX_POLICY=required MTM_WORKFLOW_PROTOCOL_VERSION=3
    TOKIO_WORKER_THREADS=2)
}

r17_taskcard() {
  local destination=$1 trial=$2 creation_key
  creation_key="mtm017-$trial-$r17_case"
  [[ $creation_key =~ ^[A-Za-z0-9_-]{16,128}$ ]] || return 1
  (
    set -o noclobber
    exec > "$destination" || exit 1
    printf '# MTM-017 %s repeat %s\n\n' "$r17_task" "$r17_repeat"
    printf '试次编号：%s。本文件是任务输入，不是通过证据。\n\n' "$trial"
    printf '## 生成会话\n\n'
    printf '只使用本次 fresh mtm-research-session-v2 连接，新建 %s workflow。problem_id 必须使用 %s，register_result=false，creation_key 必须逐字使用 %s。\n\n' "$r17_mode" "$r17_case" "$creation_key"
    printf '%s\n\n专项要求：%s\n\n' "$r17_problem" "$r17_requirement"
    printf '%s\n\n' '本轮使用 preview.2 dangerous Native。dangerous 只授予 Native 执行，不授予 workflow、verifier 或 finalizer 权限；不得复用 MTM-016 safe session、旧 run 或旧 capability。最终证明必须通过 required LaTeX。'
    printf '%s\n\n' 'rethlas_start 成功后立即在 workspace 根写 run-handoff.json：schema=mtm-research-run-handoff-v1，仅包含 trial_id、task_id、repeat、case_id、workflow_mode、problem_id、run_id、non_authorizing=true；不得包含 creation_key、OAuth client id/key/token、capability、URL 或原始日志。'
    printf '%s\n\n' '生成阶段到 verify 后停止并保持同一 TUI/Quick Tunnel 和同一已注册 OAuth connector。独立 reviewer 必须在新的聊天会话中复用同一 connector，核对 owner continuity、实际 proof、manifest 和 route evidence，再按 fresh verifier task 提交。'
    case $r17_task in
      U21)
        printf '## U21 route material\n\n'
        printf '%s\n\n' '这是 compact compiled-proof route。除最终 review.json 外没有额外 route input；不要制造 retrieval、repair、branch 或 CAS 文件。'
        ;;
      U22)
        printf '## U22 retrieval route material\n\n'
        printf '%s\n\n' '必须实际使用 rethlas_retrieve，proof_manifest.reference_ids 非空，并逐项检查 original 或 authoritative source；所有 material reference 的 reference_audit 必须达到 SOURCE_VERIFIED。'
        printf '%s\n\n' '在 workspace/research-evidence/retrieval.json 写 mtm-research-retrieval-observation-v1：run_id、calls[]；每个 call 只能包含 method=rethlas_retrieve、reference_ids[]、result_sha256、external_network_observed=true；顶层 raw_credentials_recorded=false、raw_response_bodies_recorded=false。'
        printf '%s\n\n' '在 workspace/research-evidence/sources.json 写 mtm-research-source-observation-v1：run_id、sources[]；每项包含 reference_id、source_kind=original|authoritative、locator_sha256、content_sha256、original_or_authoritative_source_inspected=true。不要复制原始网页正文或凭据。'
        ;;
      U23)
        printf '## U23 seeded repair route material\n\n'
        printf '%s\n\n' '必须是明确的 seeded repair challenge：首稿故意保留一个实质数学缺口，首次 verifier 必须具体指出 gap，然后进入 repair、重新 required-LaTeX 编译并重新 verify；不得把 seeded gap 说成自然产品错误。'
        printf '%s\n\n' '保留 workspace/research-evidence/seeded_draft.tex 为第一次提交给 verifier 的精确 proof bytes。first_findings.json 必须是首次 verifier findings 的完整 JSON，至少含 verification_report.summary、非空 gaps 或 critical_errors，以及非空 repair_hints。'
        printf '%s\n\n' '最终完成后写 repair_history.json：seeded_challenge=true、run_id、initial_draft_sha256、first_findings_sha256、final_sha256；三项 SHA 必须分别绑定 seeded_draft.tex、first_findings.json 与最终 verified TeX。'
        ;;
      U24)
        printf '## U24 branch/join route material\n\n'
        printf '%s\n\n' '必须真正产生至少两个 branch，branch/domain/session marker 互异；每个 branch 在 join 前 sealed，并实际观察 sibling private read denied；join 必须考虑恰好全部 sealed branches。'
        printf '%s\n\n' '最终写 workspace/research-evidence/branches.json，schema=mtm-research-branch-observation-v1，含 run_id、branches[] 和 join。每个 branch 只包含 branch_id、domain_id、session_marker、order_index、status=sealed、result_sha256、sibling_private_read_denied=true；join 只包含 all_required_sealed_before_join=true、considered_branch_ids[]、result_sha256。'
        ;;
    esac
    printf '## 独立复核与 collector\n\n'
    printf '%s\n\n' 'reviewer 完成后在 workspace/research-evidence/review.json 留下 substantive statement checks。不要猜 collector 需要的 raw verification-report SHA；主控会话会从私有状态取得原始 verification.json SHA，并机械规范化到 closed review schema。'
    printf '%s\n' '宿主 seal-material 只会把当前 task 的固定 allowlist 原字节复制到 workspace/research-evidence-input/。启动成功、correct 字符串或 session 退出都不是 trial acceptance；collector/precheck 不增加 corpus 计数。'
  )
}

r17_manifest() {
  local destination=$1 trial=$2 launcher_commit=$3 launcher_hash=$4
  (
    set -o noclobber
    printf '{"schema":"mtm-research-session-v2","milestone":"MTM-017","task_id":"%s","repeat":%s,"case_id":"%s","workflow_mode":"%s","trial_id":"%s","candidate_sha256":"%s","candidate_source_commit":"%s","launcher_source_commit":"%s","launcher_sha256":"%s","case_registry_sha256":"%s","corpus_sha256":"%s","native_mode":"dangerous","latex_policy":"required","session_prepared":true,"runtime_executed":false,"independent_review_recorded":false,"research_trial_passed":false,"release_qualified":false}\n' "$r17_task" "$r17_repeat" "$r17_case" "$r17_mode" "$trial" "$R17_CANDIDATE_SHA" "$R17_CANDIDATE_SOURCE" "$launcher_commit" "$launcher_hash" "$R17_CASES_SHA" "$R17_CORPUS_SHA" > "$destination"
  )
}

r17_validate_manifest() {
  local session=$1 launcher_hash
  launcher_hash=$(r17_hash "$r17_script") || return 1
  /usr/bin/python3 - "$session/session.json" "$r17_task" "$r17_repeat" "$r17_case" "$r17_mode" "$launcher_hash" <<'PY'
import json, re, sys
path, task, repeat, case_id, mode, launcher_hash = sys.argv[1:]
with open(path, "r", encoding="utf-8") as handle:
    value = json.load(handle)
keys = {
    "schema","milestone","task_id","repeat","case_id","workflow_mode","trial_id",
    "candidate_sha256","candidate_source_commit","launcher_source_commit","launcher_sha256",
    "case_registry_sha256","corpus_sha256","native_mode","latex_policy","session_prepared",
    "runtime_executed","independent_review_recorded","research_trial_passed","release_qualified",
}
assert set(value) == keys
assert value["schema"] == "mtm-research-session-v2"
assert value["milestone"] == "MTM-017"
assert value["task_id"] == task
assert value["repeat"] == int(repeat)
assert value["case_id"] == case_id
assert value["workflow_mode"] == mode
assert re.fullmatch(r"[0-9a-f]{32}", value["trial_id"])
assert value["candidate_sha256"] == "13d7890c5c763199ed39295e134ff6cc735ceaa04eaddf6c556431a7a56254f4"
assert value["candidate_source_commit"] == "7b4afe2359e688263557f62154e4bc1e640c12c0"
assert re.fullmatch(r"[0-9a-f]{40}", value["launcher_source_commit"])
assert value["launcher_sha256"] == launcher_hash
assert value["case_registry_sha256"] == "cd6d6a758e667fca21d2a04d2eba9a015c1d156350b34438660dd8bd16ae1bb9"
assert value["corpus_sha256"] == "9227aa6e199887860d88091467aa53fe45eee55cd337eac0587059f8ec434861"
assert value["native_mode"] == "dangerous"
assert value["latex_policy"] == "required"
assert value["session_prepared"] is True
for key in ("runtime_executed","independent_review_recorded","research_trial_passed","release_qualified"):
    assert value[key] is False
PY
}

r17_check() {
  local session=$1 key info
  r17_session "$session" || { r17_fail session_path_or_permissions; return 1; }
  for file in candidate session.json task.md inputs.sha256 operator-key.txt control/session.lock; do
    r17_regular "$session/$file" 268435456 || { r17_fail session_file; return 1; }
  done
  [[ $(/usr/bin/stat -c %a -- "$session/operator-key.txt") == 600 ]] || { r17_fail key_permissions; return 1; }
  IFS= read -r key < "$session/operator-key.txt" || return 1
  [[ $key =~ ^[0-9a-f]{64}$ ]] || { r17_fail key_shape; return 1; }
  key=
  [[ $(r17_hash "$r17_candidate") == "$R17_CANDIDATE_SHA" ]] || { r17_fail repository_candidate_identity; return 1; }
  [[ $(r17_hash "$session/candidate") == "$R17_CANDIDATE_SHA" ]] || { r17_fail session_candidate_identity; return 1; }
  [[ $(r17_hash "$r17_registry") == "$R17_CASES_SHA" ]] || { r17_fail case_registry_identity; return 1; }
  [[ $(r17_hash "$r17_corpus") == "$R17_CORPUS_SHA" ]] || { r17_fail corpus_identity; return 1; }
  /usr/bin/sha256sum --check --status -- "$session/inputs.sha256" || { r17_fail prepared_input_drift; return 1; }
  r17_validate_manifest "$session" || { r17_fail session_manifest; return 1; }
  info=$(/usr/bin/env -i "$session/candidate" release-info) || return 1
  [[ $info == *'"version":"0.6.0-preview.2"'* && $info == *'"state_schema_version":8'* && $info == *'"tool_contract_version":"mtm-tools-v10"'* ]] || { r17_fail release_identity; return 1; }
  r17_environment "$session"
}

r17_prepare() {
  local task=$1 repeat=$2 session trial password launcher_commit launcher_hash resolved name marker tracked
  local -a names tools
  r17_select_case "$task" "$repeat" || { r17_fail task_or_repeat; return 1; }
  [[ $(/usr/bin/git -C "$r17_repo" rev-parse --show-toplevel) == "$r17_repo" ]] || { r17_fail repository_identity; return 1; }
  marker=$(printf ' %s ' '+')
  ! /usr/bin/grep -qF "$marker" "$r17_script" || { r17_fail launcher_patch_marker; return 1; }
  for tracked in scripts/mtm017-research-session.sh conformance/mtm016-research-cases.tsv conformance/mtm016-usability-corpus.json; do
    /usr/bin/git -C "$r17_repo" ls-files --error-unmatch -- "$tracked" > /dev/null 2>&1 || { r17_fail untracked_inputs; return 1; }
  done
  /usr/bin/git -C "$r17_repo" diff --quiet HEAD -- scripts/mtm017-research-session.sh conformance/mtm016-research-cases.tsv conformance/mtm016-usability-corpus.json || { r17_fail changed_session_inputs; return 1; }
  launcher_commit=$(/usr/bin/git -C "$r17_repo" rev-parse HEAD) || return 1
  [[ $launcher_commit =~ ^[0-9a-f]{40}$ ]] || return 1
  launcher_hash=$(r17_hash "$r17_script") || return 1
  [[ $(r17_hash "$r17_registry") == "$R17_CASES_SHA" ]] || { r17_fail case_registry_identity; return 1; }
  [[ $(r17_hash "$r17_corpus") == "$R17_CORPUS_SHA" ]] || { r17_fail corpus_identity; return 1; }
  r17_regular "$r17_candidate" 268435456 && [[ -x $r17_candidate && $(r17_hash "$r17_candidate") == "$R17_CANDIDATE_SHA" ]] || { r17_fail candidate_identity; return 1; }

  names=(bwrap curl git bash sh cat printf sleep readlink dirname uname script latexmk pdflatex cloudflared python3 ls find grep sed awk head tail wc sort uniq cut tr env mkdir cp mv rm touch stat timeout sha256sum)
  tools=()
  for name in "${names[@]}"; do
    resolved=$(r17_tool "$name" "${PATH:-}") || { printf 'Missing required tool: %s\n' "$name" >&2; return 1; }
    tools+=("$resolved")
  done

  for parent in "$HOME/.mtm-acceptance" "$HOME/.mtm-acceptance/MTM-017" "$r17_base"; do
    if [[ ! -e $parent && ! -L $parent ]]; then /usr/bin/mkdir -m 700 -- "$parent" || return 1; fi
    r17_private_dir "$parent" || { r17_fail parent_not_private; return 1; }
  done
  session=$(/usr/bin/mktemp -d -- "$r17_base/$task-r$repeat.XXXXXXXX") || return 1
  /usr/bin/mkdir -m 700 -- "$session/home" "$session/tmp" "$session/tool-bin" "$session/workspace" "$session/workspace/research-evidence" "$session/workspace/research-evidence-input" "$session/data" "$session/data/private" "$session/data/debug" "$session/control" "$session/logs" || return 1
  for ((i=0; i<${#names[@]}; i++)); do
    /usr/bin/ln -s -- "${tools[$i]}" "$session/tool-bin/${names[$i]}" || return 1
  done
  (umask 077; set -o noclobber; /usr/bin/cat -- "$r17_candidate" > "$session/candidate") || return 1
  /usr/bin/chmod 500 -- "$session/candidate" || return 1

  trial=$(/usr/bin/od -An -N16 -tx1 /dev/urandom | /usr/bin/tr -d ' \n')
  password=$(/usr/bin/od -An -N32 -tx1 /dev/urandom | /usr/bin/tr -d ' \n')
  [[ $trial =~ ^[0-9a-f]{32}$ && $password =~ ^[0-9a-f]{64}$ ]] || { r17_fail randomness; return 1; }
  r17_taskcard "$session/task.md" "$trial" || { r17_fail task_card; return 1; }
  r17_manifest "$session/session.json" "$trial" "$launcher_commit" "$launcher_hash" || { r17_fail session_manifest; return 1; }
  (set -o noclobber; printf '%s\n' "$password" > "$session/operator-key.txt"; printf 'session lock\n' > "$session/control/session.lock") || return 1
  password=
  (umask 077; set -o noclobber; /usr/bin/cat -- "$session/task.md" > "$session/workspace/task.md") || return 1
  (set -o noclobber; /usr/bin/sha256sum -- "$r17_script" "$r17_registry" "$r17_corpus" "$session/candidate" "$session/session.json" "$session/task.md" "$session/workspace/task.md" > "$session/inputs.sha256") || return 1
  r17_check "$session" || return 1
  /usr/bin/timeout --signal=TERM --kill-after=3s 45s "${r17_env[@]}" "$session/candidate" attest-native --workspace "$session/workspace" --native-mode dangerous --latex-policy required > "$session/control/native-preflight.json" 2> "$session/control/native-preflight.stderr" || { r17_fail native_preflight_failed; return 1; }
  /usr/bin/grep -q '"hard_isolation":true' "$session/control/native-preflight.json" || { r17_fail native_attestation_missing; return 1; }
  printf 'SESSION_ROOT=%s\n' "$session"
  printf 'Prepared MTM-017 %s-r%s preview.2 research session. No research acceptance is claimed.\n' "$task" "$repeat"
  printf 'Start:  bash %q up %q\n' "$r17_script" "$session"
  printf 'Console: bash %q attach %q\n' "$r17_script" "$session"
  printf 'Local OAuth key: cat %q\n' "$session/operator-key.txt"
  printf 'Task card: cat %q\n' "$session/task.md"
}

r17_material_file() {
  local file=$1 size mode
  [[ -f $file && ! -L $file && $(/usr/bin/stat -c %h -- "$file") == 1 ]] || return 1
  [[ $(/usr/bin/stat -c %u -- "$file") == "$(/usr/bin/id -u)" ]] || return 1
  size=$(/usr/bin/stat -c %s -- "$file") || return 1
  ((size > 0 && size <= 1048576)) || return 1
  mode=$(/usr/bin/stat -c %a -- "$file") || return 1
  (( (8#$mode & 0022) == 0 )) || return 1
  /usr/bin/python3 - "$file" <<'PY'
import pathlib, sys
data = pathlib.Path(sys.argv[1]).read_bytes()
assert b"\0" not in data
data.decode("utf-8")
PY
}

r17_allowed() {
  local task=$1 name=$2
  case $task:$name in
    U21:review.json) return 0 ;;
    U22:review.json|U22:retrieval.json|U22:sources.json) return 0 ;;
    U23:review.json|U23:seeded_draft.tex|U23:first_findings.json|U23:repair_history.json) return 0 ;;
    U24:review.json|U24:branches.json) return 0 ;;
    *) return 1 ;;
  esac
}

r17_seal_material() {
  local session=$1 source destination_root item name destination source_hash count=0
  r17_check "$session" || return 1
  source=$session/workspace/research-evidence
  destination_root=$session/workspace/research-evidence-input
  r17_private_dir "$source" || { r17_fail evidence_source_permissions; return 1; }
  r17_private_dir "$destination_root" || { r17_fail evidence_input_permissions; return 1; }
  shopt -s nullglob dotglob
  for item in "$source"/*; do
    [[ -f $item && ! -L $item ]] || { r17_fail unknown_evidence_entry; return 1; }
    name=${item##*/}
    r17_allowed "$r17_task" "$name" || { r17_fail unknown_evidence_file; return 1; }
    r17_material_file "$item" || { r17_fail invalid_evidence_file; return 1; }
    destination=$destination_root/$name
    source_hash=$(r17_hash "$item") || return 1
    if [[ -e $destination || -L $destination ]]; then
      r17_regular "$destination" 1048576 || { r17_fail existing_evidence_invalid; return 1; }
      [[ $(/usr/bin/stat -c %a -- "$destination") == 600 && $(r17_hash "$destination") == "$source_hash" ]] || { r17_fail evidence_conflict; return 1; }
    else
      (umask 077; set -o noclobber; /usr/bin/cat -- "$item" > "$destination") || return 1
      /usr/bin/chmod 600 -- "$destination" || return 1
      [[ $(r17_hash "$destination") == "$source_hash" ]] || { r17_fail evidence_copy_mismatch; return 1; }
    fi
    ((count+=1))
  done
  ((count > 0)) || { r17_fail no_evidence_material; return 1; }
  printf 'sealed_material_files=%s task=%s source=workspace/research-evidence destination=workspace/research-evidence-input\n' "$count" "$r17_task"
}

r17_start() (
  local session=$1 log rc
  [[ -t 0 && -t 1 && -t 2 ]] || { r17_fail interactive_terminal_required; exit 1; }
  r17_check "$session" || exit 1
  exec 9< "$session/control/session.lock"
  /usr/bin/flock -n 9 || { r17_fail session_already_running; exit 1; }
  log=$(/usr/bin/mktemp -- "$session/logs/console.XXXXXXXX.log") || exit 1
  printf 'MTM-017 %s research session; workspace=%s\n' "$r17_task" "$session/workspace"
  printf 'Keep this same OAuth connector across generation and independent review.\n'
  printf 'Private console log: %s\n' "$log"
  set +e
  "${r17_env[@]}" /usr/bin/bash --noprofile --norc -c '
    set -euo pipefail
    IFS= read -r MTM_OAUTH_PASSWORD < "$1/operator-key.txt"
    export MTM_OAUTH_PASSWORD
    cd -- "$1"
    exec "$1/candidate" tui --quick-tunnel --verbose --host 127.0.0.1 --port 0 --workspace "$1/workspace" --native-mode dangerous --latex-policy required
  ' mtm-research "$session" 2>&1 | /usr/bin/tee -- "$log"
  rc=${PIPESTATUS[0]}
  printf 'MTM-017 research session stopped (exit=%s). Private state and evidence retained.\n' "$rc"
  exit "$rc"
)

r17_main() {
  [[ $# -ge 1 ]] || { r17_fail usage; return 1; }
  r17_init || return 1
  case $1 in
    prepare)
      [[ $# == 3 ]] || { r17_fail usage_prepare_task_repeat; return 1; }
      r17_prepare "$2" "$3"
      ;;
    check|up|attach|stop|seal-material)
      [[ $# == 2 && $2 == /* ]] || { r17_fail usage_session; return 1; }
      r17_session "$2" || { r17_fail session_path_or_permissions; return 1; }
      local socket=$2/control/tmux.sock
      case $1 in
        check)
          r17_check "$2" || return 1
          printf 'configuration_verified=true milestone=MTM-017 task=%s repeat=%s version=0.6.0-preview.2 schema=mtm-research-session-v2 native_mode=dangerous release_qualified=false\n' "$r17_task" "$r17_repeat"
          ;;
        seal-material)
          r17_seal_material "$2"
          ;;
        up)
          r17_check "$2" || return 1
          if /usr/bin/tmux -S "$socket" has-session -t mtm-research 2>/dev/null; then
            printf 'Already running; retaining the current OAuth client and tunnel.\n'
          else
            /usr/bin/tmux -S "$socket" new-session -d -s mtm-research -x 140 -y 45 /usr/bin/bash "$r17_script" start-internal "$2" || return 1
            printf 'Started fresh MTM-017 research console. Attach to read its HTTPS MCP URL.\n'
          fi
          ;;
        attach)
          r17_check "$2" || return 1
          exec /usr/bin/tmux -S "$socket" attach-session -t mtm-research
          ;;
        stop)
          r17_check "$2" || return 1
          /usr/bin/tmux -S "$socket" has-session -t mtm-research 2>/dev/null || { printf 'Already stopped; state retained.\n'; return 0; }
          /usr/bin/tmux -S "$socket" send-keys -t mtm-research C-c || return 1
          for ((i=0; i<100; i++)); do
            /usr/bin/tmux -S "$socket" has-session -t mtm-research 2>/dev/null || { printf 'Stopped; state and evidence retained.\n'; return 0; }
            /usr/bin/sleep 0.1
          done
          r17_fail graceful_stop_not_confirmed
          ;;
      esac
      ;;
    start-internal)
      [[ $# == 2 && $2 == /* ]] || { r17_fail usage_internal; return 1; }
      r17_session "$2" || return 1
      r17_start "$2"
      ;;
    *)
      r17_fail usage
      return 1
      ;;
  esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  set +x
  set -euo pipefail
  umask 077
  export LC_ALL=C
  r17_main "$@"
fi
