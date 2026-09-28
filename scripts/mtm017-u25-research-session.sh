#!/usr/bin/env bash
# Fresh MTM-017 U25 research sessions for the exact qualified preview.2 binary.
# No production selector/state import, release authority, or automatic acceptance.

readonly U25_CANDIDATE_SHA=13d7890c5c763199ed39295e134ff6cc735ceaa04eaddf6c556431a7a56254f4
readonly U25_CANDIDATE_SOURCE=7b4afe2359e688263557f62154e4bc1e640c12c0
readonly U25_CORPUS_SHA=9227aa6e199887860d88091467aa53fe45eee55cd337eac0587059f8ec434861
readonly U25_CASES_SHA=cd6d6a758e667fca21d2a04d2eba9a015c1d156350b34438660dd8bd16ae1bb9

u25_fail() { printf 'MTM017_U25_ERROR reason=%s\n' "$1" >&2; return 1; }
u25_hash() { local value; value=$(/usr/bin/sha256sum -- "$1") || return 1; printf '%s' "${value%% *}"; }

u25_regular() {
  local file=$1 bound=$2 size mode
  [[ -f $file && ! -L $file ]] || return 1
  [[ $(/usr/bin/stat -c %h -- "$file") == 1 ]] || return 1
  mode=$(/usr/bin/stat -c %a -- "$file") || return 1
  [[ $mode =~ ^[0-7]{1,4}$ ]] || return 1
  size=$(/usr/bin/stat -c %s -- "$file") || return 1
  [[ $size =~ ^[0-9]+$ ]] && ((size > 0 && size <= bound))
}

u25_private_dir() {
  [[ -d $1 && ! -L $1 ]] &&
    [[ $(/usr/bin/stat -c %u -- "$1") == "$(/usr/bin/id -u)" ]] &&
    [[ $(/usr/bin/stat -c %a -- "$1") == 700 ]]
}

u25_tool() {
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

u25_tool_root() {
  local executable=$1 directory leaf root
  executable=$(/usr/bin/readlink -e -- "$executable") || return 1
  directory=${executable%/*}
  [[ -n $directory ]] || directory=/
  leaf=${directory##*/}
  case $leaf in
    bin|sbin|executables)
      root=${directory%/*}
      [[ -n $root ]] || root=/
      ;;
    *) root=$directory ;;
  esac
  /usr/bin/readlink -e -- "$root"
}

u25_init() {
  u25_script=$(/usr/bin/readlink -e -- "${BASH_SOURCE[0]}") || return 1
  u25_repo=$(/usr/bin/readlink -e -- "${u25_script%/*}/..") || return 1
  u25_registry=$u25_repo/conformance/mtm016-research-cases.tsv
  u25_corpus=$u25_repo/conformance/mtm016-usability-corpus.json
  u25_candidate=$u25_repo/target/mtm017-preview2/mtm-0.6.0-preview.2-$U25_CANDIDATE_SHA/mtm
  u25_base=$HOME/.mtm-acceptance/MTM-017/research
  [[ $u25_repo != *:* && $u25_repo != *$'\n'* && $u25_repo != *$'\t'* ]] || return 1
}

u25_repeat_case() {
  case $1 in
    1) u25_case=u25-r1-rank-nullity ;;
    2) u25_case=u25-r2-finite-field-roots ;;
    3) u25_case=u25-r3-polynomial-gcd ;;
    *) return 1 ;;
  esac
  u25_repeat=$1
}

u25_session() {
  local supplied=$1 canonical leaf repeat
  canonical=$(/usr/bin/readlink -e -- "$supplied") || return 1
  [[ $canonical == "$supplied" && ${canonical%/*} == "$u25_base" ]] || return 1
  leaf=${canonical##*/}
  [[ $leaf =~ ^U25-r([1-3])\.[A-Za-z0-9]{8}$ ]] || return 1
  repeat=${BASH_REMATCH[1]}
  u25_repeat_case "$repeat" || return 1
  u25_session_root=$canonical
  for directory in home tmp tool-bin workspace workspace/research-evidence workspace/research-evidence-input data data/private data/debug control logs; do
    u25_private_dir "$canonical/$directory" || return 1
  done
}

u25_environment() {
  local session=$1 sage magma sage_root magma_root
  sage=$(/usr/bin/readlink -e -- "$session/tool-bin/sage") || return 1
  magma=$(/usr/bin/readlink -e -- "$session/tool-bin/magma") || return 1
  sage_root=$(u25_tool_root "$sage") || return 1
  magma_root=$(u25_tool_root "$magma") || return 1
  u25_env=(/usr/bin/env -i
    "HOME=$session/home" "PATH=$session/tool-bin" LC_ALL=C LANG=C.UTF-8
    "TMPDIR=$session/tmp" "XDG_CACHE_HOME=$session/home/.cache"
    "MTM_WORKSPACE=$session/workspace" "MTM_DATA_ROOT=$session/data"
    "MTM_PRIVATE_ROOT=$session/data/private" "MTM_DEBUG_ROOT=$session/data/debug"
    MTM_DEBUG=1 MTM_TRACE_PAYLOADS=0 MTM_NATIVE_EXEC_BACKEND=bubblewrap
    "MTM_NATIVE_EXEC_ALLOW_ROOTS=$session/tool-bin:$sage_root:$magma_root"
    MTM_NATIVE_MODE=dangerous MTM_LATEX_POLICY=required MTM_WORKFLOW_PROTOCOL_VERSION=3
    TOKIO_WORKER_THREADS=2)
}

u25_taskcard() {
  local destination=$1 trial=$2 line task repeat case_id mode problem requirement creation_key
  line=$(/usr/bin/awk -F '\t' -v repeat="$u25_repeat" '
    $1 == "U25" && $2 == repeat { print; found += 1 }
    END { if (found != 1) exit 1 }
  ' "$u25_registry") || return 1
  IFS=$'\t' read -r task repeat case_id mode problem requirement <<< "$line"
  [[ $task == U25 && $repeat == "$u25_repeat" && $case_id == "$u25_case" && $mode == full ]] || return 1
  creation_key="mtm017-$trial-$case_id"
  [[ $creation_key =~ ^[A-Za-z0-9_-]{16,128}$ ]] || return 1
  (
    set -o noclobber
    exec > "$destination" || exit 1
    printf '# MTM-017 U25 repeat %s\n\n' "$repeat"
    printf '试次编号：%s。本文件是任务输入，不是通过证据。\n\n' "$trial"
    printf '## 生成与 CAS 会话\n\n'
    printf '只使用本次 fresh mtm-research-session-v2 连接，新建 full workflow。problem_id 必须使用 %s，register_result=false，creation_key 必须逐字使用 %s。\n\n' "$case_id" "$creation_key"
    printf '%s\n\n专项要求：%s\n\n' "$problem" "$requirement"
    printf '%s\n\n' '一般 rank-nullity 证明必须独立于有限 CAS 检查。实际 Sage 与 Magma 各执行一次，输入先写入 workspace/research-evidence/sage_input.txt 与 magma_input.txt；把各自实际 stdout 原样保存为 sage_output.txt 与 magma_output.txt。记录实际版本、退出码和输入输出 SHA-256，并写 mtm-research-cas-observation-v2 的 cas_observation.json。不要把 exploratory web-session 计算或 MTM-016 历史结果复制为本轮证据。'
    printf '%s\n\n' 'proof_manifest 的 computational_evidence 至少保留两条，分别说明 Sage 与 Magma 的有限参数检查；它们不是一般定理的证明。所有 Native 命令使用当前 dangerous 模式；dangerous 不授予 workflow/verifier/finalizer authority。'
    printf '%s\n\n' 'rethlas_start 成功后，在 workspace 根写 run-handoff.json：schema=mtm-research-run-handoff-v1，并只包含 trial_id、task_id、repeat、case_id、workflow_mode、problem_id、run_id、non_authorizing=true；不得包含 creation_key、OAuth client id/key/token、capability 或 URL。'
    printf '## 独立复核\n\n'
    printf '%s\n\n' '生成阶段到 verify 后停止，但保持同一 TUI/Quick Tunnel 与同一已注册 OAuth connector。独立复核会话必须核对当前 owner continuity、实际 proof、manifest 和 CAS evidence 后再提交 verifier report；不得用生成会话预制 correct。'
    printf '## 私有证据文件\n\n'
    printf '%s\n' '只在 workspace/research-evidence/ 下创建以下固定文件：sage_input.txt、sage_output.txt、magma_input.txt、magma_output.txt、cas_observation.json；独立复核完成后另写 review.json。宿主 launcher 的 seal-material 子命令只会把这些 allowlisted 文件原字节复制到 workspace/research-evidence-input/，供 collector 读取。'
  )
}

u25_manifest() {
  local destination=$1 trial=$2 launcher_commit=$3 launcher_hash=$4
  (
    set -o noclobber
    printf '{"schema":"mtm-research-session-v2","milestone":"MTM-017","task_id":"U25","repeat":%s,"case_id":"%s","workflow_mode":"full","trial_id":"%s","candidate_sha256":"%s","candidate_source_commit":"%s","launcher_source_commit":"%s","launcher_sha256":"%s","case_registry_sha256":"%s","corpus_sha256":"%s","native_mode":"dangerous","latex_policy":"required","session_prepared":true,"runtime_executed":false,"independent_review_recorded":false,"research_trial_passed":false,"release_qualified":false}\n' \
      "$u25_repeat" "$u25_case" "$trial" "$U25_CANDIDATE_SHA" "$U25_CANDIDATE_SOURCE" \
      "$launcher_commit" "$launcher_hash" "$U25_CASES_SHA" "$U25_CORPUS_SHA" > "$destination"
  )
}

u25_validate_manifest() {
  local session=$1 launcher_hash
  launcher_hash=$(u25_hash "$u25_script") || return 1
  /usr/bin/python3 - "$session/session.json" "$u25_repeat" "$u25_case" "$launcher_hash" <<'PY'
import json, re, sys
path, repeat, case_id, launcher_hash = sys.argv[1:]
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
assert value["task_id"] == "U25"
assert value["repeat"] == int(repeat)
assert value["case_id"] == case_id
assert value["workflow_mode"] == "full"
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

u25_check() {
  local session=$1 key info
  u25_session "$session" || { u25_fail session_path_or_permissions; return 1; }
  for file in candidate session.json task.md inputs.sha256 operator-key.txt control/session.lock; do
    u25_regular "$session/$file" 268435456 || { u25_fail session_file; return 1; }
  done
  [[ $(/usr/bin/stat -c %a -- "$session/operator-key.txt") == 600 ]] || { u25_fail key_permissions; return 1; }
  IFS= read -r key < "$session/operator-key.txt" || return 1
  [[ $key =~ ^[0-9a-f]{64}$ ]] || { u25_fail key_shape; return 1; }
  key=
  [[ $(u25_hash "$u25_candidate") == "$U25_CANDIDATE_SHA" ]] || { u25_fail repository_candidate_identity; return 1; }
  [[ $(u25_hash "$session/candidate") == "$U25_CANDIDATE_SHA" ]] || { u25_fail session_candidate_identity; return 1; }
  [[ $(u25_hash "$u25_registry") == "$U25_CASES_SHA" ]] || { u25_fail case_registry_identity; return 1; }
  [[ $(u25_hash "$u25_corpus") == "$U25_CORPUS_SHA" ]] || { u25_fail corpus_identity; return 1; }
  /usr/bin/sha256sum --check --status -- "$session/inputs.sha256" || { u25_fail prepared_input_drift; return 1; }
  u25_validate_manifest "$session" || { u25_fail session_manifest; return 1; }
  info=$(/usr/bin/env -i "$session/candidate" release-info) || return 1
  [[ $info == *'"version":"0.6.0-preview.2"'* && $info == *'"state_schema_version":8'* && $info == *'"tool_contract_version":"mtm-tools-v10"'* ]] || { u25_fail release_identity; return 1; }
  u25_environment "$session"
}

u25_prepare() {
  local repeat=$1 session trial password launcher_commit launcher_hash resolved name sage_root magma_root marker
  local -a names tools
  u25_repeat_case "$repeat" || { u25_fail repeat_must_be_1_to_3; return 1; }
  [[ $(/usr/bin/git -C "$u25_repo" rev-parse --show-toplevel) == "$u25_repo" ]] || { u25_fail repository_identity; return 1; }
  marker=$(printf ' %s ' '+')
  ! /usr/bin/grep -qF "$marker" "$u25_script" || { u25_fail launcher_patch_marker; return 1; }
  for tracked in scripts/mtm017-u25-research-session.sh conformance/mtm016-research-cases.tsv conformance/mtm016-usability-corpus.json; do
    /usr/bin/git -C "$u25_repo" ls-files --error-unmatch -- "$tracked" > /dev/null 2>&1 ||
      { u25_fail untracked_inputs; return 1; }
  done
  /usr/bin/git -C "$u25_repo" diff --quiet HEAD -- scripts/mtm017-u25-research-session.sh conformance/mtm016-research-cases.tsv conformance/mtm016-usability-corpus.json || { u25_fail changed_session_inputs; return 1; }
  launcher_commit=$(/usr/bin/git -C "$u25_repo" rev-parse HEAD) || return 1
  [[ $launcher_commit =~ ^[0-9a-f]{40}$ ]] || return 1
  launcher_hash=$(u25_hash "$u25_script") || return 1
  [[ $(u25_hash "$u25_registry") == "$U25_CASES_SHA" ]] || { u25_fail case_registry_identity; return 1; }
  [[ $(u25_hash "$u25_corpus") == "$U25_CORPUS_SHA" ]] || { u25_fail corpus_identity; return 1; }
  u25_regular "$u25_candidate" 268435456 && [[ -x $u25_candidate && $(u25_hash "$u25_candidate") == "$U25_CANDIDATE_SHA" ]] || { u25_fail candidate_identity; return 1; }

  names=(bwrap curl git bash sh cat printf sleep readlink dirname uname script
    latexmk pdflatex cloudflared sage magma python3 ls find grep sed awk head tail
    wc sort uniq cut tr env mkdir cp mv rm touch stat timeout sha256sum)
  tools=()
  for name in "${names[@]}"; do
    resolved=$(u25_tool "$name" "${PATH:-}") || { printf 'Missing required tool: %s\n' "$name" >&2; return 1; }
    tools+=("$resolved")
  done
  sage_root=$(u25_tool_root "${tools[15]}") || return 1
  magma_root=$(u25_tool_root "${tools[16]}") || return 1
  [[ -d $sage_root && -d $magma_root ]] || return 1

  for parent in "$HOME/.mtm-acceptance" "$HOME/.mtm-acceptance/MTM-017" "$u25_base"; do
    if [[ ! -e $parent && ! -L $parent ]]; then /usr/bin/mkdir -m 700 -- "$parent" || return 1; fi
    u25_private_dir "$parent" || { u25_fail parent_not_private; return 1; }
  done
  session=$(/usr/bin/mktemp -d -- "$u25_base/U25-r$repeat.XXXXXXXX") || return 1
  /usr/bin/mkdir -m 700 -- "$session/home" "$session/tmp" "$session/tool-bin" "$session/workspace" "$session/workspace/research-evidence" "$session/workspace/research-evidence-input" "$session/data" "$session/data/private" "$session/data/debug" "$session/control" "$session/logs" || return 1
  for ((i=0; i<${#names[@]}; i++)); do
    /usr/bin/ln -s -- "${tools[$i]}" "$session/tool-bin/${names[$i]}" || return 1
  done
  (umask 077; set -o noclobber; /usr/bin/cat -- "$u25_candidate" > "$session/candidate") || return 1
  /usr/bin/chmod 500 -- "$session/candidate" || return 1

  trial=$(/usr/bin/od -An -N16 -tx1 /dev/urandom | /usr/bin/tr -d ' \n')
  password=$(/usr/bin/od -An -N32 -tx1 /dev/urandom | /usr/bin/tr -d ' \n')
  [[ $trial =~ ^[0-9a-f]{32}$ && $password =~ ^[0-9a-f]{64}$ ]] || { u25_fail randomness; return 1; }
  u25_taskcard "$session/task.md" "$trial" || { u25_fail task_card; return 1; }
  u25_manifest "$session/session.json" "$trial" "$launcher_commit" "$launcher_hash" || { u25_fail session_manifest; return 1; }
  (set -o noclobber; printf '%s\n' "$password" > "$session/operator-key.txt"; printf 'session lock\n' > "$session/control/session.lock") || return 1
  password=
  (umask 077; set -o noclobber; /usr/bin/cat -- "$session/task.md" > "$session/workspace/task.md") || return 1
  (set -o noclobber; /usr/bin/sha256sum -- "$u25_script" "$u25_registry" "$u25_corpus" "$session/candidate" "$session/session.json" "$session/task.md" "$session/workspace/task.md" > "$session/inputs.sha256") || return 1
  u25_check "$session" || return 1
  /usr/bin/timeout --signal=TERM --kill-after=3s 45s "${u25_env[@]}" "$session/candidate" attest-native --workspace "$session/workspace" --native-mode dangerous --latex-policy required > "$session/control/native-preflight.json" 2> "$session/control/native-preflight.stderr" || { u25_fail native_preflight_failed; return 1; }
  /usr/bin/grep -q '"hard_isolation":true' "$session/control/native-preflight.json" || { u25_fail native_attestation_missing; return 1; }
  printf 'SESSION_ROOT=%s\n' "$session"
  printf 'Prepared MTM-017 U25-r%s preview.2 session. No research acceptance is claimed.\n' "$repeat"
  printf 'Start:  bash %q up %q\n' "$u25_script" "$session"
  printf 'Console: bash %q attach %q\n' "$u25_script" "$session"
  printf 'Local OAuth key: cat %q\n' "$session/operator-key.txt"
  printf 'Task card: cat %q\n' "$session/task.md"
}

u25_material_file() {
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

u25_seal_material() {
  local session=$1 source destination_root item name destination source_hash count=0
  local -a allowed=(sage_input.txt sage_output.txt magma_input.txt magma_output.txt cas_observation.json review.json)
  u25_check "$session" || return 1
  source=$session/workspace/research-evidence
  destination_root=$session/workspace/research-evidence-input
  u25_private_dir "$source" || { u25_fail evidence_source_permissions; return 1; }
  u25_private_dir "$destination_root" || { u25_fail evidence_input_permissions; return 1; }
  shopt -s nullglob dotglob
  for item in "$source"/*; do
    [[ -f $item && ! -L $item ]] || { u25_fail unknown_evidence_entry; return 1; }
    name=${item##*/}
    case " ${allowed[*]} " in
      *" $name "*) ;;
      *) u25_fail unknown_evidence_file; return 1 ;;
    esac
    u25_material_file "$item" || { u25_fail invalid_evidence_file; return 1; }
    destination=$destination_root/$name
    source_hash=$(u25_hash "$item") || return 1
    if [[ -e $destination || -L $destination ]]; then
      u25_regular "$destination" 1048576 || { u25_fail existing_evidence_invalid; return 1; }
      [[ $(/usr/bin/stat -c %a -- "$destination") == 600 && $(u25_hash "$destination") == "$source_hash" ]] || { u25_fail evidence_conflict; return 1; }
    else
      (umask 077; set -o noclobber; /usr/bin/cat -- "$item" > "$destination") || return 1
      /usr/bin/chmod 600 -- "$destination" || return 1
      [[ $(u25_hash "$destination") == "$source_hash" ]] || { u25_fail evidence_copy_mismatch; return 1; }
    fi
    ((count+=1))
  done
  ((count > 0)) || { u25_fail no_evidence_material; return 1; }
  printf 'sealed_material_files=%s source=workspace/research-evidence destination=workspace/research-evidence-input\n' "$count"
}

u25_start() (
  local session=$1 log rc
  [[ -t 0 && -t 1 && -t 2 ]] || { u25_fail interactive_terminal_required; exit 1; }
  u25_check "$session" || exit 1
  exec 9< "$session/control/session.lock"
  /usr/bin/flock -n 9 || { u25_fail session_already_running; exit 1; }
  log=$(/usr/bin/mktemp -- "$session/logs/console.XXXXXXXX.log") || exit 1
  printf 'MTM-017 U25 research session; workspace=%s\n' "$session/workspace"
  printf 'Keep this same OAuth connector across generation and independent review.\n'
  printf 'Private console log: %s\n' "$log"
  set +e
  "${u25_env[@]}" /usr/bin/bash --noprofile --norc -c '
    set -euo pipefail
    IFS= read -r MTM_OAUTH_PASSWORD < "$1/operator-key.txt"
    export MTM_OAUTH_PASSWORD
    cd -- "$1"
    exec "$1/candidate" tui --quick-tunnel --verbose --host 127.0.0.1 --port 0 --workspace "$1/workspace" --native-mode dangerous --latex-policy required
  ' mtm-u25 "$session" 2>&1 | /usr/bin/tee -- "$log"
  rc=${PIPESTATUS[0]}
  printf 'U25 session stopped (exit=%s). Private state and evidence material retained.\n' "$rc"
  exit "$rc"
)

u25_main() {
  [[ $# -ge 1 ]] || { u25_fail usage; return 1; }
  u25_init || return 1
  case $1 in
    prepare)
      [[ $# == 2 ]] || { u25_fail usage_prepare_repeat; return 1; }
      u25_prepare "$2"
      ;;
    check|up|attach|stop|seal-material)
      [[ $# == 2 && $2 == /* ]] || { u25_fail usage_session; return 1; }
      u25_session "$2" || { u25_fail session_path_or_permissions; return 1; }
      local socket=$2/control/tmux.sock
      case $1 in
        check)
          u25_check "$2" || return 1
          printf 'configuration_verified=true milestone=MTM-017 task=U25 repeat=%s version=0.6.0-preview.2 schema=mtm-research-session-v2 release_qualified=false\n' "$u25_repeat"
          ;;
        seal-material)
          u25_seal_material "$2"
          ;;
        up)
          u25_check "$2" || return 1
          if /usr/bin/tmux -S "$socket" has-session -t mtm-u25 2>/dev/null; then
            printf 'Already running; retaining the current OAuth client and tunnel.\n'
          else
            /usr/bin/tmux -S "$socket" new-session -d -s mtm-u25 -x 140 -y 45 /usr/bin/bash "$u25_script" start-internal "$2" || return 1
            printf 'Started fresh U25 research console. Attach to read its HTTPS MCP URL.\n'
          fi
          ;;
        attach)
          u25_check "$2" || return 1
          exec /usr/bin/tmux -S "$socket" attach-session -t mtm-u25
          ;;
        stop)
          u25_check "$2" || return 1
          /usr/bin/tmux -S "$socket" has-session -t mtm-u25 2>/dev/null || { printf 'Already stopped; state retained.\n'; return 0; }
          /usr/bin/tmux -S "$socket" send-keys -t mtm-u25 C-c || return 1
          for ((i=0; i<100; i++)); do
            /usr/bin/tmux -S "$socket" has-session -t mtm-u25 2>/dev/null || { printf 'Stopped; state and evidence retained.\n'; return 0; }
            /usr/bin/sleep 0.1
          done
          u25_fail graceful_stop_not_confirmed
          ;;
      esac
      ;;
    start-internal)
      [[ $# == 2 && $2 == /* ]] || { u25_fail usage_internal; return 1; }
      u25_session "$2" || return 1
      u25_start "$2"
      ;;
    *)
      u25_fail usage
      return 1
      ;;
  esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  set +x
  set -euo pipefail
  umask 077
  export LC_ALL=C
  u25_main "$@"
fi
