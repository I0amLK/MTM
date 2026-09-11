#!/usr/bin/env bash
# Disposable operator-driven research only. Never submits workflow results.
# Sourcing defines primitives for synthetic tests and does not create a session.

readonly RS_CANDIDATE_SHA=46c1441b824d6cc311a276ff34fda888c36223ebf5c98f8ca65ce26570df9724
readonly RS_CANDIDATE_SOURCE=cc17b1688a2deda7db3dde4b2dbf63199bf48b13
readonly RS_CORPUS_SHA=9227aa6e199887860d88091467aa53fe45eee55cd337eac0587059f8ec434861
readonly RS_CASES_SHA=cd6d6a758e667fca21d2a04d2eba9a015c1d156350b34438660dd8bd16ae1bb9

rs_fail() { printf 'MTM_RESEARCH_SESSION_ERROR reason=%s\n' "$1" >&2; return 1; }
rs_hash() { local value; value=$(/usr/bin/sha256sum -- "$1") || return 1; printf '%s' "${value%% *}"; }

rs_regular() {
  local file=$1 bound=$2 size mode
  [[ -f $file && ! -L $file ]] || return 1
  [[ $(/usr/bin/stat -c %h -- "$file") == 1 ]] || return 1
  mode=$(/usr/bin/stat -c %a -- "$file") || return 1
  [[ $mode =~ ^[0-7]{1,3}$ ]] || return 1
  size=$(/usr/bin/stat -c %s -- "$file") || return 1
  [[ $size =~ ^[0-9]+$ ]] && ((size > 0 && size <= bound))
}

rs_private_dir() {
  [[ -d $1 && ! -L $1 ]] &&
    [[ $(/usr/bin/stat -c %u -- "$1") == "$(/usr/bin/id -u)" ]] &&
    [[ $(/usr/bin/stat -c %a -- "$1") == 700 ]]
}

rs_args() {
  [[ $# == 4 || ( $# == 5 && $5 == --prepare-only ) ]] || return 1
  [[ $1 == --task && $2 =~ ^U2[1-5]$ && $3 == --repeat && $4 =~ ^[1-3]$ ]] || return 1
  rs_task=$2; rs_repeat=$4; rs_prepare_only=false
  [[ $# == 4 ]] || rs_prepare_only=true
}

rs_registry() {
  local LC_ALL=C
  local file=$1 wanted=$2 repetition=$3 line id rep case_id mode problem requirement rest expected input size
  local count=0 found=0
  local -A seen=() cases=()
  rs_regular "$file" 32768 || return 1
  size=$(/usr/bin/stat -c %s -- "$file") || return 1
  # Preserve final newlines, reject failed reads and embedded NULs rather than
  # trusting the status of a process substitution whose producer is not waited.
  input=$(/usr/bin/cat -- "$file" && printf '.') || return 1
  (( ${#input} == size + 1 )) || return 1
  input=${input%.}
  [[ $input == *$'\n' ]] || return 1
  input=${input%$'\n'}
  line=${input%%$'\n'*}
  [[ $line == '# mtm-research-cases-v1: task<TAB>repeat<TAB>case_id<TAB>mode<TAB>problem<TAB>special_requirement' ]] || return 1
  [[ $input != "$line" ]] || return 1
  input=${input#*$'\n'}
  while IFS= read -r line || [[ -n $line ]]; do
    ((count+=1)); ((count <= 15)) || return 1
    [[ $line != *$'\r'* ]] || return 1
    rest=${line//$'\t'/}; (( ${#line} - ${#rest} == 5 )) || return 1
    IFS=$'\t' read -r id rep case_id mode problem requirement <<< "$line"
    [[ $id =~ ^U2[1-5]$ && $rep =~ ^[1-3]$ && $case_id =~ ^u2[1-5]-r[1-3]-[a-z-]+$ ]] || return 1
    [[ $case_id == "${id,,}-r$rep-"* && -n $problem && -n $requirement ]] || return 1
    [[ -z ${seen[$id-$rep]+x} && -z ${cases[$case_id]+x} ]] || return 1
    expected=full; [[ $id != U21 && $id != U23 ]] || expected=compact
    [[ $mode == "$expected" ]] || return 1
    seen[$id-$rep]=1; cases[$case_id]=1
    if [[ $id == "$wanted" && $rep == "$repetition" ]]; then
      rs_case=$case_id; rs_mode=$mode; rs_problem=$problem; rs_requirement=$requirement
      ((found+=1))
    fi
  done <<< "$input"
  ((count == 15 && found == 1))
}

rs_tool() {
  local name=$1 path=$2 part resolved
  local -a parts=()
  IFS=: read -r -a parts <<< "$path"
  for part in "${parts[@]}"; do
    # Do not interpret an empty/relative PATH entry as the caller's workspace.
    [[ $part == /* && -f $part/$name && -x $part/$name ]] || continue
    resolved=$(/usr/bin/readlink -e -- "$part/$name") || return 1
    [[ $resolved == /* && -f $resolved && ! -L $resolved && -x $resolved ]] || return 1
    [[ $(/usr/bin/stat -c %a -- "$resolved") =~ ^[0-7]{1,3}$ ]] || return 1
    printf '%s' "$resolved"; return 0
  done
  return 1
}

rs_environment() {
  local session=$1
  rs_env=(/usr/bin/env -i
    "HOME=$session/home" "PATH=$session/tool-bin" LC_ALL=C LANG=C.UTF-8
    "TMPDIR=$session/tmp" "XDG_CACHE_HOME=$session/home/.cache"
    "MTM_WORKSPACE=$session/workspace" "MTM_DATA_ROOT=$session/data"
    "MTM_PRIVATE_ROOT=$session/data/private" "MTM_DEBUG_ROOT=$session/data/debug"
    MTM_DEBUG=1 MTM_TRACE_PAYLOADS=0 MTM_NATIVE_EXEC_BACKEND=bubblewrap
    MTM_NATIVE_MODE=safe MTM_LATEX_POLICY=required MTM_WORKFLOW_PROTOCOL_VERSION=3
    TOKIO_WORKER_THREADS=2)
}

rs_snapshot() {
  local source=$1 target=$2 digest=$3
  [[ $digest =~ ^[0-9a-f]{64}$ && ! -e $target && ! -L $target ]] || return 1
  rs_regular "$source" 268435456 && [[ -x $source ]] || return 1
  [[ $(rs_hash "$source") == "$digest" ]] || return 1
  (umask 077; set -o noclobber; /usr/bin/cat -- "$source" > "$target") || return 1
  /usr/bin/chmod 500 -- "$target" || return 1
  [[ $(rs_hash "$source") == "$digest" && $(rs_hash "$target") == "$digest" ]]
}

rs_manifest() {
  local destination=$1 trial=$2 commit=$3 launcher=$4 registry=$5 expected=full
  [[ ! -e $destination && ! -L $destination ]] || return 1
  [[ $trial =~ ^[0-9a-f]{32}$ && $commit =~ ^[0-9a-f]{40}$ && $launcher =~ ^[0-9a-f]{64}$ && $registry =~ ^[0-9a-f]{64}$ ]] || return 1
  [[ $rs_task =~ ^U2[1-5]$ && $rs_repeat =~ ^[1-3]$ && $rs_mode =~ ^(full|compact)$ && $rs_case =~ ^u2[1-5]-r[1-3]-[a-z-]+$ ]] || return 1
  [[ $rs_task != U21 && $rs_task != U23 ]] || expected=compact
  [[ $rs_case == "${rs_task,,}-r$rs_repeat-"* && $rs_mode == "$expected" ]] || return 1
  # All interpolated fields are restricted ASCII identities, never shell paths,
  # problem text, URLs, private workflow identifiers or authority handles.
  (
    set -o noclobber
    printf '{"schema":"mtm-research-session-v1","milestone":"MTM-016","task_id":"%s","repeat":%s,"case_id":"%s","workflow_mode":"%s","trial_id":"%s","candidate_sha256":"%s","candidate_source_commit":"%s","launcher_source_commit":"%s","launcher_sha256":"%s","case_registry_sha256":"%s","corpus_sha256":"%s","native_mode":"safe","latex_policy":"required","session_prepared":true,"runtime_executed":false,"independent_review_recorded":false,"research_trial_passed":false,"release_qualified":false}\n' \
      "$rs_task" "$rs_repeat" "$rs_case" "$rs_mode" "$trial" "$RS_CANDIDATE_SHA" "$RS_CANDIDATE_SOURCE" "$commit" "$launcher" "$registry" "$RS_CORPUS_SHA" > "$destination"
  )
}

rs_taskcard() {
  local destination=$1 trial=$2
  [[ ! -e $destination && ! -L $destination ]] || return 1
  (
    set -o noclobber
    exec > "$destination" || exit 1
    printf '# MTM-016 %s repeat %s\n\n试次编号：`%s`。本文件是任务输入，不是通过证据。\n\n## 生成会话\n\n' "$rs_task" "$rs_repeat" "$trial"
    printf '仅使用本次一次性验收连接，新建一个 `%s` workflow，problem_id 使用 `%s`，register_result=false。不要使用旧连接、旧 run 或已有专项测试结论。\n\n' "$rs_mode" "$rs_case"
    printf '%s\n\n专项要求：%s\n\n' "$rs_problem" "$rs_requirement"
    printf '%s\n\n' '严格按 rethlas_start / rethlas_step 实际返回的任务契约工作。不得伪造 capability、引用 ID 或 verification_report；不得绕过失败。最终证明必须经 required LaTeX 编译。到 verify 后停止，由独立复核会话继续；不要替自己提交“无错误”报告。'
    printf '## 独立复核会话\n\n%s\n\n' '使用同一验收连接与原 run 所有者，在新的会话中根据 run ID 获取当前 verifier 任务。只依据该角色合法返回的题目、证明与文献审计材料逐步核查；不要读取生成会话的结论标签或兄弟分支私有域。由复核者形成具体意见，再通过当前任务契约提交。若需要 repair，退回生成/修复会话，完成后由复核会话重新检查。'
    printf '%s\n\n' '对 U23，保留故意植入的首稿及首次具体缺陷报告，并明确这是种子修复挑战；不得把它说成自然发现的产品错误。对 U24，两个分支使用不同会话，按实际分支契约工作并等待所需分支封存。对 U25，CAS 命令仍须遵循 safe 模式的真实权限请求，不切换 dangerous。'
    printf '## 完成后保留\n\n%s\n\n' '保留该会话的私有 run ID、状态序列、所有候选稿与最终 tex、编译结果、引用审计、CAS 输入输出及独立复核意见。不得上传 OAuth key、token、capability 或 operator.log。只报告脱敏状态与计数；后续收集器仍需核对最终字节及各任务专属证据。'
    printf '%s\n' '本启动器不创建或推进 run、不提交 verifier 报告、不判断数学正确性、不更新 corpus 计数、不授权发布。启动成功、correct 字符串或 Ctrl-C 正常退出均不能单独判定试次通过。'
  )
}

rs_main() {
  rs_args "$@" || { rs_fail usage_task_U21_to_U25_repeat_1_to_3_optional_prepare_only; return 1; }
  local repo script registry corpus candidate commit launcher_hash registry_hash before after
  local home parent session trial password name resolved rc
  local -a names tools pipe_status
  repo=$(cd -- "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")/.." && /usr/bin/pwd -P) || return 1
  script=$repo/scripts/mtm016-research-session.sh
  registry=$repo/conformance/mtm016-research-cases.tsv
  corpus=$repo/conformance/mtm016-usability-corpus.json
  candidate=$repo/target/mtm016-f5-frozen/mtm-0.6.0-preview.1-$RS_CANDIDATE_SHA/mtm
  [[ $(/usr/bin/git -C "$repo" rev-parse --show-toplevel) == "$repo" ]] || { rs_fail repository_identity; return 1; }
  /usr/bin/git -C "$repo" ls-files --error-unmatch -- scripts/mtm016-research-session.sh conformance/mtm016-research-cases.tsv > /dev/null 2>&1 || { rs_fail uncommitted_session_entry; return 1; }
  /usr/bin/git -C "$repo" diff --quiet HEAD -- scripts/mtm016-research-session.sh conformance/mtm016-research-cases.tsv conformance/mtm016-usability-corpus.json || { rs_fail changed_session_inputs; return 1; }
  commit=$(/usr/bin/git -C "$repo" rev-parse HEAD) || return 1
  rs_regular "$script" 65536 && rs_regular "$corpus" 65536 && rs_regular "$registry" 32768 || { rs_fail input_bounds; return 1; }
  launcher_hash=$(rs_hash "$script"); registry_hash=$(rs_hash "$registry")
  [[ $(rs_hash "$corpus") == "$RS_CORPUS_SHA" && $registry_hash == "$RS_CASES_SHA" ]] || { rs_fail corpus_or_case_identity; return 1; }
  rs_registry "$registry" "$rs_task" "$rs_repeat" || { rs_fail case_registry; return 1; }
  rs_regular "$candidate" 268435456 && [[ -x $candidate && $(rs_hash "$candidate") == "$RS_CANDIDATE_SHA" ]] || { rs_fail frozen_candidate_identity; return 1; }
  names=(bwrap curl latexmk pdflatex cloudflared sh cat printf sleep readlink dirname uname)
  [[ $rs_task != U25 ]] || names+=(sage magma)
  tools=()
  for name in "${names[@]}"; do
    resolved=$(rs_tool "$name" "${PATH:-}") || { printf 'MTM_RESEARCH_SESSION_DIAGNOSTIC tool=%s\n' "$name" >&2; rs_fail required_tool_unavailable; return 1; }
    tools+=("$resolved")
  done
  if [[ $rs_prepare_only == false ]]; then
    [[ -t 0 && -t 1 && -t 2 ]] || { rs_fail interactive_terminal_required; return 1; }
  fi
  home=$(/usr/bin/readlink -e -- "${HOME:-}") || { rs_fail home_unavailable; return 1; }
  [[ $home == /* && -d $home && $home != / ]] || { rs_fail home_invalid; return 1; }
  for parent in "$home/.mtm-acceptance" "$home/.mtm-acceptance/MTM-016" "$home/.mtm-acceptance/MTM-016/research"; do
    if [[ ! -e $parent && ! -L $parent ]]; then /usr/bin/mkdir -m 700 -- "$parent" || return 1; fi
    rs_private_dir "$parent" || { rs_fail parent_not_private; return 1; }
  done
  session=$(/usr/bin/mktemp -d -- "$parent/$rs_task-r$rs_repeat.XXXXXXXX") || return 1
  rs_private_dir "$session" || { rs_fail session_not_private; return 1; }
  /usr/bin/mkdir -m 700 -- "$session/home" "$session/tmp" "$session/tool-bin" "$session/workspace" "$session/data" "$session/data/private" "$session/data/debug"
  trial=$(/usr/bin/od -An -N16 -tx1 /dev/urandom | /usr/bin/tr -d ' \n')
  password=$(/usr/bin/od -An -N32 -tx1 /dev/urandom | /usr/bin/tr -d ' \n')
  [[ $trial =~ ^[0-9a-f]{32}$ && $password =~ ^[0-9a-f]{64}$ ]] || { rs_fail randomness; return 1; }
  for ((rc=0; rc<${#names[@]}; rc++)); do /usr/bin/ln -s -- "${tools[$rc]}" "$session/tool-bin/${names[$rc]}"; done
  rs_snapshot "$candidate" "$session/candidate" "$RS_CANDIDATE_SHA" || { rs_fail snapshot_mismatch; return 1; }
  rs_manifest "$session/session.json" "$trial" "$commit" "$launcher_hash" "$registry_hash" || { rs_fail manifest; return 1; }
  rs_taskcard "$session/task.md" "$trial" || { rs_fail task_card; return 1; }
  (set -o noclobber; printf '%s\n' "$password" > "$session/operator-key.txt")
  printf 'private_session=%s\n' "$session"
  /usr/bin/cat -- "$session/session.json"
  printf '\n本机查看任务卡：cat %q\n本机查看本次 OAuth key：cat %q\n不要上传 key、URL 或原始日志。\n' "$session/task.md" "$session/operator-key.txt"
  [[ $rs_prepare_only == false ]] || return 0
  before=$(/usr/bin/sha256sum -- "$script" "$registry" "$corpus" "$candidate" "$session/candidate")
  rs_environment "$session"
  # Exact CLI attestation precedes the public tunnel. Only new disposable state
  # roots are configured; no production path is accepted or discovered.
  if ! /usr/bin/timeout --signal=TERM --kill-after=3s 20s "${rs_env[@]}" "$session/candidate" attest-native --workspace "$session/workspace" --native-mode safe --latex-policy required > "$session/native-preflight.json" 2> "$session/native-preflight.stderr"; then
    rs_fail native_preflight_failed_private_diagnostics_retained; return 1
  fi
  printf '\n只连接这次 TUI 显示的新验收地址。先完成生成阶段，到 verify 后换独立复核会话。\n'
  set +e
  (cd -- "$session" && exec "${rs_env[@]}" "MTM_OAUTH_PASSWORD=$password" "$session/candidate" tui --quick-tunnel --verbose --host 127.0.0.1 --port 0 --workspace "$session/workspace" --native-mode safe --latex-policy required) 2>&1 | /usr/bin/tee -- "$session/operator.log"
  pipe_status=("${PIPESTATUS[@]}")
  set -e
  password=
  after=$(/usr/bin/sha256sum -- "$script" "$registry" "$corpus" "$candidate" "$session/candidate")
  [[ $before == "$after" && $commit == "$(/usr/bin/git -C "$repo" rev-parse HEAD)" ]] || { rs_fail session_input_changed; return 1; }
  [[ ${#pipe_status[@]} == 2 && ${pipe_status[1]} == 0 ]] || { rs_fail log_capture_failed; return 1; }
  rc=${pipe_status[0]}
  # Process exit is not workflow completion. Keep separate immutable start and
  # close observations; never replace session.json with a success claim.
  (set -o noclobber; printf '{"schema":"mtm-research-session-close-v1","trial_id":"%s","runtime_exit_code":%s,"inputs_unchanged":true,"research_trial_passed":false,"independent_review_recorded":false,"release_qualified":false}\n' "$trial" "$rc" > "$session/close.json")
  /usr/bin/cat -- "$session/close.json"
  printf '%s\n' 'NEXT: retain private artifacts and independent reviews; session exit alone is not research acceptance.'
  return "$rc"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  set +x
  set -euo pipefail
  umask 077
  export LC_ALL=C
  rs_main "$@"
fi
