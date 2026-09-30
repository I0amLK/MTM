#!/usr/bin/env bash
# Side-by-side operator web testing of the exact qualified preview.2 binary.
# No production selector, data import, verifier submission or release authority.

readonly WS_CANDIDATE_SHA=13d7890c5c763199ed39295e134ff6cc735ceaa04eaddf6c556431a7a56254f4
readonly WS_HELPER_SHA=6546aca2185888d0fb896cfa97ac6861378662a7c3629125f1b60ae17151429f
readonly WS_SOURCE_SHA=0adec4b02a8b54fd20fb30c796c9959ccc346cc0f9336517fc47eafcb6951e02

ws_fail() { printf 'MTM_WEB_SESSION_ERROR reason=%s\n' "$1" >&2; return 1; }

ws_init() {
  ws_script=$(/usr/bin/readlink -e -- "${BASH_SOURCE[0]}") || return 1
  ws_repo=$(/usr/bin/readlink -e -- "${ws_script%/*}/..") || return 1
  [[ $ws_repo != *:* && $ws_repo != *$'\n'* && $ws_repo != *$'\t'* ]] || return 1
  ws_helper=$ws_repo/scripts/mtm016-research-session.sh
  local digest
  digest=$(/usr/bin/sha256sum -- "$ws_helper") || return 1
  [[ ${digest%% *} == "$WS_HELPER_SHA" ]] || { ws_fail helper_identity; return 1; }
  # Reuse only pinned file/dir/tool/snapshot/environment primitives. The old
  # script's main function is NOT run and no MTM-016 case or receipt is changed.
  if [[ ${ws_bootstrapped:-false} != true ]]; then
    source "$ws_helper"
    ws_bootstrapped=true
  fi
  ws_base=$ws_repo/target/mtm017-web-sessions
}

ws_args() {
  [[ $# -ge 1 ]] || return 1
  case $1 in
    prepare) [[ $# == 1 ]] ;;
    check|start|up|attach|stop) [[ $# == 2 && $2 == /* ]] ;;
    *) return 1 ;;
  esac
}

ws_session() {
  local supplied=$1 canonical leaf directory
  canonical=$(/usr/bin/readlink -e -- "$supplied") || return 1
  [[ $canonical == "$supplied" && ${canonical%/*} == "$ws_base" ]] || return 1
  leaf=${canonical##*/}
  [[ $leaf =~ ^web-[A-Za-z0-9]{8}$ ]] || return 1
  [[ ! -L $ws_repo/target ]] || return 1
  rs_private_dir "$ws_base" && rs_private_dir "$canonical" || return 1
  ws_session_root=$canonical
  for directory in home tmp tool-bin workspace data data/private data/debug control logs; do
    rs_private_dir "$canonical/$directory" || return 1
  done
}

ws_environment() {
  local session=$1 sage_root magma_root
  sage_root=$(rs_tool_root "$session/tool-bin/sage") || return 1
  magma_root=$(rs_tool_root "$session/tool-bin/magma") || return 1
  # The pinned U25 environment is dangerous-only, required-LaTeX, protocol 3,
  # with fresh HOME/data and a curated PATH. It does not run any U25 trial.
  rs_task=U25
  rs_environment "$session" "$sage_root" "$magma_root"
}

ws_check() {
  local session=$1 key info
  ws_session "$session" || { ws_fail session_path_or_permissions; return 1; }
  for file in candidate session.json inputs.sha256 operator-key.txt control/session.lock; do
    rs_regular "$session/$file" 268435456 || { ws_fail session_file; return 1; }
  done
  [[ $(/usr/bin/stat -c %a -- "$session/operator-key.txt") == 600 ]] || { ws_fail key_permissions; return 1; }
  IFS= read -r key < "$session/operator-key.txt" || return 1
  [[ $key =~ ^[0-9a-f]{64}$ && $(/usr/bin/stat -c %s -- "$session/operator-key.txt") == 65 ]] || { ws_fail key_shape; return 1; }
  key=
  [[ $(rs_hash "$session/candidate") == "$WS_CANDIDATE_SHA" ]] || { ws_fail candidate_identity; return 1; }
  /usr/bin/sha256sum --check --status -- "$session/inputs.sha256" || { ws_fail prepared_input_drift; return 1; }
  info=$(/usr/bin/env -i "$session/candidate" release-info) || return 1
  [[ $info == *'"version":"0.6.0-preview.2"'* && $info == *'"state_schema_version":8'* && $info == *'"public_tool_count":24'* && $info == *'"tool_contract_version":"mtm-tools-v10"'* ]] || { ws_fail release_identity; return 1; }
  ws_environment "$session"
}

ws_prepare() {
  local candidate session password name resolved log
  local -a names programs
  candidate=$ws_repo/target/mtm017-preview2/mtm-0.6.0-preview.2-$WS_CANDIDATE_SHA/mtm
  rs_regular "$candidate" 268435456 && [[ -x $candidate && $(rs_hash "$candidate") == "$WS_CANDIDATE_SHA" ]] || { ws_fail qualified_candidate_missing; return 1; }
  names=(bwrap curl git bash sh cat printf sleep readlink dirname uname script
    latexmk pdflatex cloudflared sage magma python3 ls find grep sed awk head tail
    wc sort uniq cut tr env mkdir cp mv rm touch stat timeout)
  programs=()
  for name in "${names[@]}"; do
    resolved=$(rs_tool "$name" "${PATH:-}") || { printf 'Missing required tool: %s\n' "$name" >&2; return 1; }
    programs+=("$resolved")
  done
  [[ -d $ws_repo/target && ! -L $ws_repo/target ]] || return 1
  if [[ ! -e $ws_base && ! -L $ws_base ]]; then /usr/bin/mkdir -m 700 -- "$ws_base" || return 1; fi
  rs_private_dir "$ws_base" || { ws_fail session_parent_not_private; return 1; }
  session=$(/usr/bin/mktemp -d -- "$ws_base/web-XXXXXXXX") || return 1
  /usr/bin/mkdir -m 700 -- "$session/home" "$session/tmp" "$session/tool-bin" "$session/workspace" "$session/data" "$session/data/private" "$session/data/debug" "$session/control" "$session/logs" || return 1
  rs_snapshot "$candidate" "$session/candidate" "$WS_CANDIDATE_SHA" || return 1
  for ((i=0; i<${#names[@]}; i++)); do
    /usr/bin/ln -s -- "${programs[$i]}" "$session/tool-bin/${names[$i]}" || return 1
  done
  password=$(/usr/bin/od -An -N32 -tx1 /dev/urandom | /usr/bin/tr -d ' \n')
  [[ $password =~ ^[0-9a-f]{64}$ ]] || { ws_fail randomness; return 1; }
  (set -o noclobber; printf '%s\n' "$password" > "$session/operator-key.txt"; printf 'session lock\n' > "$session/control/session.lock") || return 1
  password=
  (set -o noclobber; printf '{"schema":"mtm017-operator-web-session-v1","version":"0.6.0-preview.2","candidate_sha256":"%s","source_sha256":"%s","state_schema":8,"tool_contract":"mtm-tools-v10","native_mode":"dangerous","latex_policy":"required","workflow_protocol":3,"fresh_state":true,"production_state_copied":false,"release_qualified":false,"real_web_test_passed":false}\n' "$WS_CANDIDATE_SHA" "$WS_SOURCE_SHA" > "$session/session.json") || return 1
  (set -o noclobber; /usr/bin/cat -- "$ws_repo/docs/MTM-017-WEB-TEST-CARD.md" > "$session/workspace/WEB-TEST.md") || return 1
  # Absolute locators allow restart from another directory. Keys/logs and the
  # model-writable task card are not part of a public receipt or input seal.
  (set -o noclobber; /usr/bin/sha256sum -- "$ws_script" "$ws_helper" "$session/candidate" "$session/session.json" "${programs[@]}" > "$session/inputs.sha256") || return 1
  ws_check "$session" || return 1
  log=$session/control/native-preflight.json
  /usr/bin/timeout --signal=TERM --kill-after=3s 45s "${rs_env[@]}" "$session/candidate" attest-native --workspace "$session/workspace" --native-mode dangerous --latex-policy required > "$log" 2> "$session/control/native-preflight.stderr" || { ws_fail native_preflight_failed; return 1; }
  /usr/bin/grep -q '"hard_isolation":true' "$log" || { ws_fail native_attestation_missing; return 1; }
  printf 'SESSION_ROOT=%s\n' "$session"
  printf 'Prepared preview.2 with separate state. No real-web acceptance is claimed.\n'
  printf 'Start:  bash %q up %q\n' "$ws_script" "$session"
  printf 'Console: bash %q attach %q\n' "$ws_script" "$session"
  printf 'Local OAuth key: cat %q\n' "$session/operator-key.txt"
}

ws_start() (
  local session=$1 log rc
  [[ -t 0 && -t 1 && -t 2 ]] || { ws_fail interactive_terminal_required; exit 1; }
  ws_check "$session" || exit 1
  exec 9< "$session/control/session.lock"
  /usr/bin/flock -n 9 || { ws_fail session_already_running; exit 1; }
  log=$(/usr/bin/mktemp -- "$session/logs/console.XXXXXXXX.log") || exit 1
  printf 'preview.2 web test; workspace=%s\n' "$session/workspace"
  printf 'Keep the same OAuth connection across generator/reviewer conversations.\n'
  printf 'OAuth key is local only: cat %q\n' "$session/operator-key.txt"
  printf 'Private console log: %s\n' "$log"
  set +e
  "${rs_env[@]}" /usr/bin/bash --noprofile --norc -c '
    set -euo pipefail
    IFS= read -r MTM_OAUTH_PASSWORD < "$1/operator-key.txt"
    export MTM_OAUTH_PASSWORD
    cd -- "$1"
    exec "$1/candidate" tui --quick-tunnel --verbose --host 127.0.0.1 --port 0 --workspace "$1/workspace" --native-mode dangerous --latex-policy required
  ' mtm-web "$session" 2>&1 | /usr/bin/tee -- "$log"
  rc=${PIPESTATUS[0]}
  printf 'Session stopped (exit=%s). Data retained; no deployment rollback needed.\n' "$rc"
  exit "$rc"
)

ws_main() {
  ws_args "$@" || { ws_fail 'usage_prepare_or_check_start_up_attach_stop_SESSION'; return 1; }
  ws_init || return 1
  if [[ $1 == prepare ]]; then ws_prepare; return; fi
  ws_check "$2" || return 1
  local socket=$2/control/tmux.sock
  case $1 in
    check) printf 'configuration_verified=true version=0.6.0-preview.2 schema=8 release_qualified=false\n' ;;
    start) ws_start "$2" ;;
    up)
      if /usr/bin/tmux -S "$socket" has-session -t mtm-preview2 2>/dev/null; then
        printf 'Already running; retaining the current OAuth client and tunnel.\n'
      else
        /usr/bin/tmux -S "$socket" new-session -d -s mtm-preview2 -x 140 -y 45 /usr/bin/bash "$ws_script" start "$2" || return 1
        printf 'Started isolated test console. Attach to read its current HTTPS MCP URL.\n'
      fi ;;
    attach) exec /usr/bin/tmux -S "$socket" attach-session -t mtm-preview2 ;;
    stop)
      /usr/bin/tmux -S "$socket" has-session -t mtm-preview2 2>/dev/null || { printf 'Already stopped; state retained.\n'; return; }
      /usr/bin/tmux -S "$socket" send-keys -t mtm-preview2 C-c || return 1
      for ((i=0; i<100; i++)); do
        /usr/bin/tmux -S "$socket" has-session -t mtm-preview2 2>/dev/null || { printf 'Stopped; state and evidence retained.\n'; return; }
        /usr/bin/sleep 0.1
      done
      ws_fail graceful_stop_not_confirmed ;;
  esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  set +x
  set -euo pipefail
  umask 077
  export LC_ALL=C
  ws_main "$@"
fi
