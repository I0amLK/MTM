#!/usr/bin/env bash
# Stop only the exact disposable research candidate for one MTM-016 session.
# Never uses pkill/killall or process-name matching; every signal is preceded by
# exact executable, owner and argv-role revalidation.

ss_fail() { printf 'MTM_RESEARCH_STOP_ERROR reason=%s\n' "$1" >&2; return 1; }

ss_role() {
  local proc_root=$1 candidate=$2 pid=$3 exe uid current_uid
  local -a argv=()
  [[ $pid =~ ^[0-9]+$ ]] || return 1
  exe=$(/usr/bin/readlink -- "$proc_root/$pid/exe" 2>/dev/null) || return 1
  [[ $exe == "$candidate" ]] || return 1
  uid=$(/usr/bin/stat -c %u -- "$proc_root/$pid" 2>/dev/null) || return 1
  current_uid=$(/usr/bin/id -u) || return 1
  [[ $uid == "$current_uid" ]] || return 1
  while IFS= read -r -d '' value; do argv+=("$value"); (( ${#argv[@]} <= 64 )) || return 1; done < "$proc_root/$pid/cmdline"
  (( ${#argv[@]} >= 2 )) || return 1
  case ${argv[1]} in
    tui) printf 'tui' ;;
    __native-helper) printf 'helper' ;;
    --sandbox-probe) printf 'probe' ;;
    *) printf 'unknown' ;;
  esac
}

ss_scan() {
  local proc_root=$1 candidate=$2 entry pid role
  ss_tui=(); ss_helper=(); ss_probe=(); ss_unknown=()
  for entry in "$proc_root"/[0-9]*/exe; do
    [[ -e $entry || -L $entry ]] || continue
    pid=${entry#"$proc_root/"}; pid=${pid%/exe}
    role=$(ss_role "$proc_root" "$candidate" "$pid" 2>/dev/null) || continue
    case $role in
      tui) ss_tui+=("$pid") ;;
      helper) ss_helper+=("$pid") ;;
      probe) ss_probe+=("$pid") ;;
      *) ss_unknown+=("$pid") ;;
    esac
  done
}

ss_still_exact() {
  local proc_root=$1 candidate=$2 pid=$3 role=$4
  [[ $(ss_role "$proc_root" "$candidate" "$pid" 2>/dev/null) == "$role" ]]
}

ss_signal() {
  local proc_root=$1 candidate=$2 pid=$3 role=$4 signal=$5
  ss_still_exact "$proc_root" "$candidate" "$pid" "$role" || return 0
  kill -s "$signal" -- "$pid"
}

ss_wait_gone() {
  local proc_root=$1 candidate=$2 pid=$3 role=$4 seconds=$5 index
  for ((index=0; index<seconds*10; index++)); do
    ss_still_exact "$proc_root" "$candidate" "$pid" "$role" || return 0
    /usr/bin/sleep 0.1
  done
  ! ss_still_exact "$proc_root" "$candidate" "$pid" "$role"
}

ss_main() {
  [[ $# == 3 && $1 == --session && $2 == /* && $3 == --operator-confirmed-stop ]] || { ss_fail usage; return 1; }
  local session=$2 home parent tail candidate pid
  local proc_root=/proc
  home=$(/usr/bin/readlink -e -- "${HOME:-}") || { ss_fail home_unavailable; return 1; }
  parent=$home/.mtm-acceptance/MTM-016/research
  tail=${session#"$parent/"}
  [[ $session == "$parent/"* && $tail =~ ^U2[1-5]-r[1-3]\.[a-zA-Z0-9]{8}$ ]] || { ss_fail session_scope; return 1; }
  [[ $(/usr/bin/readlink -e -- "$session") == "$session" ]] || { ss_fail session_identity; return 1; }
  [[ -d $session && ! -L $session && $(/usr/bin/stat -c %a -- "$session") == 700 ]] || { ss_fail session_private; return 1; }
  candidate=$session/candidate
  [[ -f $candidate && ! -L $candidate && -x $candidate && $(/usr/bin/sha256sum -- "$candidate") == "46c1441b824d6cc311a276ff34fda888c36223ebf5c98f8ca65ce26570df9724  $candidate" ]] || { ss_fail candidate_identity; return 1; }

  ss_scan "$proc_root" "$candidate"
  printf 'RESEARCH_STOP_SCAN tui=%s helper=%s probe=%s unknown=%s\n' "${#ss_tui[@]}" "${#ss_helper[@]}" "${#ss_probe[@]}" "${#ss_unknown[@]}"
  (( ${#ss_unknown[@]} == 0 )) || { ss_fail unknown_candidate_process; return 1; }
  (( ${#ss_tui[@]} <= 1 )) || { ss_fail multiple_tui_processes; return 1; }

  if (( ${#ss_tui[@]} == 1 )); then
    pid=${ss_tui[0]}
    printf 'RESEARCH_STOP signal=INT role=tui pid=%s\n' "$pid"
    ss_signal "$proc_root" "$candidate" "$pid" tui INT || { ss_fail tui_int_signal; return 1; }
    if ! ss_wait_gone "$proc_root" "$candidate" "$pid" tui 20; then
      printf 'RESEARCH_STOP signal=TERM role=tui pid=%s\n' "$pid"
      ss_signal "$proc_root" "$candidate" "$pid" tui TERM || { ss_fail tui_term_signal; return 1; }
      ss_wait_gone "$proc_root" "$candidate" "$pid" tui 5 || { ss_fail tui_still_running_after_term; return 1; }
    fi
  fi

  # A helper/probe with no surviving session TUI is stale acceptance plumbing.
  # Bubblewrap children use --die-with-parent, so terminating this exact helper
  # also tears down its owned sandbox instead of targeting unrelated processes.
  ss_scan "$proc_root" "$candidate"
  (( ${#ss_tui[@]} == 0 && ${#ss_unknown[@]} == 0 )) || { ss_fail tui_or_unknown_remains; return 1; }
  for pid in "${ss_helper[@]}"; do
    printf 'RESEARCH_STOP signal=TERM role=helper pid=%s\n' "$pid"
    ss_signal "$proc_root" "$candidate" "$pid" helper TERM || { ss_fail helper_term_signal; return 1; }
  done
  for pid in "${ss_probe[@]}"; do
    printf 'RESEARCH_STOP signal=TERM role=probe pid=%s\n' "$pid"
    ss_signal "$proc_root" "$candidate" "$pid" probe TERM || { ss_fail probe_term_signal; return 1; }
  done
  for pid in "${ss_helper[@]}"; do ss_wait_gone "$proc_root" "$candidate" "$pid" helper 5 || { ss_fail helper_still_running_after_term; return 1; }; done
  for pid in "${ss_probe[@]}"; do ss_wait_gone "$proc_root" "$candidate" "$pid" probe 5 || { ss_fail probe_still_running_after_term; return 1; }; done
  ss_scan "$proc_root" "$candidate"
  (( ${#ss_tui[@]} == 0 && ${#ss_helper[@]} == 0 && ${#ss_probe[@]} == 0 && ${#ss_unknown[@]} == 0 )) || { ss_fail candidate_process_remains; return 1; }
  printf 'RESEARCH_STOP complete=true session_candidate_processes=0 production_processes_targeted=false\n'
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  set +x
  set -euo pipefail
  umask 077
  export LC_ALL=C
  ss_main "$@"
fi
