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

ss_start_ticks() {
  local proc_root=$1 pid=$2 value rest
  IFS= read -r value < "$proc_root/$pid/stat" || return 1
  rest=${value#*) }
  set -- $rest
  (( $# >= 20 )) || return 1
  [[ ${20} =~ ^[0-9]+$ ]] || return 1
  printf '%s' "${20}"
}

ss_status_value() {
  local proc_root=$1 pid=$2 key=$3 value
  value=$(/usr/bin/awk -F: -v wanted="$key" '$1 == wanted {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2; found=1; exit} END {if (!found) exit 1}' "$proc_root/$pid/status" 2>/dev/null) || return 1
  [[ -n $value && $value != *$'\n'* ]] || return 1
  printf '%s' "$value"
}

ss_diagnostic() {
  local proc_root=$1 candidate=$2 pid=$3 role=$4
  local state ppid threads sigpnd shdpnd sigblk sigign sigcgt start wchan
  ss_still_exact "$proc_root" "$candidate" "$pid" "$role" || return 1
  state=$(ss_status_value "$proc_root" "$pid" State) || state=unknown
  ppid=$(ss_status_value "$proc_root" "$pid" PPid) || ppid=unknown
  threads=$(ss_status_value "$proc_root" "$pid" Threads) || threads=unknown
  sigpnd=$(ss_status_value "$proc_root" "$pid" SigPnd) || sigpnd=unknown
  shdpnd=$(ss_status_value "$proc_root" "$pid" ShdPnd) || shdpnd=unknown
  sigblk=$(ss_status_value "$proc_root" "$pid" SigBlk) || sigblk=unknown
  sigign=$(ss_status_value "$proc_root" "$pid" SigIgn) || sigign=unknown
  sigcgt=$(ss_status_value "$proc_root" "$pid" SigCgt) || sigcgt=unknown
  start=$(ss_start_ticks "$proc_root" "$pid") || start=unknown
  if [[ -r $proc_root/$pid/wchan ]]; then
    IFS= read -r wchan < "$proc_root/$pid/wchan" || wchan=unknown
  else
    wchan=unavailable
  fi
  [[ $wchan =~ ^[A-Za-z0-9_.?+-]{1,96}$ ]] || wchan=redacted
  printf 'RESEARCH_STOP_DIAGNOSTIC role=%s pid=%s state=%q ppid=%s threads=%s start_ticks=%s wchan=%s sigpnd=%s shdpnd=%s sigblk=%s sigign=%s sigcgt=%s\n' \
    "$role" "$pid" "$state" "$ppid" "$threads" "$start" "$wchan" "$sigpnd" "$shdpnd" "$sigblk" "$sigign" "$sigcgt"
}

ss_main() {
  [[ $# == 3 && $1 == --session && $2 == /* && ( $3 == --operator-confirmed-stop || $3 == --operator-confirmed-force-stop ) ]] || { ss_fail usage; return 1; }
  local session=$2 home parent tail candidate pid initial_start state
  local force=false
  [[ $3 != --operator-confirmed-force-stop ]] || force=true
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
    initial_start=$(ss_start_ticks "$proc_root" "$pid") || { ss_fail tui_start_identity; return 1; }
    printf 'RESEARCH_STOP signal=INT role=tui pid=%s\n' "$pid"
    ss_signal "$proc_root" "$candidate" "$pid" tui INT || { ss_fail tui_int_signal; return 1; }
    if ! ss_wait_gone "$proc_root" "$candidate" "$pid" tui 20; then
      printf 'RESEARCH_STOP signal=TERM role=tui pid=%s\n' "$pid"
      ss_signal "$proc_root" "$candidate" "$pid" tui TERM || { ss_fail tui_term_signal; return 1; }
      if ! ss_wait_gone "$proc_root" "$candidate" "$pid" tui 5; then
        ss_diagnostic "$proc_root" "$candidate" "$pid" tui || true
        [[ $force == true ]] || { ss_fail tui_still_running_after_term; return 1; }
        [[ $(ss_start_ticks "$proc_root" "$pid" 2>/dev/null) == "$initial_start" ]] || { ss_fail tui_pid_identity_changed; return 1; }
        state=$(ss_status_value "$proc_root" "$pid" State 2>/dev/null) || { ss_fail tui_state_unavailable; return 1; }
        [[ $state != D* ]] || { ss_fail tui_uninterruptible_state_no_kill; return 1; }
        ss_still_exact "$proc_root" "$candidate" "$pid" tui || { ss_fail tui_identity_changed_before_kill; return 1; }
        printf 'RESEARCH_STOP signal=KILL role=tui pid=%s explicit_force=true\n' "$pid"
        kill -s KILL -- "$pid" || { ss_fail tui_kill_signal; return 1; }
        ss_wait_gone "$proc_root" "$candidate" "$pid" tui 5 || { ss_diagnostic "$proc_root" "$candidate" "$pid" tui || true; ss_fail tui_still_running_after_kill; return 1; }
      fi
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
