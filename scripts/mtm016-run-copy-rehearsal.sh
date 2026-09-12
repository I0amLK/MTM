#!/usr/bin/env bash
# Host launcher: synthetic first, then one explicitly selected captured archive.
# The production directory is never an accepted argument or a mount source.
set -euo pipefail
umask 077
export LC_ALL=C
repo=$(cd -- "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")/.." && /usr/bin/pwd -P)
helper=$repo/scripts/mtm016-rehearse-operator-copy.sh
inspector=$repo/scripts/mtm016-inspect-operator-copy.sh
transport=$repo/scripts/mtm016-capture-operator-state.sh
source "$inspector"
source "$helper"
# The captured mode must complete the reviewed synthetic namespace leg first.
mode=captured
if [[ $# == 3 && $1 == --synthetic && $2 == --sqlite ]]; then
  mode=synthetic; sqlite_arg=$3
elif [[ $# == 4 && $1 == --archive-sha256 && $3 == --sqlite && $2 == 2d448c5ba1a6f61f8139775c254ad85316b05bf82c0ff6c9d8a0f98805893d8e ]]; then
  sqlite_arg=$4
else
  r_fail usage_synthetic_or_explicit_reviewed_archive_and_sqlite
fi
[[ $sqlite_arg == /* ]] || r_fail sqlite_absolute_path
sqlite=$(/usr/bin/readlink -e -- "$sqlite_arg") || r_fail sqlite_unavailable
[[ $sqlite == */bin/sqlite3 && -f $sqlite && -x $sqlite && ! -L $sqlite ]] || r_fail sqlite_path
[[ $(/usr/bin/stat -c %a -- "$sqlite") =~ ^[0-7]{1,3}$ ]] || r_fail sqlite_special_mode
copy_sqlite=$sqlite
prefix=${sqlite%/bin/sqlite3}
[[ -d $prefix/lib ]] || r_fail sqlite_libraries
candidate=$repo/target/mtm016-f6-frozen/mtm-0.6.0-preview.1-$r_candidate_sha/mtm
baseline=$repo/target/mtm016-f3/baseline/mtm
[[ $(copy_digest "$candidate") == "$r_candidate_sha" && $(copy_digest "$baseline") == "$r_baseline_sha" ]] || r_fail reviewed_artifact_mismatch
[[ $(copy_digest "$transport") == 0072b4126bf5f55495863e35c0b501ad42e95222068222843da5cd81c9eb9e82 && $(copy_digest "$inspector") == da6aca5e0a4fec09fec6ffefe2d8d6c7630a7bd01b37ee5857e9de162e19d6ef ]] || r_fail reviewed_helpers_changed
for tool in /usr/bin/bwrap /usr/bin/timeout /usr/bin/curl /usr/bin/openssl /usr/bin/base64 /usr/bin/tr /usr/bin/awk; do [[ -x $tool ]] || r_fail host_tool_missing; done
awk_executable=$(/usr/bin/readlink -e /usr/bin/awk)
[[ $awk_executable == /usr/bin/* && -f $awk_executable && -x $awk_executable ]] || r_fail awk_path
inputs=("${BASH_SOURCE[0]}" "$helper" "$inspector" "$transport" "$sqlite" "$candidate" "$baseline" "$awk_executable" /usr/bin/curl /usr/bin/openssl)
before=$(/usr/bin/sha256sum -- "${inputs[@]}")
bindings=()
if [[ $mode == synthetic ]]; then
  destination=$(/usr/bin/mktemp -d /tmp/mtm-copy-rehearsal.XXXXXXXX)
else
  # This is not a retry: it is a distinct source-free prerequisite before even
  # locating the private capture. A failed prerequisite never launches captured mode.
  printf 'MTM_COPY_REHEARSAL_STAGE stage=synthetic_prerequisite\n'
  /bin/bash "${BASH_SOURCE[0]}" --synthetic --sqlite "$sqlite" || r_fail synthetic_prerequisite_failed
  [[ $(/usr/bin/sha256sum -- "${inputs[@]}") == "$before" ]] || r_fail prerequisite_input_changed
  home=$(/usr/bin/readlink -e -- "$HOME") || r_fail home_unavailable
  parent=$home/.mtm-acceptance/MTM-016
  copy_private_directory "$home/.mtm-acceptance" && copy_private_directory "$parent" || r_fail private_capture_parent
  shopt -s nullglob
  sessions=("$parent"/copied-state.*)
  (( ${#sessions[@]} > 0 && ${#sessions[@]} <= 128 )) || r_fail capture_session_count
  matches=0; selected=
  for session in "${sessions[@]}"; do
    copy_private_directory "$session" || r_fail session_not_private
    [[ -f $session/archive.sha256 && -f $session/capture-summary.json ]] || continue
    copy_regular_input "$session/archive.sha256" 256 || r_fail digest_file
    read -r digest name < "$session/archive.sha256" || r_fail digest_file
    [[ $digest == 2d448c5ba1a6f61f8139775c254ad85316b05bf82c0ff6c9d8a0f98805893d8e && $name == preupgrade.tar ]] || continue
    selected=$session; matches=$((matches+1))
  done
  (( matches == 1 )) || r_fail ambiguous_or_missing_capture
  copy_regular_input "$selected/preupgrade.tar" 536870912 && copy_regular_input "$selected/capture-summary.json" 16384 || r_fail capture_inputs
  [[ $(/usr/bin/stat -c %a "$selected/preupgrade.tar") == 400 && $(copy_digest "$selected/preupgrade.tar") == 2d448c5ba1a6f61f8139775c254ad85316b05bf82c0ff6c9d8a0f98805893d8e ]] || r_fail archive_identity
  copy_regular_input "$selected/capture-script.sha256" 128 || r_fail capture_provenance
  read -r captured_helper < "$selected/capture-script.sha256"
  [[ $captured_helper == 0072b4126bf5f55495863e35c0b501ad42e95222068222843da5cd81c9eb9e82 ]] || r_fail capture_provenance
  inputs+=("$selected/preupgrade.tar" "$selected/capture-summary.json")
  before=$(/usr/bin/sha256sum -- "${inputs[@]}")
  destination=$(/usr/bin/mktemp -d -- "$selected/rehearsal.XXXXXXXX")
  bindings=(--ro-bind "$selected/preupgrade.tar" /input/preupgrade.tar --ro-bind "$selected/capture-summary.json" /input/capture-summary.json)
fi
# New network namespace has only loopback. No public listener, tunnel, host
# network, real home, other process roots, production tree or install selector.
rc=0
/usr/bin/timeout --signal=TERM --kill-after=5s 240s \
  /usr/bin/bwrap --unshare-all --new-session --die-with-parent --cap-drop ALL \
    --ro-bind /usr /usr --ro-bind /bin /bin --ro-bind /lib /lib --ro-bind-try /lib64 /lib64 \
    --dir /etc --ro-bind-try /etc/ld.so.cache /etc/ld.so.cache \
    --ro-bind "$awk_executable" /capture-awk \
    --ro-bind "$sqlite" /opt/copy-sqlite/bin/sqlite3 --ro-bind "$prefix/lib" /opt/copy-sqlite/lib \
    --ro-bind "$helper" /rehearsal-script --ro-bind "$inspector" /inspect-script --ro-bind "$transport" /capture-script \
    --ro-bind "$candidate" /candidate --ro-bind "$baseline" /baseline "${bindings[@]}" \
    --bind "$destination" /work --tmpfs /tmp --proc /proc --dev /dev \
    --chdir /work --clearenv --setenv PATH /usr/bin:/bin --setenv LC_ALL C --setenv HOME /tmp \
    /bin/bash --noprofile --norc /rehearsal-script --internal "$mode" \
      > "$destination/process.stdout" 2> "$destination/process.stderr" || rc=$?
if (( rc != 0 )); then
  printf 'rehearsal_complete=false synthetic_only=%s exit_code=%s\n' "$([[ $mode == synthetic ]] && printf true || printf false)" "$rc"
  if /usr/bin/grep -Fq 'bwrap: Creating new namespace failed:' "$destination/process.stderr"; then printf 'MTM_COPY_REHEARSAL_DIAGNOSTIC stage=namespace_setup\n'; fi
  /usr/bin/grep -E '^MTM_COPY_(REHEARSAL_(ERROR reason|DIAGNOSTIC stage)=[a-z_]+|INSPECT_(ERROR reason|DIAGNOSTIC stage)=[a-z_]+|BOUND_FAIL reason=[a-z_]+ entries=[0-9]+ bytes=[0-9]+)$' "$destination/process.stderr" || true
  r_fail bounded_rehearsal_failed_no_retry
fi
[[ $(/usr/bin/sha256sum -- "${inputs[@]}") == "$before" ]] || r_fail host_input_changed
copy_regular_input "$destination/rehearsal-summary.json" 16384 || r_fail missing_summary
summary_archive=$(r_doc "$destination/rehearsal-summary.json" "json_extract(j,'$.archive_sha256')") || r_fail summary_archive_missing
if [[ $mode == captured ]]; then
  [[ $summary_archive == 2d448c5ba1a6f61f8139775c254ad85316b05bf82c0ff6c9d8a0f98805893d8e ]] || r_fail summary_archive_identity
else
  [[ $(copy_digest "$destination/synthetic-preupgrade.tar") == "$summary_archive" ]] || r_fail synthetic_archive_identity
fi
r_validate_summary "$destination/rehearsal-summary.json" "$mode" "$summary_archive" || r_fail summary_validation
printf '%s\n' "$before" > "$destination/input-identities.sha256"
/usr/bin/cat "$destination/rehearsal-summary.json"
printf 'NEXT: retain private working copies and archive; this report alone does not authorize release.\n'
