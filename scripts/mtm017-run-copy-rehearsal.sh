#!/usr/bin/env bash
# Host launcher: synthetic first, then one explicitly selected captured archive.
# The production directory is never an accepted argument or a mount source.
set -euo pipefail
umask 077
export LC_ALL=C
repo=$(cd -- "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")/.." && /usr/bin/pwd -P)
helper=$repo/scripts/mtm017-rehearse-operator-copy.sh
inspector=$repo/scripts/mtm017-inspect-operator-copy.sh
transport=$repo/scripts/mtm017-capture-operator-state.sh
source "$inspector"
source "$helper"
# The captured mode must complete the reviewed synthetic namespace leg first.
mode=captured
if [[ $# == 3 && $1 == --synthetic && $2 == --sqlite ]]; then
  mode=synthetic; sqlite_arg=$3
elif [[ $# == 7 && $1 == --captured && $2 == --session && $4 == --archive-sha256 && $6 == --sqlite ]]; then
  mode=captured; selected=$3; expected=$5; sqlite_arg=$7
  [[ $expected =~ ^[0-9a-f]{64}$ ]] || r_fail archive_digest
else
  r_fail usage_synthetic_or_explicit_reviewed_archive_and_sqlite
fi
[[ $sqlite_arg == /* ]] || r_fail sqlite_absolute_path
sqlite=$(/usr/bin/readlink -e -- "$sqlite_arg") || r_fail sqlite_unavailable
[[ $sqlite == "$sqlite_arg" && $sqlite == */bin/sqlite3 && -f $sqlite && -x $sqlite && ! -L $sqlite ]] || r_fail sqlite_path
[[ $(/usr/bin/stat -c %a -- "$sqlite") =~ ^[0-7]{1,3}$ ]] || r_fail sqlite_special_mode
copy_sqlite=$sqlite
prefix=${sqlite%/bin/sqlite3}
[[ -d $prefix/lib ]] || r_fail sqlite_libraries
candidate=$repo/target/mtm017-preview2/mtm-0.6.0-preview.2-$r_candidate_sha/mtm
baseline=$repo/target/mtm017-baselines/mtm-0.6.0-preview.1-$r_baseline_sha/mtm
[[ $(copy_digest "$candidate") == "$r_candidate_sha" && $(copy_digest "$baseline") == "$r_baseline_sha" ]] || r_fail reviewed_artifact_mismatch
for tool in /usr/bin/bwrap /usr/bin/timeout /usr/bin/curl /usr/bin/openssl /usr/bin/base64 /usr/bin/tr /usr/bin/awk; do [[ -x $tool ]] || r_fail host_tool_missing; done
awk_executable=$(/usr/bin/readlink -e /usr/bin/awk)
[[ $awk_executable == /usr/bin/* && -f $awk_executable && -x $awk_executable ]] || r_fail awk_path
inputs=("${BASH_SOURCE[0]}" "$helper" "$inspector" "$transport" "$sqlite" "$candidate" "$baseline" "$awk_executable" /usr/bin/curl /usr/bin/openssl)
for input in "$helper" "$inspector" "$transport" "$candidate" "$baseline"; do
  [[ $(/usr/bin/readlink -e -- "$input") == "$input" && $(/usr/bin/stat -c %a "$input") =~ ^[0-7]{1,3}$ ]] || r_fail noncanonical_or_special_input
  copy_regular_input "$input" 134217728 || r_fail nonregular_or_linked_input
done
before=$(/usr/bin/sha256sum -- "${inputs[@]}")
decision=$repo/records/evidence/MTM-017/operator-copy-prepared-continuation-authorization-20260930.json
strict_failure=$repo/records/evidence/MTM-017/operator-copy-real-rehearsal-attempt-1-failed-20260930.json
copy_regular_input "$decision" 16384 && copy_regular_input "$strict_failure" 16384 || r_fail acceptance_adjustment_input
[[ $(copy_digest "$decision") == 953be5aa5bfa3632408f66264e129b184219ce09c8ecd5de91ee93e608ee0933 && $(copy_digest "$strict_failure") == 2fbc819765e920a8ce89ad4f94317a26275b3701c785fe2fa9e2ffee4fbd67d0 ]] || r_fail acceptance_adjustment_identity
inputs+=("$decision" "$strict_failure")
before=$(/usr/bin/sha256sum -- "${inputs[@]}")
bindings=()
if [[ $mode == synthetic ]]; then
  destination=$(/usr/bin/mktemp -d /tmp/mtm017-copy-rehearsal.XXXXXXXX)
else
  # This is not a retry: it is a distinct source-free prerequisite before even
  # locating the private capture. A failed prerequisite never launches captured mode.
  printf 'MTM017_COPY_REHEARSAL_STAGE stage=synthetic_prerequisite\n'
  /bin/bash "${BASH_SOURCE[0]}" --synthetic --sqlite "$sqlite" || r_fail synthetic_prerequisite_failed
  [[ $(/usr/bin/sha256sum -- "${inputs[@]}") == "$before" ]] || r_fail prerequisite_input_changed
  [[ $selected == /* && $(/usr/bin/readlink -e -- "$selected") == "$selected" ]] || r_fail session_noncanonical_or_linked
  parent=${selected%/*}
  [[ ${parent##*/} == MTM-017 && ${selected##*/} == copied-state.* ]] || r_fail session_namespace
  [[ $selected != "$repo" && $selected != "$repo"/* && $repo != "$selected"/* ]] || r_fail session_overlaps_repository
  copy_private_directory "$selected" && copy_private_directory "$parent" && copy_private_directory "${parent%/*}" || r_fail capture_private_ancestors
  copy_regular_input "$selected/preupgrade.tar" 536870912 && copy_regular_input "$selected/capture-summary.json" 16384 || r_fail capture_inputs
  [[ $(/usr/bin/stat -c %a "$selected/preupgrade.tar") == 400 && $(copy_digest "$selected/preupgrade.tar") == "$expected" ]] || r_fail archive_identity
  copy_regular_input "$selected/capture-script.sha256" 128 || r_fail capture_provenance
  read -r captured_helper < "$selected/capture-script.sha256"
  [[ $captured_helper == "$(copy_digest "$transport")" ]] || r_fail capture_provenance
  copy_validate_receipt "$selected/capture-summary.json" "$expected" captured || r_fail capture_receipt
  inputs+=("$selected/preupgrade.tar" "$selected/capture-summary.json" "$selected/capture-script.sha256")
  before=$(/usr/bin/sha256sum -- "${inputs[@]}")
  destination=$(/usr/bin/mktemp -d -- "$selected/rehearsal.XXXXXXXX")
  printf '%s\n' "$expected" > "$destination/archive-digest"
  bindings=(--ro-bind "$selected/preupgrade.tar" /input/preupgrade.tar --ro-bind "$selected/capture-summary.json" /input/capture-summary.json --ro-bind "$destination/archive-digest" /input/archive-digest)
fi
# Retain all private working copies and failures; no recursive cleanup.
printf 'mtm017-schema8-copy-rehearsal-v2\n' > "$destination/session-kind"
printf '%s\n' "$mode" > "$destination/fixture-mode"
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
  if /usr/bin/grep -Fq 'bwrap: Creating new namespace failed:' "$destination/process.stderr"; then printf 'MTM017_COPY_REHEARSAL_DIAGNOSTIC stage=namespace_setup\n'; fi
  /usr/bin/grep -E '^MTM017_COPY_(REHEARSAL_(ERROR reason|DIAGNOSTIC stage)=[a-z_]+|INSPECT_(ERROR reason|DIAGNOSTIC stage)=[a-z_]+|BOUND_FAIL reason=[a-z_]+ entries=[0-9]+ bytes=[0-9]+)$' "$destination/process.stderr" || true
  r_fail bounded_rehearsal_failed_no_retry
fi
[[ $(/usr/bin/sha256sum -- "${inputs[@]}") == "$before" ]] || r_fail host_input_changed
copy_regular_input "$destination/rehearsal-summary.json" 16384 || r_fail missing_summary
summary_archive=$(r_doc "$destination/rehearsal-summary.json" "json_extract(j,'$.archive_sha256')") || r_fail summary_archive_missing
if [[ $mode == captured ]]; then
  [[ $summary_archive == "$expected" ]] || r_fail summary_archive_identity
else
  [[ $(copy_digest "$destination/synthetic-preupgrade.tar") == "$summary_archive" ]] || r_fail synthetic_archive_identity
fi
r_validate_summary "$destination/rehearsal-summary.json" "$mode" "$summary_archive" || r_fail summary_validation
printf '%s\n' "$before" > "$destination/input-identities.sha256"
/usr/bin/cat "$destination/rehearsal-summary.json"

