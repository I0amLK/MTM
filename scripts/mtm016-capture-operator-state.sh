#!/usr/bin/env bash
# Host-only transport of an explicitly selected, quiescent state directory.
# No SQLite connection, runtime launch, migration, secret output or release verdict.
set -euo pipefail
umask 077
export LC_ALL=C
# Never inherit an interpreter selection from the operator environment. Sourced
# fixture tests use the host tool; the isolated entry uses one explicit RO bind.
mtm_capture_awk=/usr/bin/awk

fail() { printf 'MTM_COPY_CAPTURE_ERROR %s\n' "$1" >&2; exit 1; }

mtm_copy_tree_bounds() {
  local scan classifier_rc
  if [[ ! -f $mtm_capture_awk || ! -x $mtm_capture_awk ]]; then
    printf 'MTM_COPY_BOUND_FAIL reason=classifier_unavailable entries=0 bytes=0\n' >&2
    return 1
  fi
  scan=$(/usr/bin/mktemp /tmp/mtm-tree-bounds.XXXXXXXX) || {
    printf 'MTM_COPY_BOUND_FAIL reason=source_scan_error entries=0 bytes=0\n' >&2
    return 1
  }
  if ! /usr/bin/find "$1" -maxdepth 33 -printf '%y %s %n %m %d %D\n' > "$scan"; then
    printf 'MTM_COPY_BOUND_FAIL reason=source_scan_error entries=0 bytes=0\n' >&2
    /usr/bin/rm -f -- "$scan"
    return 1
  fi
  if "$mtm_capture_awk" '
      function reject(reason) {
        if (!failed) {
          printf "MTM_COPY_BOUND_FAIL reason=%s entries=%d bytes=%.0f\n", reason, n, total > "/dev/stderr"
        }
        failed=1
        exit 10
      }
      NR == 1 { device=$6 }
      {
        n++
        if (n>20000) reject("entry_limit")
        if ($5>=33) reject("depth_limit")
        if ($6!=device) reject("cross_device")
        if (length($4)>3) reject("special_mode")
        if ($1 != "f" && $1 != "d") reject("unsupported_file_type")
        if ($1 == "f") {
          if ($3!=1) reject("regular_file_hardlink")
          if ($2>134217728) reject("single_file_size")
          total+=$2
          if(total>268435456) reject("total_file_size")
        }
      }
      END { if(!failed) printf "%d %.0f\n", n, total }
    ' "$scan"; then
    :
  else
    classifier_rc=$?
    # Exit 10 means the classifier already emitted a fixed metadata rejection.
    # Missing loaders, execution errors and parser crashes are NOT tree bounds.
    if (( classifier_rc != 10 )); then
      printf 'MTM_COPY_BOUND_FAIL reason=classifier_execution_error entries=0 bytes=0\n' >&2
    fi
    /usr/bin/rm -f -- "$scan"
    return 1
  fi
  /usr/bin/rm -f -- "$scan"
}

mtm_copy_archive() {
  # Stable PAX names must not contain tar's process ID. Do not exclude WAL,
  # SHM, journals, keys, debug files or other state from the private archive.
  /usr/bin/tar --sort=name --format=posix \
    --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
    --numeric-owner --atime-preserve=system -C "$1" -cf - .
}

mtm_vfs_options_are_readonly() {
  local options=${1-}
  local item
  IFS=',' read -r -a items <<< "$options"
  for item in "${items[@]}"; do
    [[ $item == ro ]] && return 0
  done
  return 1
}

mtm_mount_is_readonly() {
  local options
  options=$(/usr/bin/findmnt -n -M "$1" -o VFS-OPTIONS) || return 1
  mtm_vfs_options_are_readonly "$options"
}

mtm_copy_isolated_capture() {
  local source=$1 destination=$2 helper=$3 awk_executable
  # /usr/bin/awk can point through /etc/alternatives, which is deliberately
  # absent from this namespace. Bind its resolved system executable, not /etc.
  awk_executable=$(/usr/bin/readlink -e /usr/bin/awk) || {
    printf 'MTM_COPY_CAPTURE_ERROR capture_awk_unavailable\n' >&2; return 1
  }
  [[ $awk_executable == /usr/bin/* && -f $awk_executable && -x $awk_executable && ! -L $awk_executable ]] || {
    printf 'MTM_COPY_CAPTURE_ERROR capture_awk_invalid\n' >&2; return 1
  }
  /usr/bin/timeout --signal=TERM --kill-after=5s 180s \
    /usr/bin/bwrap --unshare-all --new-session --die-with-parent --cap-drop ALL \
      --ro-bind /usr /usr --ro-bind /bin /bin --ro-bind /lib /lib \
      --ro-bind-try /lib64 /lib64 --dir /etc --ro-bind-try /etc/ld.so.cache /etc/ld.so.cache \
      --ro-bind "$awk_executable" /capture-awk \
      --ro-bind "$source" /source --bind "$destination" /capture \
      --ro-bind "$helper" /capture-script --tmpfs /tmp --proc /proc --dev /dev \
      --chdir /capture --clearenv --setenv PATH /usr/bin:/bin --setenv LC_ALL C \
      /bin/bash --noprofile --norc /capture-script --internal-readonly-capture
}

# Sourcing loads only transport primitives for disposable-fixture tests.
# The actual host entry always requires explicit source selection and a RO mount.
if [[ ${BASH_SOURCE[0]} != "$0" ]]; then return 0; fi

if [[ ${1-} == --internal-readonly-capture ]]; then
  [[ $# == 1 ]] || fail invalid_internal_arguments
  stage=capture_tools
  trap 'rc=$?; if (( rc != 0 )); then printf "MTM_COPY_DIAGNOSTIC stage=%s\n" "$stage" >&2; fi' EXIT
  mtm_capture_awk=/capture-awk
  [[ -f $mtm_capture_awk && -x $mtm_capture_awk ]] || fail capture_awk_unavailable
  if ! awk_probe=$("$mtm_capture_awk" 'BEGIN { print 6*7 }') || [[ $awk_probe != 42 ]]; then
    fail capture_awk_probe_failed
  fi
  legacy_awk_visible=false
  if [[ -x /usr/bin/awk ]]; then legacy_awk_visible=true; fi
  printf 'MTM_COPY_TOOLCHAIN awk_functional=true legacy_awk_visible=%s\n' "$legacy_awk_visible"
  stage=readonly_mount_options
  mtm_mount_is_readonly /source
  stage=readonly_mount_layout
  [[ -f /source/oauth.sqlite3 && -f /source/private/state.sqlite3 ]]
  # A hard limit on each generated archive; no automatic retry or limit increase.
  ulimit -f 524288
  stage=source_bounds
  mtm_copy_tree_bounds /source > /capture/tree-before.txt
  stage=first_copy
  mtm_copy_archive /source > /capture/preupgrade.partial.tar
  stage=source_stability
  mtm_copy_archive /source | /usr/bin/sha256sum > /capture/second-stream.sha256
  /usr/bin/sha256sum /capture/preupgrade.partial.tar > /capture/first-archive.sha256
  read -r first _ < /capture/first-archive.sha256
  read -r second _ < /capture/second-stream.sha256
  [[ $first =~ ^[0-9a-f]{64}$ && $first == "$second" ]]
  mtm_copy_tree_bounds /source > /capture/tree-after.txt
  /usr/bin/cmp -s /capture/tree-before.txt /capture/tree-after.txt
  read -r entries bytes < /capture/tree-after.txt
  stage=seal_capture
  /usr/bin/mv -T /capture/preupgrade.partial.tar /capture/preupgrade.tar
  /usr/bin/chmod 400 /capture/preupgrade.tar
  printf '%s  preupgrade.tar\n' "$first" > /capture/archive.sha256
  # This is capture evidence, deliberately NOT copied_operator_state acceptance.
  printf '{\n  "schema":"mtm-operator-state-capture-v1",\n  "milestone":"MTM-016",\n  "capture_complete":true,\n  "source_selection":"operator_supplied",\n  "source_readonly_mount_observed":true,\n  "two_source_streams_identical":true,\n  "archive_sha256":"%s",\n  "entries":%s,\n  "source_file_bytes":%s,\n  "database_opened":false,\n  "transactional_snapshot_claimed":false,\n  "migration_executed":false,\n  "old_run_resumed":false,\n  "rollback_executed":false,\n  "raw_private_state_published":false,\n  "release_qualified":false\n}\n' "$first" "$entries" "$bytes" > /capture/capture-summary.json
  /usr/bin/sync /capture/preupgrade.tar /capture/archive.sha256 /capture/capture-summary.json /capture
  exit 0
fi

[[ $# == 3 && $1 == --source && $3 == --operator-confirmed-quiescent ]] ||
  fail 'usage: bash scripts/mtm016-capture-operator-state.sh --source ABSOLUTE_DATA_ROOT --operator-confirmed-quiescent'
[[ $2 == /* && ${HOME-} == /* ]] || fail absolute_paths_required
for program in /usr/bin/bwrap /usr/bin/timeout /usr/bin/tar /usr/bin/find /usr/bin/findmnt /usr/bin/awk /usr/bin/sha256sum /usr/bin/mktemp /usr/bin/readlink /usr/bin/rm /usr/bin/stat /usr/bin/sync; do
  [[ -x $program ]] || fail required_host_tool_missing
done
source=$(/usr/bin/readlink -e -- "$2") || fail source_unavailable
home=$(/usr/bin/readlink -e -- "$HOME") || fail home_unavailable
[[ ! -L $2 && -d $source && -f $source/oauth.sqlite3 && -f $source/private/state.sqlite3 ]] ||
  fail source_layout_unavailable_no_fallback
[[ $source != / && $source != "$home" ]] || fail unsafe_source_root
script=$(/usr/bin/readlink -e -- "${BASH_SOURCE[0]}")
repo=${script%/scripts/mtm016-capture-operator-state.sh}
[[ $repo != "$script" && -f $repo/Cargo.toml ]] || fail repository_not_found
candidate_rel=target/mtm016-f5-frozen/mtm-0.6.0-preview.1-46c1441b824d6cc311a276ff34fda888c36223ebf5c98f8ca65ce26570df9724/mtm
check_artifacts() {
  ( cd "$repo"
    printf '%s\n' \
      "46c1441b824d6cc311a276ff34fda888c36223ebf5c98f8ca65ce26570df9724  $candidate_rel" \
      '2164c84701b191b06a66a5d28ba595697d355f9a3bdc78ca31ea455d49793d6a  target/mtm016-f3/baseline/mtm' |
      /usr/bin/sha256sum --check --status
  )
}
check_artifacts || fail reviewed_artifact_mismatch

# Outside the repository and outside Native PATH-discovered toolchain roots.
# Never use $MTM_DATA_ROOT inherited from the earlier browser test as a default.
parent=$home/.mtm-acceptance/MTM-016
[[ $parent != "$source" && $parent != "$source"/* && $source != "$parent"/* ]] || fail overlapping_copy_root
for directory in "$home/.mtm-acceptance" "$parent"; do
  [[ ! -L $directory ]] || fail copy_parent_is_symlink
  if [[ ! -e $directory ]]; then /usr/bin/mkdir -m 700 -- "$directory"; fi
  [[ -d $directory && $(/usr/bin/stat -c %u -- "$directory") == "$UID" && $(/usr/bin/stat -c %a -- "$directory") == 700 ]] ||
    fail copy_parent_not_owner_private
done
session=$(/usr/bin/mktemp -d -- "$parent/copied-state.XXXXXXXX")
# Keep failure diagnostics private too. No live-service stop, process attachment,
# /proc/<other-pid>/root access or alternative path into the hidden Native vault.
if ! mtm_copy_isolated_capture "$source" "$session" "$script" \
    > "$session/process.stdout" 2> "$session/process.stderr"; then
  printf 'capture_complete=false\nprivate_session=%s\n' "$session"
  /usr/bin/grep -E '^MTM_COPY_CAPTURE_ERROR capture_awk_(unavailable|invalid|probe_failed)$' "$session/process.stderr" || true
  /usr/bin/grep -E '^MTM_COPY_BOUND_FAIL reason=(classifier_unavailable|classifier_execution_error|source_scan_error|entry_limit|depth_limit|cross_device|special_mode|unsupported_file_type|regular_file_hardlink|single_file_size|total_file_size) entries=[0-9]+ bytes=[0-9]+$' "$session/process.stderr" || true
  /usr/bin/grep -E '^MTM_COPY_DIAGNOSTIC stage=[a-z_]+$' "$session/process.stderr" || true
  fail capture_failed_private_diagnostics_retained_no_retry
fi
check_artifacts || fail reviewed_artifact_changed
( cd "$session"; /usr/bin/sha256sum --check --status archive.sha256 ) || fail archive_changed
/usr/bin/sha256sum "$script" | /usr/bin/awk '{print $1}' > "$session/capture-script.sha256"
printf 'private_session=%s\n' "$session"
/usr/bin/cat "$session/capture-summary.json"
printf 'NEXT: retain this private archive; do not upload it or start a runtime against the production source.\n'
