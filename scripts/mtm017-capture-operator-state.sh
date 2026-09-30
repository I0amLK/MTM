#!/usr/bin/env bash
# Host-only transport of an explicitly selected, quiescent state directory.
# No SQLite connection, runtime launch, migration, secret output or release verdict.
set -euo pipefail
umask 077
export LC_ALL=C
# Never inherit an interpreter selection from the operator environment. Sourced
# fixture tests use the host tool; the isolated entry uses one explicit RO bind.
mtm_capture_awk=/usr/bin/awk

fail() { printf 'MTM017_COPY_CAPTURE_ERROR %s\n' "$1" >&2; exit 1; }

# Test-only cleanup. Never deletes captures or runtime rehearsal sessions.
mtm_fixture_mark() {
  [[ $root == /tmp/mtm-* && -d $root && ! -L $root && $(/usr/bin/stat -c %u:%a "$root") == "$UID:700" ]] || return 1
  fixture_identity=$(/usr/bin/stat -c %d:%i "$root") || return 1
  fixture_marker=$(/usr/bin/cat /proc/sys/kernel/random/uuid) || return 1
  printf '%s\n' "$fixture_marker" > "$root/.mtm017-fixture-owner"
}
mtm_fixture_cleanup() {
  if [[ $root == /tmp/mtm-* && -d $root && ! -L $root && $(/usr/bin/stat -c %u:%a:%d:%i "$root") == "$UID:700:$fixture_identity" && -f $root/.mtm017-fixture-owner && ! -L $root/.mtm017-fixture-owner && $(/usr/bin/stat -c %u:%h "$root/.mtm017-fixture-owner") == "$UID:1" && $(< "$root/.mtm017-fixture-owner") == "$fixture_marker" ]]; then
    /usr/bin/rm -rf --one-file-system -- "$root"
  else
    printf 'MTM017_COPY_DIAGNOSTIC stage=fixture_cleanup_identity_mismatch_retained\n' >&2
  fi
}

# Reject overlap through a differently named bind mount as well as plain paths.
# This transport deliberately requires both roots on the same containing mount.
mtm_roots_disjoint() {
  local a=$1 b=$2 at bt path ai bi
  at=$(/usr/bin/findmnt -n -T "$a" -o TARGET) || return 1
  bt=$(/usr/bin/findmnt -n -T "$b" -o TARGET) || return 1
  [[ $at == "$bt" ]] || return 1
  ai=$(/usr/bin/stat -c %d:%i "$a") && bi=$(/usr/bin/stat -c %d:%i "$b") || return 1
  path=$a
  while :; do
    [[ $(/usr/bin/stat -c %d:%i "$path") != "$bi" ]] || return 1
    [[ $path != / ]] || break
    path=${path%/*}; [[ -n $path ]] || path=/
  done
  path=$b
  while :; do
    [[ $(/usr/bin/stat -c %d:%i "$path") != "$ai" ]] || return 1
    [[ $path != / ]] || break
    path=${path%/*}; [[ -n $path ]] || path=/
  done
}

# Parse GNU tar's escaped, fixed-prefix verbose listing before extracting any
# bytes. Names with Unicode/newlines are escaped in one record; links, sparse
# over-limit sizes, duplicate names, parent traversal and special modes fail.
mtm_copy_archive_members_safe() {
  local listing
  listing=$(/usr/bin/mktemp /tmp/mtm017-archive-members.XXXXXXXX) || return 1
  if ! /usr/bin/tar --list --verbose --numeric-owner --full-time --quoting-style=escape --file="$1" > "$listing"; then
    /usr/bin/rm -f -- "$listing"; return 1
  fi
  local rc=0
  "$mtm_capture_awk" '
    function reject() { bad=1; exit 1 }
    {
      if (++n>20000 || $1 !~ /^[-d][rwx-]+$/ || length($1)!=10 || $3 !~ /^[0-9]+$/) reject()
      if ($3>134217728) reject()
      total+=$3; if(total>268435456) reject()
      name=$0; for(i=0;i<5;i++) sub(/^[^ ]+ +/,"",name)
      if (name !~ /^\.\// || name ~ /(^|\/)\.\.(\/|$)/ || name ~ /\/\.\// || name ~ /\/\// || seen[name]++) reject()
      depth=split(name,parts,"/"); if(depth>34) reject()
      if (n==1 && (name!="./" || substr($1,1,1)!="d")) reject()
    }
    END { if (bad || n<1) exit 1 }
  ' "$listing" || rc=$?
  /usr/bin/rm -f -- "$listing"
  return "$rc"
}

mtm_copy_tree_bounds() {
  local scan classifier_rc
  if [[ ! -f $mtm_capture_awk || ! -x $mtm_capture_awk ]]; then
    printf 'MTM017_COPY_BOUND_FAIL reason=classifier_unavailable entries=0 bytes=0\n' >&2
    return 1
  fi
  scan=$(/usr/bin/mktemp /tmp/mtm-tree-bounds.XXXXXXXX) || {
    printf 'MTM017_COPY_BOUND_FAIL reason=source_scan_error entries=0 bytes=0\n' >&2
    return 1
  }
  if ! /usr/bin/find "$1" -maxdepth 33 -printf '%y %s %n %m %d %D\n' > "$scan"; then
    printf 'MTM017_COPY_BOUND_FAIL reason=source_scan_error entries=0 bytes=0\n' >&2
    /usr/bin/rm -f -- "$scan"
    return 1
  fi
  if "$mtm_capture_awk" '
      function reject(reason) {
        if (!failed) {
          printf "MTM017_COPY_BOUND_FAIL reason=%s entries=%d bytes=%.0f\n", reason, n, total > "/dev/stderr"
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
      printf 'MTM017_COPY_BOUND_FAIL reason=classifier_execution_error entries=0 bytes=0\n' >&2
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
  local source=$1 destination=$2 helper=$3 mode=${4:?explicit_fixture_or_captured_mode_required} awk_executable
  [[ $mode == synthetic || $mode == captured ]] || return 1
  # /usr/bin/awk can point through /etc/alternatives, which is deliberately
  # absent from this namespace. Bind its resolved system executable, not /etc.
  awk_executable=$(/usr/bin/readlink -e /usr/bin/awk) || {
    printf 'MTM017_COPY_CAPTURE_ERROR capture_awk_unavailable\n' >&2; return 1
  }
  [[ $awk_executable == /usr/bin/* && -f $awk_executable && -x $awk_executable && ! -L $awk_executable ]] || {
    printf 'MTM017_COPY_CAPTURE_ERROR capture_awk_invalid\n' >&2; return 1
  }
  /usr/bin/timeout --signal=TERM --kill-after=5s 180s \
    /usr/bin/bwrap --unshare-all --new-session --die-with-parent --cap-drop ALL \
      --ro-bind /usr /usr --ro-bind /bin /bin --ro-bind /lib /lib \
      --ro-bind-try /lib64 /lib64 --dir /etc --ro-bind-try /etc/ld.so.cache /etc/ld.so.cache \
      --ro-bind "$awk_executable" /capture-awk \
      --ro-bind "$source" /source --bind "$destination" /capture \
      --ro-bind "$helper" /capture-script --tmpfs /tmp --proc /proc --dev /dev \
      --chdir /capture --clearenv --setenv PATH /usr/bin:/bin --setenv LC_ALL C \
      /bin/bash --noprofile --norc /capture-script --internal-readonly-capture "$mode"
}

# Sourcing loads only transport primitives for disposable-fixture tests.
# The actual host entry always requires explicit source selection and a RO mount.
if [[ ${BASH_SOURCE[0]} != "$0" ]]; then return 0; fi

if [[ ${1-} == --internal-readonly-capture ]]; then
  [[ $# == 2 && ( $2 == synthetic || $2 == captured ) ]] || fail invalid_internal_arguments
  mode=$2
  synthetic=false; [[ $mode != synthetic ]] || synthetic=true
  stage=capture_tools
  trap 'rc=$?; if (( rc != 0 )); then printf "MTM017_COPY_DIAGNOSTIC stage=%s\n" "$stage" >&2; fi' EXIT
  mtm_capture_awk=/capture-awk
  [[ -f $mtm_capture_awk && -x $mtm_capture_awk ]] || fail capture_awk_unavailable
  if ! awk_probe=$("$mtm_capture_awk" 'BEGIN { print 6*7 }') || [[ $awk_probe != 42 ]]; then
    fail capture_awk_probe_failed
  fi
  legacy_awk_visible=false
  if [[ -x /usr/bin/awk ]]; then legacy_awk_visible=true; fi
  printf 'MTM017_COPY_TOOLCHAIN awk_functional=true legacy_awk_visible=%s\n' "$legacy_awk_visible"
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
  printf '{\n  "schema":"mtm017-schema7-state-capture-v1",\n  "milestone":"MTM-017",\n  "capture_complete":true,\n  "source_selection":"explicitly_supplied",\n  "source_readonly_mount_observed":true,\n  "two_source_streams_identical":true,\n  "archive_sha256":"%s",\n  "entries":%s,\n  "source_file_bytes":%s,\n  "database_opened":false,\n  "transactional_snapshot_claimed":false,\n  "migration_executed":false,\n  "old_run_resumed":false,\n  "rollback_executed":false,\n  "raw_private_state_published":false,\n  "release_qualified":false,\n  "synthetic_only":%s,\n  "copied_operator_state_gate_passed":false,\n  "production_modified":false,\n  "selectors_modified":false\n}\n' "$first" "$entries" "$bytes" "$synthetic" > /capture/capture-summary.json
  /usr/bin/sync /capture/preupgrade.tar /capture/archive.sha256 /capture/capture-summary.json /capture
  exit 0
fi

# Real entry exists for a later separately authorized, quiescent capture only.
# No default source, HOME lookup, inherited MTM_DATA_ROOT, or automatic stop.
[[ $# == 5 && $1 == --source && $3 == --destination-parent && $5 == --operator-confirmed-quiescent ]] ||
  fail usage_explicit_source_private_destination_and_quiescence_required
[[ $2 == /* && $4 == /* ]] || fail absolute_paths_required
for program in /usr/bin/bwrap /usr/bin/timeout /usr/bin/tar /usr/bin/find /usr/bin/findmnt /usr/bin/awk /usr/bin/sha256sum /usr/bin/mktemp /usr/bin/readlink /usr/bin/rm /usr/bin/stat /usr/bin/sync; do
  [[ -x $program ]] || fail required_host_tool_missing
done
source=$(/usr/bin/readlink -e -- "$2") || fail source_unavailable
parent=$(/usr/bin/readlink -e -- "$4") || fail destination_unavailable
[[ $source == "$2" && $parent == "$4" && $source != / && ${parent##*/} == MTM-017 ]] || fail unsafe_or_noncanonical_root
[[ -d $source && -f $source/oauth.sqlite3 && -f $source/private/state.sqlite3 ]] || fail source_layout_unavailable_no_fallback
script=$(/usr/bin/readlink -e -- "${BASH_SOURCE[0]}")
repo=${script%/scripts/mtm017-capture-operator-state.sh}
[[ $repo != "$script" && -f $repo/Cargo.toml ]] || fail repository_not_found
[[ $parent != "$repo" && $parent != "$repo"/* && $repo != "$parent"/* ]] || fail archive_root_overlaps_repository
[[ $parent != "$source" && $parent != "$source"/* && $source != "$parent"/* ]] || fail overlapping_copy_root
mtm_roots_disjoint "$source" "$parent" || fail overlapping_or_aliased_copy_root
mtm_roots_disjoint "$repo" "$parent" || fail overlapping_or_aliased_repository
for directory in "$parent" "${parent%/*}"; do
  [[ -d $directory && ! -L $directory && $(/usr/bin/stat -c %u -- "$directory") == "$UID" && $(/usr/bin/stat -c %a -- "$directory") == 700 ]] || fail copy_parent_not_owner_private
done
candidate=$repo/target/mtm017-preview2/mtm-0.6.0-preview.2-13d7890c5c763199ed39295e134ff6cc735ceaa04eaddf6c556431a7a56254f4/mtm
baseline=$repo/target/mtm017-baselines/mtm-0.6.0-preview.1-f59cbddaebb8b9944d1365d6d4f1c072e2cc78e76dbbce8d870308c470c88034/mtm
check_artifacts() {
  printf '%s  %s\n' 13d7890c5c763199ed39295e134ff6cc735ceaa04eaddf6c556431a7a56254f4 "$candidate" f59cbddaebb8b9944d1365d6d4f1c072e2cc78e76dbbce8d870308c470c88034 "$baseline" | /usr/bin/sha256sum --check --status
}
check_artifacts || fail reviewed_artifact_mismatch
helper_before=$(/usr/bin/sha256sum "$script")
session=$(/usr/bin/mktemp -d -- "$parent/copied-state.XXXXXXXX")
# Failure diagnostics remain private. Only fixed categories may leave the session.
if ! mtm_copy_isolated_capture "$source" "$session" "$script" captured > "$session/process.stdout" 2> "$session/process.stderr"; then
  printf 'MTM017_COPY_CAPTURE_DIAGNOSTIC capture_complete=false\n'
  /usr/bin/grep -E '^MTM017_COPY_(CAPTURE_ERROR [a-z_]+|BOUND_FAIL reason=[a-z_]+ entries=[0-9]+ bytes=[0-9]+|DIAGNOSTIC stage=[a-z_]+)$' "$session/process.stderr" || true
  fail capture_failed_private_diagnostics_retained_no_retry
fi
check_artifacts || fail reviewed_artifact_changed
[[ $(/usr/bin/sha256sum "$script") == "$helper_before" ]] || fail helper_changed
( cd "$session"; /usr/bin/sha256sum --check --status archive.sha256 ) || fail archive_changed
printf '%s\n' "${helper_before%% *}" > "$session/capture-script.sha256"
/usr/bin/cat "$session/capture-summary.json"
