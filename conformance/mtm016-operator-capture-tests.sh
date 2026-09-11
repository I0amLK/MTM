#!/usr/bin/env bash
# Transport-only regressions on self-created disposable bytes, never real state.
set -euo pipefail
[[ $# == 0 || ( $# == 1 && $1 == --host-isolation ) ]] || {
  printf 'TRANSPORT_TEST invalid_arguments\n' >&2; exit 1
}
host_isolation=${1-}
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
script=$repo/scripts/mtm016-capture-operator-state.sh
source "$script"
mtm_vfs_options_are_readonly 'ro,nosuid,nodev'
mtm_vfs_options_are_readonly 'nosuid,ro,nodev'
if mtm_vfs_options_are_readonly 'rw,nosuid,nodev'; then
  printf 'TRANSPORT_TEST writable_vfs_options_unexpectedly_accepted\n' >&2
  exit 1
fi
if mtm_vfs_options_are_readonly 'errors=remount-ro,rw'; then
  printf 'TRANSPORT_TEST substring_ro_unexpectedly_accepted\n' >&2
  exit 1
fi
printf 'TRANSPORT_TEST readonly_vfs_option_parser=passed\n'
root=$(/usr/bin/mktemp -d /tmp/mtm-capture-test.XXXXXXXX)
trap '/usr/bin/rm -rf -- "$root"' EXIT
/usr/bin/mkdir -m 700 "$root/tree" "$root/tree/private" "$root/restored" "$root/home"
printf 'synthetic oauth\n' > "$root/tree/oauth.sqlite3"
printf 'synthetic state\n' > "$root/tree/private/state.sqlite3"
printf 'synthetic wal\n' > "$root/tree/private/state.sqlite3-wal"
printf 'synthetic shm\n' > "$root/tree/private/state.sqlite3-shm"
printf 'synthetic key\n' > "$root/tree/oauth-token-secret.hex"
printf 'UTF-8 and newline name\n' > "$root/tree/含 空格"$'\n'"name"
mtm_copy_tree_bounds "$root/tree" > "$root/bounds"
mtm_copy_archive "$root/tree" > "$root/a.tar"
mtm_copy_archive "$root/tree" > "$root/b.tar"
/usr/bin/cmp -s "$root/a.tar" "$root/b.tar"
/usr/bin/tar -xf "$root/a.tar" -C "$root/restored"
/usr/bin/diff -r "$root/tree" "$root/restored"
[[ $(/usr/bin/stat -c %a "$root/restored/private") == 700 ]]
mtm_copy_archive "$root/restored" > "$root/restored.tar"
/usr/bin/cmp -s "$root/a.tar" "$root/restored.tar"
printf 'changed\n' >> "$root/tree/private/state.sqlite3"
mtm_copy_archive "$root/tree" > "$root/c.tar"
if /usr/bin/cmp -s "$root/a.tar" "$root/c.tar"; then exit 1; fi
printf 'TRANSPORT_TEST deterministic_stream_and_content_drift=passed\n'
printf 'TRANSPORT_TEST private_keys_wal_shm_names_and_modes_preserved=passed\n'

reject_tree() {
  expected=$1
  if mtm_copy_tree_bounds "$root/tree" > /dev/null 2> "$root/reject.log"; then
    printf 'TRANSPORT_TEST unexpected_tree_acceptance\n' >&2; exit 1
  fi
  grep -qx "MTM_COPY_BOUND_FAIL reason=$expected entries=[0-9][0-9]* bytes=[0-9][0-9]*" "$root/reject.log"
}
/usr/bin/ln -s oauth.sqlite3 "$root/tree/link"
reject_tree unsupported_file_type
/usr/bin/rm "$root/tree/link"
/usr/bin/ln "$root/tree/oauth.sqlite3" "$root/tree/hardlink"
reject_tree regular_file_hardlink
/usr/bin/rm "$root/tree/hardlink"
/usr/bin/mkfifo "$root/tree/fifo"
reject_tree unsupported_file_type
/usr/bin/rm "$root/tree/fifo"
/usr/bin/chmod 1700 "$root/tree/private"
reject_tree special_mode
/usr/bin/chmod 700 "$root/tree/private"
/usr/bin/truncate -s 134217729 "$root/tree/oversized"
reject_tree single_file_size
/usr/bin/rm "$root/tree/oversized"
/usr/bin/truncate -s 134217728 "$root/tree/large-a" "$root/tree/large-b"
reject_tree total_file_size
/usr/bin/rm "$root/tree/large-a" "$root/tree/large-b"
deep=$root/tree
for ((i=0; i<33; i++)); do deep=$deep/d; /usr/bin/mkdir "$deep"; done
reject_tree depth_limit
/usr/bin/rm -rf "$root/tree/d"
printf 'TRANSPORT_TEST seven_unsafe_or_oversized_trees_rejected=passed\n'
read -r existing _ < "$root/bounds"
/usr/bin/mkdir "$root/tree/many"
for ((i=existing+1; i<20000; i++)); do : > "$root/tree/many/$i"; done
mtm_copy_tree_bounds "$root/tree" > /dev/null
: > "$root/tree/many/one-more"
reject_tree entry_limit
/usr/bin/rm -rf "$root/tree/many"
printf 'TRANSPORT_TEST entry_limit_exact_boundary=passed\n'

if mtm_copy_tree_bounds "$root/does-not-exist" > /dev/null 2> "$root/scan-error.log"; then
  printf 'TRANSPORT_TEST missing_tree_unexpectedly_accepted\n' >&2
  exit 1
fi
grep -qx 'MTM_COPY_BOUND_FAIL reason=source_scan_error entries=0 bytes=0' "$root/scan-error.log"
printf 'TRANSPORT_TEST source_scan_error_category=passed\n'

# The former code always invoked /usr/bin/awk. Primitive tests on the host
# therefore missed a broken alternatives link inside the capture namespace.
/usr/bin/ln -s "$root/absent-alternatives/awk" "$root/broken-awk"
if (mtm_capture_awk=$root/broken-awk; mtm_copy_tree_bounds "$root/tree") > "$root/awk-out" 2> "$root/awk-error"; then
  printf 'TRANSPORT_TEST unavailable_classifier_unexpectedly_accepted\n' >&2; exit 1
fi
[[ ! -s $root/awk-out ]]
grep -qx 'MTM_COPY_BOUND_FAIL reason=classifier_unavailable entries=0 bytes=0' "$root/awk-error"
if (mtm_capture_awk=/usr/bin/false; mtm_copy_tree_bounds "$root/tree") > "$root/awk-out" 2> "$root/awk-error"; then
  printf 'TRANSPORT_TEST failed_classifier_unexpectedly_accepted\n' >&2; exit 1
fi
[[ ! -s $root/awk-out ]]
grep -qx 'MTM_COPY_BOUND_FAIL reason=classifier_execution_error entries=0 bytes=0' "$root/awk-error"
canonical_awk=$(/usr/bin/readlink -e /usr/bin/awk)
(mtm_capture_awk=$canonical_awk; mtm_copy_tree_bounds "$root/tree") > "$root/canonical-bounds"
mtm_copy_tree_bounds "$root/tree" > "$root/default-bounds"
/usr/bin/cmp -s "$root/canonical-bounds" "$root/default-bounds"
printf 'TRANSPORT_TEST classifier_missing_failed_and_canonical=passed\n'

if /bin/bash "$script" > "$root/invalid.log" 2>&1; then exit 1; fi
if /usr/bin/env HOME="$root/home" /bin/bash "$script" --source "$root/missing" --operator-confirmed-quiescent > "$root/missing.log" 2>&1; then exit 1; fi
[[ ! -e $root/home/.mtm-acceptance ]]
if /bin/bash "$script" --internal-readonly-capture > "$root/unguarded.log" 2>&1; then exit 1; fi
printf 'TRANSPORT_TEST malformed_missing_source_and_missing_ro_mount_rejected=passed\n'
if [[ $host_isolation == --host-isolation ]]; then
  # Same namespace constructor and internal entry as real capture. Only this
  # test's self-created tree and output directories can be supplied here.
  /usr/bin/mkdir -m 700 "$root/isolated-good" "$root/isolated-bad"
  isolated_rc=0
  mtm_copy_isolated_capture "$root/tree" "$root/isolated-good" "$script" > "$root/host-out" 2> "$root/host-error" || isolated_rc=$?
  if (( isolated_rc != 0 )); then
    printf 'TRANSPORT_TEST isolated_capture=failed production_source_accessed=false\n' >&2
    printf 'TRANSPORT_TEST isolated_exit_code=%s\n' "$isolated_rc" >&2
    if /usr/bin/grep -Fq 'bwrap: Creating new namespace failed:' "$root/host-error"; then
      printf 'TRANSPORT_TEST namespace_setup=failed\n' >&2
    fi
    /usr/bin/grep -E '^MTM_COPY_(DIAGNOSTIC stage=[a-z_]+|BOUND_FAIL reason=[a-z_]+ entries=[0-9]+ bytes=[0-9]+|CAPTURE_ERROR [a-z_]+)$' "$root/host-error" >&2 || true
    exit 1
  fi
  (cd "$root/isolated-good"; /usr/bin/sha256sum --check --status archive.sha256)
  grep -q '"capture_complete":true' "$root/isolated-good/capture-summary.json"
  [[ $(/usr/bin/stat -c %a "$root/isolated-good/preupgrade.tar") == 400 ]]
  mtm_copy_archive "$root/tree" > "$root/host-source.tar"
  /usr/bin/cmp -s "$root/host-source.tar" "$root/isolated-good/preupgrade.tar"
  /usr/bin/grep -E '^MTM_COPY_TOOLCHAIN awk_functional=true legacy_awk_visible=(true|false)$' "$root/host-out"
  /usr/bin/ln -s oauth.sqlite3 "$root/tree/rejected-link"
  if mtm_copy_isolated_capture "$root/tree" "$root/isolated-bad" "$script" > "$root/host-bad-out" 2> "$root/host-bad-error"; then
    printf 'TRANSPORT_TEST isolated_unsafe_tree_unexpectedly_accepted\n' >&2; exit 1
  fi
  grep -qx 'MTM_COPY_BOUND_FAIL reason=unsupported_file_type entries=[0-9][0-9]* bytes=[0-9][0-9]*' "$root/host-bad-error"
  [[ ! -e $root/isolated-bad/preupgrade.partial.tar && ! -e $root/isolated-bad/preupgrade.tar && ! -e $root/isolated-bad/capture-summary.json ]]
  printf 'TRANSPORT_TEST isolated_capture_and_exact_archive=passed\n'
  printf 'TRANSPORT_TEST isolated_unsafe_tree_denial_before_archive=passed\n'
  printf 'TRANSPORT_TEST production_source_accessed=false full_host_capture_tested=true synthetic_only=true\n'
else
  printf 'TRANSPORT_TEST production_source_accessed=false full_host_capture_tested=false\n'
fi
