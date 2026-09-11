#!/usr/bin/env bash
# Transport-only regressions on self-created disposable bytes, never real state.
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
script=$repo/scripts/mtm016-capture-operator-state.sh
source "$script"
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
  if mtm_copy_tree_bounds "$root/tree" > /dev/null; then
    printf 'TRANSPORT_TEST unexpected_tree_acceptance\n' >&2; exit 1
  fi
}
/usr/bin/ln -s oauth.sqlite3 "$root/tree/link"
reject_tree
/usr/bin/rm "$root/tree/link"
/usr/bin/ln "$root/tree/oauth.sqlite3" "$root/tree/hardlink"
reject_tree
/usr/bin/rm "$root/tree/hardlink"
/usr/bin/mkfifo "$root/tree/fifo"
reject_tree
/usr/bin/rm "$root/tree/fifo"
/usr/bin/chmod 1700 "$root/tree/private"
reject_tree
/usr/bin/chmod 700 "$root/tree/private"
/usr/bin/truncate -s 134217729 "$root/tree/oversized"
reject_tree
/usr/bin/rm "$root/tree/oversized"
/usr/bin/truncate -s 134217728 "$root/tree/large-a" "$root/tree/large-b"
reject_tree
/usr/bin/rm "$root/tree/large-a" "$root/tree/large-b"
deep=$root/tree
for ((i=0; i<33; i++)); do deep=$deep/d; /usr/bin/mkdir "$deep"; done
reject_tree
/usr/bin/rm -rf "$root/tree/d"
printf 'TRANSPORT_TEST seven_unsafe_or_oversized_trees_rejected=passed\n'
read -r existing _ < "$root/bounds"
/usr/bin/mkdir "$root/tree/many"
for ((i=existing+1; i<20000; i++)); do : > "$root/tree/many/$i"; done
mtm_copy_tree_bounds "$root/tree" > /dev/null
: > "$root/tree/many/one-more"
reject_tree
/usr/bin/rm -rf "$root/tree/many"
printf 'TRANSPORT_TEST entry_limit_exact_boundary=passed\n'

if /bin/bash "$script" > "$root/invalid.log" 2>&1; then exit 1; fi
if /usr/bin/env HOME="$root/home" /bin/bash "$script" --source "$root/missing" --operator-confirmed-quiescent > "$root/missing.log" 2>&1; then exit 1; fi
[[ ! -e $root/home/.mtm-acceptance ]]
if /bin/bash "$script" --internal-readonly-capture > "$root/unguarded.log" 2>&1; then exit 1; fi
printf 'TRANSPORT_TEST malformed_missing_source_and_missing_ro_mount_rejected=passed\n'
printf 'TRANSPORT_TEST production_source_accessed=false full_host_capture_tested=false\n'
