#!/usr/bin/env bash
# Two-stage disposable-copy modes only. All inputs and writes are fixtures.
set -euo pipefail
umask 077
if [[ ${1-} == --internal ]]; then
  [[ $# == 1 ]] || exit 2
  source /capture-script
  source /inspect-script
  source /rehearsal-script
  mtm_capture_awk=/capture-awk
  copy_sqlite=/opt/copy-sqlite/bin/sqlite3
  r_mode=synthetic
  r_wire=/tmp/wire
  mkdir -m 700 "$r_wire" /work/runtime /work/seed /work/seed/private
  printf 'fixture state\n' > /work/seed/private/state.sqlite3
  printf 'fixture wal\n' > /work/seed/private/state.sqlite3-wal
  printf 'fixture shm\n' > /work/seed/private/state.sqlite3-shm
  chmod 755 /work/seed/private
  chmod 644 /work/seed/private/*
  r_archive=/work/original.tar
  mtm_copy_archive /work/seed > "$r_archive"
  chmod 400 "$r_archive"
  r_archive_sha=$(copy_digest "$r_archive")
  r_extract
  original_identity=$r_restored_identity
  reject() {
    if ("$@") > /tmp/rejected.out 2> /tmp/rejected.err; then exit 1; fi
    [[ $(stat -c %a /work/runtime/data/private/state.sqlite3) == 644 ]]
  }
  wrong_root() { r_data=/work/seed; r_prepare_private_modes; }
  active_child() { r_pid=123; r_prepare_private_modes; }
  wrong_identity() { r_restored_identity=0:0; r_prepare_private_modes; }
  wrong_archive() { r_archive_sha=0000000000000000000000000000000000000000000000000000000000000000; r_prepare_private_modes; }
  reject wrong_root
  reject active_child
  reject wrong_identity
  reject wrong_archive
  reject r_prepare_private_modes invalid
  reject r_prepare_private_modes restored_baseline
  ln /work/runtime/data/private/state.sqlite3 /work/runtime/data/private/hardlink
  reject r_prepare_private_modes
  rm /work/runtime/data/private/hardlink
  mv /work/runtime/data/private /work/held-private
  ln -s /work/held-private /work/runtime/data/private
  reject r_prepare_private_modes
  rm /work/runtime/data/private
  mv /work/held-private /work/runtime/data/private
  before=$(r_content_digest)
  r_prepare_private_modes
  [[ $(r_content_digest) == "$before" && $(copy_digest "$r_archive") == "$r_archive_sha" ]]
  [[ $(stat -c %a /work/runtime/data/private) == 700 && $(stat -c %a /work/runtime/data/private/state.sqlite3) == 600 ]]
  [[ $r_restored_identity == "$original_identity" ]]
  mv /work/runtime/data /work/prepared-candidate
  r_extract
  [[ $(stat -c %a /work/runtime/data/private) == 755 && $(stat -c %a /work/runtime/data/private/state.sqlite3) == 644 ]]
  r_check_restored_archive
  r_write_baseline_restore_proof
  reject r_write_baseline_restore_proof
  cp /work/baseline-exact-restoration.json /tmp/good-proof.json
  for mutation in \
    "json_set(j,'$.archive_sha256','wrong')" \
    "json_set(j,'$.restored_archive_sha256','wrong')" \
    "json_set(j,'$.working_copy_identity_sha256','wrong')" \
    "json_set(j,'$.bytes_and_modes_match',json('false'))" \
    "json_set(j,'$.before_baseline_mode_preparation',json('false'))" \
    "json_set(j,'$.prepared_modes_used_for_exact_check',json('true'))" \
    "json_set(j,'$.synthetic_only',json('false'))" \
    "json_set(j,'$.unknown_field',json('true'))"; do
    chmod 600 /work/baseline-exact-restoration.json
    r_doc /tmp/good-proof.json "$mutation" > /work/baseline-exact-restoration.json
    chmod 400 /work/baseline-exact-restoration.json
    reject r_prepare_private_modes restored_baseline
  done
  chmod 600 /work/baseline-exact-restoration.json
  cp /tmp/good-proof.json /work/baseline-exact-restoration.json
  chmod 400 /work/baseline-exact-restoration.json
  printf 'modified data\n' > /work/runtime/data/private/state.sqlite3
  reject r_prepare_private_modes restored_baseline
  cp -p /work/seed/private/state.sqlite3 /work/runtime/data/private/state.sqlite3
  r_check_restored_archive
  before=$(r_content_digest)
  r_prepare_private_modes restored_baseline
  [[ $r_baseline_prepared == true && $(r_content_digest) == "$before" ]]
  [[ $(stat -c %a /work/runtime/data/private/state.sqlite3) == 600 ]]
  r_validate_baseline_restore_proof
  mv /work/runtime/data /work/prepared-baseline
  r_extract
  [[ $(stat -c %a /work/runtime/data/private/state.sqlite3) == 644 ]]
  r_check_restored_archive
  [[ $(stat -c %a "$r_archive") == 400 ]]
  printf 'MODE_PREPARATION_TEST negative_cases=18 disposable_copies_only=true durable_exact_proof_before_baseline_preparation=true content_unchanged=true archive_unchanged=true exact_restore_original_modes=true unprepared_baseline_continuation_claimed=false production_accessed=false synthetic_only=true\n'
  exit 0
fi
[[ $# == 2 && $1 == --sqlite && $2 == /* ]] || exit 2
sqlite=$(readlink -e -- "$2")
[[ $sqlite == "$2" && $sqlite == */bin/sqlite3 && -f $sqlite && -x $sqlite ]] || exit 2
prefix=${sqlite%/bin/sqlite3}
[[ -d $prefix/lib ]] || exit 2
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
source "$repo/scripts/mtm017-capture-operator-state.sh"
root=$(mktemp -d /tmp/mtm-mode-preparation.XXXXXXXX)
mtm_fixture_mark
trap 'mtm_fixture_cleanup' EXIT
awk_executable=$(readlink -e /usr/bin/awk)
rc=0
/usr/bin/timeout --signal=TERM --kill-after=5s 30s \
  /usr/bin/bwrap --unshare-all --new-session --die-with-parent --cap-drop ALL \
    --ro-bind /usr /usr --ro-bind /bin /bin --ro-bind /lib /lib --ro-bind-try /lib64 /lib64 \
    --dir /etc --ro-bind-try /etc/ld.so.cache /etc/ld.so.cache \
    --ro-bind "$awk_executable" /capture-awk \
    --ro-bind "$sqlite" /opt/copy-sqlite/bin/sqlite3 --ro-bind "$prefix/lib" /opt/copy-sqlite/lib \
    --ro-bind "$repo/scripts/mtm017-capture-operator-state.sh" /capture-script \
    --ro-bind "$repo/scripts/mtm017-inspect-operator-copy.sh" /inspect-script \
    --ro-bind "$repo/scripts/mtm017-rehearse-operator-copy.sh" /rehearsal-script \
    --ro-bind "$repo/conformance/mtm017-copy-mode-preparation-tests.sh" /mode-test \
    --bind "$root" /work --tmpfs /tmp --proc /proc --dev /dev \
    --clearenv --setenv PATH /usr/bin:/bin --setenv LC_ALL C \
    /bin/bash --noprofile --norc /mode-test --internal > "$root/stdout" 2> "$root/stderr" || rc=$?
if ((rc!=0)); then
  printf 'MODE_PREPARATION_TEST failed=true exit_code=%s synthetic_only=true\n' "$rc"
  grep -E '^MTM017_COPY_REHEARSAL_ERROR reason=[a-z_]+$' "$root/stderr" || true
  exit "$rc"
fi
cat "$root/stdout"
