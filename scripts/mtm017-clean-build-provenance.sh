#!/usr/bin/env bash
# MTM-017-only preparation/runner. Never selects or executes a produced MTM binary.
set -euo pipefail
umask 077

readonly CB_SOURCE=7b4afe2359e688263557f62154e4bc1e640c12c0
readonly CB_SHA=13d7890c5c763199ed39295e134ff6cc735ceaa04eaddf6c556431a7a56254f4
readonly CB_LOCK=cd7c8da83a0750ebfca58512470bd35ee4a6c66c3b68404662d822cf5bc42a8c
readonly CB_CONFIG=abd83dd1aea7d0d6b83673fe640beb89bd1ae70a9ff3cff12183634ae93eaae2
readonly CB_TOOLCHAIN=1.98.0
readonly CB_SCOPE=MTM-017-CLEAN-BUILD
readonly CB_SOURCE_SHA=0adec4b02a8b54fd20fb30c796c9959ccc346cc0f9336517fc47eafcb6951e02
readonly CB_CACHE_MAX_BYTES=536870912
readonly CB_DISK_RESERVE=12884901888

fail() { printf 'MTM017_CLEAN_BUILD_ERROR reason=%s\n' "$1" >&2; exit 1; }
digest() { local result; result=$(sha256sum -- "$1") || return 1; printf '%s' "${result%% *}"; }
quote() {
  local value=$1
  value=${value//\\/\\\\}; value=${value//\"/\\\"}
  value=${value//$'\n'/\\n}; value=${value//$'\r'/\\r}; value=${value//$'\t'/\\t}
  printf '"%s"' "$value"
}
truth() { if "$@"; then printf true; else printf false; fi; }
private_dir() {
  [[ -d $1 && ! -L $1 && $(stat -c %u -- "$1") == "$(id -u)" && $(stat -c %a -- "$1") == 700 ]]
}


# Ignore inherited Git variables and global/system configuration. Raw source
# hashing below also catches checkout filters/line-ending normalization.
git_cmd() {
  env -i PATH=/usr/bin:/bin HOME="$HOME" LC_ALL=C GIT_OPTIONAL_LOCKS=0 \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_GLOBAL=/dev/null \
    /usr/bin/git -c core.hooksPath=/dev/null -c core.autocrlf=false \
      -c core.attributesFile=/dev/null -c init.templateDir= "$@"
}
source_digest() {
  local kind=$1 root=$2 path bytes shift
  git_cmd -C "$repo" ls-tree -rz --name-only "$CB_SOURCE" | LC_ALL=C sort -z | {
    printf 'mtm-rust-source-v1\0'
    while IFS= read -r -d '' path; do
      case "$path" in
        crates/*|xtask/*|Cargo.toml|Cargo.lock|rust-toolchain.toml|.cargo/config.toml) ;;
        *) continue ;;
      esac
      bytes=$(printf '%s' "$path" | wc -c)
      for shift in 56 48 40 32 24 16 8 0; do
        printf '%b' "\\$(printf '%03o' "$(((bytes >> shift) & 255))")"
      done
      printf '%s' "$path"
      if [[ $kind == git ]]; then
        git_cmd -C "$repo" show "$CB_SOURCE:$path" | /usr/bin/openssl dgst -sha256 -binary || return 1
      else
        [[ -f $root/$path && ! -L $root/$path ]] || return 1
        /usr/bin/openssl dgst -sha256 -binary "$root/$path" || return 1
      fi
    done
  } | sha256sum | cut -d ' ' -f 1
}
cache_stats() {
  local root=$1 device
  [[ -d $root && ! -L $root && $(realpath -e -- "$root") == "$root" ]] || return 1
  device=$(stat -c %d -- "$root") || return 1
  timeout 30 find -P "$root" -xdev -printf '%y %s %n %D\n' | awk -v device="$device" '
    { count++; if (count > 100000) exit 1 }
    $4 != device { exit 1 }
    $1 != "d" && $1 != "f" { exit 1 }
    $1 == "f" { if ($3 != 1 || $2 > 67108864) exit 1; bytes += $2 }
    END { if (bytes > 536870912) exit 1; printf "%d %d\n", count, bytes }
  '
}
tree_digest() {
  (
    cd -- "$1"
    timeout 30 find -P . -xdev -type f -print0 |
      LC_ALL=C sort -z | xargs -0 -r sha256sum --zero
  ) | sha256sum | cut -d ' ' -f 1
}
disk_check() {
  local available required
  available=$(df -B1 --output=avail "$repo" | tail -n 1 | tr -d ' ')
  [[ $available =~ ^[0-9]+$ ]] || fail disk_measurement
  required=$((CB_DISK_RESERVE + cache_bytes + index_bytes))
  ((available >= required)) || fail insufficient_disk_for_private_inputs_and_build
}
copy_dependency_inputs() {
  local kind source destination before after copied
  mkdir -m 700 -- "$session/cargo-home/registry" "$session/cargo-home/registry/cache" "$session/cargo-home/registry/index"
  for kind in cache index; do
    source=$cargo_home/registry/$kind/$registry_namespace
    destination=$session/cargo-home/registry/$kind/$registry_namespace
    cache_stats "$source" > "$session/evidence/dependency-$kind-source-stats.txt" || fail dependency_source_bounds
    before=$(tree_digest "$source") || fail dependency_source_hash
    mkdir -m 700 -- "$destination"
    timeout 120 cp -R --no-dereference --reflink=auto --no-preserve=mode,ownership -- "$source/." "$destination/" || fail dependency_copy_failed
    cache_stats "$destination" > "$session/evidence/dependency-$kind-copy-stats.txt" || fail dependency_copy_bounds
    cmp -- "$session/evidence/dependency-$kind-source-stats.txt" "$session/evidence/dependency-$kind-copy-stats.txt" || fail dependency_copy_shape
    after=$(tree_digest "$source") || fail dependency_source_recheck
    copied=$(tree_digest "$destination") || fail dependency_copy_hash
    [[ $before == "$after" && $before == "$copied" ]] || fail dependency_copy_drift
    printf '%s %s\n' "$kind" "$copied" >> "$session/evidence/dependency-inputs.sha256"
  done
}
toolchain_manifest() {
  sha256sum -- "$rustc" "$rustdoc" "$cargo"
  for tool in ar as c++ cc g++ gcc ld nm objcopy pkg-config ranlib strip; do
    sha256sum -- "$(realpath -e -- "$session/tool-bin/$tool")"
  done
}

# Cargo also discovers configuration in checkout ancestors. A private CARGO_HOME
# alone does not prevent that. Only the pinned alias-only config is permitted.
check_build_config() {
  local ancestor=$session/checkout configuration
  : > "$result/cargo-configs.sha256"
  while :; do
    for configuration in "$ancestor/.cargo/config" "$ancestor/.cargo/config.toml"; do
      if [[ -e $configuration || -L $configuration ]]; then
        [[ -f $configuration && ! -L $configuration ]] || fail cargo_config_type
        [[ $configuration == "$session/checkout/.cargo/config.toml" || $configuration == "$repo/.cargo/config.toml" ]] || fail unexpected_ancestor_cargo_configuration
        [[ $(digest "$configuration") == "$CB_CONFIG" ]] || fail cargo_config_identity
        sha256sum -- "$configuration" >> "$result/cargo-configs.sha256"
      fi
    done
    [[ $ancestor != / ]] || break
    ancestor=${ancestor%/*}; [[ -n $ancestor ]] || ancestor=/
  done
  [[ ! -e $session/cargo-home/config && ! -e $session/cargo-home/config.toml ]] || fail private_cargo_configuration_changed
}

# Only these two scratch children, created in this invocation, can be removed.
# Their marker is inside the child, and identity includes device/inode to reject
# replacement directories. Evidence, candidate staging and other caches are never
# deletion targets. This is not protection against a hostile same-UID race.
mark_scratch() {
  local name=$1 marker
  [[ $name == checkout || $name == build-cache ]] || fail scratch_name
  [[ -d $session/$name && ! -L $session/$name ]] || fail scratch_type
  marker=$session/$name/.mtm017-clean-build-owner
  [[ $name != checkout ]] || marker=$session/$name/.git/mtm017-clean-build-owner
  printf '%s\n%s\n%s\n' "$CB_SCOPE" "$session" "$(stat -c '%d:%i' -- "$session/$name")" > "$marker"
}
remove_scratch() {
  local name=$1 path marker expected actual
  [[ $name == checkout || $name == build-cache ]] || fail cleanup_name
  private_dir "$session" || fail cleanup_session_mode
  [[ $(realpath -e -- "$session") == "$session" && $session == "$parent"/session.* ]] || fail cleanup_session_path
  [[ -f $session/.mtm017-session && ! -L $session/.mtm017-session ]] || fail cleanup_session_marker
  [[ $(cat "$session/.mtm017-session") == "$CB_SCOPE:$session" ]] || fail cleanup_session_identity
  path=$session/$name
  [[ -d $path && ! -L $path && $(realpath -e -- "$path") == "$path" ]] || fail cleanup_child_path
  [[ $(stat -c %u -- "$path") == "$(id -u)" ]] || fail cleanup_child_owner
  marker=$path/.mtm017-clean-build-owner
  [[ $name != checkout ]] || marker=$path/.git/mtm017-clean-build-owner
  [[ -f $marker && ! -L $marker && $(stat -c %h -- "$marker") == 1 ]] || fail cleanup_child_marker
  expected=$(printf '%s\n%s\n%s' "$CB_SCOPE" "$session" "$(stat -c '%d:%i' -- "$path")")
  actual=$(cat "$marker")
  [[ $actual == "$expected" ]] || fail cleanup_child_identity
  rm -rf --one-file-system -- "$path"
  [[ ! -e $path && ! -L $path ]] || fail cleanup_incomplete
}

mode=plan
if [[ $# == 3 && $1 == --plan && $2 == --dependency-cache ]]; then dependency_input=$3
elif [[ $# == 5 && $1 == --run && $2 == --authorize && $3 == "$CB_SCOPE" && $4 == --dependency-cache ]]; then mode=run; dependency_input=$5
else fail usage_plan_or_explicit_run_authorization_and_dependency_cache
fi
[[ $dependency_input == /* && $dependency_input != *[[:cntrl:]]* ]] || fail dependency_cache_path

script=$(realpath -e -- "${BASH_SOURCE[0]}")
repo=$(realpath -e -- "${script%/*}/..")
[[ $repo != / && $repo != *:* && $repo != *[[:cntrl:]]* ]] || fail unsupported_checkout_path
[[ $(git_cmd -C "$repo" rev-parse --show-toplevel) == "$repo" ]] || fail checkout_identity
git_cmd -C "$repo" cat-file -e "$CB_SOURCE^{commit}" || fail source_commit_missing
source_tree=$(git_cmd -C "$repo" rev-parse "$CB_SOURCE^{tree}")
source_hash=$(source_digest git "$repo") || fail frozen_source_hash_failed
[[ $source_hash == "$CB_SOURCE_SHA" ]] || fail frozen_source_hash_mismatch
candidate=$repo/target/mtm017-preview2/mtm-0.6.0-preview.2-$CB_SHA/mtm
[[ -f $candidate && ! -L $candidate ]] || fail candidate_type
[[ $(digest "$candidate") == "$CB_SHA" ]] || fail candidate_hash
[[ $(git_cmd -C "$repo" show "$CB_SOURCE:Cargo.lock" | sha256sum | cut -d ' ' -f 1) == "$CB_LOCK" ]] || fail source_lock_identity
rustc=$(rustup which --toolchain "$CB_TOOLCHAIN" rustc)
rustdoc=$(rustup which --toolchain "$CB_TOOLCHAIN" rustdoc)
cargo=$(rustup which --toolchain "$CB_TOOLCHAIN" cargo)
for executable in "$rustc" "$rustdoc" "$cargo"; do
  [[ -f $executable && -x $executable && ! -L $executable ]] || fail toolchain_executable
done
cargo_home=$(realpath -e -- "$dependency_input")
rustup_home=$(realpath -e -- "${RUSTUP_HOME:-$HOME/.rustup}")
[[ -d $cargo_home/registry && -d $rustup_home ]] || fail offline_dependency_cache_missing
parent=$repo/target/mtm017-clean-build-provenance
registry_namespace=index.crates.io-1949cf8c6b5b557f
lock_sources=$(git_cmd -C "$repo" show "$CB_SOURCE:Cargo.lock" | grep '^source = ' | LC_ALL=C sort -u)
[[ $lock_sources == 'source = "registry+https://github.com/rust-lang/crates.io-index"' ]] || fail unsupported_dependency_source
cache_info=$(cache_stats "$cargo_home/registry/cache/$registry_namespace") || fail archive_cache_bounds
index_info=$(cache_stats "$cargo_home/registry/index/$registry_namespace") || fail sparse_index_bounds
read -r cache_entries cache_bytes <<< "$cache_info"
read -r index_entries index_bytes <<< "$index_info"
((cache_bytes + index_bytes <= CB_CACHE_MAX_BYTES)) || fail combined_dependency_input_limit
disk_check

if [[ $mode == plan ]]; then
  printf 'MTM017_CLEAN_BUILD_PLAN source=%s tree=%s\n' "$CB_SOURCE" "$source_tree"
  printf 'candidate=%s\nexpected_sha256=%s\n' "$candidate" "$CB_SHA"
  printf 'qualified_scratch_parent=%s\n' "$parent"
  printf 'dependency_input_cache=%s\n' "$cargo_home"
  printf 'toolchain=%s\ncargo=%s\nrustc=%s\n' "$CB_TOOLCHAIN" "$cargo" "$rustc"
  printf '%s\n' 'command=cargo build --release --locked --offline -p mtm-cli --bin mtm'
  printf '%s\n' 'runs=2 serial; one fixed checkout path and one scratch cache within this new session'
  printf '%s\n' 'each run starts with a fresh exact-commit clone and empty compiled-product cache'
  printf 'verified_raw_source_sha256=%s\n' "$source_hash"
  printf 'private_dependency_input_bytes=%s private_dependency_entries=%s disk_reserve_bytes=%s\n' "$((cache_bytes + index_bytes))" "$((cache_entries + index_entries))" "$CB_DISK_RESERVE"
  printf '%s\n' 'dependency archives/index will be bounded private copies; no writable source-cache links'
  printf '%s\n' 'existing compiled operator/tool caches are not used or cleaned'
  printf '%s\n' 'absolute compilation paths differ from the frozen build; exact candidate reproduction is not assumed'
  printf '%s\n' 'plan_only=true files_written=false cargo_build_started=false release_qualified=false'
  exit 0
fi

[[ -d $repo/target && ! -L $repo/target && $(realpath -e -- "$repo/target") == "$repo/target" ]] || fail target_directory
if [[ ! -e $parent && ! -L $parent ]]; then mkdir -m 700 -- "$parent"; fi
private_dir "$parent" || fail qualification_parent
[[ $(realpath -e -- "$parent") == "$parent" ]] || fail qualification_parent_path
session=$(mktemp -d "$parent/session.XXXXXXXX")
printf '%s\n' "$CB_SCOPE:$session" > "$session/.mtm017-session"
mkdir -m 700 -- "$session/evidence" "$session/tool-bin" "$session/home" "$session/cargo-home"
printf 'MTM017_CLEAN_BUILD_SESSION %s\n' "$session"
trap 'printf "MTM017_CLEAN_BUILD_INTERRUPTED private_session_preserved=%s\n" "$session" >&2; exit 130' INT TERM

# Build PATH contains only the pinned Rust toolchain and these reviewed tools.
# Do not add /usr/bin as a fallback if a missing tool causes a build failure.
for tool in ar as c++ cc g++ gcc ld nm objcopy pkg-config ranlib strip; do
  resolved=$(realpath -e -- "/usr/bin/$tool") || fail compiler_tool_missing
  [[ -f $resolved && -x $resolved ]] || fail compiler_tool_invalid
  ln -s -- "$resolved" "$session/tool-bin/$tool"
  printf '%s %s %s\n' "$tool" "$(digest "$resolved")" "$resolved" >> "$session/evidence/compiler-tools.txt"
done
"$rustc" --version --verbose > "$session/evidence/rustc-version.txt"
toolchain_manifest > "$session/evidence/toolchain-initial.sha256"
"$cargo" --version > "$session/evidence/cargo-version.txt"
sha256sum -- "$rustc" "$rustdoc" "$cargo" > "$session/evidence/toolchain-tools.sha256"
printf '%s\n' "$cargo_home" > "$session/evidence/dependency-cache-path.txt"
# Copy only bounded crates.io archive/index inputs. No shared cache is mounted
# writable or linked into the private Cargo home. Keep the private copy on failure.
copy_dependency_inputs
printf '%s\n' "$(digest "$script")  $script" > "$session/evidence/runner.sha256"
sha256sum -- "$repo/AGENTS.md" "$repo/records/governance/mtm017-readiness-decisions.json" > "$session/evidence/authorization-sources.sha256"
printf '%s\n' "$(git_cmd -C "$repo" rev-parse HEAD)" > "$session/evidence/runner-checkout-head.txt"
git_cmd -C "$repo" status --porcelain > "$session/evidence/runner-checkout-status.txt"
build_path=${rustc%/*}:$session/tool-bin
for name in python python3 python2; do [[ ! -e ${rustc%/*}/$name && ! -e $session/tool-bin/$name ]] || fail python_on_build_path; done

for round in 1 2; do
  disk_check
  result=$session/evidence/run-$round
  mkdir -m 700 -- "$result"
  [[ ! -e $session/checkout && ! -e $session/build-cache ]] || fail scratch_not_empty
  git_cmd -c core.hooksPath=/dev/null clone --local --no-hardlinks --no-checkout --quiet "$repo" "$session/checkout" > "$result/clone.log" 2>&1
  git_cmd -C "$session/checkout" -c core.hooksPath=/dev/null checkout --detach --quiet "$CB_SOURCE" >> "$result/clone.log" 2>&1
  mark_scratch checkout
  [[ $(git_cmd -C "$session/checkout" rev-parse HEAD) == "$CB_SOURCE" ]] || fail cloned_source_identity
  git_cmd -C "$session/checkout" status --porcelain > "$result/source-before.txt"
  [[ ! -s $result/source-before.txt ]] || fail cloned_source_dirty
  [[ $(digest "$session/checkout/Cargo.lock") == "$CB_LOCK" ]] || fail cloned_lock_identity
  check_build_config
  source_before=$(source_digest files "$session/checkout") || fail cloned_source_hash_failed
  [[ $source_before == "$CB_SOURCE_SHA" ]] || fail cloned_source_raw_bytes_mismatch
  toolchain_manifest > "$result/tools-before.sha256"
  cmp -s -- "$session/evidence/toolchain-initial.sha256" "$result/tools-before.sha256" || fail toolchain_changed_since_session_start
  mkdir -m 700 -- "$session/build-cache"
  mark_scratch build-cache
  printf '%s\0' "HOME=$session/home" "PATH=$build_path" LC_ALL=C TZ=UTC \
    "CARGO_HOME=$session/cargo-home" "RUSTUP_HOME=$rustup_home" \
    "RUSTUP_TOOLCHAIN=$CB_TOOLCHAIN" RUSTUP_AUTO_INSTALL=0 \
    "RUSTC=$rustc" "RUSTDOC=$rustdoc" "CARGO_TARGET_DIR=$session/build-cache" \
    > "$result/build-environment.nul"
  started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  build_exit=0
  (
    cd -- "$session/checkout"
    ulimit -f 524288
    timeout --signal=TERM --kill-after=10 1800 env -i \
      HOME="$session/home" PATH="$build_path" LC_ALL=C TZ=UTC \
      CARGO_HOME="$session/cargo-home" RUSTUP_HOME="$rustup_home" \
      RUSTUP_TOOLCHAIN="$CB_TOOLCHAIN" RUSTUP_AUTO_INSTALL=0 \
      RUSTC="$rustc" RUSTDOC="$rustdoc" CARGO_TARGET_DIR="$session/build-cache" \
      "$cargo" build --release --locked --offline -p mtm-cli --bin mtm
  ) > "$result/build.log" 2>&1 || build_exit=$?
  completed=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  git_cmd -C "$session/checkout" status --porcelain > "$result/source-after.txt"
  source_after=$(source_digest files "$session/checkout") || fail built_source_hash_failed
  toolchain_manifest > "$result/tools-after.sha256"
  tools_stable=$(truth cmp -s -- "$result/tools-before.sha256" "$result/tools-after.sha256")
  dependency_source_stable=true
  while read -r kind expected_hash; do
    observed_hash=$(tree_digest "$cargo_home/registry/$kind/$registry_namespace") || fail dependency_source_recheck
    [[ $observed_hash == "$expected_hash" ]] || dependency_source_stable=false
  done < "$session/evidence/dependency-inputs.sha256"
  candidate_after=$(digest "$candidate")
  artifact_sha=
  if [[ $build_exit == 0 && -f $session/build-cache/release/mtm && ! -L $session/build-cache/release/mtm ]]; then
    cp --no-clobber -- "$session/build-cache/release/mtm" "$result/mtm"
    chmod 500 -- "$result/mtm"
    artifact_sha=$(digest "$result/mtm")
  fi
  (
    cd -- "$session/checkout"
    sha256sum Cargo.lock Cargo.toml rust-toolchain.toml .cargo/config.toml
  ) > "$result/source-inputs.sha256"
  {
    printf '{\n  "schema":"mtm017-clean-build-run-v1",\n  "milestone":"MTM-017",\n  "round":%s,\n' "$round"
    printf '  "source_commit":"%s",\n  "source_tree":"%s",\n' "$CB_SOURCE" "$source_tree"
    printf '  "checkout_path":'; quote "$session/checkout"; printf ',\n  "cache_path":'; quote "$session/build-cache"
    printf ',\n  "started_at":"%s",\n  "completed_at":"%s",\n  "build_exit_code":%s,\n' "$started" "$completed" "$build_exit"
    printf '  "command":["cargo","build","--release","--locked","--offline","-p","mtm-cli","--bin","mtm"],\n'
    printf '  "build_locked":true,\n  "build_offline":true,\n  "toolchain":"%s",\n' "$CB_TOOLCHAIN"
    printf '  "fresh_detached_checkout":true,\n  "empty_compiled_product_cache":true,\n  "private_dependency_inputs":true,\n  "shared_dependency_cache_linked":false,\n'
    printf '  "raw_source_sha256_before":"%s",\n  "raw_source_sha256_after":"%s",\n' "$source_before" "$source_after"
    printf '  "build_environment_sha256":"%s",\n  "environment_format":"complete_env_i_allowlist_nul_separated",\n' "$(digest "$result/build-environment.nul")"
    printf '  "tools_before_sha256":"%s",\n  "tools_after_sha256":"%s",\n  "tools_unchanged":%s,\n' "$(digest "$result/tools-before.sha256")" "$(digest "$result/tools-after.sha256")" "$tools_stable"
    printf '  "dependency_inputs_manifest_sha256":"%s",\n  "original_dependency_inputs_unchanged":%s,\n' "$(digest "$session/evidence/dependency-inputs.sha256")" "$dependency_source_stable"
    printf '  "clean_source_after":%s,\n' "$(truth test ! -s "$result/source-after.txt")"
    printf '  "artifact_sha256":"%s",\n  "selected_candidate_sha256":"%s",\n  "candidate_sha256_after":"%s",\n' "$artifact_sha" "$CB_SHA" "$candidate_after"
    printf '  "exact_candidate_bytes_reproduced":%s,\n' "$(truth test "$artifact_sha" = "$CB_SHA")"
    printf '  "build_log_sha256":"%s",\n  "source_inputs_sha256":"%s",\n' "$(digest "$result/build.log")" "$(digest "$result/source-inputs.sha256")"
    printf '  "compiler_tools_manifest_sha256":"%s",\n  "rustc_version_sha256":"%s",\n  "cargo_version_sha256":"%s",\n' "$(digest "$session/evidence/compiler-tools.txt")" "$(digest "$session/evidence/rustc-version.txt")" "$(digest "$session/evidence/cargo-version.txt")"
    printf '  "toolchain_executables_manifest_sha256":"%s",\n  "runner_identity_file_sha256":"%s",\n' "$(digest "$session/evidence/toolchain-tools.sha256")" "$(digest "$session/evidence/runner.sha256")"
    printf '  "initial_toolchain_manifest_sha256":"%s",\n' "$(digest "$session/evidence/toolchain-initial.sha256")"
    printf '  "authorization_sources_manifest_sha256":"%s",\n' "$(digest "$session/evidence/authorization-sources.sha256")"
    printf '  "discovered_cargo_configs_manifest_sha256":"%s",\n' "$(digest "$result/cargo-configs.sha256")"
    printf '  "existing_cargo_configuration_or_credentials_used":false,\n  "cargo_home_private_and_initialized_once_per_session":true,\n  "fresh_dependency_extraction_each_round":false,\n'
    printf '  "rustflags_override":false,\n  "source_date_epoch_override":false,\n  "absolute_path_remapping":false,\n'
    printf '  "python_on_build_path":false,\n  "produced_binary_executed":false,\n  "production_selector_changed":false,\n  "production_state_modified":false,\n  "release_qualified":false\n}\n'
  } > "$result/receipt.json"
  (cd -- "$result"; sha256sum receipt.json build.log source-inputs.sha256 > evidence.sha256)
  [[ $build_exit == 0 && -n $artifact_sha && ! -s $result/source-after.txt && $candidate_after == "$CB_SHA" && $source_after == "$CB_SOURCE_SHA" && $tools_stable == true && $dependency_source_stable == true ]] || fail build_failed_evidence_and_scratch_preserved
  # Delete only marked, self-created scratch after its retained artifact/receipt.
  remove_scratch checkout
  remove_scratch build-cache
done

first=$(digest "$session/evidence/run-1/mtm")
second=$(digest "$session/evidence/run-2/mtm")
{
  printf '{\n  "schema":"mtm017-clean-build-comparison-v1",\n  "milestone":"MTM-017",\n  "source_commit":"%s",\n' "$CB_SOURCE"
  printf '  "selected_candidate_sha256":"%s",\n  "first_sha256":"%s",\n  "second_sha256":"%s",\n' "$CB_SHA" "$first" "$second"
  printf '  "both_builds_equal":%s,\n  "both_match_selected_candidate":%s,\n' "$(truth test "$first" = "$second")" "$(truth test "$first:$second" = "$CB_SHA:$CB_SHA")"
  printf '  "run_1_receipt_sha256":"%s",\n  "run_2_receipt_sha256":"%s",\n' "$(digest "$session/evidence/run-1/receipt.json")" "$(digest "$session/evidence/run-2/receipt.json")"
  printf '  "readiness_adapter_acceptance_claimed":false,\n  "production_selector_changed":false,\n  "production_state_modified":false,\n  "release_qualified":false,\n  "deployment_authorized":false\n}\n'
} > "$session/evidence/comparison.json"
printf 'MTM017_CLEAN_BUILD_RESULT comparison=%s\n' "$session/evidence/comparison.json"
[[ $first == "$CB_SHA" && $second == "$CB_SHA" ]] || fail exact_candidate_not_reproduced
