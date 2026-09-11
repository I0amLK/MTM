#!/usr/bin/env bash
# Synthetic files/configuration only; no proof, tunnel, OAuth or production state.
set -euo pipefail
umask 077
export LC_ALL=C
repo=$(cd -- "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")/.." && /usr/bin/pwd -P)
[[ $# == 2 && $1 == --sqlite && $2 == /* ]] || { printf 'RESEARCH_SESSION_TEST_ERROR usage_explicit_sqlite\n' >&2; exit 1; }
sqlite=$(/usr/bin/readlink -e -- "$2")
[[ -f $sqlite && -x $sqlite ]] || exit 1
source "$repo/scripts/mtm016-research-session.sh"
source "$repo/scripts/mtm016-stop-research-session.sh"
tmp=$(/usr/bin/mktemp -d /tmp/mtm-research-primitives.XXXXXXXX)
trap '/usr/bin/rm -rf -- "$tmp"' EXIT
negative=0
deny() { if ( "$@" ) > "$tmp/denial.stdout" 2> "$tmp/denial.stderr"; then printf 'RESEARCH_SESSION_TEST_ERROR unexpected_acceptance function=%s\n' "$1" >&2; exit 1; fi; ((negative+=1)); }
sql() { "$sqlite" -batch -init /dev/null -noheader ':memory:' "$1"; }
fixture_git() {
  # Only the new synthetic repository uses this empty configuration. Never
  # disable the real checkout's hooks or inherit a caller's GIT_DIR/index.
  /usr/bin/env -i PATH=/usr/bin:/bin "HOME=$tmp/git-home" GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    /usr/bin/git -c core.hooksPath=/dev/null -c commit.gpgsign=false "$@"
}
registry=$repo/conformance/mtm016-research-cases.tsv

for id in U21 U22 U23 U24 U25; do
  for repeat in 1 2 3; do
    rs_args --task "$id" --repeat "$repeat"
    [[ $rs_prepare_only == false ]]
    rs_args --task "$id" --repeat "$repeat" --prepare-only
    [[ $rs_prepare_only == true ]]
    rs_registry "$registry" "$id" "$repeat"
    [[ $rs_case == "${id,,}-r$repeat-"* && -n $rs_problem && -n $rs_requirement ]]
  done
done
deny rs_args
deny rs_args --task U20 --repeat 1
deny rs_args --task U26 --repeat 1
deny rs_args --task U21 --repeat 0
deny rs_args --task U21 --repeat 4
deny rs_args --task U21 --repeat 01
deny rs_args --repeat 1 --task U21
deny rs_args --task U21 --repeat 1 --binary /bin/true
deny rs_args --task U21 --repeat 1 --source /nonexistent-production
deny rs_args --task U21 --repeat 1 --approve
deny rs_args --task U21 --repeat 1 --prepare-only --prepare-only
printf 'RESEARCH_SESSION_TEST fifteen_cases_and_no_override_arguments=passed\n'

/usr/bin/head -n 15 "$registry" > "$tmp/missing.tsv"
deny rs_registry "$tmp/missing.tsv" U21 1
{ /usr/bin/cat "$registry"; /usr/bin/sed -n '2p' "$registry"; } > "$tmp/duplicate.tsv"
deny rs_registry "$tmp/duplicate.tsv" U21 1
for edit in 's/U21/U26/' 's/u21-r1/u21-r2/' 's/compact/full/' 's/mtm-research-cases-v1/unknown/'; do
  /usr/bin/sed "$edit" "$registry" > "$tmp/mutated.tsv"
  deny rs_registry "$tmp/mutated.tsv" U21 1
done
/usr/bin/printf '%s\n' incomplete > "$tmp/bad.tsv"
deny rs_registry "$tmp/bad.tsv" U21 1
/usr/bin/ln -s "$registry" "$tmp/link.tsv"
deny rs_registry "$tmp/link.tsv" U21 1
deny rs_registry "$registry" U21 4
{ /usr/bin/cat "$registry"; printf '\n'; } > "$tmp/blank.tsv"
deny rs_registry "$tmp/blank.tsv" U21 1
{ printf '\0'; /usr/bin/cat "$registry"; } > "$tmp/nul.tsv"
deny rs_registry "$tmp/nul.tsv" U21 1
/usr/bin/sed '2s/$/\textra/' "$registry" > "$tmp/extra-field.tsv"
deny rs_registry "$tmp/extra-field.tsv" U21 1
printf 'RESEARCH_SESSION_TEST missing_duplicate_mode_and_linked_cases_rejected=passed\n'

mkdir -m 700 "$tmp/private" "$tmp/tools"
rs_private_dir "$tmp/private"
chmod 755 "$tmp/private"
deny rs_private_dir "$tmp/private"
chmod 700 "$tmp/private"
ln -s "$tmp/private" "$tmp/private-link"
deny rs_private_dir "$tmp/private-link"
deny rs_private_dir "$tmp/absent"
ln -s /usr/bin/true "$tmp/tools/stub"
[[ $(rs_tool stub "$tmp/tools") == /usr/bin/true ]]
deny rs_tool stub '.:relative:'
deny rs_tool absent "$tmp/tools"
printf 'RESEARCH_SESSION_TEST private_directory_and_minimal_path_guards=passed\n'

cp /usr/bin/true "$tmp/artifact"
artifact_hash=$(rs_hash "$tmp/artifact")
rs_snapshot "$tmp/artifact" "$tmp/private/snapshot" "$artifact_hash"
[[ $(rs_hash "$tmp/private/snapshot") == "$artifact_hash" && $(stat -c %a "$tmp/private/snapshot") == 500 ]]
deny rs_snapshot "$tmp/artifact" "$tmp/private/snapshot" "$artifact_hash"
deny rs_snapshot "$tmp/artifact" "$tmp/no-copy" "$(printf '0%.0s' {1..64})"
[[ ! -e $tmp/no-copy ]]
ln -s "$tmp/artifact" "$tmp/linked-artifact"
deny rs_snapshot "$tmp/linked-artifact" "$tmp/linked-copy" "$artifact_hash"
chmod 4755 "$tmp/artifact"
deny rs_snapshot "$tmp/artifact" "$tmp/special-copy" "$artifact_hash"
chmod 755 "$tmp/artifact"
ln "$tmp/artifact" "$tmp/hardlink"
deny rs_snapshot "$tmp/artifact" "$tmp/hardlinked-copy" "$artifact_hash"
printf 'RESEARCH_SESSION_TEST exact_snapshot_no_clobber_and_special_file_denials=passed\n'

rs_environment "$tmp/private"
MTM_DATA_ROOT=/never-use-production MTM_PRIVATE_ROOT=/never-use-vault MTM_TOKEN_SECRET=synthetic-test-secret MTM_OAUTH_PASSWORD=synthetic-test-password MTM_NATIVE_MODE=dangerous \
  "${rs_env[@]}" /usr/bin/env > "$tmp/child-environment"
grep -Fx "HOME=$tmp/private/home" "$tmp/child-environment" > /dev/null
grep -Fx "MTM_DATA_ROOT=$tmp/private/data" "$tmp/child-environment" > /dev/null
grep -Fx 'MTM_NATIVE_MODE=safe' "$tmp/child-environment" > /dev/null
grep -Fx 'MTM_LATEX_POLICY=required' "$tmp/child-environment" > /dev/null
grep -Fx "MTM_NATIVE_EXEC_ALLOW_ROOTS=$tmp/private/tool-bin" "$tmp/child-environment" > /dev/null
if grep -E 'never-use|synthetic-test|MTM_TOKEN_SECRET|MTM_OAUTH_PASSWORD|MTM_CAPABILITY_SECRET' "$tmp/child-environment" > /dev/null; then exit 1; fi
printf 'RESEARCH_SESSION_TEST inherited_roots_and_secrets_removed=passed\n'
deny rs_environment '/tmp/session:another-root'
deny rs_environment $'/tmp/session\nextra'
deny rs_environment relative
mkdir -m 700 "$tmp/card-session" "$tmp/card-session/workspace"
printf '%s\n' 'Public input, no credential.' > "$tmp/card-session/task.md"
rs_visible_taskcard "$tmp/card-session"
cmp "$tmp/card-session/task.md" "$tmp/card-session/workspace/task.md"
deny rs_visible_taskcard "$tmp/card-session"
rm "$tmp/card-session/workspace/task.md"
ln -s "$tmp/card-session/task.md" "$tmp/card-session/workspace/task.md"
deny rs_visible_taskcard "$tmp/card-session"
printf 'RESEARCH_SESSION_TEST visible_task_no_clobber_and_single_tool_root=passed\n'

rs_args --task U21 --repeat 1 --prepare-only
rs_registry "$registry" U21 1
trial=0123456789abcdef0123456789abcdef
commit=0123456789abcdef0123456789abcdef01234567
digest=$(rs_hash "$registry")
rs_manifest "$tmp/session.json" "$trial" "$commit" "$digest" "$digest"
[[ $(sql "SELECT json_valid(readfile('$tmp/session.json')) AND json_extract(readfile('$tmp/session.json'),'$.session_prepared')=1 AND json_extract(readfile('$tmp/session.json'),'$.runtime_executed')=0 AND json_extract(readfile('$tmp/session.json'),'$.research_trial_passed')=0 AND json_extract(readfile('$tmp/session.json'),'$.independent_review_recorded')=0 AND json_extract(readfile('$tmp/session.json'),'$.release_qualified')=0 AND json_extract(readfile('$tmp/session.json'),'$.task_id')='U21';") == 1 ]]
deny rs_manifest "$tmp/session.json" "$trial" "$commit" "$digest" "$digest"
deny rs_manifest "$tmp/invalid.json" '../invalid' "$commit" "$digest" "$digest"
deny rs_manifest "$tmp/invalid.json" "$trial" invalid "$digest" "$digest"
manifest_wrong_mode() { rs_mode=full; rs_manifest "$tmp/invalid.json" "$trial" "$commit" "$digest" "$digest"; }
manifest_wrong_case() { rs_case=u22-r1-mismatch; rs_manifest "$tmp/invalid.json" "$trial" "$commit" "$digest" "$digest"; }
deny manifest_wrong_mode
deny manifest_wrong_case
rs_taskcard "$tmp/task.md" "$trial"
grep -F 'dim(U+W)' "$tmp/task.md" > /dev/null
grep -F 'verify' "$tmp/task.md" > /dev/null
task_before=$(rs_hash "$tmp/task.md")
deny rs_taskcard "$tmp/task.md" "$trial"
[[ $(rs_hash "$tmp/task.md") == "$task_before" ]]
ln -s "$tmp/absent-target" "$tmp/task-link"
deny rs_taskcard "$tmp/task-link" "$trial"
deny rs_manifest "$tmp/task-link" "$trial" "$commit" "$digest" "$digest"
[[ ! -e $tmp/absent-target ]]
printf 'RESEARCH_SESSION_TEST task_and_metadata_never_claim_review_or_acceptance=passed\n'

# Exercise the actual entry point in a newly created repository and HOME. The
# fake tool directory is ONLY inventory for --prepare-only, never executed.
# The candidate copy is the exact reviewed artifact, not a mock report writer.
fixture=$tmp/fixture
fake_home="$tmp/home with 'quotes'"
mkdir -m 700 "$fixture" "$fixture/scripts" "$fixture/conformance" "$fake_home" "$tmp/inventory"
cp "$repo/scripts/mtm016-research-session.sh" "$fixture/scripts/"
cp "$registry" "$repo/conformance/mtm016-usability-corpus.json" "$fixture/conformance/"
frozen=target/mtm016-f5-frozen/mtm-0.6.0-preview.1-$RS_CANDIDATE_SHA/mtm
mkdir -p "$fixture/${frozen%/mtm}"
cp "$repo/$frozen" "$fixture/$frozen"
for tool in bwrap curl latexmk pdflatex cloudflared sh cat printf sleep readlink dirname uname; do
  ln -s /usr/bin/true "$tmp/inventory/$tool"
done
GIT_DIR="$tmp/must-not-be-created" GIT_WORK_TREE="$tmp/must-not-be-used" fixture_git -C "$fixture" init -q
[[ ! -e $tmp/must-not-be-created && ! -e $tmp/must-not-be-used ]]
fixture_git -C "$fixture" add scripts conformance
fixture_git -C "$fixture" -c user.name='Synthetic test' -c user.email='fixture@example.invalid' commit -qm 'temporary research entry fixture'
printf 'RESEARCH_SESSION_TEST synthetic_git_ignores_inherited_repository_and_signing=passed\n'
HOME="$fake_home" PATH="$tmp/inventory" /bin/bash "$fixture/scripts/mtm016-research-session.sh" --task U21 --repeat 1 --prepare-only > "$tmp/prepared.stdout"
session_line=$(/usr/bin/head -n 1 "$tmp/prepared.stdout")
session=${session_line#private_session=}
[[ $session == "$fake_home/.mtm-acceptance/MTM-016/research/U21-r1."* ]]
rs_private_dir "$session"
[[ $(stat -c %a "$session/operator-key.txt") == 600 && ! -e $session/operator.log && ! -e $session/close.json ]]
[[ $(rs_hash "$session/candidate") == "$RS_CANDIDATE_SHA" ]]
[[ -f $session/workspace/task.md && ! -L $session/workspace/task.md ]]
[[ $(rs_hash "$session/task.md") == "$(rs_hash "$session/workspace/task.md")" ]]
IFS= read -r fixture_key < "$session/operator-key.txt"
[[ $fixture_key =~ ^[0-9a-f]{64}$ ]]
if grep -Fq "$fixture_key" "$tmp/prepared.stdout"; then exit 1; fi
fixture_key=
printf 'RESEARCH_SESSION_TEST actual_prepare_entry_and_quoted_home_no_password_output=passed\n'

# check-config neither opens a workflow DB nor starts a server. This probes the
# actual frozen CLI environment mapping, not Native/LaTeX runtime acceptance.
rs_environment "$session"
"${rs_env[@]}" "$session/candidate" check-config --workspace "$session/workspace" --native-mode safe --latex-policy required > "$tmp/config.json"
[[ $(sql "SELECT json_valid(readfile('$tmp/config.json')) AND json_extract(readfile('$tmp/config.json'),'$.ok')=1 AND json_extract(readfile('$tmp/config.json'),'$.native_mode')='safe' AND json_extract(readfile('$tmp/config.json'),'$.latex_policy')='required' AND json_extract(readfile('$tmp/config.json'),'$.native_exec_backend')='bubblewrap' AND json_extract(readfile('$tmp/config.json'),'$.workflow_protocol_version')=3;") == 1 ]]
for expected in "$session/workspace" "$session/data" "$session/data/private"; do grep -F "$expected" "$tmp/config.json" > /dev/null; done
[[ ! -e $session/data/oauth.sqlite3 && ! -e $session/data/private/state.sqlite3 ]]
printf 'RESEARCH_SESSION_TEST frozen_candidate_configuration_only_no_database_or_server=passed\n'

# Missing inventory and modified task input fail before a second session exists.
rm "$tmp/inventory/cloudflared"
actual_prepare() { HOME="$fake_home" PATH="$tmp/inventory" /bin/bash "$fixture/scripts/mtm016-research-session.sh" --task U21 --repeat 2 --prepare-only; }
deny actual_prepare
ln -s /usr/bin/true "$tmp/inventory/cloudflared"
printf '\n' >> "$fixture/conformance/mtm016-research-cases.tsv"
deny actual_prepare
shopt -s nullglob
sessions=("$fake_home"/.mtm-acceptance/MTM-016/research/*)
[[ ${#sessions[@]} == 1 ]]
printf 'RESEARCH_SESSION_TEST changed_inputs_and_missing_tool_stop_before_new_session=passed\n'
source "$repo/scripts/mtm016-resume-research-session.sh"
rs_args --task U21 --repeat 1 --prepare-only
rs_registry "$registry" U21 1
rs_manifest "$tmp/resume-good.json" "$trial" 1d1fcb737039b10ae0dea1683a8ccaf90c296941 e4e2a30175976c7bd1db7874db12699d5589203b381248036829c488db7a2b91 "$RS_CASES_SHA"
rr_metadata "$tmp/resume-good.json" "$sqlite"
for field in schema milestone task_id repeat case_id workflow_mode trial_id candidate_sha256 candidate_source_commit launcher_source_commit launcher_sha256 case_registry_sha256 corpus_sha256 native_mode latex_policy session_prepared runtime_executed independent_review_recorded research_trial_passed release_qualified; do
  sql "SELECT json_remove(CAST(readfile('$tmp/resume-good.json') AS TEXT),'\$.$field');" > "$tmp/resume-bad.json"
  deny rr_metadata "$tmp/resume-bad.json" "$sqlite"
done
for mutation in "'\$.extra',1" "'\$.repeat',1.0" "'\$.repeat',2" "'\$.session_prepared',1" "'\$.runtime_executed',json('true')" "'\$.trial_id','../../escape'" "'\$.candidate_sha256','unknown'" "'\$.native_mode','dangerous'" "'\$.latex_policy','static_only'" "'\$.research_trial_passed',json('true')"; do
  sql "SELECT json_set(CAST(readfile('$tmp/resume-good.json') AS TEXT),$mutation);" > "$tmp/resume-bad.json"
  deny rr_metadata "$tmp/resume-bad.json" "$sqlite"
done
sed 's/"repeat":1/"repeat":1,"repeat":1/' "$tmp/resume-good.json" > "$tmp/resume-bad.json"
deny rr_metadata "$tmp/resume-bad.json" "$sqlite"
printf 'broken' > "$tmp/resume-bad.json"
deny rr_metadata "$tmp/resume-bad.json" "$sqlite"
deny rr_main --session /never-read-production --sqlite "$sqlite" --operator-confirmed-stopped --check-only
deny rr_main --session "$session" --sqlite "$sqlite"
# A synthetic historical manifest is used only to test read-only validation;
# no assertion that these temporary files contain an executed research run.
cp "$tmp/resume-good.json" "$session/session.json"
printf '%s\n' 'Synthetic previous log.' > "$session/operator.log"
before_resume=$(sha256sum "$session/session.json" "$session/candidate" "$session/operator-key.txt" "$session/operator.log" "$session/task.md")
HOME="$fake_home" rr_main --session "$session" --sqlite "$sqlite" --operator-confirmed-stopped --check-only
[[ $(sha256sum "$session/session.json" "$session/candidate" "$session/operator-key.txt" "$session/operator.log" "$session/task.md") == "$before_resume" ]]
[[ ! -e $session/research-resume.lock ]]
printf 'RESEARCH_SESSION_TEST stopped_session_metadata_strict_and_check_only_readonly=passed\n'

# Process classification is tested against a fake proc tree. No host process is
# signalled here. Symlinked exe entries and NUL-delimited argv mirror procfs.
proc_fixture=$tmp/proc-fixture
candidate_fixture=$tmp/process-candidate
cp /usr/bin/true "$candidate_fixture"
chmod 500 "$candidate_fixture"
for spec in '101 tui' '102 __native-helper' '103 --sandbox-probe' '104 unknown-role'; do
  read -r pid role <<< "$spec"
  mkdir -p "$proc_fixture/$pid"
  ln -s "$candidate_fixture" "$proc_fixture/$pid/exe"
  printf '%s\0%s\0' "$candidate_fixture" "$role" > "$proc_fixture/$pid/cmdline"
done
ss_scan "$proc_fixture" "$candidate_fixture"
[[ ${#ss_tui[@]} == 1 && ${ss_tui[0]} == 101 ]]
[[ ${#ss_helper[@]} == 1 && ${ss_helper[0]} == 102 ]]
[[ ${#ss_probe[@]} == 1 && ${ss_probe[0]} == 103 ]]
[[ ${#ss_unknown[@]} == 1 && ${ss_unknown[0]} == 104 ]]
rm -rf "$proc_fixture/104"
ss_scan "$proc_fixture" "$candidate_fixture"
[[ ${#ss_unknown[@]} == 0 && ${#ss_tui[@]} == 1 && ${#ss_helper[@]} == 1 && ${#ss_probe[@]} == 1 ]]
printf 'RESEARCH_SESSION_TEST exact_candidate_process_roles_are_classified_without_signals=passed\n'

mkdir -p "$proc_fixture/201"
ln -s "$candidate_fixture" "$proc_fixture/201/exe"
printf '%s\0%s\0' "$candidate_fixture" tui > "$proc_fixture/201/cmdline"
cat > "$proc_fixture/201/status" <<'EOF'
Name: candidate
State: S (sleeping)
PPid: 77
Threads: 4
SigPnd: 0000000000000000
ShdPnd: 0000000000000000
SigBlk: 0000000000000000
SigIgn: 0000000000000002
SigCgt: 0000000100004000
EOF
printf '201 (candidate) S 77 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 999 0 0\n' > "$proc_fixture/201/stat"
printf 'ep_poll\n' > "$proc_fixture/201/wchan"
[[ $(ss_status_value "$proc_fixture" 201 State) == 'S (sleeping)' ]]
[[ $(ss_start_ticks "$proc_fixture" 201) == 999 ]]
[[ $(ss_status_value "$proc_fixture" 201 SigIgn) == 0000000000000002 ]]
deny ss_status_value "$proc_fixture" 201 MissingField
printf 'RESEARCH_SESSION_TEST bounded_proc_state_diagnostic_parser=passed\n'
printf 'RESEARCH_SESSION_TEST negative_cases=%s production_source_accessed=false runtime_config_only=true runtime_server_started=false research_trials_executed=0 tunnel_started=false\n' "$negative"
