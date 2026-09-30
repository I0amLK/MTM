#!/usr/bin/env bash
# MTM-017 one-off public-evidence governance integration. No product entrypoint.
set -euo pipefail
SQLITE=/home/lk/miniconda3/bin/sqlite3
BASE=target/mtm017-authority-corpus-20260930
SQL=$BASE/union-validator.sql
SHAPES=$BASE/union-shapes.sql
NEGATIVE=$BASE/union-negative-mutations.sql
INPUT=records/evidence/MTM-017/corpus-union-inputs-20260930.json
REVIEW=records/evidence/MTM-017/corpus-union-input-review-20260930.json
SOURCE=e23c984936c6d2945b82db5a0fc26f3ab1ebf4629d7d1bbe14078cca0953620f
MODE="$1"
[[ "$MODE" == --self-test || "$MODE" == --propose ]] || exit 2
[[ $# == 1 ]] || exit 2
[[ -x "$SQLITE" && -f Cargo.toml && -d records ]] || exit 2
TMP=$(mktemp -d "$BASE/union-work.XXXXXXXX")
chmod 700 "$TMP"
trap 'printf "retained_execution_archive=%s\n" "$TMP" >&2' EXIT
# Retain private bounded snapshots/logs as execution evidence, including failures.
meta() { stat -c '%d:%i:%s:%f:%u:%g:%h:%y:%z' -- "$1"; }
digest() { sha256sum -- "$1" | cut -d' ' -f1; }
safe_copy() {
  local p="$1" want="$2" out="$3" walk="" rest="$1" part before after size mode parent
  [[ "$p" =~ ^[a-zA-Z0-9_./-]+$ && "$p" != /* && "$p" != *..* && "$p" != *//* ]] || return 1
  [[ "$want" =~ ^[0-9a-f]{64}$ ]] || return 1
  : > "$out.dirs"
  while [[ "$rest" == */* ]]; do
    part=$(printf '%s' "$rest" | cut -d/ -f1)
    rest=$(printf '%s' "$rest" | cut -d/ -f2-)
    walk="$walk$part"
    [[ -d "$walk" && ! -L "$walk" ]] || return 1
    printf '%s|%s\n' "$walk" "$(meta "$walk")" >> "$out.dirs"
    walk="$walk/"
  done
  [[ -f "$p" && ! -L "$p" ]] || return 1
  before=$(meta "$p"); size=$(stat -c %s -- "$p"); mode=$(stat -c %a -- "$p")
  parent=$(dirname "$p")
  [[ $(stat -c %h -- "$p") == 1 && $(stat -c %u -- "$p") == "$(stat -c %u -- "$parent")" ]] || return 1
  (( size > 0 && size <= 1048576 && (8#$mode & 07113) == 0 )) || return 1
  # Regular-file metadata is checked before/after; NOFOLLOW refuses leaf
  # symlinks and NONBLOCK plus a byte cap bounds special-file substitutions.
  (umask 077; dd if="$p" of="$out" iflag=nofollow,nonblock,count_bytes count=1048577 status=none) || return 1
  after=$(meta "$p")
  [[ "$before" == "$after" && ! -L "$p" && $(stat -c %s -- "$out") == "$size" && $(digest "$out") == "$want" ]] || return 1
  printf '%s\n' "$before" > "$out.meta"
  while IFS='|' read -r part before; do [[ ! -L "$part" && "$(meta "$part")" == "$before" ]] || return 1; done < "$out.dirs"
}
manifest() {
cat <<'REFS'
base records/evidence/MTM-017/partial-corpus-accepted-20260930.json a08866847b55fb1e896e98a2cd746c4d61e550515f3167122015e282051adaf9
base_pointer records/governance/mtm017-partial-corpus.json 0f2562453258f469a99a8f8b084cb4fb718ed089470dd185222da613ceb403c2
research_pointer records/governance/mtm017-research-corpus.json 27aff327aba433e907e3ee639bad5ce0cee1512ba61359bfc2f988c42626eb24
driver records/governance/mtm016-release-inputs.json e55f2c5624e6f94f4805bed38dd968626808f7df00d95bff9168cf86eb8cda04
authority_inputs records/evidence/MTM-017/authority-corpus-inputs-20260930.json cb710ff1d7639ef1404358863497ede19c390101e3e05baaa392e112b4005c8a
authority_recording records/evidence/MTM-017/authority-corpus-recording-20260930.json 43ad7af0549c977db5cd56977eeb92780f1ac2e274e364e53d000253d269faf6
authority_proposal records/evidence/MTM-017/authority-corpus-observed-proposal-20260930.json df55a45d7caf42e88bb99d03efc919d464e1925c90b741d16c8e00b25335aad7
authority_validation records/evidence/MTM-017/authority-corpus-preexecution-validation-20260930.json 054c663c680e9cdc721a4addd070ed9bcdbc61462b8210999717eb535ada28f1
authority_preexecution_review records/evidence/MTM-017/authority-corpus-preexecution-review-20260930.json a7dc4a68a1368dafc6eaa8d4191748194dfbfc1f5340264411304fc7922c4c8f
mapping records/evidence/MTM-017/u27-u28-operator-mapping-authorization-20260930.json 3fded16a067a77f6935aca556593e2c955563562c1ec8bf02a76d138ba24fcbc
u29_aggregate records/evidence/MTM-017/operator-copy-prepared-rehearsal-aggregate-20260930.json 95190cfb08f3a5efc71d913a272ba8db2dd2779465e5c2b4c77ece09ae30731f
u29_review records/evidence/MTM-017/operator-copy-prepared-rehearsal-review-20260930.json 31e3129197014901f9824d6a48ac26b52b1db59aa4e158af9f98ceef06a8702c
u29_audit records/evidence/MTM-017/u29-import-input-audit-20260930.json a0c785a2b222f64ccdd790316541ed806e477e2c17ca6ddc605c00f234d78957
u29o1 records/evidence/MTM-017/operator-copy-prepared-repeat-1-20260930.json 5d9025999c0ee6ae8d50e68238b2e4721bf9ec5a93e2327f250cd88fcfda39a4
u29o2 records/evidence/MTM-017/operator-copy-prepared-repeat-2-20260930.json ba289d1d69e18539c014f138343f8c1b70993a9f86ab2fc0ff846fa503ec3571
u29o3 records/evidence/MTM-017/operator-copy-prepared-repeat-3-20260930.json bdaecd8199b73cb1d5b6c3325e2ed07c5a9305aeb9d8fdc94f2af40baecaf6c3
u29p1 records/evidence/MTM-017/operator-copy-prepared-repeat-1-exact-restoration-20260930.json 935ab7c1ccc28721dc1d358b541f9597031af68a8b33ef2fa3e15e15fee4119c
u29p2 records/evidence/MTM-017/operator-copy-prepared-repeat-2-exact-restoration-20260930.json 62874beaa1e3638dcd08a51253022f57700e722740c3e46e360f03dba3e506ef
u29p3 records/evidence/MTM-017/operator-copy-prepared-repeat-3-exact-restoration-20260930.json aca2da5e94bcedbdfc94ec5e696658da3e051a382ea83b365d7624bf28946f17
state_decision records/evidence/MTM-017/operator-copy-prepared-continuation-authorization-20260930.json 953be5aa5bfa3632408f66264e129b184219ce09c8ecd5de91ee93e608ee0933
clarification records/evidence/MTM-017/operator-copy-prepared-continuation-order-clarification-20260930.json ec2638268b0b419d6f4ca0cd03985336965a8e7b4cb47bcc31f43c6fcfee03c1
strict_failure records/evidence/MTM-017/operator-copy-real-rehearsal-attempt-1-failed-20260930.json 2fbc819765e920a8ce89ad4f94317a26275b3701c785fe2fa9e2ffee4fbd67d0
capture records/evidence/MTM-017/operator-state-capture-20260930.json 404e0205ed7fee18bfe3a15c5999d3be2082fb8dad69bc9b5cb8efc6e0917771
source_gate records/evidence/MTM-017/authority-corpus-whole-source-final-20260930.json ded9f3362936b08589df6d58f909c0f8046e069592d609f7d31ef033e69428bc
regression records/evidence/MTM-017/authority-corpus-source-regression-followup-20260930.json e5d4d5a4374f75abb113b0dd995f9a8a2e9118788d9ccba5a922232f5611fa45
REFS
}
script_sha=$(digest "$0"); sql_sha=$(digest "$SQL")
shape_sha=$(digest "$SHAPES"); negative_sha=$(digest "$NEGATIVE")
safe_copy "$0" "$script_sha" "$TMP/script.sh"
safe_copy "$SQL" "$sql_sha" "$TMP/validator.sql"
safe_copy "$SHAPES" "$shape_sha" "$TMP/shapes.sql"
safe_copy "$NEGATIVE" "$negative_sha" "$TMP/negative.sql"
safe_copy "$INPUT" "$(digest "$INPUT")" "$TMP/input.json"
printf '.bail on\nCREATE TABLE docs(id TEXT PRIMARY KEY,path TEXT,sha TEXT,body TEXT);\n' > "$TMP/load.sql"
printf "INSERT INTO docs VALUES('input','%s','%s',CAST(readfile('%s/input.json') AS TEXT));\n" "$INPUT" "$(digest "$TMP/input.json")" "$TMP" >> "$TMP/load.sql"
manifest > "$TMP/manifest"
while read -r id p sha; do
  safe_copy "$p" "$sha" "$TMP/$id.json"
  printf "INSERT INTO docs VALUES('%s','%s','%s',CAST(readfile('%s/%s.json') AS TEXT));\n" "$id" "$p" "$sha" "$TMP" "$id" >> "$TMP/load.sql"
done < "$TMP/manifest"
testing=0
if [[ "$MODE" == --self-test ]]; then
  testing=1
else
  safe_copy "$REVIEW" "$(digest "$REVIEW")" "$TMP/review.json"
  printf "INSERT INTO docs VALUES('review','%s','%s',CAST(readfile('%s/review.json') AS TEXT));\n" "$REVIEW" "$(digest "$TMP/review.json")" "$TMP" >> "$TMP/load.sql"
fi
printf "CREATE TABLE context(script_sha TEXT,sql_sha TEXT,shape_sha TEXT,negative_sha TEXT,testing INTEGER); INSERT INTO context VALUES('%s','%s','%s','%s',%s);\n" "$script_sha" "$sql_sha" "$shape_sha" "$negative_sha" "$testing" >> "$TMP/load.sql"
# This is the reviewed Rust six-row validator, not a trial rerun.
BIN=$BASE/frozen/mtm-xtask-06e379af877588460fe9aad8436dc3ee9f4a25b8615de1e8ce5a1561f4370de5
[[ -f "$BIN" && ! -L "$BIN" && $(digest "$BIN") == 06e379af877588460fe9aad8436dc3ee9f4a25b8615de1e8ce5a1561f4370de5 ]] || exit 1
"$BIN" schema8-authority-observation-check --inputs records/evidence/MTM-017/authority-corpus-inputs-20260930.json > "$TMP/authority-recheck.json"
[[ $(digest "$TMP/authority-recheck.json") == df55a45d7caf42e88bb99d03efc919d464e1925c90b741d16c8e00b25335aad7 ]] || exit 1
run_sql() { { cat "$TMP/load.sql"; printf '%s\n' "$1"; printf 'CREATE TEMP TABLE assertion(label TEXT, ok INTEGER NOT NULL CHECK(ok=1));\n'; cat "$TMP/shapes.sql" "$TMP/validator.sql"; } | "$SQLITE" -bail :memory:; }
run_sql "" > "$TMP/proposal.json" 2> "$TMP/validation.stderr"
if [[ "$MODE" == --self-test ]]; then
  n=0
  while IFS= read -r mutation; do
    [[ -n "$mutation" ]] || continue
    n=$((n+1))
    if run_sql "$mutation" > "$TMP/negative-$n.stdout" 2> "$TMP/negative-$n.stderr"; then echo "negative mutation unexpectedly passed: $n" >&2; exit 1; fi
  done < "$TMP/negative.sql"
  # Reader negatives use only newly created fixtures, never original evidence.
  printf '{}' > "$TMP/fixture"; h=$(digest "$TMP/fixture")
  ln -s fixture "$TMP/link"
  if safe_copy "$TMP/link" "$h" "$TMP/linked-copy"; then exit 1; fi
  ln "$TMP/fixture" "$TMP/hard"
  if safe_copy "$TMP/hard" "$h" "$TMP/hard-copy"; then exit 1; fi
  printf '{}' > "$TMP/mode"; chmod 666 "$TMP/mode"
  if safe_copy "$TMP/mode" "$h" "$TMP/mode-copy"; then exit 1; fi
  truncate -s 1048577 "$TMP/oversize"
  if safe_copy "$TMP/oversize" "$h" "$TMP/oversize-copy"; then exit 1; fi
  if safe_copy "$TMP/../fixture" "$h" "$TMP/escape-copy"; then exit 1; fi
  mkdir "$TMP/control" "$TMP/copies"
  printf '{}' > "$TMP/control/ordinary"; chmod 600 "$TMP/control/ordinary"
  safe_copy "$TMP/control/ordinary" "$h" "$TMP/copies/positive"
  ln -s control "$TMP/ancestor-link"
  if safe_copy "$TMP/ancestor-link/ordinary" "$h" "$TMP/copies/ancestor"; then exit 1; fi
  mkfifo "$TMP/control/fifo"
  if safe_copy "$TMP/control/fifo" "$h" "$TMP/copies/fifo"; then exit 1; fi
  if safe_copy "$TMP/control/ordinary" "$(printf '%064d' 0)" "$TMP/copies/wrong-sha"; then exit 1; fi
  mv "$TMP/control/ordinary" "$TMP/control/original-inode"
  printf '{}' > "$TMP/control/ordinary"; chmod 600 "$TMP/control/ordinary"
  safe_copy "$TMP/control/ordinary" "$h" "$TMP/copies/replaced"
  if cmp -s "$TMP/copies/positive.meta" "$TMP/copies/replaced.meta"; then exit 1; fi
  chmod 640 "$TMP/control/ordinary"
  safe_copy "$TMP/control/ordinary" "$h" "$TMP/copies/changed-mode"
  if cmp -s "$TMP/copies/replaced.meta" "$TMP/copies/changed-mode.meta"; then exit 1; fi
  printf '{"schema":"mtm017-union-governance-self-test-v1","semantic_negative_cases":%s,"reader_negative_cases":10,"passed":true,"accepted_delta":0}\n' "$n" > "$TMP/self-test-result.json"
fi
# Recheck original paths after every read/evaluation; fail the command on drift.
while read -r id p sha; do
  safe_copy "$p" "$sha" "$TMP/recheck-$id.json"
  cmp "$TMP/$id.json.meta" "$TMP/recheck-$id.json.meta"
  cmp "$TMP/$id.json.dirs" "$TMP/recheck-$id.json.dirs"
done < "$TMP/manifest"
safe_copy "$INPUT" "$(digest "$TMP/input.json")" "$TMP/recheck-input.json"
safe_copy "$0" "$script_sha" "$TMP/recheck-script.sh"
safe_copy "$SQL" "$sql_sha" "$TMP/recheck-validator.sql"
safe_copy "$SHAPES" "$shape_sha" "$TMP/recheck-shapes.sql"
safe_copy "$NEGATIVE" "$negative_sha" "$TMP/recheck-negative.sql"
for name in input.json script.sh validator.sql shapes.sql negative.sql; do
  cmp "$TMP/$name.meta" "$TMP/recheck-$name.meta"
  cmp "$TMP/$name.dirs" "$TMP/recheck-$name.dirs"
done
if [[ "$MODE" == --propose ]]; then safe_copy "$REVIEW" "$(digest "$TMP/review.json")" "$TMP/recheck-review.json"; fi
if [[ "$MODE" == --propose ]]; then
  cmp "$TMP/review.json.meta" "$TMP/recheck-review.json.meta"
  cmp "$TMP/review.json.dirs" "$TMP/recheck-review.json.dirs"
  cat "$TMP/proposal.json"
else
  cat "$TMP/self-test-result.json"
fi
