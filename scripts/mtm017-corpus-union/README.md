# MTM-017 corpus union source archive

These four files are byte-identical copies of the Bash/SQLite governance
implementation independently reviewed and used for the 87-cell proposal.
The evidence mapping is
`records/evidence/MTM-017/corpus-union-source-archive-20260930.json`.
This is governance integration, not a Rust CLI or product runtime.

## Replay requirements

The frozen implementation binds its original path and other archived inputs.
Invoke it from the repository root at its original target path, not from this
archive directory. The public JSON inputs, original sealed execution logs,
preserved maintenance executable and explicit
`/home/lk/miniconda3/bin/sqlite3` are required. A clone contains the implementation
and public records, not all historical target archives or private evidence.
Missing evidence is a verification blocker; never synthesize it.

To restore missing source files only, without replacing an existing file:

```sh
set -eu
base=target/mtm017-authority-corpus-20260930
mkdir -p "$base"
for f in union-validator.sh union-validator.sql union-shapes.sql union-negative-mutations.sql; do
  if test -e "$base/$f"; then
    cmp "scripts/mtm017-corpus-union/$f" "$base/$f"
  else
    cp "scripts/mtm017-corpus-union/$f" "$base/$f"
  fi
done
# Only after the complete sealed replay prerequisites have been restored:
bash "$base/union-validator.sh" --self-test
bash "$base/union-validator.sh" --propose
```

No old evidence locator or hash is rewritten. The original 65 semantic and 10
reader negatives remain their recorded test evidence; byte-copying the scripts
does not claim a new test run or full clone reproduction. The proposal remains
zero-delta. Count activation still requires independent review and explicit
governance authorization. No production, release or deployment authority follows.
