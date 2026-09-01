# ADR 0008: atomic Rust cutover and bounded Python retirement

## Status

Accepted and completed.

## Decision

The final user command remains `re-ctm`. A versioned Rust release is copied to an
owner-controlled release root and verified by SHA-256 plus a typed `release-info`
contract. The command in the user's binary directory is an atomically replaced
symlink selecting exactly one runtime.

The migration uses three independently reviewable phases:

1. qualify the Rust candidate without changing the live command;
2. switch the live command to Rust, prove live rollback to Python, then recutover;
3. only after the Rust deployment remains healthy, stop residual Python Re-CTM
   processes and remove the installed Python tool environment while retaining an
   immutable, hash-recorded Re-CTM 0.3.0 wheel and the historical source repository.

Python and Rust never write the production state simultaneously. A retirement action
fails closed unless the command points to the recorded Rust release, the rollback
wheel exists with its recorded hash, and no process still executes from the Python
tool root.

The live transfer stopped four Python sessions and their owned descendants with
SIGINT only, selected the Rust release, exercised a real rollback to the recorded
Python command, selected Rust again, and restarted all four sessions from the Rust
binary. Generated operator keys are written only to owner-mode `0600` secret files;
background session logs contain the fixed `configured externally` marker rather than
raw keys.

The final retirement upgraded all four sessions to release SHA-256
`7142cf77775552533fc6472f46391989cc1d5d3ed12d1bdf08c48b7d7ae70728`,
removed `/home/lk/.local/share/uv/tools/re-ctm` and the legacy
`re-ctm-native-helper` entry, and confirmed that no Python Re-CTM process remained.
After deletion, rollback wheel SHA-256
`7133ee2ba083760081b7055a2c75447c5c7f0e7e45b10649badd70bbdc50fd9b`
was installed in an isolated uv tool root and served real OAuth metadata. Historical
source remains preserved but has no production authority.

## Performance claim boundary

A6 applies only to the report's authenticated local OAuth/MCP mixed request path:
`ping`, `tools/list`, `server_info`, `read_file`, and
`check_exec_environment` under eight concurrent clients. It does not imply that
network retrieval, Sage, Magma, LaTeX, or mathematical proof generation is faster by
the same factor.

## Rollback

After retirement, verify the immutable wheel hash, restore it into an owner-controlled
tool root, verify `re-ctm 0.3.0` and OAuth metadata, stop the Rust sessions, and
atomically select the restored command. Database and private-vault formats remain
schema-compatible and were never dual-written during the drill.
