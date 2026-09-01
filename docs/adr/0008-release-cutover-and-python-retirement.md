# ADR 0008: atomic Rust cutover and bounded Python retirement

## Status

Accepted through the live authority-transfer phase. Python retirement remains a
separate commit.

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

## Performance claim boundary

A6 applies only to the report's authenticated local OAuth/MCP mixed request path:
`ping`, `tools/list`, `server_info`, `read_file`, and
`check_exec_environment` under eight concurrent clients. It does not imply that
network retrieval, Sage, Magma, LaTeX, or mathematical proof generation is faster by
the same factor.

## Rollback

Before retirement, atomically select the recorded previous Python command. After
retirement, restore the immutable wheel into an isolated tool root, verify
`re-ctm 0.3.0`, and atomically select it. Database and private-vault formats remain
schema-compatible and are never dual-written during the drill.
