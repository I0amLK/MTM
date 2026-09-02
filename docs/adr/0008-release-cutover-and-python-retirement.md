# ADR 0008: atomic Rust cutover and bounded Python retirement

## Status

Accepted and completed.

## Decision

The final MTM user command is `mtm`. A versioned Rust release is copied to an
owner-controlled MTM release root and verified by SHA-256 plus a typed `release-info`
contract. `re-ctm` is reserved exclusively for the separate Re-CTM project; MTM does
not install a compatibility alias under that name.

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

The retirement phase removed Python from MTM production authority after restoring and
probing the Re-CTM wheel. The subsequent command-namespace correction installed MTM
under `/home/lk/.local/bin/mtm` and `/home/lk/.local/share/mtm`, then restored
Re-CTM under `/home/lk/.local/bin/re-ctm` and its independent uv tool root. Four MTM
sessions were restarted on the MTM release. The projects can now be installed
simultaneously without sharing an executable name or installation root.

## Performance claim boundary

A6 applies only to the report's authenticated local OAuth/MCP mixed request path:
`ping`, `tools/list`, `server_info`, `read_file`, and
`check_exec_environment` under eight concurrent clients. It does not imply that
network retrieval, Sage, Magma, LaTeX, or mathematical proof generation is faster by
the same factor.

## Rollback

Re-CTM recovery is now a separate-project operation: verify its immutable wheel and
restore `re-ctm` under its own tool root. MTM recovery uses the `mtm` release selector
only. Neither recovery path aliases or overwrites the other project's command.
Database and private-vault formats remain schema-compatible and were never dual-written
during the migration drills.
