# MTM-reboot acceptance method

## A0 — build and local static gate

- `cargo fmt --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- migration and architecture graph validators
- commit-message and record validators
- `git diff --check`

## A1 — contract and golden parity

- public tools, aliases, schemas, defaults, errors, and annotations match the source;
- JSON and artifact bytes are normalized and compared;
- valid, invalid, historical, boundary, and adversarial fixtures are included;
- every intentional difference has a separately approved contract-change record.

## A2 — differential shadow

- Python and Rust receive the same frozen inputs;
- shadow uses disposable state and produces no production side effects;
- differences are persisted with fingerprints and classification;
- unresolved differences block authority cutover.

## A3 — integration, persistence, and security

- OAuth/MCP behavior, permission denials, capability lifecycle, transaction rollback,
  concurrent conflicts, branch barriers, verifier firewall, process ownership,
  shutdown, and finalization are exercised;
- production state has one writer;
- secret scanning and negative tests pass.

## A4 — target/manual acceptance

Where relevant, a human runs:

- real webpage OAuth/DCR/PKCE;
- real Bubblewrap and dangerous-mode isolation;
- Sage, Magma, ordinary shell, TTY, timeout, and kill;
- copied production database migration and old-run resume;
- real network retrieval and redirect policy;
- real LaTeX compilation and proof-repair-finalization;
- install/upgrade/rollback on target machines.

Mocks do not satisfy A4.

## A5 — resource non-regression

Compare equivalent configurations for:

- startup p50/p95;
- idle and active RSS;
- request p95/p99;
- threads, tasks, and child processes;
- database and filesystem writes;
- queue/backpressure behavior;
- graceful and forced shutdown bounds.

Unexplained material regression blocks cutover.

## A6 — performance claim

A6 exists only after A0–A5. It records environment, workload, input scale, warmup,
repetition count, median, p95/p99, RSS, and confidence/variance. The claim must name
the exact function or user-visible path improved.

## Acceptance by milestone

| Milestone | Minimum acceptance before completion |
|---|---|
| MTM-001 | A0 foundation checks and recorded source baseline |
| MTM-002 | A0, A1, A2 for pure contract/policy behavior |
| MTM-003 | A0–A5 including target native isolation |
| MTM-004 | A0–A5 including copied database migration/rollback |
| MTM-005 | A0–A5 including real OAuth/MCP client path |
| MTM-006 | A0–A5 including full proof, repair, and finalization |
| MTM-007 | A0–A5 including package, TUI, tunnel, external tools |
| MTM-008 | A0–A6, rollback drill, and Python retirement evidence |
| MTM-009 | A0–A5 plus protocol-1/2 non-regression, deterministic bounded research-state projection, adversarial graph/firewall tests, copied-state rollback, and paired real web-driven mathematical evaluation with verified `.tex` non-regression |
| MTM-012 | A0, A1, A3, A4 for compact-by-default TUI information hierarchy, verbose diagnostic fallback, redaction, and a real OAuth/MCP operator-monitor smoke |
| MTM-013 | A0, A1, A3, A4, A5 for fail-closed capability refresh, validation-metadata consistency, clean public installation, existing-state upgrade, proof finalization, stable rollback/recutover and bounded soak |
| MTM-014 | A0, A1, A3, A4 for typed Rust Native permission authority, complete eight-kind permission classification, fail-closed grant binding/expiry/replay handling, unchanged Bubblewrap isolation authority, and real safe/trusted/dangerous permission-path validation |
