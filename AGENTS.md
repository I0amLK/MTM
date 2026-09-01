# MTM-reboot engineering rules

Read `docs/CODE_STANDARD.md`, `docs/COMMIT_STANDARD.md`,
`docs/ACCEPTANCE.md`, and `migration-graph.json` before changing code.

## Priority

1. Functionality, compatibility, mathematical finalization, and security boundaries.
2. Recorded, tested, reviewable, and reversible implementation.
3. Measured performance and structural optimization.

No lower-priority goal may weaken a higher-priority goal.

## Authority rules

- Every migrated component has exactly one production authority.
- Rust shadow implementations are read-only and side-effect-free.
- Python and Rust never write the same production state concurrently.
- There is one workflow transition authority and one finalizer authority.
- Native `dangerous` authority never grants workflow or project authority.
- No migration may change the 24-tool contract, hidden aliases, state schema,
  workflow protocol, OAuth behavior, or artifact semantics without a separate,
  explicitly approved contract-change milestone.

## Change rules

- Every commit references one `MTM-NNN` milestone.
- Every status change appends a migration event.
- Every completed, rejected, or cutover milestone appends a receipt.
- Do not add a new crate before its milestone is approved.
- Do not mix functional migration, unrelated cleanup, formatting, and optimization.
- Do not claim performance without A6 evidence.
- Preserve the source baseline and all failed/rollback evidence.

## Required local gate

```bash
python3 scripts/run_checks.py
```

Local success is not target/browser/CAS/LaTeX acceptance.
