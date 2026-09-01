# MTM-reboot

MTM-reboot is the incremental Rust reboot of Re-CTM. The migration is deliberately
split into eight independently accepted and reversible milestones.

The governing order is:

1. preserve and deliver functionality, compatibility, and security;
2. implement with records, differential checks, and rollback evidence;
3. optimize only after equivalent behavior is demonstrated.

## Current status

- Source baseline: Re-CTM 0.3.0.
- Current production authority: Re-CTM's Python implementation.
- MTM-reboot authority: bootstrap contracts only; no production request path has moved.
- Active milestone: `MTM-001` foundation, governance, and conformance bootstrap.

## Eight milestones

1. Foundation, governance, source baseline, and conformance harness.
2. Typed contract and pure policy core.
3. Native process lifecycle and isolation worker.
4. Persistence, migration, project state, and capability authority.
5. OAuth, MCP, HTTP gateway, and public tool dispatch.
6. Workflow, vault, verifier/finalizer, and project registry behavior.
7. Remaining tools, integrations, TUI, Quick Tunnel, and packaging.
8. Full cutover, target acceptance, performance evidence, and Python retirement.

The authoritative milestone graph is [`migration-graph.json`](migration-graph.json).

## Bootstrap commands

```bash
python3 scripts/run_checks.py
cargo run -q -p mtm-cli -- contract
cargo run -q -p mtm-cli -- status
```

The project does not claim parity, safety, or performance merely because a Rust
binary builds. See [`docs/ACCEPTANCE.md`](docs/ACCEPTANCE.md) and
[`docs/MIGRATION_PLAN.md`](docs/MIGRATION_PLAN.md).
