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
- MTM-reboot Rust authority: typed side-effect-free contracts and pure policy only;
  no production request, persistence, process, network, workflow, or finalizer path has moved.
- Completed milestones: `MTM-001`, `MTM-002`.
- Next approved milestone: `MTM-003` Native process lifecycle and isolation.

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
python3 scripts/run_mtm002_conformance.py
```

`MTM-002` compares 135 valid, invalid, boundary, and adversarial cases against the
frozen Re-CTM Python source. Rust is authoritative only for the new project's pure
core; the old runtime remains the production and rollback implementation until later
milestones are independently accepted.

The project does not claim parity, safety, or performance merely because a Rust
binary builds. See [`docs/ACCEPTANCE.md`](docs/ACCEPTANCE.md) and
[`docs/MIGRATION_PLAN.md`](docs/MIGRATION_PLAN.md).
