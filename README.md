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
- MTM-reboot Rust authority: typed pure contracts/policies, the independent Native
  process/isolation component, and the copied-state persistence/capability component.
  No deployed Re-CTM request path or production database writer has moved.
- Completed milestones: `MTM-001` through `MTM-004`.
- Next approved milestone: `MTM-005` OAuth, MCP, HTTP, and public tool dispatch.

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
python3 scripts/run_mtm003_conformance.py
python3 scripts/validate_mtm003_target_evidence.py
python3 scripts/run_mtm004_conformance.py
python3 scripts/validate_mtm004_target_evidence.py
cargo run -q -p mtm-cli -- contract
cargo run -q -p mtm-cli -- status
python3 scripts/run_mtm002_conformance.py
```

`MTM-002` compares 135 pure valid, invalid, boundary, and adversarial cases against
the frozen Re-CTM Python source. `MTM-003` adds exact/semantic Native differential
checks plus hash-bound real target evidence for Bubblewrap, TTY, SageMath, Magma,
read-only toolchains, private-root denial, timeout/kill provenance, and Quick Tunnel
ownership. The old runtime remains the deployed production and rollback
implementation until later milestones are independently accepted. `MTM-004` adds a
52-operation exact state/capability corpus, v0/v1/v2 migration and rollback fixtures,
and hash-bound real target evidence from a read-only backup of the configured Re-CTM
state database. No private database row, run/project id, token, proof, or source
content is written to the report.

The project does not claim parity, safety, or performance merely because a Rust
binary builds. See [`docs/ACCEPTANCE.md`](docs/ACCEPTANCE.md) and
[`docs/MIGRATION_PLAN.md`](docs/MIGRATION_PLAN.md).
