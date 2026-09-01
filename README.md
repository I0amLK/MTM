# MTM-reboot

MTM-reboot is the incremental Rust reboot of Re-CTM. The migration is deliberately
split into eight independently accepted and reversible milestones.

The governing order is:

1. preserve and deliver functionality, compatibility, and security;
2. implement with records, differential checks, and rollback evidence;
3. optimize only after equivalent behavior is demonstrated.

## Current status

- Source baseline: Re-CTM 0.3.0.
- Current production authority: Re-CTM's Python implementation. The Rust 0.3.0
  release is cutover-candidate qualified but has not yet replaced the live command.
- MTM-reboot Rust authority: typed pure contracts/policies, Native process/isolation,
  copied-state persistence/capabilities, the OAuth/MCP/HTTP gateway, and the
  workflow/private-vault/verifier/finalizer component, plus the single Rust runtime
  composition, remaining adapters, CLI/TUI, Quick Tunnel session, and installable
  release binary. No deployed Re-CTM request path or production database writer has moved.
- Completed milestones: `MTM-001` through `MTM-007`.
- `MTM-008` status: `shadow`. Candidate qualification, immutable Python-wheel
  restore, temporary cutover/rollback/recutover, 60-second soak, and bounded A6
  acceptance pass. Live cutover and Python production retirement remain separate
  commits.

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
python3 scripts/run_mtm005_conformance.py
python3 scripts/validate_mtm005_target_evidence.py
python3 scripts/run_mtm006_conformance.py
python3 scripts/validate_mtm006_target_evidence.py
python3 scripts/run_mtm007_conformance.py
python3 scripts/validate_mtm007_target_evidence.py
python3 scripts/run_mtm008_performance.py
python3 scripts/run_mtm008_soak.py
python3 scripts/run_mtm008_candidate_validation.py
python3 scripts/validate_mtm008_candidate_evidence.py
cargo run -q -p mtm-cli -- contract
cargo run -q -p mtm-cli -- status
cargo run -q -p mtm-cli -- release-info
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
content is written to the report. `MTM-005` adds 44 deterministic OAuth/MCP records,
exact hashes for all 35 tool definitions, and real Firefox + HTTP validation of DCR,
PKCE, fixed/dynamic issuers, Origin/CORS gates, legacy/modern MCP, public listing,
hidden aliases, and mirror headers. The old runtime remains the deployed traffic and
state authority until later milestones are independently accepted. `MTM-006` adds 82
exact workflow/vault/database checkpoints with zero Python-Rust mismatches plus real
`pdflatex` evidence for mechanical finalization, VERIFIED project promotion,
post-verifier proof-tamper denial, and server-derived reference-audit gaps. L2
capability claims and the finalization permit are non-public-construction Rust
authority types rather than caller-supplied role/state booleans. `MTM-007` adds an
18-checkpoint full HTTP/OAuth/MCP/tool composition differential with frozen SHA-256
`6aa4f5699df7099d29c12859788430bd6b1c66a8295828598b6cae62a964d830`, static
hash-bound catalog/methodology assets, real release Bubblewrap/research/LaTeX/TUI/
Quick-Tunnel acceptance, and `cargo install --path` single-binary distribution without
Python/libpython linkage. Its A5 resource samples are non-regression evidence only;
A6 performance conclusions remain `MTM-008` work. The current MTM-008 A6 statement
is deliberately narrow: on the recorded authenticated loopback OAuth/MCP mix
(`ping`, `tools/list`, `server_info`, `read_file`, and
`check_exec_environment`) under eight clients, Rust passed conservative throughput,
p95-latency, and RSS thresholds. That evidence is not a claim about external
retrieval, Sage, Magma, LaTeX, or proof-generation time.

The project does not claim parity, safety, or performance merely because a Rust
binary builds. See [`docs/ACCEPTANCE.md`](docs/ACCEPTANCE.md) and
[`docs/MIGRATION_PLAN.md`](docs/MIGRATION_PLAN.md).
