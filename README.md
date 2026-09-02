# MTM-reboot

MTM-reboot is the incremental Rust reboot of Re-CTM. The migration is deliberately
split into eight independently accepted and reversible milestones.

The governing order is:

1. preserve and deliver functionality, compatibility, and security;
2. implement with records, differential checks, and rollback evidence;
3. optimize only after equivalent behavior is demonstrated.

## Current status

- Source baseline: Re-CTM 0.3.0.
- Current MTM production authority: the hash-recorded Rust 0.3.0 release selected by
  `/home/lk/.local/bin/mtm`, SHA-256
  `abe861df86dded73a5fba08bc1b71cba46164a846318d004e846409e240e8438`.
- MTM-reboot Rust authority: typed pure contracts/policies, Native process/isolation,
  copied-state persistence/capabilities, the OAuth/MCP/HTTP gateway, and the
  workflow/private-vault/verifier/finalizer component, plus the single Rust runtime
  composition, remaining adapters, CLI/TUI, Quick Tunnel session, and installable
  release binary. All transferred live Re-CTM sessions now execute that Rust release.
- Completed milestones: `MTM-001` through `MTM-008`.
- `MTM-008` status: `completed`. Candidate qualification, immutable Python-wheel
  restore, live cutover/rollback/recutover, 60-second soak, bounded A6 acceptance,
  four-session transfer, final release upgrade, secret-free operator logging, and
  Python production retirement all pass.
- MTM no longer owns the `re-ctm` command. Re-CTM 0.3.0 is installed independently at
  `/home/lk/.local/bin/re-ctm`, while MTM uses only `/home/lk/.local/bin/mtm` and
  `/home/lk/.local/share/mtm`. The two command names and installation roots are
  mechanically required to remain distinct; MTM provides no `re-ctm` compatibility alias.
- Historical Python source is preserved as a non-production reference, and the tested
  Re-CTM wheel remains owner-controlled at
  `/home/lk/.local/share/re-ctm-rust/rollback/re_ctm-0.3.0-py3-none-any.whl`
  with SHA-256
  `7133ee2ba083760081b7055a2c75447c5c7f0e7e45b10649badd70bbdc50fd9b`.

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
python3 scripts/validate_mtm_command_namespace.py
cargo run -q -p mtm-cli -- contract
cargo run -q -p mtm-cli -- status
cargo run -q -p mtm-cli -- release-info
python3 scripts/run_mtm002_conformance.py
```

`MTM-002` compares 135 pure valid, invalid, boundary, and adversarial cases against
the frozen Re-CTM Python source. `MTM-003` adds exact/semantic Native differential
checks plus hash-bound real target evidence for Bubblewrap, TTY, SageMath, Magma,
read-only toolchains, private-root denial, timeout/kill provenance, and Quick Tunnel
ownership. At that milestone the old runtime remained the deployed production and
rollback implementation until later milestones were independently accepted. `MTM-004` adds a
52-operation exact state/capability corpus, v0/v1/v2 migration and rollback fixtures,
and hash-bound real target evidence from a read-only backup of the configured Re-CTM
state database. No private database row, run/project id, token, proof, or source
content is written to the report. `MTM-005` adds 44 deterministic OAuth/MCP records,
exact hashes for all 35 tool definitions, and real Firefox + HTTP validation of DCR,
PKCE, fixed/dynamic issuers, Origin/CORS gates, legacy/modern MCP, public listing,
hidden aliases, and mirror headers. At that milestone the old runtime remained the
deployed traffic and state authority until later milestones were independently
accepted. `MTM-006` adds 82
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
The accepted MTM-008 A6 statement is deliberately narrow: on the recorded
authenticated loopback OAuth/MCP mix
(`ping`, `tools/list`, `server_info`, `read_file`, and
`check_exec_environment`) under eight clients, Rust passed conservative throughput,
p95-latency, and RSS thresholds. That evidence is not a claim about external
retrieval, Sage, Magma, LaTeX, or proof-generation time.

## Normal operation

```bash
mtm tui --quick-tunnel --native-mode dangerous
```

`mtm` is the only MTM command. `re-ctm` belongs to the separate Re-CTM project and is
not an alias for MTM. This allows both projects to be installed on the same machine
without executable-name or installation-root collisions.

The command above runs the MTM Rust release. Bubblewrap remains the Linux operating-system
isolation actuator for Native tools; it is not a Python dependency and it does not
grant workflow or finalizer authority.

The project does not claim parity, safety, or performance merely because a Rust
binary builds. See [`docs/ACCEPTANCE.md`](docs/ACCEPTANCE.md) and
[`docs/MIGRATION_PLAN.md`](docs/MIGRATION_PLAN.md).
