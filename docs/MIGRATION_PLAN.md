# MTM-reboot eight-milestone plan

## MTM-001 — foundation and governance

Create the repository, source baseline, Cargo skeleton, code and commit standards,
acceptance hierarchy, migration/architecture graphs, validation scripts, golden
bootstrap contract, and first receipt. No production authority moves.

## MTM-002 — typed contract and pure policy core

Migrate stable errors, enums, schema validation, redaction, URL/path validation,
command policy, patch parsing, and other side-effect-free logic. Rust begins in
read-only shadow mode and cuts over only after golden/differential parity.

Completion evidence is recorded in `records/iterations/ITER-002.json`. The source
corpus contains 135 cases with an immutable response hash, and the Rust implementation
is authoritative only for the pure MTM-reboot core. Re-CTM remains the production
runtime while all stateful milestones are still pending.

## MTM-003 — native process and isolation plane

Migrate bounded capture, process groups, command IDs, TTY, timeout/kill provenance,
toolchain exposure, Bubblewrap helper, and Quick Tunnel child ownership. Preserve the
separate isolation-process bridge. Require target-machine evidence.

## MTM-004 — persistence and capability authority

Migrate SQLite schema/migrations, run/project/claim state, optimistic promotion,
capability signing/validation/revocation, and transactional invariants. Use copied
databases for shadow comparison; never dual-write production state.

## MTM-005 — OAuth, MCP, HTTP, and tool dispatch

Migrate DCR, PKCE, token binding, fixed/dynamic origins, route Origin policy, JSON-RPC,
modern/legacy MCP shaping, the exact 24-tool catalog, hidden aliases, and gateway error
semantics. Require a real browser/client acceptance path before cutover.

## MTM-006 — workflow, vault, verifier, and finalizer

Migrate the deterministic workflow transition kernel, role/capability resource rules,
branch barriers, compact/full escalation, proof manifests, reference audits, repair,
project promotion, private vault, and the sole finalizer. Use historical trace replay;
keep one transition and one finalization authority.

## MTM-007 — remaining adapters and distribution

Migrate file/Git/image compatibility, research adapters, LaTeX gate, diagnostics,
TUI, Quick Tunnel presentation, configuration, CLI, installer, and release artifacts.
The binary becomes operationally complete but Python remains a tested rollback until
MTM-008.

## MTM-008 — cutover and Python retirement

Run complete local, target, browser, CAS, LaTeX, upgrade, rollback, soak, resource,
and performance acceptance. Switch all remaining authority to Rust, prove rollback,
then remove Python production code and interpreter dependency in a separate commit.

## Stop rules

Stop a milestone rather than widening it when:

- parity differences are unexplained;
- source behavior is not sufficiently specified;
- a security or transaction boundary would be weakened;
- rollback cannot be performed without data loss;
- the milestone requires unrelated protocol redesign;
- target/manual evidence is unavailable for a required boundary;
- measured resource behavior regresses materially.
