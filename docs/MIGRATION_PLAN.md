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

Implemented and accepted on the current Linux target with exact/semantic
Python–Rust differential checks, real Bubblewrap attestation, generic explicit
toolchain execution, read-only mounts, SageMath, Magma, isolated TTY, timeout,
explicit process-group kill and owned Quick Tunnel cleanup. Other targets remain
future release evidence rather than inferred parity.

## MTM-004 — persistence and capability authority

Migrate SQLite schema/migrations, run/project/claim state, optimistic promotion,
capability signing/validation/revocation, and transactional invariants. Use copied
databases for shadow comparison; never dual-write production state.

Implemented and accepted with exact 52-operation Python–Rust state/capability parity,
v0/v1/v2 migration parity, future-schema fail-closed behavior, failed-migration
rollback, promotion rollback/idempotency, and cross-runtime capability signatures.
The current Linux target additionally validated a read-only SQLite backup of the
configured Re-CTM state database, exact Python/Rust copy digests, temporary-copy
mutation and restoration, registry tamper denial, and serialized `BEGIN IMMEDIATE`
writers. Re-CTM Python remains the only deployed production database writer.

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
