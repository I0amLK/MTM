# MTM-016 E2: transactional caller database writes

Base: `c120c0aa8daa5a336821c0bf74b3a538a809fe96`. Development only.

Close the remaining caller-write database window for `proof_manifest` and
`reference_audit`. Persist the ordinary normalized record and its accepted-write
checkpoint in the same short SQLite transaction. Recheck the reserved execution,
current authority, exact write index and resource permission under that transaction.
No transaction spans a file read, callback, network request or LaTeX invocation.
Keep the existing normalizers and SQL persistence semantics shared with ordinary
workflow writes. Do not introduce a generic public transaction or raw-SQL tool.

An acknowledgement failure must roll back insertion or replacement of the database
record as well. A committed write survives response loss with its checkpoint, so
`recover_only` can report the retained prefix without executing the action. A
correction summary must match the durable count; an error category is not evidence
that the count is zero. Pending recovery and database execution must have only one
transactional winner. Old opaque journals remain unknown and are not rewritten.

The existing schema-6 between-writes checkpoint is sufficient: no schema migration,
new journal type, crate or dependency is needed. Tool-contract documentation will
distinguish these atomic database writes from historical opaque pending work.
The new contract identity is `mtm-tools-v6`. Manifest serialization and total audit
text are bounded to 1 MiB per record. The existing HTTP request limit still applies.

Tests cover failed insert and replacement, checkpoint rollback, current authority
changes, cross-run references, verifier-domain binding, stale write indices,
concurrent recovery, lost continuation, and end-to-end retained-prefix correction.
Use disposable OAuth/MCP servers and independent SQL/file assertions, then run the
full source gate and exact-SHA protocol qualification. Preserve prior failures and
sealed reports. No production deployment, Python deletion, power-loss claim,
arbitrary action recovery or final-release acceptance is part of this checkpoint.

## Delivery

Implementation `4fadcffe312cf604e2b5db002cd8e5f24ce8a887` passed twelve added
regressions: nine storage, one tool-contract and two actual OAuth/MCP tests. The
manifest regression failed before the change and passed after transaction coupling.
Audit fixtures follow the ordinary full route for registered references, inject
failures in owned temporary SQLite state, force-restart the candidate, and inspect
retained rows/counts before completing through the unchanged verifier/finalizer.

The separately built `target/mtm016-e2-database/release/mtm`, SHA-256
`58dd00995d9eb4ca173a283d977c5b7c6e03e4a4aa51c427eb9b09d5eac1688d`, passed
post-commit protocol qualification against that implementation commit. Its raw
report is sealed in
`records/evidence/MTM-016/candidate-protocol-e2-database-4fadcff.json`, with its
SHA-256 recorded in ITER-016. Qualification includes the two new database fixtures,
500 assessment first hops and three scripted complete protocol flows. These are
not independent mathematical proofs or actual browser/Native/compiled-LaTeX tests.

The full source gate still reports the same ten nested-Bubblewrap Runtime failures,
with no additional suppression. All 56 storage, 102 workflow, 29 gateway and 33
public fixture functions pass; two host-specific functions are inert unless their
profile is explicitly selected and do not qualify the host. Entered-action effects,
legacy unknown records, Python retirement and final release acceptance remain
pending. There is no new schema migration, dependency package, production install,
selector change, or production database/key modification.
