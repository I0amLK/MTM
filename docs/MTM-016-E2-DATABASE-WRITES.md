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
