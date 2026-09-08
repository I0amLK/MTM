# MTM-016 E2: evidenced caller-write reconciliation

Base: `70fa5ef21a655e6224b1e90147d9d91cfd16c448`. Development only.
This delivery reconciles interrupted caller writes without replaying their content
or executing the requested action. It is not arbitrary action/crash recovery.

Schema 6 enrolls new executions in one bounded write journal per step. A journal
is between writes, in an opaque database operation, or describes one file effect.
Store only a relative logical-file locator, existence/length/SHA-256 before and
after, never a capability, normalized research record, proof or request body.
The journal and accepted-write checkpoint change atomically. Legacy running work
without enrollment remains unknown.

All relevant vault file writers share permanent, nonblocking per-file OS locks.
Caller memory appends prepare complete replacement bytes and publish atomically;
normalizers run once, before recording the intended hashes. Reconciliation under
the same lock observes old or new bytes and closes the original step as correction
required with an exact retained prefix count. It never appends a missing record,
repeats normalization, runs the action, issues authority or changes a finalizer.
Ambiguous equal before/after images, conflicting bytes, opaque writes, commit-ready
actions and legacy unknown work remain unknown. A current task is fetched separately.

Recovery between writes races the next write through the same SQLite boundary.
For an in-flight file, lock exclusion plus a compare-and-swap journal snapshot
fences the original executor. No lock spans network, observers, model turns or
LaTeX. Only bounded local file I/O and short metadata transactions occur under it.
Files are bounded to 64 MiB, private temporaries are created at 0600, path/type/link
checks reject unsafe targets, and existing bytes are never silently discarded.

Cover: before/after publication, checkpoint failure after publication, competing
recovery, live-writer locks, same-resource repeated records, changed digest/path,
owner/domain/request binding, mixed opaque writes, cancellation and migrations.
Use actual disposable OAuth/MCP processes and independent file/transition checks;
keep the full protocol and source gates. Process-interruption tests are not power
failure or hostile same-UID filesystem tests. No deployment or Python retirement.

Review boundary: a generic Validation/Conflict error does not prove that an
outstanding effect did not occur. Completion recording must reject a file/opaque
or corrupt journal rather than clearing it with an inaccurate prefix count.
The acknowledgement transaction validates the marker before clearing it.

The memory format itself is unchanged, but malformed/non-object records are now
reported as MEMORY_CORRUPT instead of omitted. Oversized files and unsafe type,
link or writable-permission drift are rejected, not truncated or chmod-repaired.
Copy-on-write memory append may cost more for large histories; resource/performance
acceptance remains pending and no performance improvement is claimed.

## Delivery

Implementation `56c2263abacb40649657747d44bf654e15a8f76e` passed 18 added tests:
eight storage, six vault and four actual authenticated socket tests. The latter
cover normalized-memory acknowledgement loss, concurrent recovery, a live file
lock, conflict bytes, proof-versus-database effects, corruption during acknowledgement
and actual two-branch domain/barrier preservation. Faults are injected in owned
temporary state, followed by actual forced process restart; not power-cut tests.

The separately built `target/mtm016-e2-writes/release/mtm`, SHA-256
`7610e0366fbe7094ed14b4e969ef00c44c5a33863a6e37a3a99e12ad2d92d736`, passed
post-commit protocol qualification. The raw report is sealed in
`records/evidence/MTM-016/candidate-protocol-e2-writes-56c2263.json` and bound by
ITER-016. It includes 500 normal assessment first hops and three scripted complete
protocol flows, not 500 independent mathematical proofs.

The full source gate remains false inside the nested Native environment: the same
ten Runtime failures remain, with no new suppression. Two explicit host-profile
test functions are inert without their selected profile and do not count as host
acceptance. Supported caller-write reconciliation is delivered; entered-action,
opaque-database and final release qualification remain pending. No production
artifact, selector, database or key was modified.
