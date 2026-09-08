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
