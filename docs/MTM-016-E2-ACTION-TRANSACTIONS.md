# MTM-016 E2: transactional action completion

Base: `a38482a5220c90a33fbfec836a2a25d9570224ae`. Development only.

Move domain sealing into the same short SQLite transaction as the workflow
transition and its durable receipt. For assessment, exploration, proof submission
(including compact escalation), and repair submission, also include their metadata
and project-mode updates in that transaction. File reads, validation, normalization
and observers stay outside transactions. The existing WorkflowEngine and kernel
still determine the transition; no second finalizer or public SQL interface exists.

Only these explicitly enrolled atomic actions can be reconciled after action entry:
either their transaction committed with the original receipt or no action mutation
committed. Recovery closes the old submission as correction-required, preserving
the exact caller-write prefix, and never executes the action. A concurrent original
executor is fenced by the same receipt/transaction boundary. Historical commit-ready
work and actions with file effects must not be inferred to be atomic.

Branch completion must couple its branch status, domain seal, barrier decision and
state transition, but its preceding result/memory file writes are still partial
effects. A failed branch action therefore remains unknown in this checkpoint.
Planning, direct screening, join, verification, mechanical branch preparation and
finalization require their own effect coverage and are not automatically resumable.

Add real socket fault fixtures before implementation, then test transaction failure,
commit-before-response loss, exact original recovery, changed-owner/request denial,
old journal refusal and execution/recovery races. Preserve all earlier evidence and
run full source and exact-candidate protocol checks. No deployment, Python deletion,
resource improvement or arbitrary crash/power-failure claim is authorized here.

Schema 7 adds one nullable, bounded action-kind column to the existing checkpoints;
no new journal table, dependency or framework is introduced. Old rows remain null.
The runtime and catalog use `mtm-tools-v7`; the workflow protocol is unchanged.
Rollback uses untouched pre-upgrade database copies, not a lowered user_version.

The assessment fault fixture failed before implementation with
`failed transition left a sealed domain or action metadata`. After the transaction
change the targeted socket fixtures pass for assessment, exploration, proof,
compact escalation, repair and conservative branch handling. The source and exact
artifact gates are still required; targeted checks do not qualify production.

The first full-gate failure is sealed separately and never relabelled. Its extra
test failures covered an overlooked latest-schema assertion, a malformed fault
fixture rejected by SQL before reaching recovery, and a read-only projection's
first SELECT changing transient WAL-index read marks. The projection measurement
now establishes its read view using read-only status before freezing the complete
directory. It still compares all database, WAL, SHM and private bytes; a separate
positive-control regression detects real SQL and file writes. No assertion or test
is suppressed, no product projector code changed, and no weak isolation mode is used.
