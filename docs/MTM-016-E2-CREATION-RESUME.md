# MTM-016 E2: restartable keyed initialization

Base: `b824e164354df401d1e287e931dc568b10ebdbb0`. This checkpoint addresses
initialization interruptions, not arbitrary running-step or action replay.

New keyed creations enroll in schema-5 creation checkpoints. Old schema-4 pending
creations have no evidence of this protocol and remain unknown. The authenticated
owner must supply the same creation key, workspace and normalized request.

Acquire a nonblocking OS file lock for the bound run inside the private vault.
All participating initialization attempts obey it; no timeout, PID guess, lease
expiration or database-status inference licenses takeover. Keep its inode for the
run lifetime, release its file descriptor on every return, and never run commands,
network, model turns or LaTeX under this lock. Only bounded local initialization
I/O and short SQLite transactions are allowed here.

Prevalidate bounded input and unique reference names. Publish missing input files
without replacing existing paths, using private temporary files, sync and no-clobber
publication. Existing bytes must match exactly; symlinks, hardlinked files,
permissions drift and mismatches fail closed. A replay cannot reset research files.

Initialize the run, selected project snapshot/link, inline references and their
source snapshots in one database transaction. Store a digest of the initialized
database projection in the checkpoint. A retry reuses the same database rows and
snapshot; corruption or an intervening owner cancellation is not overwritten.
The existing workflow engine alone performs `created -> assess`, retaining its
atomic creation receipt. Completed replays stay read-only historical receipts.

Tests must interrupt publication, database preparation and transition independently;
verify exact inputs, one run/snapshot/reference set and unchanged existing bytes;
exercise distinct-process locks, actual restart, races and cross-owner/request
denials. Keep failed observations and historical evidence. Reuse the existing
locked nix 0.30.1 filesystem binding in the workflow crate; no new package or
version is introduced. The pinned compiler remains unchanged. No production
deployment or deletion of unported Python responsibilities is implied.

Scope: process-interruption recovery on a local filesystem supporting the tested
locking/publication operations. This is not a power-cut test, distributed lease,
hostile same-UID filesystem defense, or arbitrary partial-step reconciliation.

## Delivery

Implementation `0cfdf7c` passed ten new regressions (five vault, three storage,
two public socket tests). The complete source gate has 39 passing storage tests,
96 passing workflow tests and 27 passing public fixture functions, including two
explicit host functions that are inert without a selected host profile. Runtime
still has the same ten nested-Bubblewrap failures; none were suppressed.

The separately built `target/mtm016-e2-init/release/mtm` passed post-commit
SHA-bound protocol qualification. Its raw report is sealed as
`records/evidence/MTM-016/candidate-protocol-e2-init-0cfdf7c.json` and bound by the
iteration ledger. This includes the forced-restart initialization fixtures, 500
normal assessment first hops and three complete scripted protocol flows, not
independent mathematical, browser or final-host release acceptance.

Enrolled keyed initialization recovery is complete for this scope. General
running-step/action partial effects, legacy unknown work and final qualification
remain pending. No production artifact, selector, database or key changed.
