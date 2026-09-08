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
