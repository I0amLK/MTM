# MTM-017 U27/U28 current-candidate authority observations

Decision `MTM017-READINESS-DECISION-004` approves only this mapping for candidate
`13d7890c5c763199ed39295e134ff6cc735ceaa04eaddf6c556431a7a56254f4`.
The old corpus file, MTM-016 parsers/driver and accepted 78-row snapshot stay frozen.
This test-only harness changes no runtime, public tools, schema or workflow protocol.

U27 checks all exec/patch and once/session compatibility requests, repeated twice
per phase. The fixed dangerous marker and null expiry are not a new grant. Calls
have no command, workspace, workflow, capability or consent/grant-ledger effects.
Ordinary transport and audit events remain allowed. A disabled-backend negative
control proves a request does not enable command execution.

U28 uses a real Bubblewrap dangerous candidate with Native command and workspace
API positive controls. Each phase then rejects actual Native synthetic-private
canary reads/writes, workspace API escapes, grammar-valid invalid workflow tokens
and a foreign OAuth owner's use of the real owner's task capability. The same
synthetic business state, file contents and modes survive the negative calls.
No real user's secret or private proof is read. No human consent is tested.

Each task has three fresh trials, each using a new temporary root, process and DCR
owner. Within a trial initial, same-owner reconnect and same-state process restart
are distinguished by hashed session identity and PID. SQLite logical snapshots
include every table's rows and sqlite_master schema, plus database mode. Separate
private-file/workspace digests include bytes and modes; WAL/SHM layout and audit
transport are not business state. All hashes are synthetic-state observations.

The explicit integration runner requires MTM017_AUTHORITY_CORPUS=1 plus the exact
candidate path/hash, task, repeat, unique trial marker and current harness source
SHA. Ordinary source checking clears these flags. Independent pre-execution code
and collector review is required before enabling the runner. It prints one bounded
JSON summary marker; a recorder retains original stdout/stderr and extracts exact
summary bytes into flat MTM-017 evidence without copying any credentials.

`schema8-authority-observation-check --inputs <flat MTM-017 JSON>` requires a closed
six-reference input, current harness SHA and exact authorization hash. It rejects
unknown/duplicate JSON fields, path escape, symbolic/hard links, unsafe modes,
incorrect hashes, stale source, missing/duplicate cells and nonfresh trials. It
reopens every bounded input before returning six observed rows with accepted delta
zero. Public evidence may be 0644/0664; other-write and special bits are rejected.
The checker never runs a candidate or writes acceptance. Independent input/result
review and a later separately authorized import are still required to count cells.
The original accepted78 and research15 pointers must not be rewritten or recounted.

Rollback: retain failed observations and append a superseding scoped decision or
observation; no deployment or production rollback is involved.
