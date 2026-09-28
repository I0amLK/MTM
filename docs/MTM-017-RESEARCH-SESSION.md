# MTM-017 U21-U24 preview.2 research sessions

## Scope

This launcher covers only U21-U24 on the exact MTM-017 0.6.0-preview.2
candidate SHA-256:

13d7890c5c763199ed39295e134ff6cc735ceaa04eaddf6c556431a7a56254f4

with source commit:

7b4afe2359e688263557f62154e4bc1e640c12c0

Historical MTM-016 sessions remain unchanged:

- U21-U24: mtm-research-session-v1, Native safe
- U25: mtm-research-session-v2, Native dangerous

MTM-017 uses:

- U21-U24: mtm-research-session-v2, Native dangerous
- U25: the separate scripts/mtm017-u25-research-session.sh launcher

The U21-U24 trial receipt schema remains
mtm-research-trial-evidence-v1; session/native policy is versioned by
milestone. This does not relabel historical MTM-016 receipts.

No production selector, production state, release input, corpus count or
deployment is changed by preparing or running these sessions.

## Prepare

Use one fresh session for every task/repeat cell:

    bash scripts/mtm017-research-session.sh prepare U21 1

Supported tasks are U21, U22, U23 and U24. Repeats are 1, 2 and 3.
Workflow mode is taken only from the frozen case registry:

- U21 and U23: compact
- U22 and U24: full

The prepare command creates a fresh private HOME, schema-8 state root,
workspace, OAuth operator key, candidate snapshot, required-LaTeX policy,
dangerous Native policy and both route-material directories:

    workspace/research-evidence/
    workspace/research-evidence-input/

The command performs a dangerous-Native Bubblewrap preflight before the
session may be started.

## Start and connect

After prepare prints the exact absolute session path:

    SESSION='<printed path>'
    bash scripts/mtm017-research-session.sh check "$SESSION"
    bash scripts/mtm017-research-session.sh up "$SESSION"
    bash scripts/mtm017-research-session.sh attach "$SESSION"

Read the new Quick Tunnel /mcp address from the private tmux console.
Read operator-key.txt only in a local terminal and enter it only on that
session's OAuth page. Never copy the tunnel URL, key, token or capability into
public evidence.

Keep the same TUI/tunnel and already registered OAuth connector alive from
generation through the independent reviewer. A newly registered connector does
not inherit workflow ownership.

## Common workflow boundary

Every run is new, uses the exact problem_id and creation_key printed in
task.md, and sets register_result=false.

After rethlas_start, write run-handoff.json in the workspace root using the
exact run ID returned by the server. The handoff is non-authorizing and must not
contain secrets, capabilities, OAuth identifiers or URLs.

Generation stops at verify. A separate chat session reuses the same connected
OAuth connector, independently checks the proof and route material, and submits
the fresh verifier task. The main operator session later binds review.json to
the raw private verification/verification.json bytes before collection.

## Fixed route material

The generator/reviewer writes route observations only under
workspace/research-evidence/. The launcher copies only the task-specific
allowlist into workspace/research-evidence-input/:

- U21: review.json
- U22: retrieval.json, sources.json, review.json
- U23: seeded_draft.tex, first_findings.json, repair_history.json, review.json
- U24: branches.json, review.json

Use:

    bash scripts/mtm017-research-session.sh seal-material "$SESSION"

The copy is non-overwriting and content-preserving. Unknown files, directories,
symlinks, hardlinks, oversized files, invalid UTF-8 or conflicting destination
bytes fail closed.

### U22

retrieval.json uses mtm-research-retrieval-observation-v1 and records actual
rethlas_retrieve calls, reference IDs, result SHA-256 values and
external_network_observed=true; raw credentials and response bodies remain
false.

sources.json uses mtm-research-source-observation-v1 and binds each material
reference to an inspected original or authoritative source using locator and
content SHA-256 values. The server-side reference audits must independently
reach SOURCE_VERIFIED.

### U23

The route is an explicit seeded repair challenge, not a naturally discovered
product failure. Preserve the first submitted proof as seeded_draft.tex, the
first concrete verifier findings as first_findings.json, and bind both plus the
final verified proof in repair_history.json with seeded_challenge=true.

### U24

The run must actually use at least two isolated branches. branches.json uses
mtm-research-branch-observation-v1 and records distinct branch/domain/session
markers, sealed result hashes, observed sibling-private-read denials, and a join
covering exactly all sealed branches.

## Collection

After the run is done, sealed, independently reviewed, and route files are
sealed:

    CARGO_TARGET_DIR="$PWD/target/mtm-tool" cargo xtask research-collect --session "$SESSION" --run-id '<exact run id>' --sqlite /home/lk/miniconda3/bin/sqlite3

Then run the read-only bundle precheck:

    CARGO_TARGET_DIR="$PWD/target/mtm-tool" cargo xtask research-precheck --bundle '<absolute private evidence-bundle path>'

The collector and precheck never grant mathematical acceptance, mutate workflow
state, increment corpus counts or authorize release. Standalone reviewed trial
receipts are prepared separately; final corpus import remains a later reviewed
step.

## Lifecycle

Detach from tmux with Ctrl+B, then D.

Intentional stop:

    bash scripts/mtm017-research-session.sh stop "$SESSION"

Do not delete a session while independent review, collection or receipt
preparation is pending.
