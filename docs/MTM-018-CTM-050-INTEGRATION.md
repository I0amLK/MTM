# MTM-018: Coding Tools MCP 0.5 foundation integration

## Scope and pinned source

The operator approved the 25-tool / mtm-tools-v11 development contract on
2026-10-01, then explicitly approved narrow patches for structured file
transactions, copy-source revalidation, rollback integrity, caller-scoped replay
and the remaining old-tool adaptations. This is source integration, not deployment.

Upstream: https://github.com/xyTom/coding-tools-mcp/tree/aa1cbf3832e0c85994600f2249d9544fbae2f49e
(tag v0.5.0). The downloaded source archive SHA-256 is
411cfc2a8a4121857787870af631155295cf5e94a7c419c13c1fa9555e969460.
No upstream script, package installer or server was executed. The Python design
was adapted into MTM-owned Rust; no Python runtime or new dependency/crate is added.
Reference documents are upstream CHANGELOG.md and docs/migration-0.5.md.

Baseline HEAD: afa207e68eefd8cb9e6ab20aaafe497f9616e341. The existing uncommitted
step-schema and submission-correction changes are part of the protected baseline.
Their eleven tracked sections and four untracked files were independently checked
before this integration; they are not reset or folded into a false clean baseline.

## Authority and compatibility

Current Native surface: 19; workflow surface: 6; public total: 25; contract:
mtm-tools-v11. Historical bootstrap constants remain 18/24. State schema remains 8,
workflow protocol remains 3, and no historical acceptance receipt is relabeled.
The package version is not a deployment or release verdict.

OAuth authenticates every call before replay lookup. Dangerous-only Native,
executable revalidation, path policy, Bubblewrap private-vault isolation, signed
workflow capabilities, role ACLs, state checks and the one finalizer remain separate.
request_permissions retains its non-mutating compatibility response and historical
fields; no consent or grant ledger is restored. U27/U28 authority expectations remain.

## New structured changes

apply_changes accepts create, write, edit, delete, move and copy. Existing sources
require the SHA-256 revision returned by read_file. create asserts absence; write
can create an absent file without revision. move/copy destinations must be absent.
Resolved paths are unique across the entire request, including destination aliases.
Inputs use flat object schemas; action-specific field combinations are checked by
the typed runtime parser without introducing oneOf into this new tool.

Preparation performs no writes. Normalized source/destination bindings, revision
fingerprints, classified path facts and Git metadata are retained and revalidated.
Copy sources and identical writes are read-only dependencies: they do not acquire
a replacement inode or count as writes. The existing authorization and rollback
transaction commits prepared mutations. A changed dependency after an earlier
mutation rolls it back. Rollback backup fingerprints are checked before restoration;
uncertain restoration preserves evidence and reports NATIVE_PATCH_ROLLBACK_FAILED.

The patch commit lock serializes this process only. Baseline rechecks do not make
multiple server processes or hostile external writers a globally atomic system.
There is no durable crash journal for Native multi-file changes and no claim of
power-loss atomicity; interrupted/unknown outcomes require file reconciliation.

Limits: 1 MiB request, 100 changes, 200 edits per changed file, 64 MiB per source
and aggregate captured source bytes. Structured sources reject hardlinks, symlinks
and nonregular files. Revisions and result evidence come from captured/staged bytes,
not a potentially changed post-commit reread.

MTM line numbers remain LF-delimited, exactly matching its lossless read_file.
Bare CR is content in an existing file. New replacement text normalizes LF/CRLF/CR
separators; untouched line endings are preserved. BOM-only files still have the
reader's one line; deleting all lines removes the BOM. Empty replacement means
zero lines; a trailing newline in replacement text adds an empty line, including
when the old file lacked a final newline. Edit evidence counts actual placements,
not unchanged context.

## Replay and failure limits

apply_patch and apply_changes accept an optional 1..128-byte idempotency_key.
A single bounded store scopes keys to the validated subject, OAuth client, scope,
tool and this workspace/backend instance. Same-key changed arguments conflict.
Concurrent duplicates receive NATIVE_WRITE_IN_PROGRESS without a second execution.
The cache lock never spans file or Git work. There are at most 64 total pending,
successful and unknown slots, with success-only LRU eviction and at most 1 MiB
retained per result. Dry runs are never recorded.

Runtime/internal failures, failed rollback, oversized results and malformed error
payloads retain a blocked unknown slot. NATIVE_WRITE_RESULT_UNKNOWN is not a
zero-write result. A new key or restart is not permission to retry uncertain work.
Successful replay is historical evidence and does not reread or restore current
files. It grants no workflow authority and uses no durable workflow submission
receipt. There is no exactly-once guarantee across crashes, restarts or eviction.

The upstream broad repeated-failure circuit breaker is deliberately deferred:
filesystem-dependent errors can become repairable after external edits that a server
does not observe. Blocking those retries from an in-memory stale verdict would
regress MTM recovery. Normal bounded validation, conflict responses and replay
admission remain enforced. This is an explicit unported behavior, not parity.

## Existing 18-tool delta matrix

Every Native tool now has tool-specific output fields while retaining the common
ok/error envelope and extensibility. Workflow result contracts are unchanged.

| Existing tool | Integration status and deliberate boundaries |
|---|---|
| server_info | Current counts/v11, retention TTL 300s and retained cap 32 disclosed; mutation description derives actual backend. MTM Bubblewrap/authority facts retained; structured-only Landlock policy is not imported |
| check_exec_environment | Existing backend/attestation/private-vault/toolchain facts retained. MTM fails closed when its execution backend is unavailable rather than adopting an unconfined non-Linux fallback |
| read_file | Same-read revision/algorithm added; model text banner and verbatim continuation expose revision and partial-line offset. Existing sha256, byte-exact content, UTF-8 paging and expected_sha256 retained |
| list_dir | No targeted upstream 0.5 runtime change; bounded directory and hidden/generated filtering retained, output schema specialized |
| list_files | No targeted runtime change; workspace/glob/filter/result bounds retained, output schema specialized |
| search_text | Explicit-file selection, bounded context/results preserved. Shared text truncation now stops at UTF-8 boundaries without replacement-byte overflow |
| apply_patch | Forward anchors/cursor, missing-anchor failure, EOF placement, graded matching, bounded repair hints, accurate changed ranges/revisions/counts, conservative already-applied and caller-scoped replay integrated. See explicit path differences below |
| exec_command | Default total lifetime 300000 ms across schema/parser/process/fallback; yield remains 10000 ms/max 30000, lifetime max 600000. argv/cmd, executable revalidation and Bubblewrap retained; truthful outcome and terminal-once evidence added |
| write_stdin | Existing bounded polling and stdin semantics retained; outcome/terminal-once metadata added. Nonempty stdin is not replay-deduplicated |
| kill_command | Existing managed-process TERM/INT/KILL/escalation retained; truthful outcome/terminal-once reporting, never claim completion while still running |
| read_output | Existing head/tail, gap and continuation retained; command_id/outcome added. First terminal observation can occur here without consuming polling output |
| git_status | Existing repo_path/literal selection and boundary rules retained; specialized schema |
| git_diff | Untracked additions included by default only in unstaged pass, respecting ignored files and literal filters. Stable captured bytes, link refusal, UTF-8 bounds and known filenames; false restores old selection behavior |
| git_log | Existing bounded revision/history and literal repository-relative filters retained; specialized schema |
| git_show | Existing no-external-diff/no-textconv and repo/revision filters retained; specialized schema |
| git_blame | Existing bounded paging, repo/revision/range-preserving continuation retained; specialized schema |
| request_permissions | Existing dangerous-only fixed compatibility result retained; stale consent wording corrected. Legacy eight permission fields remain; no new authorization state |
| view_image | Existing bounded local image behavior and private-path boundary retained; specialized schema. No upstream remote image fetching or isolation relaxation |

### Patch path differences

MTM retains Add-no-overwrite and a single Move's existing destination-overwrite
semantics. A self/alias move is rejected. Production envelopes reject interacting
source/destination paths across operations, including repeated destinations and
move-then-edit chains; use separate reviewed calls instead. MTM does not claim
upstream staged chaining/last-write-wins equivalence. Proven unchanged edits retain
their source inode; path/mode changes remain mutations. Move evidence includes the
source deletion and destination old_path. Frozen pure-policy compatibility
results remain isolated from Native filesystem mutation: the evaluator retains
the original parse_patch/apply_hunks behavior and its 135-case corpus, while
PatchInvocation explicitly selects the current parser and Native mutation uses
the detailed current matcher. Those compatibility helpers perform no file I/O.
Current patch requests are bounded to 1 MiB, 100 operations and 200 hunks per file;
matching also has a conservative 512 MiB byte-comparison work budget, including
near-match and whitespace fallback scans. Context trimming is linear.

### Git bounds

Untracked enumeration must be a complete UTF-8 NUL-record stream; truncated output
fails closed rather than treating tail fragments as filenames. Work is bounded to
128 untracked files, a 15-second processing window, 8 MiB pre-read file bound and the
aggregate requested output byte budget. Oversized/remaining output is explicitly
truncated. Binary files get a binary marker. File identities come from the known
enumeration, including quoted or newline-containing filenames. No external Git
diff/textconv helper runs for these bytes.

### Command observation

A successful MCP observation keeps ok=true even if a child exits nonzero. The
separate operation_outcome is running, exited_0, exited_nonzero, timeout or signal.
One locked status snapshot supplies lifecycle/outcome fields; the first terminal
observation across exec/write_stdin/kill/read_output emits one command event. The
internal once flag never appears in public payloads. Workflow submission-event
classification remains separate.

## Excluded upstream infrastructure

No upstream OAuth/session model, unscoped cross-client replay, shared-quota change,
Landlock fail-open behavior, structured-only mode, npm/container/tunnel deployment,
dashboard rewrite or benchmark harness is imported. These are independent designs,
not prerequisites for Native editing reliability.

## Validation and rollback

Focused and full source gates are required; all intermediate failed logs remain
under the bounded integration staging directory. A zero-test filter is not a pass.
A current source gate is not a release, live-service or copied-production-data test.
The original development gate did not include commit, push, install, selector
change, live restart or production database access. A later operator-authorized
connected-client smoke and publication follow-up is recorded below.
Revert only MTM-018 integration hunks to roll back source,
retaining the protected preexisting uncommitted fixes. No state migration is needed.

## Verified development result

The final full source gate passed: 749 tests, zero failures, one inherited ignored.
Format, warnings-denied Clippy, records/architecture/retirement, diff and Native
preflight passed with source SHA-256
`9b7dbe7ab33d85a455f17198e9340cbe4f88c5cf082b2485a56fc43a3aeea07d` unchanged before/after.
The independent review has no blocking findings. Failed intermediate logs, including
the two frozen-policy-corpus failures, remain preserved; their expectations were
not rewritten to make the gate pass.

The optimized build succeeded. The independently copied, single-link read-only
artifact is `target/mtm018-artifacts/mtm-ctm050-1dfbc1c86a5d`, SHA-256
`1dfbc1c86a5dbed845aa79e0a944aa8f2ebb2e05619e36c8d020212f62696ae5`. Its offline identity reports
25 public tools, mtm-tools-v11, schema8 and workflow protocol3. It was not installed
and no live service or production state was changed. Evidence and the explicit
limits are recorded in `records/evidence/MTM-018/ctm050-integration-20261001.json`.

## Connected-client smoke and publication follow-up

On 2026-10-01 the connected authenticated client reported 25 tools/v11. The running
process executable was independently hash-verified against the artifact above.
Structured create, same-key replay, revision-bound edit and exact readback passed.
Two newly created compact smoke workflows reached done: the ordinary path and a
missing-manifest correction that retained its one proof write, accepted only the
missing manifest with a fresh returned capability, and then finalized. Both final
artifacts were 308 bytes with the same recorded SHA-256. No old pending run was
inspected, reset or replayed.

The operator authorized continued correction and push at 04:48:36 UTC. Publication
includes the protected prior step-schema/submission corrections and this foundation
integration on the existing work branch. Sanitized observations are recorded in
`records/evidence/MTM-018/live-client-smoke-20261001.json`; no capability, credential,
private proof body or private-state locator is included. The unchanged source keeps
the 749/0/1 gate result. These bounded smoke results do not establish all-scenario
correctness, independent mathematics, fresh browser OAuth, CAS, compiled-LaTeX,
resource, installation or rollback acceptance, and do not change old release receipts.
