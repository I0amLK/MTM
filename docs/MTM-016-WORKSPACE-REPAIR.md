# MTM-016: close concrete paging, Git and PATH omissions

This is a development-source checkpoint, not an installed-runtime repair or a
release receipt. The existing preview.2 installation is unchanged. The changes
address reproduced B-stage failures before more maintenance retirement.

## Lossless read pages

`read_file` treats `end_line` as the inclusive requested range and `max_lines` as
the page size. They can be supplied together without specifying identical ranges.
`max_bytes` bounds the returned content bytes, not the JSON envelope size.

A partial line is never discarded or decoded with replacement characters. Its
continuation keeps the same line number and supplies `line_byte_offset`. Clients
should copy `next_action.arguments`, not increment the line number themselves.
The continuation includes `expected_sha256`; changing the file returns
`READ_FILE_CHANGED` rather than silently joining pages from different contents.

`truncated` means that the requested range has unread content. It remains true
when the last line is only partially returned, and becomes false at an explicit
range end even if the file contains later lines. Budgets too small for one UTF-8
character return `READ_PAGE_TOO_SMALL` rather than making zero progress.

Reads are restricted to regular UTF-8 files of at most 64 MiB, with bounded input
reads and before/after identity checks. This is not a streaming large-file engine,
an atomic cross-process filesystem snapshot, or an owner/ACL/xattr preservation
claim. The existing workspace/private-root access guards remain in force.

## One repository selection contract

All five Git tools accept `repo_path`, relative to the Native workspace. Discovery
walks up only as far as the workspace root; it no longer silently adopts a parent
repository outside that root. Results identify the selected repository.

For diff/log/show/blame, `path` and `paths` are literal filters relative to the
selected repository, not directory selectors. Missing files can still be used
for history. An explicit `*.txt` denotes that literal filename, not all text files.
For status only, the older `path` directory selector is used if `repo_path` is
omitted. A supplied `repo_path` takes precedence.

Git-directory and common-directory pointers must remain inside the workspace;
ordinary nested repositories and in-workspace linked worktrees are supported.
Arbitrary external Git metadata, bare repositories, hostile Git configuration
and all possible concurrent metadata races are not claimed as qualified here.

Status uses NUL-delimited porcelain records, so UTF-8 names containing newlines
or ` -> ` are not split. Exactly reaching a result limit is not itself truncation.
Blame clamps its requested range to the available source, and carries the repo,
revision and range into its continuation. Symbolic revisions such as HEAD are
preserved, not promised to be an immutable snapshot across separate requests.

Structured Git output must be complete before parsing. Text diff/show report
output truncation. Commands explicitly disable external diff/textconv helpers,
fsmonitor, hooks and color where applicable; this does not claim a general Git
configuration sandbox. Non-UTF-8 filenames and exact quoted-name extraction from
diff headers remain outside this checkpoint's tests.

## Match executable checks to the request environment

Executable fact collection now uses `env.PATH` when supplied, just as the sandbox
actuator does. Relative and empty PATH entries resolve from the invocation's
workdir and remain workspace-bounded. PATH search skips non-executable candidates;
an explicitly named non-executable file still fails instead of falling back.
The selected file's privilege bits and identity are checked again before execution.

The normal `cmd` wrapper is `/bin/sh -c`, not a login shell that may reset PATH
through profile files. A fixture exercises that shell with an empty inherited
environment. This does not qualify Bubblewrap execution on the target host.

`NATIVE_EXECUTABLE_UNRESOLVED` keeps its fail-closed code/category and adds safe
candidate indexes, a no-side-effects result and a correction action. No command,
program name, environment value or credential is echoed by that diagnostic.

Complex shell grammar, shell-local assignments, working-directory changes within
a script, explicit login shells and complete builtin/wrapper analysis remain open.
Use explicit `argv`, `workdir` and `env` for the reliably modeled single-program
case. This checkpoint does not replace uncertain syntax with permissive execution.

## Recording and remaining work

### Public runtime follow-up

`crates/mtm-cli/tests/support/workspace_smoke.rs` now starts the actual built
binary with temporary workspace/data, performs OAuth DCR/password/PKCE and sends
MCP calls through the published schemas to the real workspace backend. It checks
lossless UTF-8 continuation, changed-file rejection, all five Git tools against
a nested repository, blame continuation and a file-valued repo_path rejection.

Run this focused check with:

```sh
cargo test -p mtm-cli --test capability_runtime --locked workspace_smoke -- --nocapture
```

The existing owned loopback fixture is reused, without a new test framework or
production dependency. Its workspace variant exposes only real curl and Git in
the subprocess PATH. The capability test retains its separate curl-only PATH,
500 independent assessment runs and unchanged strict summary scope. This is real
binary/socket/OAuth coverage, not browser rendering or Native sandbox execution.

Before/after regression results and full source-check outcomes are appended to
`records/iterations/ITER-016.json`. Earlier failures are retained as failures.
The same inherited nested-Bubblewrap tests must remain visible; none is waived.

No Python file is retired merely because these tool tests pass. Stage D's target
and release responsibilities, stage E's persistent workflow idempotency, the older
unexplained capability-signature sample, and stage F's real-client/host/LaTeX/
resource/upgrade/rollback qualification remain separate open work.
