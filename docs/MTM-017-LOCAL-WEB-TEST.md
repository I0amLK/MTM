# Preview.2 local deployment for operator web testing

## Boundary

This entry runs the already qualified `0.6.0-preview.2` binary at SHA-256
`13d7890c5c763199ed39295e134ff6cc735ceaa04eaddf6c556431a7a56254f4`.
No rebuild, production installation, selector switch, database import or live
session restart is involved. It is a side-by-side test service, not a release.
The Rust source identity and eight machine-profile receipts remain unchanged.

The launcher reuses only hash-pinned preparation primitives from the historical
research launcher. It does not execute an MTM-016 trial or change that launcher.
Its own file, the helper, executable, prepared manifest and resolved host tools
are checked before launch. Missing or changed inputs stop startup.

## Prepared instance

The operator instance prepared for this checkpoint is:

```text
target/mtm017-web-sessions/web-q7gYA08c/
```

It has its own candidate snapshot, OAuth key, HOME, workspace, schema-8 state,
private diagnostics and tmux control socket. The session directory is 0700 and
the key file is 0600. The candidate listens on a randomly allocated loopback port;
its own Quick Tunnel publishes the HTTPS MCP endpoint. The service runs with
Bubblewrap, dangerous-only Native, required LaTeX and protocol 3. It inherits
neither production data roots nor production credentials. Native tools receive
only the curated PATH and validated read-only tool roots, not the private state.

The instance is supervised in its own tmux session. No boot-time system service
or automatic restart is installed. Do not delete or clean this directory while
tests or evidence collection are in progress.

From the repository root, inspect and attach with:

```bash
SESSION="$PWD/target/mtm017-web-sessions/web-q7gYA08c"
bash scripts/mtm017-web-session.sh check "$SESSION"
bash scripts/mtm017-web-session.sh attach "$SESSION"
```

Read the current `Quick Tunnel: https://.../mcp` line from this console and use
that full address for a NEW test connection in the web client. Do not use the
ordinary `mtm` command or reuse the production connection: those still select
the released schema-7 preview.1.

Read the authorization password in a separate local terminal:

```bash
cat "$PWD/target/mtm017-web-sessions/web-q7gYA08c/operator-key.txt"
```

Enter this key only on the test service's OAuth authorization page. It is not a
client secret and should not be pasted into a model conversation, source control
or a public issue. The URL and raw console logs likewise stay local. Public
discovery and unauthenticated 401 checks are preparation evidence only; the
operator's real browser login and workflow trials still need to be performed.

## Run the real test

The workspace contains `WEB-TEST.md`, copied from
`docs/MTM-017-WEB-TEST-CARD.md`. Start by asking the test connection for
`server_info` and confirming preview.2, schema 8, mtm-tools-v10 and the dedicated
workspace. Then exercise a genuine compact proof, an independent review and
compiled final artifact before trying full/repair/CAS and cross-run project memory.

Keep the current tunnel and the same registered OAuth client through generation,
review and repair. Merely entering the same operator key on a newly registered
connection does not preserve ownership. Keep the run ID and use the existing run
after a lost response rather than making an unrecorded replacement. Real review
findings and observed failures are evidence; scripted empty verdicts are not.

To leave the console without stopping the service, press Ctrl+B and then D.
For an intentional stop or a later restart:

```bash
bash scripts/mtm017-web-session.sh stop "$SESSION"
bash scripts/mtm017-web-session.sh up "$SESSION"
```

`up` is idempotent while the console is running. A session lock prevents a second
runtime. `stop` requests Ctrl+C in this test console only and confirms termination;
it does not kill unrelated MTM processes or delete data. A restart normally gives
a new tunnel URL: avoid restarting between generator and reviewer handoffs.

For a genuinely independent future test environment, run
`bash scripts/mtm017-web-session.sh prepare` and retain the newly printed exact
session path. Do not infer a latest directory or overwrite the previous trial.

## Evidence and remaining decisions

Only redacted preparation observations are committed. Operator logs, keys, OAuth
storage, run data and actual proof files stay under the ignored private session.
The setup verifies path isolation, pinned bytes, real Native prerequisites,
supervisor lifecycle, HTTPS discovery and rejection of unauthenticated MCP calls.
It does not pre-certify a real browser login, independent mathematical review,
complete corpus coverage, production-copy migration or the release decision.

After testing, retain the version, run ID, scenario, expected/observed behavior,
error code, independent-review procedure and final artifact locator. Never upload
the key, bearer/capability bytes or whole private logs. Stopping this service is
sufficient to return to production-only operation; no database downgrade or global
selector rollback is needed.
