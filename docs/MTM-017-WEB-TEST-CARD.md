# Preview.2 real-web test card

This is a fresh, isolated operator test workspace, not the engineering checkout
or production state. The intended binary is MTM 0.6.0-preview.2, schema 8,
mtm-tools-v10, workflow protocol 3, 24 tools. Native is dangerous-only with
Bubblewrap; LaTeX is required. Actual results must be observed, not assumed.

## Connect and identify

Use the new test connection, not the existing production connection. Check
`server_info` for the version, tool contract, schema and Native backend. Read this
card with the workspace tools. Check that the workspace is the dedicated session's
`workspace` directory. Locally record the OAuth client ID for ownership continuity;
never put credentials, capabilities or raw console logs in a handoff artifact.

## Exercise the real workflow

First run a small, genuine mathematical task using compact mode, required LaTeX
and a final proof export. Do not use a scripted or prewritten verifier pass. Keep
the `run_id` locally as soon as initialization succeeds. On an uncertain outcome,
inspect or resume the existing run; do not silently create a replacement.

For independent review, stop generation at `verify`. In a separate reviewing
conversation, reuse the SAME connected endpoint and OAuth client without deleting
or re-registering the connection. Confirm the same owner before requesting the
current verifier task. Review the actual statement, proof and references and submit
specific findings. A different owner is a stop condition, not permission to edit
ownership or copy a capability from another conversation.

## Exercise project memory

Use the public project/claim interfaces advertised by the current tool catalog.
Complete and independently verify a project-linked claim with result registration.
Create a second run in that same project and inspect `project_memory` for the
verified fact, predecessor-closed graph and relevant findings. Check that only the
final verified proof promoted facts. Fact IDs are locators, not proof certificates.
Test operator revocation separately from model actions: the fact-graph revoke CLI
is not a public model tool and is not an acceptance step to execute automatically.

Then exercise a full route with real retrieval, an actual identified proof gap
and repair, and Sage/Magma work where relevant. Reconnect or resume the existing
task to check ownership, persistence and absence of duplicated submissions.

## Record outcomes

Keep version, scenario, run ID, route/state, expected versus observed behavior,
error code, reviewer/session separation and final proof locator. Do not store
OAuth passwords, tokens, capabilities, tunnel URLs or raw private logs in the
repository or public reports. Store actual mathematical review separately from
mechanical pass counts. A completed script or `correct` label alone is not
independent verification, a 90-case corpus pass or a release decision.
