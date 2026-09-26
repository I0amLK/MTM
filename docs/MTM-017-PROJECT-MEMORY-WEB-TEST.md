# MTM-017 real-web project-memory test

Use the same already registered preview.2 OAuth connection. Do not delete or
re-add it, copy capabilities between conversations, or retroactively attach the
completed non-project run to a project.

## Stage A: verifier-gated project promotion

Create project \`web-memory-integer-identities\`. Create claim
\`web-memory-odd-sum\` with statement:

\[
\sum_{k=1}^{n}(2k-1)=n^2,\qquad n\ge1.
\]

Start a new compact run with \`register_result:true\`,
\`project_id:web-memory-integer-identities\`, and
\`target_claim_id:web-memory-odd-sum\`. Generate a genuine proof. At \`verify\`,
hand the same run to a separate reviewer on the same OAuth client. Do not prewrite
a correct report. If a real gap exists, exercise repair.

After \`done\`, fetch the project manifest and record the promoted revision whose
\`source_run_id\` is this run. It must be a new verified revision. The revision ID
or fact ID is a locator, not mathematical evidence.

## Stage B: later-run project memory

Create claim \`web-memory-shifted-odd-sum\` with statement:

\[
\sum_{k=1}^{n}(2k+1)=n(n+2),\qquad n\ge1.
\]

Start its project-linked run with \`register_result:true\`. On the first
\`rethlas_step\` response, before any submission, inspect
\`context.mathematical_research_state.project_memory\`.

Require \`advisory_only=true\`, require the verified base odd-sum fact to appear,
and require the earlier non-project run not to appear as a promoted fact. Record
visible fact node/edge counts and the base fact locator.

## Stage C: real dependency edge

Prove the shifted identity by using the verified base identity:

\[
\sum_{k=1}^{n}(2k+1)
=\sum_{k=1}^{n}(2k-1)+2n
=n^2+2n
=n(n+2).
\]

Put the promoted base revision ID from Stage A in the second run's
\`dependency_revision_ids\`. This is a genuine mathematical dependency. Again use
a separate independent reviewer at \`verify\`.

After finalization, start one third lightweight run in the same project with
\`register_result:false\` and no target claim. Inspect its initial
\`project_memory\`; it should expose both active facts and a predecessor edge from
the shifted-sum target fact to the base fact. Stop/cancel this third run after the
memory observation; it need not produce a proof.

Report run IDs, independent-review results, promoted revision IDs, final artifact
locators, project-memory node/edge counts, and observed errors/repairs. Never
report OAuth passwords, bearer tokens, capabilities, tunnel URLs, or raw private
logs. Operator fact revocation is outside this web-model test.
