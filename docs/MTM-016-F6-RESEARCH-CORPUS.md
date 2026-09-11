# MTM-016 F6: operator-driven research corpus U21-U25

## Scope of this delivery

The accepted corpus remains 63 passed / 0 failed / 27 blocked. This delivery
provides fifteen input cases and a disposable exact-candidate session launcher.
It does not execute mathematical research automatically, submit verification
reports, certify independent reviewers, import a completed trial or advance the
release manifest. No model API, background agent, crate, product change or new
workflow authority is introduced.

`conformance/mtm016-research-cases.tsv` declares three input variants for each
already frozen workflow scenario U21-U25. The original thirty-task definition and
three-repeat requirement are unchanged. These are repetitions of workflow
scenarios with prespecified inputs, not a performance comparison of identical
problems. The launcher verifies the original corpus SHA and the new case-registry
SHA before creating a session. Problem statements are input challenges, not
completed mathematical proofs or claims of novel results.

| Task | Three prespecified inputs | Required route-specific observations |
| --- | --- | --- |
| U21 | Subspace dimension, Cauchy-Schwarz, monotone convergence | Independent compact proof, required compilation and final sealed bytes. |
| U22 | Chinese remainder, polynomial roots, orbit-stabilizer | Real capability-gated retrieval, checked original sources, citations and audit in a full compiled workflow. |
| U23 | Uniform continuity, finite integral domains, one-sided matrix inverses | A declared seeded logical gap in the initial compilable draft, a concrete independent finding, repair, re-compilation and re-verification. |
| U24 | Geometric series, idempotent decomposition, sum of squares | At least two real independent alternative-route branches, domain separation, required branch sealing, join and final verification. |
| U25 | Rank/nullity, finite-field polynomial roots, polynomial gcd | Actual Sage and Magma inputs/outputs plus independent reasoning; bounded computations are not general proofs. |

U23 is explicitly a seeded repair challenge. Do not present its planted defects
as naturally observed product failures or use a prewritten empty/wrong report in
place of the reviewer's actual reasoning. U24 branches are alternative proof
routes; they must follow the existing MTM branch contract, not an invented
conjunctive-sublemma scheduler.

## Independence is an observed procedure, not a Boolean shortcut

`crates/mtm-workflow/src/verifier.rs::from_submitted_report` derives its verdict
from the submitted findings. The existing required-LaTeX fixture explicitly
disclaims independent mathematical verification. Replaying its fixed proof and
empty findings cannot establish U21-U25 acceptance.

The generating conversation stops at `verify`. A different reviewing conversation
or human reviewer, using the same disposable connection and preserved run owner,
requests the current verifier task. It checks the legally provided statement,
proof and references and submits its own specific findings. A repair returns to a
separate repair/generation conversation, then receives a new independent review.
U24 branch work likewise uses separate conversations and the actual branch
capabilities. No task card supplies capabilities or authorizes cross-domain reads.

This is a procedural handoff, not technical proof that two people or models are
independent. Record who/what reviewed, the separate session boundary and the exact
draft reviewed. A pseudonym or file hash alone is not an authenticated witness.
Never call a workflow's `correct` string an independent proof certificate.

## Session launcher and confidentiality

From the committed checkout in an interactive host terminal:

```sh
bash conformance/mtm016-research-session-tests.sh --sqlite /home/lk/miniconda3/bin/sqlite3 &&
bash scripts/mtm016-research-session.sh --task U21 --repeat 1
```

The only selectors are `--task U21|U22|U23|U24|U25` and `--repeat 1|2|3`.
`--prepare-only` creates an unexecuted session for inspection and is not a trial.
There is no binary override, production-source argument, mode downgrade,
automatic approval, task retry or resume-by-guessing-latest-directory option.

Each invocation creates a new owner-only directory outside the repository:

```text
$HOME/.mtm-acceptance/MTM-016/research/U21-r1.XXXXXXXX/
```

The original frozen executable is never run in place: a new private snapshot is
hash checked before execution. `env -i` removes inherited production roots,
tokens, server URLs, debug configuration and dangerous-mode settings. The new
HOME, workspace, data, private and debug roots are all under the fresh session.
The minimal PATH contains reviewed resolved host tool executables; U25 alone adds
Sage and Magma. `Native=safe`, `LaTeX=required`, workflow protocol 3 and disabled
payload tracing are explicit. Native CLI attestation runs before the tunnel;
failure retains private diagnostics and stops without retry or fallback.

The TUI is a foreground host process, not an additional outer OS sandbox. Its
Native commands and LaTeX retain the existing candidate's isolation. Do not infer
that the TUI itself has no host filesystem privileges. Disposable configured
state roots and non-use of production directories are not equivalent to a
cryptographic read-only mount of the entire host. This launcher never discovers,
copies or opens production databases.

The local console prints the private session path and shell-quoted commands to
read `task.md` and `operator-key.txt`. The latter is mode 0600 and is the password
for this session's OAuth page; `configured externally` refers to that key. Read
it in a second local terminal. It is not printed by the script or included in the
public manifest. Only the newly displayed tunnel URL is used in the real client.
Do not paste the URL, key, credentials or raw operator log into a conversation.
If the TUI reports an unavailable tunnel or the client denies a call, stop and
retain that observation; do not route around the failed authorization path.

`session.json` is an immutable preparation observation and explicitly says
`runtime_executed=false`, `research_trial_passed=false` and
`independent_review_recorded=false`. It never gets overwritten with a green
verdict. Normal TUI exit writes a separate `close.json`, which records only the
process outcome and input stability and still claims no research acceptance.
An abrupt kill can leave no close report; absence must not become success.
Input hashes and the launcher commit are rechecked on return. Keep the checkout
unchanged while a research session is running. Do not run the launcher again to
hide an interrupted attempt.

## Evidence collection still required

The newly delivered entry is a preparation/interaction path, not the research
evidence collector or release adapter. Before any U21-U25 row can be accepted,
the next collection stage must bind this session, task/repeat, actual run,
candidate bytes, ordered transitions, required compiler results, final exact
`.tex` bytes and substantive independent review. It must additionally verify the
retrieval/citation, repair, branch-domain or CAS facts required for that task.
Keep draft versions, verifier findings and tool outputs privately for that check;
do not publish the raw workflow database or transport log.

No accepted fixture or current release input is edited by this delivery. Script,
case and documentation changes are outside the existing raw Rust source-hash
scope; existing source/Native/copy gates need not be rerun for this launcher.
Future Rust collector changes will require their own source check. U26-U29 and
the complete research importer remain explicitly unfinished. The current corpus
aggregate deliberately continues to reject complete/release claims.
