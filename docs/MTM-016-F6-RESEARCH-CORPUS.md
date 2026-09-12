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

For quick-tunnel sessions, "same disposable connection" means the same already
registered OAuth client, not merely the same data directory or operator password.
Before creating the run, record the session's `server_info.oauth_client_id`
locally. Keep the TUI/tunnel alive through the generator-to-reviewer handoff. The
reviewing conversation must reuse the existing connected MTM endpoint without
deleting/reconnecting/re-registering it, and must confirm the same client ID before
requesting the verifier task. A different client ID is a hard owner-continuity
failure; do not repair it by changing database ownership or copying capabilities.

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

Safe mode does not auto-discover the foreground process's PATH directories.
The launcher now declares only the new session's `tool-bin` as an explicit
read-only tool root. It never declares the parent session, HOME, data or private
directory. This is necessary because the fixed compiler helper receives the
absolute alias found on the foreground PATH; an unmounted alias can fail even
when `/usr/bin/latexmk` works. This change does not enable host-PATH inheritance,
change Native modes or disable the required compilation gate. Non-system CAS
dependencies remain a separate U25 prerequisite, not acceptance from this repair.

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
A byte-identical, no-clobber copy of `task.md` is now published in the disposable
workspace so a client can read the prescribed case ID and handoff rules. The
operator key and session manifest remain outside that writable workspace.
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

Later MTM-016 maintenance work adds the read-only private-bundle consistency gate
in `docs/MTM-016-F6-RESEARCH-PRECHECK.md` and the closed U21-U25 release adapter in
`docs/MTM-016-F6-RESEARCH-AGGREGATION.md`. Those layers do not retroactively turn
this launcher into an evidence collector. Until fifteen real reviewed trial
receipts exist, the active corpus remains 63 passed / 0 failed / 27 blocked. A
future complete research batch advances only to the deliberately partial 78/12
boundary; U26-U29 remain independently required.

The host-side bridge from one sealed private session into the precheck format is
`docs/MTM-016-F6-RESEARCH-COLLECTOR.md`. It is intentionally unable to run through
the connected maintenance Native sandbox because that sandbox does not expose the
private acceptance-session root. Do not widen Native mounts for collection. Run
the collector from the host checkout against the explicit disposable session and
retain its bundle under that private session rather than repository evidence.

### Exact-session stop and interrupted-session recovery

If a foreground research TUI or an internal `__native-helper` remains after an
interrupted session, do not use `pkill mtm`, `killall`, executable-name matching,
or delete the state directory. `scripts/mtm016-stop-research-session.sh` accepts
only one canonical private research session and the explicit
`--operator-confirmed-stop` acknowledgement. It scans procfs for processes whose
executable is the session's exact frozen candidate, rechecks process ownership and
classifies only `tui`, `__native-helper` and `--sandbox-probe` argv roles. Unknown
roles or multiple TUI processes fail before signalling.

The stop helper sends SIGINT to one exact TUI first so the runtime can use its
existing Ctrl-C shutdown path. After a bounded wait it may send TERM to that same
revalidated TUI. Once no TUI remains, exact stale helper/probe processes may receive
TERM; the Native Bubblewrap command includes `--die-with-parent`, so owned sandbox
children are not deliberately detached. There is no automatic KILL fallback. A
remaining exact process is preserved as a blocker instead of broadening process
authority. This helper never signals the installed production binary or a process
selected only by name.

If the exact TUI remains after both INT and TERM, the helper emits only bounded
procfs diagnostics: process state, parent, thread count, start-time ticks, wait
channel and signal masks. It does not publish environment, file descriptors,
credentials or the raw command line. Normal `--operator-confirmed-stop` still
fails at this point. The separate `--operator-confirmed-force-stop` acknowledgement
permits SIGKILL only after the executable, uid, `tui` argv role and original proc
start-time have all been revalidated, and only when Linux does not report the task
in uninterruptible `D` state. There is no PID/name fallback, and helper/probe or
unknown roles do not receive this KILL path. Abruptly stopping the disposable
runtime is a recovery action only; it never makes a workflow or corpus row pass.

## Recovery of the first U21-r1 compiler-path interruption

The operator reported an accepted assembly entering `repair` before verification.
Read-only inspection confirmed `repair`, sequence 4, no pending submission,
no verdict and no sealing. A direct `/usr/bin/latexmk -v` worked on the actual
research connection, while its private tool-bin alias was not executable in the
Native namespace. The original task card was outside the workspace. These are
launcher-path defects, not a mathematical verifier finding or missing host package.

The new host regression first checks Native prerequisites and then calls the
frozen candidate's fixed compiler helper on harmless synthetic TeX. It checks
failure without the alias root and successful compilation with that one read-only
root, while retaining safe network isolation and private-vault exclusion. It does
not launch a workflow, certify mathematics or use the operator's real state.

`scripts/mtm016-resume-research-session.sh` accepts an explicit stopped U21-r1
session made by the original launcher at `1d1fcb7`, an explicit SQLite CLI for
reading its preparation JSON, and `--operator-confirmed-stopped`. It does not
search for the latest session. It checks all twenty manifest fields, exact
artifact/case identities, private directories, the saved key and original log.
`--check-only` performs metadata validation without starting a runtime or writing
the session. The foreground recovery requires a terminal, uses an exclusive
recovery lock and additionally refuses a visible running candidate at that path;
this does not replace the operator's stopped-service confirmation.

It preserves the original state roots, candidate, key, preparation receipt and
failure log. New logs/observations go to `compiler-recovery.XXXXXXXX`. It only
adds the missing public task card and restarts the same candidate with the narrow
tool root. It never reads a workflow database directly, creates a run, submits
proofs, edits an owner or certifies success. After reconnect, inspect the existing
run first. If the client registers a different owner or reports RUN_OWNER_MISMATCH,
stop; reusing state and keys does not guarantee that a web client preserves its
OAuth registration when a quick-tunnel URL changes. Do not alter database owners.

The original run used a different problem_id from the task card's prescribed
case_id. Retain that procedural discrepancy and the infrastructure failure in
future collection; never rename the database record or silently credit the trial.
No mathematical review has taken place in this maintenance conversation. Once
connected as the original owner, use the current repair task (not the consumed
assembly submission) to retry compilation, and stop at verify for a separate
reviewer. This infrastructure repair does not count as U23's seeded logical gap.

The first U21-r1 recovery did not preserve the OAuth owner. After the exact TUI
was stopped (including an explicit, identity-bound force stop) and the same state
roots were relaunched, the recovered endpoint authenticated a newly registered
OAuth client. `rethlas_inspect(status)` on the preserved run correctly returned
`RUN_OWNER_MISMATCH`. In this runtime the workflow owner is the OAuth `client_id`;
reusing the data directory, operator password and signing key therefore does not
authorize a newly registered client to adopt the run. Do not edit `runs.owner_id`,
copy capabilities, or mint a replacement verifier token to salvage this attempt.

Treat that original session as a retained, non-counting infrastructure-invalid
attempt. It is structurally ineligible for U21 acceptance anyway: it used the old
launcher with the unmounted LaTeX alias and a problem_id different from the fixed
case registry. A replacement U21-r1 acceptance attempt must start from a fresh
session under the repaired launcher and keep the same live OAuth connection from
generation through independent review/finalization. If that live connection is
lost again, retain the attempt and do not silently convert a restarted quick
tunnel registration into the old owner.

## Read-only evidence preparation entry

`cargo xtask research-precheck --bundle <absolute-private-directory>` now checks
bounded supplied evidence and reports missing U21-U25 material. Its contract and
normalization rules are in `docs/MTM-016-F6-RESEARCH-PRECHECK.md`. It never imports
a research trial, authenticates independent reviewers or authorizes release;
every inventory keeps accepted-trial delta zero and manual validation required.
Route-specific semantic checking and the research corpus importer remain pending.
This Rust maintenance change requires a fresh source gate; earlier shell-only
source-equivalence observations must not be reused to cover it automatically.
