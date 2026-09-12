# MTM-016 F6: private research evidence collector

## Purpose

`cargo xtask research-collect --session <absolute-session> --run-id <run-id>
--sqlite <absolute-sqlite3>` converts one already sealed disposable U21-U25
research run into the private bundle consumed by `cargo xtask research-precheck`.

The collector is maintenance/evidence plumbing only. It does not start or resume a
runtime, issue or consume a capability, submit a workflow action, edit an owner,
decide mathematical correctness, add a corpus pass or grant release authority.
The selected run must already be `done`, `sealed`, `correct`, required-LaTeX passed
and have no pending step receipt.

## Host-only private-state boundary

The collector deliberately accepts only an explicit absolute session whose
canonical path contains `.mtm-acceptance/MTM-016/research/` and whose basename is a
fixed U21-U25/repeat session shape. It accepts no production-root option, binary
override, release flag, skip switch or latest-session search.

Run this command from the ordinary host checkout. The connected MTM maintenance
Native sandbox does not expose the acceptance session's parent private state and a
tool-side invocation is expected to fail with `research session is unavailable`.
Do not weaken that sandbox, mount the private state into a maintenance command, or
copy a production database into the repository merely to make collection work.

The session root and workflow private run directory must be owner-private mode
0700. All selected leaf inputs are regular single-link files, bounded before read,
owned by the session owner, not writable by group/other and checked for inode,
size and timestamp stability during the read. Candidate bytes must be the frozen
MTM-016 candidate and retain mode 0500.

## Database read boundary

The collector never links a new SQLite library into the maintenance crate. The
operator supplies one explicit absolute `sqlite3` executable. The collector
canonicalizes and hashes that bounded regular executable, records its version, and
invokes only fixed `sqlite3 -readonly -json -batch` queries with `query_only=ON`.
The run id is restricted to the existing identifier alphabet before it can enter a
fixed SQL string. No caller-provided SQL or database path other than the fixed
selected session database is accepted.

The collector reads only `<session>/data/private/state.sqlite3`. Schema 7 is
mandatory. It reads only the selected run, ordered transitions, proof manifest and,
for U22, registered references and reference audits. It refuses a pending step
receipt. The bounded sqlite3 child has a cleared environment, fixed timeout/output
limit and owned process-group cleanup. A sqlite3 error or stderr is a collection
failure; there is no writable fallback.

The run/database evidence is collected twice around private-file collection and
must be byte-semantically identical. The immutable session manifest and candidate
are also reread and compared. A live TUI may remain online for owner continuity;
the selected run itself must already be sealed and cannot change during the
collector interval. The collector never opens the OAuth database and never reads
the operator key or `operator.log`.

## Private proof and compiler evidence

The collector requires the private verifier-reviewed draft and final proof to be
byte-identical. It also opens the already published workspace export path from the
run metadata and requires those bytes to equal the private final proof. The final
transition's SHA-256 must equal those same bytes.

The last `latex_validate -> verify` transition must contain an actual required
compiler result with static validation, compiler availability, compilation and the
overall gate all true, no compiler errors and nonempty compiler output. Because
the runtime's `compile_passed` contract itself is defined by helper exit code 0,
no timeout and an existing PDF, the collector records a derived `latexmk` exit 0
observation and binds its exact retained output bytes. It never reruns LaTeX.

## Independent review input

The collector never synthesizes reviewer evidence from the server verdict. A real
reviewing session must first place
`workspace/research-evidence-input/review.json`, schema
`mtm-research-review-observation-v1`. The observation contains no raw OAuth client
ID; both generator and reviewer identities are represented only by the SHA-256 of
the locally observed same OAuth owner. It also binds the exact trial, run, reviewed
TeX and verification-report hashes and includes concrete statement-check summaries.

The collector recomputes the selected run owner fingerprint directly from the
read-only run row and rejects a different owner, proof or report. The separate
reviewer-session marker and review-before-finalization facts are then checked again
by `research-precheck`. A structurally correct review observation is still a
procedural record, not cryptographic proof of a different human/model identity.

For route-specific tasks the same fixed input directory holds only the evidence
that cannot be reconstructed safely from the database/vault:

- U22: `retrieval.json`, `sources.json`; reference-audit rows come from SQLite.
- U23: `seeded_draft.tex`, `first_findings.json`, `repair_history.json`.
- U24: `branches.json`.
- U25: Sage/Magma input/output files and `cas_observation.json`.

Missing route files stop collection. There is no fabricated default or partial
success bundle.

## Publication and failure behavior

The collector writes only a new owner-private staging directory inside the same
disposable session. Every file is mode 0600. It writes `bundle.json` last and calls
the same internal `research-precheck` on the staging directory. Only when all
required material is present and consistent, while precheck still reports
`research_trial_passed=false` and `accepted_trials_delta=0`, is the directory
atomically renamed to `evidence-bundle.<trial-id>`.

An existing final bundle is never overwritten. A failed partial staging directory
may remain private for diagnosis and is not a recognized final bundle. The public
collector summary exposes hashes/counts, the relative bundle-directory name and an
owner fingerprint only; it never emits proof text, run-owner bytes, OAuth secrets,
capabilities, databases or raw compiler/retrieval/CAS bodies.

Successful collection still does not create `mtm-research-trial-evidence-v1` or a
corpus pass. Substantive review of the private bundle and the separately reviewed
sanitized trial receipt remain required before the v3 research aggregate can
advance from 63/27 to 78/12.
