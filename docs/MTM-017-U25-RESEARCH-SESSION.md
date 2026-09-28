# MTM-017 U25 preview.2 research session

## Purpose and boundary

U25 acceptance for MTM-017 must run against the exact qualified
0.6.0-preview.2 candidate, SHA-256
13d7890c5c763199ed39295e134ff6cc735ceaa04eaddf6c556431a7a56254f4,
with candidate source commit
7b4afe2359e688263557f62154e4bc1e640c12c0.

Historical MTM-016 research sessions remain bound to preview.1 and the
HOME/.mtm-acceptance/MTM-016/research root. This path does not relabel or import
those trials. MTM-017 U25 uses the separate
HOME/.mtm-acceptance/MTM-017/research root and the existing
mtm-research-session-v2 dangerous-Native evidence contract.

The current versioned extension is intentionally U25-only. It does not apply
the historical safe-mode U21-U24 research-session policy to preview.2, whose
current Native product semantics are dangerous-only.

No production selector, production state, release input or deployment is
changed by this session.

## Prepare and start

From the repository root, after the launcher is committed and clean:

    bash scripts/mtm017-u25-research-session.sh prepare 1

The command prints the exact private SESSION_ROOT. Preserve that path literally.
Then:

    SESSION='<printed absolute session path>'
    bash scripts/mtm017-u25-research-session.sh check "$SESSION"
    bash scripts/mtm017-u25-research-session.sh up "$SESSION"
    bash scripts/mtm017-u25-research-session.sh attach "$SESSION"

Read the Quick Tunnel MCP address from the private console and connect a fresh
test connector. Read operator-key.txt only in a local terminal and enter the
key only on that session's OAuth page. Do not paste the key, URL, bearer token,
capability or raw console log into evidence.

The launcher creates a fresh HOME, workspace, schema-8 data root, OAuth key,
candidate snapshot and tool-bin. Sage and Magma installation roots are exposed
read-only to the Bubblewrap Native executor. Native mode is dangerous, LaTeX
policy is required, and workflow protocol is 3.

## U25 CAS evidence

The workflow proof must establish the general theorem independently of finite
CAS calculations. For U25-r1, Sage and Magma each check

    A(t) = [[1,t,0],[0,1,t],[1,t+1,t]]
    t = -1, 0, 1, 2

over the rationals.

The generator writes only these CAS files under
workspace/research-evidence/:

    sage_input.txt
    sage_output.txt
    magma_input.txt
    magma_output.txt
    cas_observation.json

The independent reviewer later writes review.json in the same directory.
cas_observation.json uses mtm-research-cas-observation-v2, records
native_mode=dangerous, general_proof_independent=true,
raw_credentials_recorded=false, and exactly one Sage plus one Magma tool
observation with actual version, exact input/output SHA-256 and exit code zero.

The proof manifest keeps at least two computational_evidence entries, one for
each CAS execution. Those entries are finite cross-checks and are not the
general rank-nullity proof.

## Seal fixed route material

The model-visible workspace never gains direct access to the session root,
OAuth key or private workflow database. After CAS material is ready, the
operator can copy only the fixed allowlist from workspace/research-evidence/
into the collector's fixed workspace/research-evidence-input/ directory:

    bash scripts/mtm017-u25-research-session.sh seal-material "$SESSION"

The operation is non-overwriting and content-preserving. Unknown files,
directories, symlinks, hardlinks, oversized files, invalid UTF-8 or conflicting
existing destination bytes fail closed. It is safe to run again after
review.json appears; already sealed identical files are left unchanged.

## Review and collection

Keep the same TUI, tunnel and already registered OAuth connector from generation
through independent review. At verify, a separate review conversation checks
the actual proof, manifest and CAS evidence before submitting the verifier
report. A newly registered connector does not inherit workflow ownership.

After the run is sealed done, fixed route material and review.json are sealed,
and the private session remains unchanged, collect with:

    CARGO_TARGET_DIR="$PWD/target/mtm-tool" cargo xtask research-collect \
      --session "$SESSION" --run-id '<exact run id>' --sqlite /usr/bin/sqlite3

The collector is read-only with respect to workflow state. It creates a private
evidence bundle, runs the non-authorizing research precheck, and reports
research_trial_passed=false and accepted_trials_delta=0; mathematical acceptance
still comes from the separately reviewed evidence and the later corpus
governance step.

## Lifecycle

Leaving the console without stopping the service uses tmux detach: Ctrl+B, then
D. An intentional stop is:

    bash scripts/mtm017-u25-research-session.sh stop "$SESSION"

Do not delete the session while collection or evidence review is pending.
