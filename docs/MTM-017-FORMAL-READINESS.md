# MTM-017 formal readiness consumption contract

Contract revision: `mtm017-release-readiness-contract-v1`.

This adds `cargo xtask release-check-schema8 --inputs <flat-MTM017-JSON>
--input-review <flat-MTM017-JSON>`. It evaluates the exact preview.2 artifact
13d7890c… and schema-7 baseline f59cbdda…, without executing either. There are
no record, accept, force, deployment or arbitrary-candidate options. MTM-016
and the old fixed-inventory draft are unchanged.

## Existing requirements and their mapping

The eighteen presentation rows preserve the old draft's gap-accounting shape;
that count is not an independently approved release standard. These rows map
existing requirements, not new real-world tests:

1. Exact candidate/baseline bytes and product identity: preview.2 qualification
   snapshot and MTM-017-PREVIEW2-QUALIFICATION.
2. Current complete source gate: ACCEPTANCE A0 and CODE_STANDARD; recompute the
   final maintenance source hash rather than borrowing historical counts.
3. Protocol: exact 500 assessments, adversarial, lifecycle and workspace summaries.
4. Generated schema-7/8/7 upgrade: MTM-017-SCHEMA8-UPGRADE's 21 checks, not real data.
5. Native: dangerous command/isolation/TTY/process/CAS scoped qualification.
6. Compiled LaTeX: required full/compact/repair and shell-escape rejection fixtures.
7. Resource: the existing paired baseline/candidate thresholds, no performance claim.
8. Native corpus: U16-U20 fifteen rows under the dangerous-only mapping; a subset.
9. Installation recovery: process-SIGKILL profile and three separately accepted
   U30 trials. No physical-power-loss or production-cutover claim.
10. Retrieval: exact-candidate external HTTPS and redirect-policy qualification.
11. Research: only the previously accepted U21-U25 fifteen-row public evidence
    chain; no reacceptance, private bundle replay or newly proved mathematics.
12. Real operator copy: DECISION-005 and its ordering clarification. Three real
    repetitions verify exact original bytes/modes before mode-only preparation,
    then the same old run under the schema-7 baseline, with candidate migration
    and restart. Original strict failure remains failed. Capture quiescence is
    operator-attested; no transactional snapshot or complete process visibility.
13. Browser U26: DECISION-006 applies to exactly repeats 1-3, preserves the
    incomplete browser observation and technical pending status. This does not
    waive any different finding or create three successful browser trials.
14. Current corpus: reconstruct the accepted 78 plus six U27/U28 observations
    under DECISION-004 and three real U29 observations under DECISION-005.
    The accepted 87 and separate U26 waiver yield 90 accounted governance cells,
    still only 87 technical accepts and three technical pending cells.
15. Static integrity: current records, architecture, retirement, Rust-only audit
    and diff checks. Historical retirement prose does not revive F2 consent.
16. Mapping/adapter completeness: machine integrity of this contract, with no
    additional user-facing trial or acceptance requirement.
17. Clean build: DECISION-003 is one exact-candidate human override. Preserve the
    two equal rebuilds that differ from the candidate and technical passed=false.
18. Historical binary: DECISION-001 excludes only the old missing preview.2
    artifact. The actual schema-7 baseline and real-copy restoration remain required.

The eight committed-source qualification profiles keep their original runner
milestone and scopes. Their source hash is independently recomputed from 7b4afe…
Git bytes. Later corpus/harness observations from uncommitted trees retain their
observed before/after hashes and reviewed provenance; their recorded HEAD is not
falsely represented as a reconstructable Git tree.

Product identity compares all crate files, including build scripts and embedded
assets, and root Cargo/lock/toolchain/.cargo inputs against the selected product
commit. Only three explicitly reviewed integration-test paths may differ:
mtm-cli/tests/support/loopback.rs, mtm-cli/tests/schema8_authority_corpus.rs and
mtm-runtime/tests/domain_collision.rs. Their exact current hashes are bound by
the reviewed inputs and the complete current source gate. No arbitrary tests/
or non-src path exemption exists.

## Closed input and separate input review

`mtm017-release-inputs-v1` has schema, milestone, criteria_revision, criteria
path/hash, candidate_sha256, baseline_sha256, prepared_by, current source_gate,
qualification snapshot, corpus state/acceptance, research state, decision ledger,
clean-build and U26 states, real-copy aggregate/review, known failure/followup/
mechanism diagnostic, optional paired risk disposition/review, and exactly the
three test_only_sources path/hash references. It carries no user-selected pass,
count or release/deployment booleans. The fixed candidate and accepted historical
roots cannot be replaced by arbitrary newly sealed records.

`mtm017-release-input-review-v1` binds inputs_sha256, implementation_source_sha256
and maintenance_binary_sha256, prepared_by, a distinct reviewer_session, decision
`approved_for_read_only_readiness_evaluation`, recorded_unix_seconds, false
release/deployment flags, and these ordered checks:
- eighteen_mapping_scopes_reviewed
- public_chain_refs_and_scoped_waivers_reviewed
- known_failure_disposition_scope_reviewed
- current_source_and_binary_bound
- negative_tests_and_no_action_boundary_reviewed
- separate_result_review_required

Review markers are procedural evidence, not cryptographic identity. Actual
independent review is required; a JSON approval string does not authorize its own
creation. Freeze code, test it, run the final source gate, assemble inputs and
obtain review in that order. Source-receipt hashes live in inputs, not embedded in
the code whose source hash they cover.

## Known failure and scoped disposition

Finding MTM017-SOURCE-R3-NORMAL-ASSESSMENT names the immutable failed r3 source
gate and the test-only collision diagnostic. A mechanism reproduction neither
proves the original cause nor fixes runtime. The root cause remains indeterminate.
Absent a separately reviewed disposition, evaluation is unresolved/nonzero even
when the current source gate passes. This is not a permanent veto on all past
failures, and DECISION-001/003/006 cannot silently dispose of it.

The current supported disposition is a distinct explicit operator risk acceptance:
`mtm017-source-risk-disposition-v1`, milestone, decision_id=DECISION-007,
finding_id, failed_evidence, exact candidate_sha256, root_cause_status=indeterminate,
release_disposition=accepted_by_operator, passed=false, runtime_fix_claimed=false,
diagnostic and deployment_authorized=false. Its closed operator_authorization
contains source=direct_operator_confirmation, user_message_id, question_verbatim
and answer_verbatim. The identical decision must be in the current sealed ledger.
A separate `mtm017-source-risk-disposition-review-v1` binds finding_id,
disposition path/hash, decision=approved_for_scoped_readiness, reviewer_session,
original_failure_preserved=true and deployment_authorized=false. Other evidence-
based dispositions require their own reviewed supported contract; no force flag
turns a future or unsupported record into permission.
This version fixes the already reviewed followup, mechanism diagnostic, exact
operator disposition and its independent review to their paths and SHA-256 seals.
It additionally checks the diagnostic's observed collision/reopen/zero-write/
recovery facts and the actual accepted authorization message. A different or
declined authorization, substituted diagnostic, or self-review cannot be selected
merely by supplying another hash. The risk reviewer must differ from the preparer.

## File and revalidation boundary

All new envelopes and references reject unknown fields and duplicate JSON keys,
including nested duplicates/trailing bytes. Historical records are sealed exact
bytes and rechecked semantically by role. Use descriptor-relative, no-follow reads,
bounded file sizes, ownership/link/mode checks and metadata/byte rechecks before
output. Public JSON can retain 0664; executable candidates may not be group/other
writable and must have owner execute. Maximum 256 files and 64 MiB total, 1 MiB
per JSON/data file and 32 MiB per artifact. Unknown roles, paths, missing evidence,
cross-gate substitutions, repeated decisions or inconsistent shared seals fail.

The reference graph is role-directed, not a recursive opening of every archived
path string. Prior mutable maintenance/source paths remain historical. The four
version-controlled union source files are verified as byte-identical archives,
not executed. This evaluator revalidates public receipt/review chains and their
semantics; it does not replay target archives, reopen private copies or rehash
private research bundles. Full original Bash/SQLite replay still needs the explicit
SQLite, target logs/executable and other dependencies listed in that archive's
README. Missing full-replay prerequisites cannot be synthesized or described as
a successful replay.

## Two-stage result and qualification

A valid evaluated result uses `mtm017-readiness-evaluation-v1`. Every row states
its criterion source, evidence scope, technical result and governance disposition.
It preserves implementation_complete=unknown for the whole project, separately
states the validated adapter scope, and keeps research_accepted only for the prior
fifteen rows. Technical qualification remains incomplete because explicit waivers
are not technical passes. Count activation never occurs.

If the mapped requirements and scoped disposition are satisfied, the first run
can return readiness_evaluation_passed=true and exit 0. It still emits
release_qualified=false, result_review_required=true, result_review_pending=true
and deployment_authorized=false. Unresolved findings return a structured report
and nonzero exit; malformed/drifting evidence produces no evaluation.

A subsequent independent result review binds exact evaluation, inputs, current
source and binary hashes. Only then may a separately authorized coordinator append
an accepted-readiness record with release_qualified=true and
qualification_basis=technical_evidence_plus_scoped_operator_waivers. This command
does not write or activate that record. Deployment always requires separate
authorization. No commit, push, tag or installation action belongs to this tool.

Tests must exercise semantic mutations as well as seals: 87-to-90 inflation,
scope/waiver swaps, duplicate cells and decisions, source/test drift, unresolved
finding hidden by a later pass, restoration ordering, malformed inputs, ancestor
links/replacement and total budgets. Run focused maintenance and complete source
checks on the final implementation; preserve failed attempts rather than skipping
or relabeling them.
