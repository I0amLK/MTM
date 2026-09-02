# MTM-009 implementation plan: mathematical research state

## 1. Purpose

This plan narrows MTM-009 to one product outcome:

> MTM continuously derives a compact, reliable picture of the mathematical target,
> active subgoals, failed methods, counterexample coverage, and current obstruction,
> then presents one transparent advisory next action to the web model without changing
> workflow authority or the final verified `.tex` delivery path.

The plan is divided into seven separately reviewable deliveries. No production code is
to be written until the proposal is approved and the milestone/record scaffolding is
created.

## 2. Baseline and hard constraints

The implementation starts from the accepted MTM-008 Rust authority at the exact Git
baseline recorded when MTM-009 is approved.

The following constraints are release blockers:

| Constraint | Budget |
|---|---:|
| New crates | 0 |
| New public tools | 0 |
| New hidden aliases | 0 |
| New workflow states | 0 |
| New SQLite schema versions | 0 |
| New long-running workers | 0 |
| Model/Codex/API integrations | 0 |
| New independent web applications | 0 |
| New final artifact kinds | 0 |
| Current final artifact | verified `.tex` only |

Permitted structural additions are limited to:

- one or a few cohesive modules inside `mtm-workflow`;
- protocol-3 methodology and typed contract facts;
- pure graph/projector tests and fixtures;
- bounded context fields in existing Rethlas task envelopes;
- milestone, acceptance, benchmark, and iteration records.

## 3. Target architecture

### 3.1 Responsibility split

```text
web model
    │ proposes plans, attempts, examples, counterexamples, and proof text
    ▼
existing rethlas_step contract
    │
    ▼
workflow authority
    ├── validates state, role, capability, and submission
    ├── assigns canonical plan/subgoal/attempt identifiers
    ├── writes normalized append-only research records
    ├── performs existing transitions and barriers
    └── calls pure ResearchStateProjector
              │
              ▼
       compact advisory research view
              │
              ▼
          next task envelope
```

The existing verifier, LaTeX gate, finalization permit, and finalizer are not modified
except for compatibility tests proving that they remain the only path to the final
`.tex` file.

### 3.2 Proposed module surface

The initial implementation should fit in these existing crates:

```text
mtm-contracts
  protocol/research enum wire facts only when they are public stable facts

mtm-workflow
  research_state/types.rs       named non-authority data types
  research_state/normalize.rs   raw protocol-3 content to server records
  research_state/project.rs     deterministic append-only replay
  research_state/graph.rs       cycle/frontier/reachability algorithms
  research_state/advice.rs      ordered advisory rule table
  research_state/view.rs        bounded model-facing quotient
```

The exact file split is optional. A single module is preferred until its size or test
surface justifies splitting. No module may become a second workflow engine.

### 3.3 No graph dependency

Do not add a general graph crate in the first version. The graph is small and needs
only:

- adjacency maps using `BTreeMap`/`BTreeSet`;
- depth-first cycle detection;
- reverse reachability to the target;
- deterministic topological ordering;
- actionable-frontier selection.

This keeps binary size, supply-chain surface, and semantics small and reviewable.

## 4. Mathematical data model

### 4.1 Claim nodes

The server-normalized claim node has the conceptual shape:

```text
ResearchNode {
  node_id,                 // server issued
  statement,
  kind,                    // target | lemma | construction | definition
  plan_id,
  critical,                // on a declared route to the target
  dependencies,
  status,                  // open | partial | route_solved | refuted | blocked | superseded
  revision,
  created_round,
  latest_event_seq
}
```

`route_solved` is deliberately not named `verified`. It means that a generator or
branch reports a usable route; only the existing verifier/finalizer can produce a
verified final artifact.

### 4.2 Attempts

```text
ResearchAttempt {
  attempt_id,              // server issued
  node_id,
  actor_domain_id,
  method,
  outcome,
  summary,
  obstruction,
  evidence_ids,
  created_round,
  event_seq
}
```

Initial closed method enum:

```text
direct
reduction
toy_example
counterexample
retrieval
computation
synthesis
repair
```

Initial closed outcome enum:

```text
progress
route_solved
failed
refuted
inconclusive
```

Initial closed obstruction enum:

```text
false_claim
missing_hypothesis
missing_lemma
missing_reference
computational_bottleneck
notation_mismatch
circular_dependency
incompatible_partial_results
no_progress
unknown
```

Enums are intentionally small. New values require evidence from real runs and a
separate contract review; they are not added merely to make classifications look
complete.

### 4.3 Decisions

```text
ResearchDecision {
  decision_id,
  superseded_plan_ids,
  preserved_node_ids,
  new_constraints,
  selected_focus_node_id,
  reason,
  event_seq
}
```

### 4.4 Identity rules

- All canonical IDs are server issued.
- Model-local subgoal keys exist only inside one submission and are never authority
  identifiers.
- The server never automatically merges two claims because their text is similar.
- Reuse across replanning requires an explicit existing `node_id` and exact owner/run
  validation.
- Reusing a node with materially different statement text is rejected.
- Node and attempt records are append-only. Current state is obtained by deterministic
  replay, not in-place mutation of historical memory.

## 5. Protocol-3 submission design

The public `rethlas_step` input schema remains the same generic step envelope. Only
the task-specific methodology contracts change for new protocol-3 runs.

### 5.1 Plan proposal

Protocol 3 accepts ordered structured subgoals:

```json
{
  "plans": [
    {
      "summary": "Route through a constituent rank identity",
      "subgoals": [
        {
          "key": "s1",
          "statement": "Establish the local constituent formula.",
          "depends_on": [],
          "critical": true
        },
        {
          "key": "s2",
          "statement": "Sum the constituent contributions.",
          "depends_on": ["s1"],
          "critical": true
        }
      ],
      "motivation": ["The decomposition matches the code structure."],
      "risks": ["The duality convention may differ on paired factors."]
    }
  ]
}
```

The server maps local keys to canonical subgoal IDs and rejects unknown, duplicate,
self-dependent, or cyclic local graphs.

### 5.2 Direct screening

Each existing screening result gains bounded optional research fields:

```json
{
  "status": "partial",
  "summary": "The self-conjugate factor is handled; the paired case remains.",
  "method": "direct",
  "obstruction": "missing_lemma",
  "evidence_ids": []
}
```

The existing `solved|partial|stuck` compatibility values may remain on the wire and be
normalized into research outcomes server-side.

### 5.3 Branch result

The current branch payload remains valid. Protocol 3 may add a bounded optional
`obstructions` array linked only to nodes assigned to that branch. Cross-branch node
references fail closed.

### 5.4 Failure synthesis and replanning

`failures_identified` and `replan_complete` receive strict optional fields for:

- affected node IDs;
- obstruction class;
- route exclusions;
- preserved node IDs;
- newly required hypotheses or references;
- selected next focus.

The old free-form summary remains present for readability, but server decisions use
only validated structured fields.

### 5.5 Exploration records

Exploration continues to write one logical event at a time. Protocol 3 recognizes a
small set of typed event forms:

```text
toy_example_result
counterexample_probe
retrieval_assessment
new_candidate_lemma
notation_resolution
```

Each record contains concise conclusions and evidence locators. It must not contain a
raw transcript or hidden reasoning trace.

## 6. Projector semantics

### 6.1 Inputs

The pure projector receives an immutable snapshot consisting of:

- target statement and run metadata;
- server-normalized plan/subgoal records;
- direct-screening records;
- branch and join results visible to the active role;
- classified failure and decision records;
- retrieval events with registered reference IDs;
- verification findings when the active role is Repair;
- current workflow state and round.

It performs no file, database, network, process, clock, random, or capability action.

### 6.2 Output

```text
ResearchState {
  target_node_id,
  nodes,
  attempts,
  decisions,
  active_plan_ids,
  actionable_frontier,
  critical_blockers,
  invalid_routes,
  retrieval_summary,
  advisory_action,
  warnings,
  digest
}
```

### 6.3 Core graph rules

- The active dependency graph must be acyclic.
- A superseded route is excluded from the active graph but retained in history.
- A refuted node makes every active route depending on it invalid until replanning.
- A node is actionable only when every active dependency is `route_solved`.
- A node is critical when it can reach the target in the reverse dependency graph.
- Stable ordering is by round, plan order, node order, then canonical ID.
- Missing references or unknown IDs produce explicit projection warnings; malformed
  authority-bearing records are rejected at write time rather than silently ignored.

### 6.4 Advisory rule table

The first matching rule wins:

| Rule | Condition | Advisory action |
|---|---|---|
| `R01_REPLAN_REFUTED` | critical node refuted | replan around the counterexample |
| `R02_REPLAN_CYCLE` | active dependency cycle | remove the circular dependency |
| `R03_TEST_COUNTEREXAMPLE` | repeated direct failure and no falsification attempt | test smallest meaningful examples |
| `R04_RETRIEVE_FOCUSED` | missing-reference obstruction and no focused retrieval | retrieve one targeted result |
| `R05_STOP_RETRIEVAL` | repeated retrieval adds no new reference IDs | synthesize existing sources without more search |
| `R06_SCREEN_FRONTIER` | untouched actionable critical node | attempt direct proof or a diagnostic toy example |
| `R07_CONSOLIDATE` | compatible partial attempts exist | consolidate into one reusable lemma |
| `R08_ASSEMBLE` | all critical target dependencies route-solved | assemble the complete LaTeX proof |
| `R09_REVIEW_STATE` | no rule applies | review declarations and choose the next mathematical action |

Every advisory contains `rule_id`, `focus_node_id`, a concise reason, and the evidence
facts used by the rule. It contains no unsupported natural-language speculation.

## 7. Compact task view

The research view appears before the existing task contract:

```json
{
  "mathematical_research_state": {
    "advisory_only": true,
    "target": "...",
    "current_blocker": {"node_id": "...", "statement": "...", "status": "blocked"},
    "frontier": [],
    "recent_attempts": [],
    "counterexample_coverage": "not_attempted",
    "retrieval": {"recent_queries": 2, "new_reference_ids": 0},
    "preserved_partial_results": [],
    "suggested_next_action": {"rule_id": "R03_TEST_COUNTEREXAMPLE", "summary": "..."},
    "graph_digest": "sha256:...",
    "truncated": false
  }
}
```

Initial view limits must be constants with tests, not configuration sprawl:

- at most 5 frontier nodes;
- at most 5 recent relevant attempts;
- at most 5 preserved partial results;
- at most 3 warnings;
- at most 1 advisory action;
- bounded string lengths and total serialized bytes.

Full memory remains accessible through existing tools. The compact view does not echo
capabilities, raw private paths, or data outside the active role's firewall.

## 8. Implementation-specific code standard

The repository-wide `docs/CODE_STANDARD.md` remains authoritative. MTM-009 adds these
rules for this feature.

### 8.1 Authority discipline

- `ResearchStateProjector` is pure and side-effect-free.
- Advice cannot call `transition`, `write`, `commit`, capability issuance, verifier,
  finalizer, or artifact publication.
- No boolean such as `advice_followed` may weaken a workflow precondition.
- Research-local `route_solved` never implies verifier correctness.
- All final output continues through the existing LaTeX, verifier, permit, and
  finalizer path.

### 8.2 Type discipline

- Raw JSON stops at protocol boundaries.
- Canonical IDs, enums, records, graph nodes, and advisory rules use named types.
- Unknown enum values fail closed for writes and become explicit compatibility errors.
- Authority-bearing constructors remain private.
- Server-generated sequence, time, and IDs are not accepted from the model.

### 8.3 Determinism

- Use `BTreeMap`/`BTreeSet` where ordering affects output or hashes.
- Canonical serialization is versioned.
- Same normalized input produces byte-identical compact view and digest.
- No wall-clock age heuristic appears in the pure projector; relative recency is based
  on event sequence and round.
- Ties are resolved by documented stable ordering, never hash-map iteration.

### 8.4 Boundedness

- Every string, array, graph, and record count has a hard bound.
- Deeply nested arbitrary JSON is not accepted in protocol-3 research fields.
- Replay work is bounded by accepted record counts.
- No background compaction is added. If history grows, explicit server snapshots may
  be considered only in a later measured milestone.

### 8.5 Record quality

- Store concise mathematical conclusions, not full conversations.
- Each failure record identifies the target node, attempted method, outcome, and
  concrete obstruction.
- Counterexample records distinguish `found`, `not_found_within_scope`, and
  `inconclusive`; failure to find a counterexample is never proof.
- Retrieval records distinguish new registered source IDs from repeated metadata.
- Evidence locators are references, workspace paths, computation IDs, or record IDs;
  they are not unsupported assertions.

### 8.6 Scope control

- Do not refactor unrelated workflow code.
- Do not split crates or introduce a generic graph framework.
- Do not introduce an all-purpose event bus.
- Do not add configuration until a fixed constant is shown inadequate by target data.
- Do not add an obstruction enum value without a real fixture requiring it.
- Do not optimize replay before measuring it.

## 9. Edge and adversarial test matrix

### 9.1 Graph shape

- Empty research history with target only.
- One plan with one subgoal.
- Multiple plans sharing no nodes.
- Explicit reuse of one preserved lemma across replans.
- Duplicate local subgoal keys.
- Unknown local dependency.
- Unknown existing node ID.
- Self-loop.
- Two-node and long dependency cycles.
- Cross-plan cycle after explicit reuse.
- Disconnected noncritical node.
- Refuted node on every route to target.
- Refuted node on only one alternative route.
- Superseded route retained in history but excluded from frontier.

### 9.2 Status and event replay

- Partial then route-solved.
- Partial then refuted.
- Route-solved then verifier gap during Repair.
- Duplicate event sequence.
- Out-of-order event input normalized by server sequence.
- Status event for unknown node.
- Invalid status regression.
- Replayed identical commit after retained writes.
- Crash between normalized record append and workflow transition.
- Recovery from copied vault and database state.

### 9.3 Attempt classification

- Direct failure with no obstruction.
- Two direct failures triggering counterexample advice.
- Counterexample found with witness/evidence locator.
- Counterexample not found within a clearly bounded scope.
- Counterexample marked found without witness.
- Retrieval obstruction with no retrieval.
- Retrieval producing new reference IDs.
- Repeated retrieval returning only previously registered IDs.
- Computation timeout recorded as inconclusive, not false claim.
- Conflicting branch attempts on the same reused lemma.
- Compatible partial results triggering consolidation.

### 9.4 Identity and branch firewall

- Model-supplied canonical ID rejected.
- Cross-run node reuse rejected.
- Cross-owner node reuse rejected.
- Branch A references Branch B private attempt ID.
- Branch result references a node not assigned to that branch.
- Join sees only sealed branch results.
- Generator compact view cannot expose branch-private notes.
- Verifier task cannot expose generation research state.
- Repair receives verifier findings and allowed generation context only.

### 9.5 Size and parsing

- Empty strings and whitespace-only statements.
- Maximum accepted Unicode/LaTeX statement.
- Invalid UTF-8 at outer boundary.
- Excess nodes, edges, attempts, evidence IDs, or warnings.
- Excess nesting depth.
- Oversized serialized compact view.
- Extremely long canonical IDs.
- Duplicate evidence IDs.
- JSON numbers where strings/enums are required.
- Unknown fields under `additionalProperties:false` protocol-3 records.

### 9.6 Advisory correctness

- Each `R01`-`R09` rule has a positive fixture.
- Every higher-priority rule suppresses lower-priority rules.
- Stable tie ordering.
- Advice references an existing visible node.
- Advice evidence matches the facts in the projected state.
- Truncation cannot change which rule fires.
- Advice cannot alter transition result.
- Ignoring advice still permits every otherwise valid submission.

### 9.7 Compatibility and rollback

- Protocol-1 frozen fixtures unchanged.
- Protocol-2 frozen fixtures unchanged.
- Current 82-checkpoint workflow corpus unchanged for protocols 1/2.
- Old protocol-2 run resumes under new binary.
- Protocol-3 run copied to the accepted prior binary degrades to protocol-2 task
  behavior without database corruption or finalization bypass.
- Public tool count remains 24; hidden alias count remains 11.
- State schema remains 2.
- Existing final `.tex` hash binding tests remain unchanged.

## 10. Validation plan

### 10.1 A0 — local and static

Run on every delivery:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python3 scripts/validate_engineering_graph.py
python3 scripts/validate_migration_graph.py
git diff --check
```

Feature-specific static validators check:

- no new crate/workspace member;
- no new public tool or hidden alias;
- no new workflow state;
- state schema remains 2;
- no Codex/model API/provider dependency;
- projector module contains no storage, network, process, clock, random, capability,
  transition, verifier, or finalizer import;
- compact-view limits are present and tested.

### 10.2 A1 — contract and golden

- Freeze normalized protocol-3 task and submission fixtures.
- Re-run all protocol-1/2 golden fixtures.
- Freeze canonical research-record serialization.
- Freeze graph digest and compact-view bytes for representative cases.
- Include valid, invalid, boundary, historical, and adversarial fixtures.

### 10.3 A2 — shadow projection and deterministic replay

There is no Python authority for the new semantics. A2 for MTM-009 therefore consists
of two parts:

1. Existing Python/Rust protocol-1/2 differential evidence remains zero-mismatch.
2. The new projector runs read-only against copied protocol-2 histories and frozen
   protocol-3 histories, with repeated replay producing identical state, digest, and
   compact view and no production side effects.

Before exposure to the web model, candidate builds compute the projection in shadow
and record only bounded nonprivate metrics and hashes.

### 10.4 A3 — integration and security

- Atomic relationship between normalized records and commit transition.
- Capability/state/role validation before accepting research content.
- Branch and verifier firewall canaries.
- Restart, retained-write, retry, and concurrent conflict behavior.
- Secret and private-text scanning of logs and evidence.
- Proof verification and finalization remain the sole publication path.

### 10.5 A4 — real web/workspace mathematical acceptance

Mocks do not establish mathematical usefulness. Run the candidate through the actual
web-driven usage path, including the model's own literature tools and MTM workspace
commands where appropriate.

For each frozen problem, record only:

- problem ID and category;
- exact problem hash;
- MTM version/protocol and model identity as displayed by the web product;
- research-state digest sequence;
- normalized attempts, obstruction classes, and advisory rule IDs;
- whether the model followed or rejected each advisory and its concise reason;
- final workflow outcome;
- verifier findings and repair count;
- final `.tex` hash when produced;
- independent human correctness/readability assessment.

Do not store raw hidden reasoning or a full private conversation transcript.

### 10.6 A5 — resource non-regression

Measure equivalent protocol-2 and protocol-3 runs for:

- task-envelope byte size;
- projector time at p50/p95/p99 over bounded histories;
- peak RSS;
- vault/database writes;
- startup and idle resources;
- request latency;
- restart and shutdown bounds.

Initial release blockers:

- compact research view stays within its declared byte budget;
- no idle thread/process is added;
- replay remains bounded at maximum accepted history;
- no unexplained material request-latency or RSS regression.

### 10.7 Mathematical effect gate

Use a frozen paired corpus with the same web model and problem statements under:

- accepted protocol 2;
- candidate protocol 3.

The corpus must contain direct, multi-route, counterexample-sensitive, and
failure/replanning-heavy problems. Pilot problems used while tuning rules are kept
separate from acceptance problems.

Primary metrics:

- verified `.tex` completion rate;
- first-verification acceptance rate;
- number of repeated failed methods without new evidence;
- proportion of stuck critical nodes receiving a counterexample probe;
- quality and specificity of obstruction identification;
- preservation of useful partial lemmas across replanning;
- repair count and unresolved-gap count;
- human rating of logical completeness and readability.

MTM-009 may claim only effects actually supported by the frozen results. A small
corpus may justify a bounded product decision but not a broad statistical claim.

## 11. Recording method

### 11.1 Run-time mathematical records

Records are append-only JSON objects in existing logical memory. Every normalized
record contains:

```text
schema_version
record_type
event_id            // server issued
run_id fingerprint  // public evidence only; full ID stays private
round_index
actor_role
actor_domain_id     // private vault only
event_seq           // server issued
created_at          // server issued
typed content
```

The public/debug evidence form replaces private IDs and text with hashes or bounded
redacted summaries.

### 11.2 Engineering iteration record

When approved, create `records/iterations/ITER-009.json` with seven phase receipts.
Each phase receipt contains:

- phase ID and status;
- baseline and resulting commit;
- exact files changed;
- authority before/after;
- graph delta;
- commands and exit codes;
- fixture/evidence hashes;
- discovered bugs and their classification;
- rollback action;
- remaining risks and manual checks.

Failed attempts are recorded rather than erased. A phase is not marked accepted until
its previously recorded failures are resolved or explicitly deferred outside scope.

### 11.3 Acceptance artifacts

Proposed artifacts:

```text
records/iterations/ITER-009.json
conformance/golden/mtm009-research-state.jsonl
mtm009-research-state-target.json
mtm009-research-state-math-evaluation.json
```

Evidence files contain implementation, harness, corpus, and result hashes. Raw OAuth
secrets, capabilities, private problem text, private proof text, and raw web
conversation transcripts are excluded.

### 11.4 Commit discipline

Each delivery uses one independently buildable commit group. Suggested subjects:

```text
docs(workflow): approve mathematical research state [MTM-009]
feat(workflow): add pure research graph projection [MTM-009]
feat(workflow): normalize append-only research records [MTM-009]
feat(workflow): add protocol-three research contracts [MTM-009]
feat(workflow): expose bounded research advisory context [MTM-009]
test(workflow): validate research-state boundaries [MTM-009]
feat(runtime): release mathematical research state [MTM-009]
```

No commit mixes unrelated cleanup, Native work, source-ingest work, or formatting-only
changes.

## 12. Seven-delivery implementation plan

### Delivery 1 — governance, baseline, and frozen contracts

**Goal:** approve the exact feature boundary before production code.

Tasks:

- [x] Accept ADR-0009 and this plan.
- [x] Add proposed MTM-009 to `migration-graph.json` with explicit non-goals.
- [x] Create `records/iterations/ITER-009.json` in `in_progress` state.
- [x] Record the clean Git/GitHub baseline and accepted release hash.
- [x] Freeze complexity budgets and graph invariants in validators.
- [x] Freeze protocol-1/2 current task outputs and workflow traces again.
- [x] Add protocol-3 record and task schema fixtures without runtime behavior.
- [x] Define rollback and stop rules.

Acceptance:

- [x] A0 passes.
- [x] Existing differential/golden hashes remain unchanged.
- [x] No production behavior changes.

Rollback: remove proposal scaffolding; MTM-008 remains authoritative.

### Delivery 2 — pure types and graph algorithms

**Goal:** implement a side-effect-free projector core with exhaustive unit/property
tests.

Tasks:

- [ ] Add named enums and record types.
- [ ] Add canonical ID wrappers and validation.
- [ ] Implement dependency construction and reverse adjacency.
- [ ] Implement cycle detection and deterministic topological order.
- [ ] Implement target reachability, critical blockers, and actionable frontier.
- [ ] Implement canonical serialization and digest.
- [ ] Add size/depth/count limits.
- [ ] Add positive, boundary, and malformed fixtures.

Acceptance:

- [ ] Projector core imports no authority or I/O layer.
- [ ] Same input is byte-deterministic across repeated runs.
- [ ] All graph-shape and size tests pass.
- [ ] A0 passes.

Rollback: delete the unused pure module; no state or contract change exists.

### Delivery 3 — server-normalized append-only research records

**Goal:** derive reliable research history from existing workflow submissions without
showing advice to the model yet.

Tasks:

- [ ] Extend plan normalization to issue canonical research node IDs.
- [ ] Normalize direct-screening attempts and statuses.
- [ ] Normalize branch and join outcomes into existing channels.
- [ ] Normalize failure synthesis and replanning decisions.
- [ ] Normalize retrieval novelty using registered reference IDs.
- [ ] Normalize verification findings for Repair context.
- [ ] Make record append and transition retry-safe.
- [ ] Run the projector in read-only shadow mode.

Acceptance:

- [ ] Existing protocol-2 outputs remain unchanged.
- [ ] Shadow projection has no side effects.
- [ ] Retry/crash/concurrency tests pass.
- [ ] Branch and verifier firewalls remain intact.
- [ ] A0–A3 applicable gates pass.

Rollback: ignore/remove shadow normalization; old memory remains valid JSONL.

### Delivery 4 — protocol-3 mathematical contracts

**Goal:** make graph and attempt information explicit for new runs while preserving old
runs.

Tasks:

- [ ] Add protocol 3 to validation and release facts.
- [ ] Add structured plan subgoals with local dependency keys.
- [ ] Add bounded method/obstruction/evidence fields to screening.
- [ ] Add bounded branch obstruction fields.
- [ ] Add structured failure and replan fields.
- [ ] Add typed exploration event schemas.
- [ ] Keep protocol-1/2 methodology rendering unchanged.
- [ ] Test accepted prior binary against copied protocol-3 state.

Acceptance:

- [ ] Public tool catalog unchanged.
- [ ] State schema unchanged.
- [ ] Protocol-1/2 fixtures unchanged.
- [ ] Protocol-3 valid/invalid/boundary fixtures pass.
- [ ] Copied-state rollback succeeds without finalization bypass.

Rollback: new binary may default back to protocol 2; protocol-3 state remains safely
readable as protocol-2-compatible history.

### Delivery 5 — advisory engine and compact model context

**Goal:** expose the useful mathematical picture without increasing protocol burden.

Tasks:

- [ ] Implement ordered `R01`–`R09` advisory rules.
- [ ] Implement bounded compact view and explicit truncation.
- [ ] Insert the view before mechanical task details.
- [ ] Keep full records available through existing reads/searches.
- [ ] Ensure advice is omitted from Verifier context.
- [ ] Include verifier findings only in Repair-appropriate form.
- [ ] Add task-envelope byte and deterministic-order tests.
- [ ] Add tests proving advice cannot affect transition/finalization.

Acceptance:

- [ ] Every advisory rule has positive and precedence fixtures.
- [ ] Compact view stays within fixed budget.
- [ ] Ignoring advice never invalidates an otherwise legal step.
- [ ] Information-firewall canaries remain absent.
- [ ] A0–A3 and envelope resource checks pass.

Rollback: disable protocol-3 view and continue protocol-2 task rendering.

### Delivery 6 — real web/workspace mathematical evaluation

**Goal:** establish whether the feature improves research behavior rather than merely
producing a cleaner architecture.

Tasks:

- [ ] Freeze pilot and acceptance corpora separately.
- [ ] Run paired protocol-2/protocol-3 experiments with the same web model.
- [ ] Permit normal web literature tools and MTM workspace/Bash use.
- [ ] Record normalized graph/advice sequence, not hidden reasoning.
- [ ] Independently assess final `.tex` correctness and readability.
- [ ] Analyze repeated failures, counterexample probes, obstruction quality, preserved
  lemmas, verifier acceptance, and repairs.
- [ ] Remove or simplify rules that show no benefit or cause distraction.
- [ ] Run maximum-history resource tests.

Acceptance:

- [ ] Verified `.tex` completion does not regress on the frozen acceptance corpus.
- [ ] At least one predeclared research-control metric improves.
- [ ] No advisory rule causes a material negative pattern without correction.
- [ ] A4 and A5 evidence is implementation/harness/corpus-hash bound.

Stop rule: if the feature adds protocol burden without measurable research benefit,
do not cut over; retain the pure analysis as diagnostic tooling or reject MTM-009.

### Delivery 7 — cutover, release, and final records

**Goal:** make protocol 3 the default for new runs only after every prior gate passes.

Tasks:

- [ ] Revalidate all earlier MTM target evidence affected by the shared release.
- [ ] Set the current workflow protocol fact to 3.
- [ ] Preserve stored protocol-1/2 run behavior.
- [ ] Build and hash the release candidate.
- [ ] Run full local, target, browser/workspace, LaTeX, verifier, repair, and finalizer
  paths.
- [ ] Drill default rollback to the accepted prior release/protocol behavior.
- [ ] Complete A5 resource comparison.
- [ ] Append final migration event and immutable receipt.
- [ ] Update architecture, acceptance, progress, and authority inventories with only
  claims supported by evidence.

Acceptance:

- [ ] All A0–A5 requirements pass.
- [ ] Mathematical effect gate passes.
- [ ] Final `.tex` publication path and hashes remain correct.
- [ ] Worktree is clean and release identity is exact.
- [ ] Remaining limitations are recorded honestly.

Rollback: reinstall the accepted prior release or set new-run protocol default back to
2; existing final artifacts and protocol-1/2 runs remain unchanged.

## 13. Stop and simplification rules

Stop or reduce scope when any of the following occurs:

- A new workflow state appears necessary only to represent a research tactic.
- A new service or worker is proposed for a pure projection problem.
- A graph library is added without measured need.
- The compact view is larger than the mechanical task contract it is meant to clarify.
- The model spends more effort maintaining records than solving mathematics.
- Similar-text node auto-merging is proposed without a sound identity rule.
- Advice begins to influence authority, verification, or finalization.
- Protocol-1/2 behavior cannot remain stable.
- Rollback cannot safely resume copied state.
- The paired mathematical evaluation shows no useful effect.

When a fixed limit or enum is insufficient, first record the failing real case. Do not
generalize the design preemptively.

## 14. Definition of done

MTM-009 is done only when all of the following are true:

- [ ] The mathematical graph, attempt ledger, and advisory rules are deterministic.
- [ ] All canonical identities are server issued and run/owner/domain scoped.
- [ ] Active dependency cycles and invalid references fail closed.
- [ ] Research history is append-only and retry-safe.
- [ ] The web model receives a bounded, useful obstruction-centered view.
- [ ] Advice remains explicitly advisory and can be ignored.
- [ ] No new crate, tool, workflow state, database version, worker, or model integration
  exists.
- [ ] Protocol-1/2 compatibility and copied-state rollback pass.
- [ ] Branch, verifier, capability, and finalizer boundaries are unchanged.
- [ ] The only final mathematical delivery remains the verified `.tex` file.
- [ ] The frozen real-use evaluation demonstrates non-regression and a declared
  research-control improvement.
- [ ] Complete records, hashes, rollback evidence, and remaining limitations are
  committed.
