# ADR-0009: Mathematical research state as a derived advisory layer

## Status

Accepted for `MTM-009` on 2026-09-01. Production behavior remains unchanged until
the later implementation deliveries pass their own acceptance gates.

## Context

MTM already provides the strongest parts of the current system boundary:

- one workflow transition authority;
- role- and branch-scoped private memory;
- server-issued plan, subgoal, branch, and capability identifiers;
- direct screening, branch barriers, join, failure synthesis, replanning, repair,
  verification, and mechanical finalization;
- a verified final LaTeX artifact as the only mathematical delivery target.

The remaining material difference from Rethlas is not the availability of web search,
paper discovery, Bash, CAS, or document inspection. In the deployed web-driven use
case, the model can combine its own research tools with MTM's workspace tools. Nor is
the primary problem verifier cognitive isolation: MTM controls data and authority, but
does not control the internal conversation lifecycle of the external web model.

The important gap is research control. Rethlas continuously organizes work around the
mathematical obstruction currently blocking the target. MTM currently organizes work
primarily around workflow states and submission contracts. The methodology asks the
model to explore examples, counterexamples, plans, failures, and repairs, but the
server does not yet assemble these facts into a compact mathematical picture that
answers:

1. Which proof-critical claim is currently blocking the target?
2. Which methods have already failed on it?
3. Has a counterexample probe been attempted?
4. Has retrieval produced genuinely new material?
5. Which partial lemmas should be preserved during replanning?
6. What is the cheapest useful next research action?

Adding more workflow states would encode research tactics as authority transitions,
multiply the state space, and make the system larger without making it better at
mathematics.

## Decision

MTM-009 will add a small, deterministic, read-only **Mathematical Research State**
layer inside `mtm-workflow`.

The layer will:

- derive a claim/dependency/obstruction graph from existing server-normalized plans,
  screenings, branch results, failure summaries, decisions, retrieval events, and
  verification findings;
- retain an append-only attempt ledger linked to server-issued mathematical node IDs;
- classify obstructions using a closed enum;
- compute a bounded research frontier and one advisory next-action hint;
- render a compact model-facing research context before the mechanical task contract;
- never authorize a transition, declare a proof correct, or publish an artifact.

The layer will not:

- call Codex or any model API;
- run an Agent process, scheduler, daemon, or background worker;
- add a model-provider abstraction;
- add a new public tool or hidden alias;
- add a new workflow state;
- add a new crate;
- add a new database schema version;
- create a parallel mutable graph database;
- store raw web-conversation transcripts or private chain-of-thought;
- replace the existing verifier, LaTeX gate, finalization permit, or finalizer;
- produce any final deliverable other than the existing verified `.tex` artifact.

## Protocol boundary

The new model-facing behavior will be identified as workflow protocol 3.

- Persisted protocol-1 and protocol-2 runs keep their original contracts.
- Protocol 3 remains state-compatible with protocol 2: it adds structured research
  records and derived context, not new workflow states or new finalization semantics.
- An accepted rollback binary may ignore protocol-3 advisory records and continue the
  run using protocol-2 behavior. This fallback must be tested on copied state before
  cutover.
- The public tool catalog remains exactly 24 public tools and 11 hidden aliases.

## Graph model

Three graphs remain intentionally distinct.

### Authority graph

The runtime authority graph remains a directed acyclic graph. The new projector is a
pure read-only child of workflow authority:

```text
workflow authority
    ├── state store
    ├── private vault
    ├── verifier/finalizer gates
    └── research-state projector ──► advisory task context
```

There is no edge from the projector back to transition, capability, verification, or
finalization authority.

### Workflow graph

The existing workflow graph remains unchanged. In particular, no states such as
`search`, `deep_think`, `counterexample`, `obstruction`, or `research_ready` are added.

### Mathematical graph

For a run, let

\[
G_M=(V_M,E_D),
\]

where vertices are target/subgoal claims and `u -> v` means that proving `v` depends
on `u`. Active proof dependencies must be acyclic. Attempts, evidence, and decisions
are append-only records attached to vertices rather than additional workflow states.

The projector computes:

- the actionable frontier: unresolved nodes whose declared dependencies are solved;
- critical blockers: unresolved nodes that lie on a dependency path to the target;
- refuted or circular routes that require replanning;
- method coverage for each blocker;
- retrieval novelty from newly registered reference IDs;
- a deterministic advisory action selected by a small ordered rule table.

No centrality metric or heuristic score may become an authority decision. Ties use
stable server-issued IDs and deterministic ordering.

## Record ownership

The model proposes mathematical content. The server owns identity, normalization,
timestamps, ordering, and status derivation.

Existing logical channels are reused:

| Existing channel | Protocol-3 normalized records |
|---|---|
| `subgoals` | claim declarations, dependency edges, status events |
| `proof_steps` | direct and synthesis attempts |
| `counterexamples` | counterexample probes and witnesses |
| `failed_paths` | classified obstructions and excluded routes |
| `big_decisions` | replanning decisions and preserved lemmas |
| `branch_states` | branch-derived node and route outcomes |
| `events` | retrieval novelty and general research events |
| `verification_reports` | proof-repair obstructions derived from verifier findings |

No new SQLite table or vault channel is required for the first accepted version.

## Advisory policy

The next-action engine is transparent and ordered. The initial rule family is:

1. A refuted critical node or dependency cycle suggests replanning.
2. Repeated direct failure without a counterexample probe suggests falsification on
   the smallest meaningful examples.
3. A classified missing-reference obstruction without a retrieval attempt suggests
   focused retrieval.
4. Repeated retrieval with no new registered references suggests stopping retrieval
   and synthesizing existing material.
5. An actionable untouched critical node suggests direct screening, supported by a
   toy example when appropriate.
6. Several compatible partial attempts suggest consolidation into one lemma.
7. All proof-critical nodes solved suggests assembly.

The task explicitly labels the result `advisory`. The model may choose a different
action and record why. The server does not block a legal submission merely because it
does not follow the hint.

## Context budget

The model-facing view is a bounded quotient of the full research record. It contains:

- exact target;
- current critical blocker;
- a small ordered frontier;
- recent relevant attempts and obstruction classes;
- counterexample and retrieval coverage;
- preserved partial results;
- one suggested next action and its rule identifier;
- a graph digest and counts.

Full records remain available through the existing role-authorized memory reads and
searches. The compact view has fixed limits for node count, record count, and text
length. Truncation is explicit and deterministic.

## Consequences

Positive consequences:

- research attention is centered on the mathematical problem rather than the protocol;
- failed paths become reusable constraints instead of narrative history;
- counterexample testing and retrieval discipline become visible and testable;
- the model receives less bookkeeping and more mathematically relevant context;
- MTM retains its web-driven, provider-neutral architecture;
- final verification and `.tex` publication remain unchanged.

Costs and risks:

- protocol-3 contracts and backward-compatibility fixtures must be maintained;
- graph identity and append-only status events require careful normalization;
- advisory rules can be unhelpful even when deterministic;
- poorly bounded context could increase task size;
- over-structured records could burden the model rather than help it.

These risks are controlled by a seven-slice implementation, shadow projection before
exposure, strict size budgets, real web-driven mathematical evaluation, and stop rules
that reject complexity without measured research benefit.

## Acceptance summary

MTM-009 is complete only when:

- protocol 1 and 2 retain their accepted behavior;
- the crate, authority, and workflow graphs retain their current topology;
- malformed, cyclic, stale, cross-branch, and oversized research records fail closed;
- the projector is deterministic and side-effect-free;
- the compact view is bounded and contains no private verifier or cross-branch data;
- advisory hints cannot cause transitions or finalization;
- copied-state rollback to the accepted prior release is demonstrated;
- a frozen web-driven mathematics corpus shows non-regression in verified `.tex`
  completion and improvement in at least one declared research-control metric;
- the full local, target, browser/workspace, LaTeX, verification, and finalization
  gates pass.

The detailed implementation and test plan is
[`../MTM-009-MATHEMATICAL-RESEARCH-STATE-PLAN.md`](../MTM-009-MATHEMATICAL-RESEARCH-STATE-PLAN.md).
