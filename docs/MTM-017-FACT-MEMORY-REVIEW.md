# MTM-017 fact-memory closing review

## Scope and decision boundary

This source review covers fact promotion/revocation transaction boundaries,
bounded predecessor closure and content-addressed fact identity. It is a
development review with executable regressions, not an independent mathematical
review, a browser trial or exact-artifact release qualification. Final validation
identities and the development-completion receipt live in
`records/iterations/ITER-017.json`.

## Findings and corrections

### Revision dependencies polluted intermediate fact identities

`prepare_verified_facts` formerly added every `dependency_revision_ids` fact to
every manifest entry. It now adds those dependencies only to the final target;
intermediate entries retain their explicit predecessors. The previously recorded
red/green tests show the old extra edges and protect independent lemma IDs and
the revocation boundary. Single-entry and omitted-facts manifests retain their
dependencies; explicit dependencies remain sorted and deduplicated.

### Export could combine different database snapshots

The exporter formerly read nodes before taking the connection lock for its edge
query. A concurrent connection could commit new edges between those reads.
Nodes, revocation flags and edges now use one deferred SQLite read transaction.
Serialization happens after the transaction and lock have ended. A concurrent
96-commit/export regression checks exact edge/node agreement, and a reopened
read-only connection produces the same graph after the writer finishes.

### Invalid batches could be rejected too late

The per-entry predecessor bound did not bound the union with revision
dependencies. Distinct local keys could also resolve to the same content ID,
which the storage layer would reject only during promotion. The pure preparer
now rejects both conditions before proof submission can advance. Tests accept
64 merged predecessors, reject 65, preserve deduplication and reject duplicate
content even when its local names differ. Storage still independently validates
its batch; no validation or finalizer gate is removed.

## Transaction review

Fact rows, their edges, the target claim revision and matching finding status
events are inserted in the existing immediate promotion transaction. A late
claim-revision insertion fault is now injected after fact/status writes and
must roll everything back, including the previous active revision's lifecycle.

Revocation uses one immediate transaction for the recursive descendant set,
revocation rows and superseded finding events. An injected superseded-status
failure must preserve both the original graph and verified finding status.
Repeated revocation is idempotent. Active predecessor/project checks remain
inside fact insertion, so a predecessor revoked after preparation cannot be
accepted during a later promotion. These are SQLite transaction tests, not
physical power-loss or production-data migration evidence.

## Bounded graph review

The selector admits only complete predecessor closures whose union fits its
eight-node implementation budget (within the approved maximum of twelve).
It does not keep a partially traversed oversized closure. The DAG validator
requires all predecessors and orders them before their dependents. Findings
are trimmed independently; graph nodes and edges are not individually popped
to satisfy the findings budget.

Both a 16-fact chain and a dense shared-predecessor graph with 80 findings now
assert every persisted predecessor is present, exact edge-set agreement,
topological order, the 24 KiB combined task-view bound and a digest recomputed
from the emitted graph. Repeated task views must be byte-equivalent in unchanged
state. Advisory selection is not promotion or verification authority.

## Identity review

The existing canonical SHA-256-prefix algorithm and golden vectors are unchanged.
Preparation resolves local keys into sorted predecessor IDs before hashing.
Regression tests verify that local renaming and intuition changes do not change
fact IDs, whereas different projects, proof text and dependencies do. Run IDs,
timestamps and retrieval annotations are not introduced into the fact hash.
Existing rows and IDs are never rewritten by these corrections.

## Retained limitations and forward acceptance

BM25 still uses ASCII tokenization and a bounded recent candidate window; this
review makes no Chinese/Unicode retrieval-quality or complete-history recall
claim. Bounded task views and graph exports are summaries, not a standalone
proof archive. Independent cross-run mathematical trials must evaluate the
actual proof and dependency material rather than infer correctness from IDs or
scripted passing verifier reports.

Exact-artifact Native qualification, real web-client use, compiled LaTeX,
independent mathematics, authorized copied-operator-state migration/rollback
and resource/install/rollback qualification remain separate release work.
No installed selector, production database, workflow authority, public tool
count or historical evidence is changed by this review.
