# MTM-017: Dangerous-only Native and Danus-style fact memory

Design attribution: Danus (Apache-2.0) informed the fact-memory data model and
content-addressed ID scheme. No Danus source code is copied into MTM.

Approved by the operator in the project conversation on 2026-09-25.
Branch: `work/mtm017-dangerous-fact-memory`. Record: `records/iterations/ITER-017.json`.

## Stage A amendment (operator decision)

The operator additionally approved retiring the consent/grant ledger, since
`dangerous` implicitly grants every permission kind and no path could reach it:
`NativePermissionGrantAuthority`, `NativePermissionConsentAuthority`, the
`request_permissions` form elicitation, and the F2 `qualify --profile permissions`
harness are removed. Risk classification, executable fact revalidation, protected
patch-path facts and Bubblewrap isolation remain; an incomplete profile fails
closed (`NATIVE_PERMISSION_PROFILE_INCOMPLETE`). Fixed adapters (LaTeX) now request
an explicitly isolated network namespace instead of inheriting it from `safe`.
Sealed MTM-016 native-command and permission receipts continue to validate; U20
reports failed until a dangerous-only corpus revision is approved.

## Context

Two requests from the operator:

1. **`dangerous` is the only Native mode we need.** `NativeMode` (`crates/mtm-contracts/src/enums.rs:5`) still carries `Safe` and `Trusted`, which cost ~66 branch sites across 14 files plus their tests, and the default is still `safe` (`crates/mtm-runtime/src/config.rs:58`).
2. **`rethlas_step` needs long memory.** Today memory is split and lossy:
   - per-run MTM-009 graph (`crates/mtm-workflow/src/research_state.rs`) — capped (256 nodes), rebuilt every step, discarded between runs, model sees ≤5 frontier/≤5 attempts (`research_state/view.rs:10-19`);
   - cross-run `claims`/`claim_revisions`/`claim_edges` (`crates/mtm-storage/src/schema.rs:188-227`) — only whole promoted results; lemmas and dead ends are lost.

   Danus (github.com/frenzymath/Danus, Apache-2.0, successor of Rethlas; spec `danus/core/DATA_MODEL.md`) solves this with three tiers: private *local memory* → project-shared typed *global memory* (claim + evidence, incl. dead ends) → verifier-gated, content-addressed *fact graph* DAG (the only thing proofs may cite).

**Operator decisions (fixed):** remove Safe/Trusted, with the Stage A amendment above retiring their unreachable consent/grant ledger while keeping Bubblewrap; keep tool name `rethlas_step`; all memory reaches the model through `rethlas_step` (public tool count stays 24); facts come only from the **final verified proof**; **SQLite** is the source of truth, with a deterministic **JSON graph** as the model view and export format; track as new milestone **MTM-017**.

**Mapping:** MTM vault/per-run research state = Danus local memory (kept); new `memory_findings` = global memory; new `facts`/`fact_edges` = fact graph.

---

## Phase A — Dangerous-only Native (own commit)

Keep `NativeMode` as a one-variant enum (`Dangerous`) so the wire value `"native_mode":"dangerous"` in reports/receipts is unchanged.

- `crates/mtm-contracts/src/enums.rs` — delete `Safe`, `Trusted`.
- `crates/mtm-runtime/src/config.rs:54-59,396-405` — default becomes `dangerous`; `parse_native_mode` rejects `safe`/`trusted` with an explicit "removed in MTM-017; only `dangerous` is supported" validation error (no silent mapping).
- `crates/mtm-cli/src/main.rs:161-173` — same rejection for `--native-mode`.
- Collapse branches to the dangerous path:
  - `crates/mtm-core/src/native_permission.rs:162` `native_mode_implicitly_grants` → always the dangerous profile;
  - `crates/mtm-core/src/command_policy.rs:42,73,115,130`;
  - `crates/mtm-native/src/bubblewrap.rs:230` (network namespace always `Shared`; delete `Isolated` if unreachable);
  - `crates/mtm-native/src/toolchain.rs:121` (auto-discovery always on);
  - `crates/mtm-runtime/src/native_tools.rs:135,206-232,423`;
  - `crates/mtm-runtime/src/tool_backend.rs:238-251` (keep report keys, constant values).
- Tests: delete Safe/Trusted-only cases; tests that used `Safe` merely as a fixture (e.g. `native_authority.rs` `bubblewrap_candidate_fixture(NativeMode::Safe)`, `native_tools.rs` tests, `crates/mtm-cli/tests/support/{native_command_runtime,native_corpus,permission_runtime}.rs`) switch to `Dangerous` and have their assertions re-checked, not just re-labelled.
- Keep: the `disabled` exec backend (it means "no bwrap"; a separate concept), all Bubblewrap isolation, `dangerous` never granting workflow/project authority.
- The approved Stage A amendment retires the unreachable consent/grant ledger and scripted F2 profile; executable revalidation, protected patch facts, risk classification, and Bubblewrap remain enforced.
- Docs: README/AGENTS/current docs are updated; historical `records/evidence/**` is never edited.

## Phase B — Fact graph in SQLite (schema 7 → 8)

**Pure logic** — new module `crates/mtm-workflow/src/memory/` (no new crate; `BTreeMap`-only graph, as MTM-009 §3.3):
- `fact.rs`:
  - `normalize(text)` = collapse whitespace + trim, matching Danus `schema._normalize`;
  - `compute_fact_id` = first 16 hex of SHA-256 over canonical JSON `{problem_id: project_id, predecessors: sorted, glossary_introduces: sorted, statement, proof}` — the Danus scheme, so the same content gets the same id. `external_refs` is excluded.
- `graph.rs`: DAG validation (acyclic, predecessors exist and are not revoked), `descendants`, deterministic topological order, and the JSON-graph struct (JSON Graph Format–style `{graph:{id, nodes:{fact_id:{label, metadata}}, edges:[{source, target, relation:"depends_on"}]}}`, sorted keys).

**Storage** — `crates/mtm-storage/src/schema.rs` + `store.rs`:
- `STATE_SCHEMA_VERSION` 7 → 8 (`crates/mtm-contracts/src/lib.rs:24`);
- `migrate_7_to_8` modelled on `migrate_6_to_7` (`store.rs:328`), additive only:
  - `facts(fact_id PK, project_id, source_run_id, statement_tex, proof_tex, intuition, glossary_json, external_refs_json, created_at)` — immutable;
  - `fact_edges(fact_id, predecessor_id, PK(both))`;
  - `fact_revocations(fact_id, reason, actor, created_at)` — append-only; revoked = has a row;
  - nullable `claim_revisions.fact_id`.
- No backfill of old revisions: they have no proof text, consistent with the project's no-backfill rule.

**Where facts come from** — the final proof only:
- `proof_manifest` gains an **optional** `facts` array (`crates/mtm-workflow/src/methodology.rs:525-548` schema + `engine.rs:1967` normalizer). Each entry: `{key, statement_tex, proof_tex, predecessors: [key | existing fact_id], glossary_introduces, intuition?}`, and the last entry is the target.
- If `facts` is omitted, the target statement plus the verified proof become one fact.
- The verifier's task context already receives the manifest, so the lemma breakdown is verified together with the proof. The verifier gets no global memory (Danus: cold-start verifier).

**Promotion:**
- Inside the existing promotion transaction in `store.rs` (~1440-1500), insert facts and edges (`INSERT OR IGNORE`, since ids are content-addressed) and set `claim_revisions.fact_id` — all in one commit.
- Stop writing `claim_edges` `depends_on` there (replaced by `fact_edges`); keep `supersedes`; historical rows stay.
- `dependency_revision_ids` keeps working; those revisions' `fact_id`s become predecessors of the target fact only (the last entry, or the synthesized fact when `facts` is omitted). Intermediate facts use only their explicit `predecessors`, so unrelated whole-proof dependencies do not change independent lemma IDs or cause their cascading revocation.

**Operator CLI** (not a model tool, so revocation authority stays with the operator):
- `mtm fact-graph export --project <id> [--out <file>]` — byte-deterministic JSON graph;
- `mtm fact-graph revoke <fact_id> --reason <text>` — cascade revocation, one transaction.

## Phase C — Global memory findings

- Schema-8 tables:
  - `memory_findings(finding_id PK, project_id, run_id, kind, claim, evidence, verifiable, links_json, created_at)`;
  - `memory_finding_status(finding_id, seq, status, fact_id, created_at)` — append-only.
- Kinds: Danus's worker kinds `conclusion | example | counterexample | proof_attempt | plan | dead_end | direction | obstacle`.
- **No new submission fields.** Findings are a deterministic projection of the already-normalized research state (`normalize_legacy_research`, `engine.rs:507`):
  - failed attempts → `dead_end`
  - obstructions → `obstacle`
  - counterexample attempts → `counterexample`
  - plans → `plan`
  - partial / route-solved nodes → `conclusion` / `proof_attempt`
- Exact enum mapping is fixed in code with tests.
- Written **after** each committed transition: read the vault first, then one short `INSERT OR IGNORE` transaction. Ids are content-addressed, so re-running is idempotent and crash-safe without a new journal. This follows the AGENTS.md rule: no file I/O under a SQLite transaction.
- On promotion, the run's findings that became facts get a `verified` status event carrying the `fact_id`.

## Phase D — `rethlas_step` task view

Extend `protocol_three_research_task_view` (`engine.rs:510`, inserted at `engine.rs:1534`) with a `project_memory` block:

```json
"project_memory": {
  "advisory_only": true,
  "fact_graph": {
    "nodes": [{"fact_id": "…", "statement": "…"}],
    "edges": [["from", "to"]],
    "truncated": false
  },
  "prior_dead_ends": [],
  "prior_counterexamples": [],
  "obstacles": [],
  "graph_digest": "sha256:…"
}
```

- Selection: a pure-Rust BM25 (`memory/bm25.rs`, ~80 lines, as Danus `bm25.py`) scores against the target plus the current blocker; take the top facts plus a bounded predecessor closure, and the top findings.
- Hard constants with tests: facts ≤ 12, findings ≤ 5 per kind; total budget raised from 16 KB to **24 KB** (constant, tested).
- Existing role firewall preserved: the verifier sees only dependency facts (`engine.rs:1386` logic, rewritten to use fact ids).
- Facts may be cited in `dependency_revision_ids` via their revision, or via the new manifest `predecessors`.

## Contracts & governance

- `TOOL_CONTRACT_VERSION` `mtm-tools-v9` → `mtm-tools-v10` (`crates/mtm-gateway/src/catalog/mod.rs:12`, test at `catalog/tests.rs:9`): proof_manifest and task-view change.
- Tool count stays 24; workflow protocol stays 3 (additive, optional field).
- New files:
  - `docs/MTM-017-DANGEROUS-ONLY-AND-FACT-MEMORY.md`;
  - `records/iterations/ITER-017.json` (same shape as ITER-016);
  - a migration event in `records/governance/migration-graph.json`;
  - an AGENTS.md MTM-017 section;
  - a design attribution in this plan; the frozen repository NOTICE remains unchanged.
- Commits, each validated by `cargo xtask commit-message`, in format `type(scope): summary [MTM-017]`:
  1. `feat(native)` Phase A
  2. `feat(storage)` schema 8 + fact graph
  3. `feat(workflow)` findings + view
  4. `feat(cli)` export/revoke
  5. `docs(records)` governance
- No production deployment, no installed-selector change, no edits to sealed evidence.

## Verification

- `cargo test --workspace`, plus new tests:
  - `compute_fact_id` golden vectors generated by running Danus's own `compute_fact_id` (Python, from the `/tmp/danus-src` clone) on fixtures, so ids match Danus exactly;
  - graph checks: cycle rejection, revoked-predecessor refusal, cascade revoke, deterministic topological order;
  - target-only revision dependencies: independent lemma IDs remain stable across different external dependencies; explicit lemma dependencies remain intact; target dependencies are sorted/deduplicated; single-fact and omitted-facts manifests retain their dependencies;
  - a verified three-fact workflow with a non-empty `dependency_revision_ids` checks persisted edges, the promoted revision, cross-run memory and revocation of only the external fact and target, leaving independent lemmas active;
  - migration: a schema-7 fixture DB goes 7 → 8, and newer or unknown versions still refuse to open;
  - promotion atomicity with fault injection, reusing the existing recovery-test pattern (`crates/mtm-storage/tests/recovery.rs`);
  - finding-projection idempotence (run twice, same rows);
  - task view byte budget and truncation;
  - `fact-graph export` byte-identical across two runs;
  - `--native-mode safe` and `MTM_NATIVE_MODE=trusted` are rejected.
- `cargo xtask check --record`, `cargo xtask records`, `cargo xtask capability --record`.
- End-to-end: the scripted workflow fixture drives a run to Done with a 3-fact manifest; then check the rows in `facts`/`fact_edges`, that a second run's task view shows them in `project_memory`, and that export produces the expected JSON graph.
- **Host boundary:** the Linux development host runs the inherited Bubblewrap tests and positive Native preflight. A fresh exact-artifact Native qualification, real web client, independent mathematics, compiled LaTeX, copied operator state, and release checks remain separate forward acceptance.

## Development result

Stages A-D are implemented on the MTM-017 branch. The earlier checkpoint's
final-source A0 was blocked in the managed sandbox; validation of the later
target-dependency correction is recorded below. Schema 8 and `mtm-tools-v10`
are development identities only. Verified final proofs promote fact batches and
claim revisions in one transaction; a schema-7 verified revision without a fact
ID is explicitly refused as a new fact dependency. Project findings are advisory
until exact final-proof promotion marks matching eligible findings verified;
cascading fact revocation appends superseded finding status in the same
transaction. The deterministic JSON graph, CLI export/revoke, and bounded
`rethlas_step` view are covered by local tests. The installed selector, frozen
MTM-016 candidate, production databases, and sealed evidence are unchanged. The
managed continuation sandbox prevented loopback test-server startup and blocked
the Bubblewrap probe, so that checkpoint's full source gate remained nonzero;
its failures are not relabelled as passes.

### Target-dependency correction scope

The target-only dependency correction restores the approved promotion semantics;
it does not change schema 8, the fact-ID hash algorithm, verification authority,
the public tool contract, or existing persisted facts. Previously created fact
IDs and edges are not rewritten. Rollback of this correction is limited to its
workflow implementation, regression tests and documentation changes; any test
state is disposable, and production state and installed selectors are untouched.

Validation of the correction is bound to Rust source SHA-256
`64f31e652898d4a9c06da7cec624d102860bd9156e326fdb7cc1622a99f1c846`
under the existing `mtm-rust-source-v1` scope. Before the implementation fix, two
new unit regressions and the new workflow integration regression failed; the
integration fixture persisted five edges instead of the expected three. After
the fix, `cargo test -p mtm-storage -p mtm-workflow --locked --offline` passed
194 tests with zero failures or ignored tests. `cargo xtask check` then exited
0, with matching before/after source hashes, passing format, warnings-denied
all-target Clippy, workspace tests, record/architecture/retirement validation,
diff checks and a positive Bubblewrap preflight. The workspace retained its
existing target-only DNS/HTTPS ignored test; no new test was ignored. These are
development source checks, not exact-artifact release qualification. Earlier
failed evidence and aggregate reports remain unchanged.

### Closing source review and packaging

The closing review is `docs/MTM-017-FACT-MEMORY-REVIEW.md`. It additionally fixes
mixed-snapshot graph export and rejects merged-predecessor overflow and duplicate
content-addressed entries before proof submission. Late promotion/revocation
fault injection, concurrent export and predecessor-closure/digest checks cover
the reviewed boundaries. The storage/workflow regression command now passes
199 tests, with no failures or ignored tests.

The source implementation is separated into four independently build-checked
commits, each validated by the Rust commit-message hook:

| Commit | Scope | Additional stage tests |
|---|---|---|
| `7858056` | Dangerous-only Native | Contracts/core/native/runtime library suites |
| `0462985` | Schema-8 fact storage | Complete storage suite |
| `8acae5d` | Verified facts and bounded project memory | Complete workflow/gateway suites |
| `2cb4923` | Operator fact-graph CLI | Fact-graph and identity CLI tests; all-target Clippy |

Each staged source tree was checked with `cargo check --workspace --all-targets
--locked --offline` before committing. Unstaged stages were temporarily retained
in Git stashes, restored and byte-checked against their full snapshots; only
these temporary stashes were dropped. All builds used this checkout's existing
`target/mtm-tool` cache, never the operator's default build directories.

The frozen closing Rust source SHA-256 is
`61922484c1f969365660b052ab878250738542bf25bd870f40b3b6851ef1930d`.
The fifth commit seals the review, current-source reports and development
receipt. It does not select a release artifact or upgrade production state.

### Release handoff remains separate

Development closure does not authorize any of the following operations or
reinterpret an old MTM-016 receipt as current evidence. A release owner must
first freeze an explicit artifact built from the reviewed source and bind every
new qualification report to its exact hash. The remaining gates are:

| Gate | Required forward evidence |
|---|---|
| Native and corpus | Exact-artifact dangerous-only isolation/command/TTY/process-lifecycle qualification and the current corpus; a positive preflight alone is insufficient. |
| Research and clients | Real web-client workflow trials, independent mathematical review and required compiled-LaTeX full/compact/repair flows. Scripted verifier fixtures are not independent review. |
| Existing operator state | Explicitly authorized copies for schema-7 to schema-8 migration, old-run resume and exact pre-upgrade restoration. Never test against the live original. |
| Resources and distribution | Artifact-bound resource comparison, installation and rollback/recovery qualification followed by a separate release decision. |

Keep the original schema-7 state copy and the installed release unchanged until
that separate decision. Existing schema-8 fact IDs, edges and immutable proof
artifacts are not backfilled or rewritten merely to roll back this source work.

### Development closeout

MTM-017 development A0/A1/A3 is complete under receipt `MREC-017`. The closing
source gate passed 628 tests, with zero failures and one inherited target-only
ignore. The separate current-source capability runner completed successfully:
500 independent assessments (250 compact and 250 full), zero normal INVALID
or rejected submissions, all eight adversarial checks and restart/shutdown
checks passed. The source remained the frozen closing identity above.

The final records-only commit seals the current reports and preserves the earlier
failed sandbox evidence. No release artifact was selected, production data
upgraded, live session restarted or remote branch pushed. The release handoff
is `docs/MTM-017-RELEASE-HANDOFF.md`; MTM-016's separate status is unchanged.
