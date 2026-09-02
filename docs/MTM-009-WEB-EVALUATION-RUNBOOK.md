# MTM-009 real web evaluation runbook

This runbook executes Delivery 6 only. It does not authorize Delivery 7 or change the
production workflow-protocol default.

## 1. Preconditions

- The web model must be connected to the current MTM-009 evaluation binary, not the
  accepted MTM-008/0.3.0 production binary.
- Within one case pair, Protocol 2 and Protocol 3 use the same web-model surface,
  connector profile, research-tool availability, and user-visible problem statement.
- Normal web research and MTM workspace/Bash/CAS are allowed when useful.
- Do not expose `research_control_focus`, capability tags, difficulty labels, or
  evaluator checks to the solving conversation.
- Do not record raw web transcripts or private reasoning.

Verify the engineering evidence before starting:

```bash
python3 scripts/validate_mtm009_research_resource.py
python3 scripts/validate_mtm009_math_corpus.py
python3 scripts/validate_mtm009_math_evaluation.py
```

## 2. Get exactly one treatment

```bash
python3 scripts/next_mtm009_web_treatment.py
```

The command emits only `case_id`, `protocol`, and `problem_tex` plus non-mathematical
execution facts. Run that problem in a fresh treatment conversation with the printed
protocol. Do not inspect the corresponding evaluator fields while solving.

## 3. Complete the MTM workflow normally

Use the ordinary connector workflow. Web search, literature search, Bash, downloaded
papers, CAS, and workspace files remain available. The run is successful only if the
existing mechanical path reaches `proof_verified.tex`; MTM-009 adds no alternate final
artifact.

After the run, obtain and hash the final `.tex` when present, transition log, and
verification report. Record only a hashed run fingerprint and the predeclared metric
counts. Do not copy conversation text into the evaluation file.

Record the treatment with:

```text
python3 scripts/record_mtm009_web_run.py ...
```

The recorder refuses to overwrite a treatment slot, rejects treatment-pair model or
connector drift, computes the `.tex` hash itself, and hardcodes transcript/private
reasoning retention to false.

Repeat `next_mtm009_web_treatment.py` until all sixteen treatments are recorded.

## 4. Blind-score each completed pair

For each case, prepare treatment-free A/B files:

```text
python3 scripts/prepare_mtm009_blind_bundle.py \
  --case-id <case> \
  --protocol2-tex <p2-proof.tex> \
  --protocol3-tex <p3-proof.tex> \
  --output-dir <blind-dir> \
  --mapping-path <owner-only-map.json>
```

The bundle contains only `A.tex`, `B.tex`, and treatment-free hashes. The separate
mapping file is created mode 0600 and remains hidden until scores are frozen.

The evaluator scores logic completeness, readability, and research efficiency from 1
to 5 and gives a concise rationale. Then record the still-blind score with:

```text
python3 scripts/record_mtm009_blind_score.py ...
```

## 5. Finalize only after 8/8 pairs

When all sixteen treatments and eight blind scores exist:

```bash
python3 scripts/finalize_mtm009_math_evaluation.py
python3 scripts/validate_mtm009_math_evaluation.py
python3 scripts/validate_mtm009_release_gate.py
```

The finalizer recomputes aggregates. It cannot aggregate partial evidence. Delivery 7
is blocked unless Protocol 3 does not regress verified `.tex` completion, improves at
least one predeclared primary research-control metric, has no systematic harmful
advice, and the A5 resource gate remains valid.

## 6. Stop rules

Stop rather than widen the system if the paired evidence shows no useful research
control improvement, if advice repeatedly pushes the model toward worse actions, if
the compact context becomes a bookkeeping burden, or if a proposed repair requires a
new workflow state, model runtime, public tool, database version, or final artifact.
