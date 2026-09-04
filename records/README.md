# Repository record layout

`records/` is the only repository location for generated governance, milestone
evidence, iteration ledgers, and validation reports. JSON record files are not
stored in the repository root.

## Layout

```text
records/
├── governance/          # current authoritative project/governance state
├── iterations/          # append-oriented ITER-NNN milestone ledgers
├── evidence/
│   └── MTM-NNN/         # milestone-owned acceptance/release evidence
└── validation/          # reproducible aggregate/local validation reports
```

`conformance/` is intentionally separate. Files there are test inputs, golden
fixtures, corpora, and simulation inputs rather than project records.

## Record classes

### `governance/`

Mutable authoritative project state such as the migration graph, engineering
graph, source baseline, authority inventory, and project progress. These files
may change when the corresponding governance state changes; references use
repository-relative paths.

### `iterations/`

One ledger per milestone, named `ITER-NNN.json`. Accepted historical facts are
not silently rewritten. Later corrections or lifecycle decisions are appended or
recorded as explicit newer fields/events.

### `evidence/MTM-NNN/`

Machine-produced or accepted evidence owned by one milestone. The milestone ID
is carried by the directory, so filenames describe the evidence role without
repeating the `mtmNNN-` prefix, for example:

```text
records/evidence/MTM-013/runtime-hardening.json
records/evidence/MTM-013/stable-qualification.json
records/evidence/MTM-013/stable-release.json
```

Accepted evidence is immutable by content. A repository-layout migration may
move or rename it only byte-for-byte. `record-layout.json` binds relocated
accepted evidence to its SHA-256 so a cleanup cannot rewrite history.

### `validation/`

Regenerable aggregate reports. `local-validation.json` is rewritten by
`scripts/run_checks.py`; it is evidence of the latest local gate, not an
append-only historical ledger.

## Rules for new records

1. Do not add `*.json` to the repository root.
2. Decide whether the JSON is governance state, an iteration ledger, milestone
   evidence, validation output, or a conformance fixture before creating it.
3. Milestone evidence goes under `records/evidence/MTM-NNN/` and uses a
   role-oriented filename such as `target-validation.json` or `stable-release.json`.
4. Code and documentation store repository-relative canonical paths, not bare
   historical root filenames.
5. Accepted evidence is never reformatted or edited just to update a path. If an
   old payload records its historical filename, keep the bytes and resolve the
   move through `record-layout.json`.
6. No OAuth token, capability, private proof text, generated secret, or other
   sensitive runtime material may be written to repository records.
7. Run `python3 scripts/validate_record_layout.py` and
   `python3 scripts/run_checks.py` after changing record structure.

Hash-bound historical measurement harnesses may still contain their original
root output filename because changing that source line would invalidate the
already accepted harness SHA. They are not normal record writers. Current
validators read accepted evidence from the canonical `records/` tree, and
historical locators embedded in sealed payloads are resolved through
`records/governance/record-layout.json`. Re-running such a historical harness
requires its documented report-path override or a new, separately qualified
harness; a root output produced by direct legacy invocation will be rejected by
the record-layout gate.

## Legacy relocation

The September 2026 layout cleanup moved the former root JSON records into this
hierarchy. `records/governance/record-layout.json` is the machine-readable
legacy-to-canonical mapping. Historical evidence payloads themselves were kept
byte-identical; only their repository location and external references changed.
