# ADR 0002: typed pure policy core before stateful migration

- Status: accepted for MTM-002
- Date: 2026-09-01
- Source baseline: Re-CTM 0.3.0 at `50d08eb89e3ecc46317fd49709fa4ebcda135b5a`

## Context

The highest fan-in Python modules are error, debug/redaction, and enum contracts.
Schema, URL, path, command, and patch rules are also widely reused but are
side-effect-free. Migrating a database, process manager, network gateway, or workflow
engine before these facts are typed would create unstable cross-language boundaries.

## Decision

Create one `mtm-core` crate for pure, bounded policy and parsing behavior, with
`mtm-contracts` owning wire-visible error and enum facts. The implemented slice is:

- error payloads and stable enum wire values;
- the source JSON-schema subset;
- secret redaction and SHA-256 fingerprints;
- OAuth origin, redirect URI, TryCloudflare, and workspace-path validation;
- Native command permission ordering and inline-script recognition;
- patch-envelope parsing and deterministic hunk application.

The CLI `evaluate` and `evaluate-batch` commands are conformance adapters only. They
accept bounded JSON through standard input, execute no network, database, filesystem,
or child-process side effect, and are not a public Re-CTM request path.

Rust becomes the authoritative implementation of these pure facts inside
MTM-reboot after A0/A1/A2/A5 pass. Re-CTM's Python runtime remains the source-product
production authority until later milestones connect stateful components.

## Conformance decision

A frozen corpus sends the same 135 valid, invalid, historical, boundary, and
adversarial cases to the source Python implementation and the Rust shadow. Complete
result and error payloads must match exactly. The canonical Python response corpus is
bound by SHA-256:

```text
1aab731f737a00a9b40e614b7751e54d1418676febbb82cbc2e009dfc994430d
```

The source repository HEAD must equal the recorded source commit before the harness
runs, and every Python file imported by the reference evaluator must be clean relative
to that commit. Unrelated source-repository documentation work does not invalidate the
corpus, but a dirty reference runtime file blocks the gate. Unexplained differences
block completion.

## Dependency decision

The crate uses only purpose-specific, locked dependencies:

- `serde` and `serde_json` for typed deterministic JSON boundaries;
- `regex` for source-compatible bounded policy patterns;
- `sha2` for the existing fingerprint contract;
- `shell-words` for shell-token semantics without executing a shell;
- `url` for standards-based URL parsing.

`url` introduces Unicode/IDNA support through transitive ICU crates. This larger
dependency footprint is accepted because hand-written URL authority parsing is a
security risk. `Cargo.lock` is committed, no dependency performs runtime network
access, and later dependency changes require their own recorded review.

## Rejected alternatives

- Migrating stateful components first: rejected because it would combine contract
  discovery with authority and rollback risk.
- Copying Python regex/string logic without differential tests: rejected because
  superficially equivalent parsers already exposed an IPv6 representation mismatch.
- A fine-grained Python/Rust FFI call for every field: rejected because it would
  create a permanent high-frequency boundary before the runtime architecture exists.
- Claiming a speedup from Rust: rejected. A5 records resource non-regression only;
  A6 performance acceptance remains future work.

## Consequences

- `mtm-core` is a lower-level dependency and must remain free of storage, process,
  network, workflow, and finalizer authority.
- Future crates consume these typed rules instead of reimplementing them.
- Rollback is deletion or bypass of the Rust pure core; no state or protocol migration
  is required.
