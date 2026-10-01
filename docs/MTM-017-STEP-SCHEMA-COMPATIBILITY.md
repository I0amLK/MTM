# MTM-017: step schema connector compatibility repair

## Scope and evidence

The operator requested this source repair through CTM on 2026-09-30 after the
freshly installed `afa207e` candidate reproduced a connector-side
`oneOf: Value matches multiple schemas` rejection for a complete `rethlas_step`
submission. Run-only task fetch succeeded. The rejected call did not advance the
observed assessment task. This development patch does not authorize installation,
restart, publication, production-state access or a repeated live submission.

The source catalog already closed both alternatives with
`additionalProperties: false`. Its run-only and submission branches are disjoint
under standard JSON Schema. The effective connector schema and its transformation
are not observable here; the exact external cause remains unknown. Framework
`_meta` appearing beside submission fields is not proof of that cause: adding it
to the original tool arguments makes both strict branches fail, rather than both
succeed. MTM reads MCP metadata from `params._meta`, separate from tool arguments.

## Design

Retain one closed top-level object and all six existing fields. `run_id` remains
the sole unconditionally required field. JSON Schema `dependentRequired` makes
`capability` and `action` require each other, and makes each of `payload`, `writes`
and `recover_only` require both. Dependencies are triggered by field presence,
including explicit false, empty objects/arrays and null; ordinary field types
still reject null. No defaults are inserted and input values are never changed.
The `recover_only` default annotation is removed from the public schema so a
client that materializes schema defaults cannot turn a run-only fetch into a
partial submission. The runtime still treats omitted `recover_only` as false;
this default is described in prose instead.

This accepts exactly the previous two request forms:

- `run_id` alone requests the current task
- a submission requires `run_id`, `capability` and `action`, with the same optional
  `payload`, ordered `writes` and `recover_only`

Replacing `oneOf` with `anyOf` while retaining branch-specific property maps was
rejected: a hypothetical pruning client could choose the run-only alternative and
discard a submission's fields. The single-object representation avoids that
particular risk. The core validator implements the standard presence-dependency
keyword; the catalog remains the sole gateway validation schema. Unknown fields,
partial submissions, malformed types and malformed write entries still fail
before backend dispatch. Capability, ownership, receipt, action, ACL, verifier and
finalizer checks are unchanged. No connector policy or security check is disabled.

The public tool count (24), field names, runtime defaults, valid request language, state
schema (8), workflow protocol (3) and tool contract (`mtm-tools-v10`) are unchanged.
The catalog fingerprint changes. Validation retains `INVALID_ARGUMENT` and RPC
`-32602`; dependency-specific messages now identify missing fields instead of the
former generic oneOf message. This is an equivalent schema representation repair,
not a waiver, new authority grant or promotion of old qualification evidence.

## Verification and remaining acceptance

Regressions compare all 32 submission-field subsets with the previous strict
schema, mutate each field through malformed types, and reject unknown root/write
fields. Core tests exercise cyclic dependencies without recursion and explicit
null presence. Hypothetical branch relaxation and argument pruning are labeled as
diagnostics, not the live connector's proven implementation. Real in-process MCP
HTTP tests verify exact argument preservation through both legacy and modern
dispatch, metadata separation, and no backend call for partial/unknown inputs.
These local tests do not establish external connector acceptance.

The 2026-09-30 CTM source run passed `cargo xtask check`: format, all-target
workspace Clippy, 716 tests, one inherited ignored test, record/architecture/
retirement validation and diff checks. The current-binary 500-assessment
capability regression passed inside that suite. The before/after
`mtm-rust-source-v1` identity was
`042f654c0ed3df24761d3124b386cbc56b810b52bd8f03d9f90f1f30c0837c5b`.
The retained source log is `target/mtm-tool/step-schema-source-check.log`
(SHA-256 `1ae2a1d0aa6d18c9cc7254a006da970e7da387e49d2618e1680e67cd3d3ef71d`).
Independent source review found no blocking finding. These observations do not
replace exact-candidate or refreshed-connector acceptance.

After separate installation/restart authorization, the connector must rediscover
the updated `tools/list` catalog (its discovery response advertises
`listChanged: false`). Verify the new binary hash and catalog fingerprint rather
than only the unchanged preview version string. A fresh nonregistered disposable
run must then reach the server with the exact server-issued capability and current
submission contract. Check durable receipt and actual state/sequence progression,
not just absence of an error: an unchanged fetched task would expose a silent
submission downgrade. End-to-end real-client acceptance remains pending until
that new-catalog test succeeds. No production reset is required by this patch.

Rollback is to revert this source patch and rebuild the prior catalog; no database
migration or state restoration is required. Preserve the historical failed U26
observations, their waivers and all previously sealed evidence unchanged.
