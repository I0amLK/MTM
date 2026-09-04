# ADR-0014: Rust Native permission authority

## Status

Accepted for implementation on 2026-09-04.

## Context

MTM 0.4.0 already executes Native command policy, workspace validation, toolchain
exposure, Bubblewrap planning, process lifecycle, and isolation attestation in Rust.
However, the Native permission surface is not yet represented as one typed authority
model. `request_permissions` still reports `ELICITATION_UNSUPPORTED` outside
dangerous mode, policy checks expose string permission names, safe/trusted/dangerous
behavior is partly encoded as control-flow shortcuts, and three public permission
kinds (`long_timeout`, `privileged_executable`, and
`write_generated_or_ignored`) are not represented by one complete Rust permission
classifier.

The public tool contract already names eight permission kinds and two scopes. This
milestone is an explicitly approved contract-hardening milestone for that existing
surface. It must not silently interpret a tool invocation as user consent.

Bubblewrap is not the permission authority. It is the accepted Linux isolation
actuator and remains in place unless a later milestone demonstrates a concrete reason
to replace it.

## Decision

Introduce one typed Rust Native permission model with these layers:

```text
untrusted tool arguments
        ↓
PermissionRequest validation
        ↓
PermissionClassifier
        ↓
PermissionNeed(s)
        ↓
validated profile/explicit grants
        ↓
EffectiveNativePolicy
        ↓
typed SandboxPlan
        ↓
BubblewrapBackend (actuator only)
```

The eight canonical permission kinds are:

```text
network
destructive_command
long_timeout
sensitive_env
shell_expansion
inline_script
privileged_executable
write_generated_or_ignored
```

Scopes are `once` and `session`. A future explicit grant is bound to the authenticated
owner, workspace identity, target tool, permission kind, canonical argument digest,
scope, issuance time, and expiry. An `once` grant is consumed atomically at most once.
A `session` grant is process-local and disappears on server restart. Grant material
must not confer Rethlas workflow, project, verifier, or finalizer authority.

Until a verified MCP client elicitation path exists, safe/trusted `request_permissions`
continues to fail closed with `ELICITATION_UNSUPPORTED`; this milestone may implement
and test the grant authority internally but may not mint an explicit user grant from a
plain tool call. Dangerous mode retains its already documented implicit Native profile
and still does not inherit workflow authority.

Mode profiles become data, not policy bypasses:

- safe: no implicit risky permission grants;
- trusted: preserves the currently accepted local-development behavior for network,
  shell expansion, and inline scripts while continuing to deny sensitive environment,
  destructive commands, privileged executable escape, and unsafe write targets;
- dangerous: implicit Native grants for the complete permission set, while Bubblewrap
  hard isolation, capability dropping, private-vault absence, workspace scoping, and
  workflow non-inheritance remain enforced.

## D3 frozen permission semantics

The reference Coding Tools contract names all eight permissions, but its current
implementation only gives direct enforcement semantics for a subset; in particular,
`long_timeout` and `write_generated_or_ignored` are schema/security-contract names
without an implementation rule to copy. MTM therefore freezes the missing D3 rules
explicitly before implementing them rather than inferring authority from the names.

The D3 shadow evaluator uses these rules:

- `sensitive_env`, `destructive_command`, `shell_expansion`, `inline_script`, and
  `network` preserve the already accepted Rust classifier semantics and ordering;
- `long_timeout` is required when `exec_command.timeout_ms` is greater than the public
  default of 30,000 ms; the schema maximum remains 600,000 ms;
- `privileged_executable` is required when a statically resolvable command executable
  has a setuid or setgid mode bit (`0o6000`), matching the reference Coding Tools
  implementation;
- `write_generated_or_ignored` is required for a non-dry-run `apply_patch` when any
  source or destination path is Git-ignored or contains one of MTM's canonical
  generated/excluded path components (`.git`, `.venv`, `venv`, `node_modules`,
  `dist`, `build`, `__pycache__`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`,
  `target`); dry-run patch validation does not require write authority;
- an `EffectiveNativePolicy` reports required, implicitly granted, explicitly granted,
  and missing permission kinds without widening any other dimension;
- D3 is shadow-only. These additional rules do not change production
  `check_command_policy`, `exec_command`, `apply_patch`, or Bubblewrap behavior before
  D5 target acceptance and authority cutover.

For an exec request with multiple risks, D3 preserves the accepted Rust order for
existing dimensions and appends the newly frozen checks: `sensitive_env`,
`destructive_command`, `shell_expansion`, `inline_script`, `network`, `long_timeout`,
then `privileged_executable`. This ordering is part of the shadow contract and must be
covered by adversarial tests before cutover.

## Sandbox boundary

MTM shall introduce a typed `SandboxPlan` before further expansion of Native
permissions. Permission code may decide required capabilities and effective policy;
the Bubblewrap adapter may only compile an already-authorized plan into isolation
arguments. It must not inspect OAuth state, user consent, grant scope, or workflow
capabilities.

## Security invariants

1. A permission request is never itself proof of consent.
2. Grants are owner/workspace/tool/permission/argument bound and expire fail-closed.
3. Argument mutation invalidates a bound grant.
4. Cross-owner, cross-workspace, cross-tool, expired, revoked, and replayed once-grant
   use is denied.
5. Dangerous Native mode never grants workflow/project/finalizer authority.
6. A network grant changes only network policy; it does not widen filesystem mounts,
   environment inheritance, capabilities, or vault visibility.
7. A destructive-command grant changes command permission only; it does not widen the
   writable filesystem.
8. A sensitive-environment grant is key/value scoped; it never restores the complete
   parent environment.
9. `unsafe_code = "forbid"` remains the workspace default.

## Delivery order

1. Freeze typed permission enums, request normalization, canonical argument digest,
   and permission classification with adversarial unit tests.
2. Add an in-memory grant ledger with once/session semantics, expiry, revocation,
   owner/workspace/tool/argument binding, and concurrency tests; keep it shadow-only
   until a consent source is explicitly validated.
3. Convert Native mode behavior to an `EffectiveNativePolicy` derived from profile
   grants plus validated explicit grants, preserving current safe/trusted/dangerous
   behavior where the existing contract is defined.
4. Introduce `SandboxPlan` and make Bubblewrap a pure actuator.
5. Run real target acceptance for network/DNS, shell expansion, inline scripts,
   destructive denials, sensitive environment filtering, privileged executable
   denial, generated/ignored write controls, TTY, timeout/kill, Sage, Magma, LaTeX,
   Git, and workflow-authority non-inheritance.

## Non-goals

- No Bubblewrap replacement or OCI/container-runtime migration.
- No new public tool, workflow state, SQLite schema, artifact kind, or Agent runtime.
- No persistence of temporary permission grants in the workflow/project database.
- No automatic permission approval based only on model intent or tool invocation.
- No weakening of private-vault, filesystem, capability, or workflow firewalls.

## Rollback

Before authority cutover, remove the MTM-014 typed permission/grant shadow path and
retain the accepted MTM 0.4.0 Native policy plus Bubblewrap behavior. After any later
permission-authority cutover, restore the frozen pre-cutover Native profile evaluator
and invalidate all process-local MTM-014 grants; no workflow, project, database, or
verified proof artifact rewrite is required.
