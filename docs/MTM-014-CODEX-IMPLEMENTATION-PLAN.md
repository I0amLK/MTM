# MTM-014 Rust Native Permission Authority — Codex Implementation Plan

## 0. Document status

This document is an execution plan for Codex. It is not acceptance evidence, does
not move production authority, and does not authorize a release or selector cutover.

The governing documents remain, in order:

1. `AGENTS.md`
2. `docs/CODE_STANDARD.md`
3. `docs/COMMIT_STANDARD.md`
4. `docs/ACCEPTANCE.md`
5. `docs/adr/0014-rust-native-permission-authority.md`
6. `records/governance/migration-graph.json`
7. `records/iterations/ITER-014.json`

When this plan conflicts with a governing document, the governing document wins.

## 1. Exact starting point

At the time this plan was written, the repository state was:

```text
HEAD: 079103210e99b52030183293d269962f549dea1a
branch: main
origin/main...HEAD: 0 behind / 4 ahead
```
Accepted commits already present:

```text
e712a92 docs(mtm014): freeze native permission authority scope [MTM-014]
31b9e25 docs(mtm013): complete stable zero-four release qualification [MTM-013]
1fb4141 feat(mtm014): add typed native permission shadow [MTM-014]
0791032 feat(mtm014): add process-local native grants [MTM-014]
```

The following uncommitted files already contain the beginning of the D3 contract and
must not be discarded, reset, or overwritten:

```text
M docs/adr/0014-rust-native-permission-authority.md
M records/iterations/ITER-014.json
M records/validation/local-validation.json
```

The uncommitted D3 contract freezes these rules:

```text
sensitive_env
destructive_command
shell_expansion
inline_script
network
long_timeout: timeout_ms > 30_000
privileged_executable: statically resolvable executable has 0o6000 mode bits
write_generated_or_ignored:
  non-dry-run apply_patch touches a Git-ignored or canonical generated path
```

D1 and D2 are already accepted:

- eight typed permission kinds;
- typed `once` and `session` scopes;
- typed `exec_command` and `apply_patch` targets;
- canonical SHA-256 binding of recursively key-sorted arguments;
- process-local grant ledger;
- owner/workspace/tool/kind/arguments/scope/expiry binding;
- one-shot atomic consumption for one grant;
- concurrent one-shot replay has exactly one winner;
- session grants are reusable for the exact bound invocation and vanish on restart;
- expiry, revocation, cross-owner, cross-workspace, cross-tool, kind mutation, and
  argument mutation fail closed;
- `VerifiedNativePermissionConsent` has no public production constructor;
- no raw nested tool arguments are retained in the grant ledger;
- production `request_permissions`, `exec_command`, `apply_patch`, command policy,
  and Bubblewrap behavior have not yet changed.

## 2. Non-negotiable invariants

Codex must preserve all of the following throughout MTM-014:

1. Stable MTM `0.4.0` remains the rollback release until a separately qualified
   MTM-014 preview is accepted.
2. Bubblewrap remains the Linux isolation actuator. Do not add crun, Youki,
   libcontainer, nsjail, Minijail, OCI bundles, or a custom namespace implementation.
3. `unsafe_code = "forbid"` remains in force.
4. Do not add a new crate.
5. Do not add or remove public tools or hidden aliases.
6. Do not change workflow protocol 3, the explicit protocol-2 rollback, state schema
   2, Rethlas capabilities, verifier authority, finalizer authority, vault semantics,
   or `proof_verified.tex` semantics.
7. Native dangerous mode never inherits workflow, project, verifier, or finalizer
   authority.
8. A `request_permissions` call is a request, not proof of user consent.
9. Safe/trusted explicit grants remain disabled until an independent, verified human
   approval path exists and passes real target tests.
10. The private workflow vault remains absent from arbitrary Native command mounts.
11. Linux capabilities remain dropped and privilege escalation remains disabled in
    every Native mode, including dangerous.
12. A permission may widen only its named dimension.
13. Temporary grants remain process-local. Do not add them to workflow/project SQLite.
14. No raw OAuth token, capability, grant identifier, secret environment value,
    command body, patch body, or private mathematical content may enter evidence.
15. Accepted MTM-013 evidence is immutable. Never regenerate it using an MTM-014
    development binary.
16. Repository-root JSON files remain forbidden.
17. Do not mix unrelated cleanup, mass formatting, renaming, or performance work into
    MTM-014 commits.

## 3. Required Codex operating procedure

Before editing:

```bash
cd ~/桌面/tempcoding/MTM-reboot

cat AGENTS.md
cat docs/CODE_STANDARD.md
cat docs/COMMIT_STANDARD.md
cat docs/ACCEPTANCE.md
cat docs/adr/0014-rust-native-permission-authority.md
cat records/iterations/ITER-014.json

git status --short
git log --oneline -8
git diff --check
git diff -- \
  docs/adr/0014-rust-native-permission-authority.md \
  records/iterations/ITER-014.json \
  records/validation/local-validation.json
```

Codex must then follow these rules:

- Preserve all user and prior-agent changes.
- Use small, independently reviewable commits.
- Add tests in the same commit as behavior.
- Run the narrow test first, then the full local gate.
- Record every failed test or rejected design attempt under
  `recorded_failures_and_repairs` in `ITER-014.json`; do not erase failure history.
- Regenerate `records/validation/local-validation.json` only by running
  `python3 scripts/run_checks.py`.
- Do not edit generated evidence by hand.
- Do not push, publish, install, change the selector, or restart production without
  an explicit release step.
- Stop rather than inventing a consent mechanism when verified human approval cannot
  be demonstrated.

## 4. Target architecture

The intended final architecture is:

```text
untrusted MCP arguments
        │
        ▼
typed invocation validation
        │
        ▼
Rust intrinsic risk classification
        │
        ▼
Rust Native mode profile
  + verified explicit grants
        │
        ▼
EffectiveNativePolicy
        │
        ▼
typed SandboxPlan / PreparedPatch
        │
        ├───────────────┐
        ▼               ▼
Bubblewrap actuator   atomic patch commit
        │
        ▼
Linux kernel isolation
```

Authority layers remain separate:

```text
L0 OAuth identity
L1 Native permission authority      <- MTM-014
L2 Rethlas workflow capability
L3 verifier/finalizer authority
```

No type or grant from L1 may be accepted as evidence at L2 or L3.

## 5. Delivery map

`ITER-014.json` currently defines five deliveries:

| Delivery | State at plan start | Goal |
| --- | --- | --- |
| D1 | accepted | typed request, permission kinds, scopes, tools, canonical digest |
| D2 | accepted | process-local grant ledger and exact binding |
| D3 | in progress, contract uncommitted | complete eight-kind evaluator and effective policy |
| D4 | pending | typed SandboxPlan; Bubblewrap becomes a pure actuator |
| D5 | pending | verified consent, production enforcement, real target qualification |

The implementation below subdivides D3–D5 into safe review units without changing
the five recorded deliveries.

## 6. First action: preserve and commit the D3 contract

Before writing D3 implementation code, finish the existing contract-only change.

### 6.1 Add a governance test

Extend `tests/test_governance.py` so it freezes at least:

- D3 status is `in_progress`;
- exact permission order;
- `long_timeout_threshold_ms_exclusive == 30000`;
- schema maximum remains `600000`;
- privileged executable rule contains `0o6000`;
- canonical generated components match the eleven frozen components;
- dry-run patch requires no write permission;
- D3 remains `shadow_only_before_d5`;
- production command, patch, and Bubblewrap paths are unchanged.

### 6.2 Run gates

```bash
python3 -m unittest tests.test_governance -v
python3 scripts/validate_migration_graph.py
python3 scripts/validate_record_layout.py
python3 scripts/run_checks.py
git diff --check
```

### 6.3 Commit only the D3 contract/planning unit

Suggested subject:

```text
docs(mtm014): freeze complete permission semantics [MTM-014]
```

Required body:

```text
Milestone: MTM-014
Authority-Before: rust-shadow
Authority-After: rust-shadow
Acceptance: A0,A1
Receipt: records/iterations/ITER-014.json
Rollback: Revert the D3 contract commit; D1/D2 remain pre-authority and stable 0.4.0 behavior remains unchanged.
Manual-Pending: D3 implementation, D4 SandboxPlan, verified consent, real target A4, and authority cutover.
```

Include this plan document in that commit. Do not include D3 implementation code in
the contract commit.

## 7. D3 implementation: complete typed Native policy

### 7.1 Replace mode-dependent risk classification with intrinsic classification

The current D1 helper `classify_current_command_permissions(mode, ...)` reflects
existing production shortcuts. D3 must add a mode-neutral classifier:

```rust
pub struct ExecPermissionFacts { /* validated facts only */ }

pub fn classify_exec_permissions(
    invocation: &ExecInvocation,
    facts: &ExecPermissionFacts,
) -> Result<Vec<NativePermissionKind>, ReCtmError>;
```

Intrinsic classification must report every risk in frozen order regardless of
safe/trusted/dangerous mode. Mode profiles are applied later.

Frozen order:

```text
1. sensitive_env
2. destructive_command
3. shell_expansion
4. inline_script
5. network
6. long_timeout
7. privileged_executable
```

For patches, `write_generated_or_ignored` is the sole D3 patch risk dimension.

Keep `classify_current_command_permissions` temporarily as the pre-cutover
compatibility reference. Mark its role clearly and delete or retire it only in a
separate post-cutover cleanup commit.

### 7.2 Add typed invocation inputs

Raw `Map<String, Value>` must stop at the runtime boundary.

Recommended types:

```rust
pub enum NativeInvocation {
    Exec(ExecInvocation),
    Patch(PatchInvocation),
}

pub struct ExecInvocation {
    argv: Vec<String>,
    policy_text: String,
    workdir: WorkspaceRelativePath,
    timeout_ms: u64,
    yield_time_ms: u64,
    max_output_bytes: usize,
    stdin_present: bool,
    tty: bool,
    environment: BTreeMap<String, String>,
    arguments_sha256: String,
}

pub struct PatchInvocation {
    operations: Vec<PatchOperation>,
    dry_run: bool,
    arguments_sha256: String,
}
```

The exact names may differ, but these properties are mandatory:

- parsing is deterministic;
- defaults exactly match the public schemas;
- `workdir` and `cwd` conflict remains a validation error;
- raw secret values are not exposed through `Debug`;
- the canonical digest is computed from the complete original tool arguments, not a
  reduced subset;
- `cmd` and `argv` forms remain behaviorally distinct but converge on one typed
  invocation;
- malformed values fail before any grant lookup or side effect.

### 7.3 Keep filesystem-dependent facts outside `mtm-core`

`mtm-core` must remain pure. It must not stat executables or run Git.

Use two stages:

```text
pure argument parsing/classification candidates        mtm-core
filesystem/Git fact collection                         mtm-runtime or mtm-native
pure final risk evaluation from typed facts             mtm-core
```

Recommended fact types:

```rust
pub struct ResolvedExecutableFact {
    requested: String,
    resolved_path: PathBuf,
    device: u64,
    inode: u64,
    mode: u32,
    size: u64,
    modified_fingerprint: Option<...>,
}

pub struct PatchPathFact {
    path: String,
    canonical_generated_component: bool,
    git_ignored: bool,
}
```

Do not put OAuth principals, grant IDs, or consent state in these fact types.

### 7.4 Implement `long_timeout`

Rules:

- `timeout_ms <= 30_000`: no `long_timeout` requirement;
- `timeout_ms == 30_001`: requirement present;
- `timeout_ms == 600_000`: requirement present;
- values outside the public schema fail validation before classification;
- `yield_time_ms` does not imply `long_timeout`;
- a long-timeout grant changes only the accepted deadline, not output limits, process
  counts, filesystem mounts, networking, or environment.

### 7.5 Implement `privileged_executable`

The classifier must inspect all statically resolvable command executables, not just
the first token of the whole command.

Required cases:

- direct `argv` executable;
- direct `cmd` executable;
- pipelines and shell control segments;
- `env KEY=value command ...` wrappers;
- relative executable paths resolved against the validated workdir;
- absolute executable paths only when already permitted by existing Native path and
  toolchain exposure rules;
- bare executable names resolved using the exact effective sandbox PATH, not an
  unrelated login-shell PATH.

If a statically resolvable executable has setuid or setgid bits (`mode & 0o6000 != 0`),
require `privileged_executable`.

Safety requirements:

- inability to inspect a path that should be inspectable fails closed;
- executable metadata is rechecked immediately before command start;
- a path/inode/mode change between classification and spawn returns a stable
  `NATIVE_EXECUTABLE_CHANGED` security error;
- granting this permission never restores Linux capabilities, setuid privilege,
  parent environment, host root access, or the private vault;
- Bubblewrap continues `--cap-drop ALL` and no-new-privileges behavior.

### 7.6 Implement `write_generated_or_ignored`

Classify every source and destination path in every patch operation:

- add target;
- update source;
- delete source;
- move source;
- move destination.

Require `write_generated_or_ignored` when a non-dry-run patch touches either:

1. a Git-ignored path; or
2. a path containing one frozen generated/excluded component:

```text
.git
.venv
venv
node_modules
dist
build
__pycache__
.pytest_cache
.mypy_cache
.ruff_cache
target
```

Rules:

- component matching is path-component based, not substring based;
- `builder/file.txt` does not match `build`;
- case behavior follows the host filesystem and Git behavior; do not invent global
  lowercase matching;
- `dry_run=true` performs complete validation and classification but requires no
  write grant and makes zero writes;
- Git-ignore lookup failures that are not the ordinary “not ignored” result fail
  closed;
- the grant is bound to the exact complete patch arguments, so changing one byte of
  the patch invalidates it;
- a grant does not permit symlink writes, workspace escape, baseline conflicts, or
  invalid patch syntax.

### 7.7 Add `EffectiveNativePolicy`

The evaluator must produce one named result, for example:

```rust
pub struct EffectiveNativePolicy {
    tool: NativePermissionTool,
    arguments_sha256: String,
    required: Vec<NativePermissionKind>,
    implicitly_granted: BTreeSet<NativePermissionKind>,
    explicitly_granted: BTreeSet<NativePermissionKind>,
    missing: Vec<NativePermissionKind>,
}
```

It must answer these questions without side effects:

- What intrinsic permissions are required?
- Which are implicitly granted by safe/trusted/dangerous profile data?
- Which are satisfied by verified explicit grants?
- Which are missing, in stable frozen order?
- Is execution authorized?

Profile rules remain:

```text
safe:
  implicit = {}

trusted:
  implicit = {network, shell_expansion, inline_script}

dangerous:
  implicit = all eight Native permissions
```

Dangerous mode remains a Native profile, not a bypass in downstream code.

### 7.8 Make multi-permission grant use atomic

The existing D2 API authorizes and consumes one grant at a time:

```rust
authorize(grant_id, owner, workspace, tool, kind, arguments)
```

That API is insufficient for a multi-risk invocation. Sequential calls could consume
one one-shot grant and then fail because another permission is missing.

Add one atomic authority operation, with a name such as:

```rust
authorize_invocation(...)
authorize_matching_grants(...)
```

Required algorithm under one ledger mutex:

1. Compute the canonical arguments digest once.
2. Compute all missing permission kinds first.
3. Find exactly one eligible matching grant for each missing kind.
4. Validate every candidate: owner, workspace, tool, kind, argument digest, expiry,
   revocation, and consumption state.
5. Reject duplicate grant IDs and duplicate coverage.
6. If any required permission lacks a valid grant, return an error and consume none.
7. Only after all checks pass, mark every one-shot grant consumed in one critical
   section.
8. Return one unforgeable invocation-level permit containing only the authorized
   dimensions and binding digest.

Do not require a client-supplied grant ID in `exec_command` or `apply_patch`; those
public schemas have no grant field. The authority should locate grants by the exact
authenticated binding. The `grant_id` returned by `request_permissions` remains an
opaque audit handle, not a bearer capability accepted by other authority layers.

Freeze one-shot consumption timing:

- parse, schema validation, path validation, fact collection, patch preparation, and
  SandboxPlan construction occur before consumption;
- all required grants are atomically consumed immediately before command start or
  patch commit;
- if process spawning fails after final authorization, the one-shot grant remains
  consumed; do not implement unsafe rollback of user consent;
- invalid patch syntax, path escape, stale baseline, or incomplete grants consume
  nothing.

### 7.9 D3 must remain shadow-only

Before D5, D3 may be called by tests and validation harnesses but must not change the
production outcome of:

- `NativeToolRuntime::request_permissions`;
- `NativeToolRuntime::exec_command`;
- `NativeWorkspace::apply_patch`;
- Bubblewrap network mode or mounts.

Do not add a permissive fallback such as “new evaluator error -> use old policy and
continue.” Authorization comparisons always choose the less permissive result.

### 7.10 D3 unit and adversarial corpus

At minimum, add tests for:

#### Command risk ordering

```text
safe + sensitive env + rm -rf + $(...) + python -c + curl + 30001 ms + setuid exe
=> all seven permissions in frozen order
```

#### Boundary values

```text
timeout 1
timeout 30000
timeout 30001
timeout 600000
timeout 600001 -> schema failure
```

#### Command parsing

```text
env FOO=1 python3 -c ...
command1 | command2
command1 && command2
quoted metacharacters
heredoc payloads
relative executable path
bare executable through effective PATH
unresolvable executable
setuid and setgid fixtures
executable metadata mutation before spawn
```

#### Patch classification

```text
dry-run ignored add -> no permission required, zero writes
real ignored add -> permission required
update ignored file
delete ignored file
move into ignored file
move out of ignored source
target/foo
builder/foo -> not canonical generated component
Git ignored by root .gitignore
Git ignored by nested .gitignore
Git negation rule
non-repository workspace
Git lookup failure
symlink destination remains denied even with grant
argument mutation after grant
```

#### Multi-grant atomicity

```text
two required, one grant present -> zero grants consumed
two required, both once grants present -> both consumed once
two concurrent invocations using same two once grants -> exactly one full winner
session + once combination
expired + valid combination -> none consumed
revoked + valid combination -> none consumed
duplicate kind coverage -> fail closed
cross-owner/cross-workspace/cross-tool -> fail closed
```

#### Secret and Debug behavior

No Debug/event/error/evidence output may contain:

- raw command body;
- raw patch body;
- environment values;
- OAuth token;
- raw grant ID;
- canonical full arguments JSON.

### 7.11 D3 completion criteria

D3 is accepted only when:

- all eight permission kinds have typed classification semantics;
- intrinsic classification is mode-neutral;
- `EffectiveNativePolicy` is deterministic;
- multi-permission authorization is atomic;
- D3 remains production-shadow-only;
- targeted Rust tests pass;
- full `run_checks.py` passes;
- `ITER-014.json` has a D3 receipt and recorded edge corpus;
- no accepted MTM-013 evidence hash changes.

Suggested D3 implementation commit:

```text
feat(mtm014): evaluate complete native permission policy [MTM-014]
```

Suggested hardening commit, only if independently reviewable:

```text
test(mtm014): harden atomic multi-permission grants [MTM-014]
```

## 8. D4 implementation: typed SandboxPlan and prepared patch

### 8.1 Goal

Bubblewrap must become a pure actuator. It may execute an already-authorized concrete
plan, but it must not inspect:

- `NativeMode`;
- OAuth principal;
- user consent;
- grant scope;
- permission kind;
- workflow capability;
- project/verifier/finalizer state.

### 8.2 Separate planning from actuation

Introduce concrete plan types in `mtm-native` or the lowest valid existing crate.
Do not create a new crate.

Recommended shape:

```rust
pub enum NetworkNamespacePlan {
    Isolated,
    Shared,
}

pub struct SandboxPlan {
    workspace: PathBuf,
    workdir: String,
    argv: Vec<String>,
    environment: BTreeMap<String, String>,
    network: NetworkNamespacePlan,
    read_only_roots: Vec<PathBuf>,
    forbidden_paths: Vec<PathBuf>,
    resolver_mount: Option<PathBuf>,
    capabilities: EmptyCapabilitySet,
    no_new_privileges: bool,
    clear_parent_environment: bool,
    private_vault_mounted: bool,
}
```

The exact representation may differ, but invalid states must be unrepresentable or
rejected by one validator.

The planner may receive `EffectiveNativePolicy`; the Bubblewrap compiler may not.

### 8.3 Replace mode branches mechanically

Current Bubblewrap behavior derived from mode must become explicit plan data:

```text
safe without network grant       -> isolated network namespace
trusted                          -> shared network namespace
dangerous                        -> shared network namespace
safe with verified network grant -> shared network namespace for that invocation only
```

Resolver mounting is derived from `network == Shared`, not from mode.

All other invariant properties remain fixed:

- workspace RW;
- selected system/toolchain roots RO;
- `/tmp` tmpfs;
- isolated `/proc` and `/dev` view;
- parent environment cleared;
- private roots absent;
- capabilities empty;
- no-new-privileges true;
- nested user namespaces disabled;
- broad `/run` hidden;
- only the trusted resolver target is exposed when required.

### 8.4 Differential plan tests

Before production switch, compile old and new plans for accepted profile cases and
compare normalized semantics:

- safe;
- trusted;
- dangerous;
- safe plus a synthetic verified network permit;
- explicit toolchain roots;
- resolver symlink target;
- forbidden root overlap;
- TTY and non-TTY commands;
- fixed LaTeX helper.

Unexplained differences block D4.

### 8.5 Split patch preparation from commit

To enforce authorization immediately before writes, refactor patch handling into:

```text
parse
validate paths
read baselines
apply hunks in memory
collect affected path facts
produce PreparedPatch
        ↓
final atomic permission authorization
        ↓
commit PreparedPatch
```

`PreparedPatch` must:

- contain baseline fingerprints;
- be non-serializable as authority input unless necessary;
- expose no public constructor bypass;
- revalidate baselines at commit;
- commit all changes or none;
- retain existing symlink and workspace-boundary protections;
- make dry-run return without requesting or consuming a grant.

Do not hold a lock across Git commands or other external processes. If Git-ignore
state participates in authorization, use a bounded retry/revalidation strategy:

1. collect Git-ignore facts;
2. record relevant ignore/index metadata fingerprints;
3. acquire the patch commit lock;
4. verify fingerprints and file baselines are unchanged;
5. if changed, release and retry a bounded number of times;
6. fail closed after the retry bound.

### 8.6 D4 completion criteria

- Bubblewrap compiler accepts only a validated `SandboxPlan`;
- no mode/grant/OAuth/workflow branch remains in the actuator;
- production profile behavior is semantically unchanged before explicit-grant
  cutover;
- new network-grant plan exists in shadow tests;
- patch preparation and commit are separated;
- differential and full gates pass;
- D4 receipt is recorded.

Suggested commits:

```text
refactor(mtm014): introduce typed native sandbox plans [MTM-014]
refactor(mtm014): prepare patches before authority commit [MTM-014]
```

Do not switch explicit-grant authority in D4.

## 9. D5A: verified human consent feasibility gate

This is the most important go/no-go decision. A plain model/tool invocation cannot
mint a grant.

### 9.1 Preferred consent sources

Evaluate in this order:

1. A standards-compliant MCP elicitation path, but only if the actual supported
   client capability and transport can be demonstrated end to end.
2. A local `mtm tui` operator prompt owned by the Rust operator session, with an
   independent keyboard approval event.
3. Headless `mtm serve` remains `ELICITATION_UNSUPPORTED` when no verified provider is
   attached.

Do not implement any of these as a substitute for human approval:

- approval inferred from `reason` text;
- approval inferred from a second identical model call;
- environment variable that globally auto-approves;
- approval file dropped into the workspace;
- query-string or header bearer grant;
- OAuth authentication alone;
- dangerous mode grant copied into safe/trusted mode;
- “allow once” represented only by a model-generated boolean.

### 9.2 Consent provider boundary

Use a narrow interface such as:

```rust
trait NativePermissionConsentProvider: Send + Sync {
    fn request_consent(
        &self,
        principal: &OAuthPrincipal,
        workspace: &Path,
        request: &NativePermissionRequest,
        summary: &RedactedPermissionSummary,
    ) -> Result<ConsentDecision, ReCtmError>;
}
```

Production implementations:

```text
UnsupportedConsentProvider
VerifiedMcpElicitationProvider       only after real capability proof
TuiOperatorConsentProvider           only while mtm tui owns a terminal
```

The verified approval event, not the request object, is the only code path allowed to
construct `VerifiedNativePermissionConsent`.

Because crate dependency direction is strict, do not create a gateway/runtime cycle.
If a validated elicitation result must cross crates, define the authority-bearing
validated type at the lowest legitimate existing boundary, keep fields private, and
expose no public forgeable constructor.

### 9.3 TUI prompt requirements

If the TUI path is selected:

- one prompt is active at a time;
- prompt wait is bounded and cancellable;
- no server lock is held while waiting for input;
- other unrelated tool calls remain bounded;
- the prompt shows tool, permission, scope, TTL, workspace, and a redacted summary;
- it shows an argument fingerprint, never the raw full command/patch or env values;
- explicit `y`/`n` or an equally unambiguous input is required;
- EOF, disconnect, timeout, TUI shutdown, or malformed input means deny;
- the approval is bound to the exact pending request nonce and OAuth owner;
- a stale response cannot approve a later request;
- prompt events are redacted in compact and verbose TUI modes;
- headless `serve` behavior remains unsupported unless verified MCP elicitation is
  separately present.

### 9.4 Consent result contract

Freeze additive `request_permissions` statuses before implementation. Recommended:

```text
granted
denied
unsupported
not_required
```

Rules:

- requested permission must actually be intrinsic to the exact bound invocation;
- requesting a permission already implicit in the active mode returns `not_required`
  or a clearly non-ledger profile result, not a reusable explicit grant;
- denied/unsupported paths mint no grant;
- approved path returns the existing opaque `grant_id`, expiry, scope, tool, kind,
  and safe constraints;
- returned data never includes raw arguments;
- dangerous mode preserves its current documented implicit result and still creates
  no process-local explicit grant unless a later contract says otherwise.

### 9.5 Mandatory feasibility evidence

Create a redacted report under:

```text
records/evidence/MTM-014/elicitation-capability.json
```

It must state:

- exact binary/source hash;
- client and transport tested;
- consent provider selected;
- independent human action observed;
- timeout/deny/disconnect behavior;
- owner/request nonce binding;
- raw arguments/tokens/grant IDs not recorded;
- whether headless mode remains unsupported;
- go/no-go decision.

If no provider passes, record D5 as blocked and stop. Do not weaken the invariant to
finish the milestone.

## 10. D5B: production enforcement cutover

Proceed only after D5A passes.

### 10.1 Runtime orchestration

Move permission orchestration into `RuntimeToolBackend` or another existing runtime
composition boundary that has both:

- validated `OAuthPrincipal`;
- access to `NativePermissionGrantAuthority`;
- access to typed invocation parsing/fact collection;
- access to `NativeToolRuntime` and `NativeWorkspace`.

The desired call flow for `exec_command` is:

```text
validate public schema
parse typed ExecInvocation
resolve workdir and executable facts
classify intrinsic permissions
apply implicit profile
atomically locate/validate explicit grants
build concrete SandboxPlan
recheck executable facts
consume all required once grants atomically
start Bubblewrap command
```

The desired call flow for `apply_patch` is:

```text
validate public schema
parse typed PatchInvocation
prepare patch and baselines
collect generated/Git-ignore facts
classify intrinsic permission
apply implicit profile
atomically locate/validate explicit grants
revalidate facts/baselines
consume required once grants atomically
commit PreparedPatch atomically
```

### 10.2 No client grant parameter

Do not add `grant_id` to public `exec_command` or `apply_patch` schemas. Matching is
automatic by:

```text
owner + workspace + tool + permission kind + complete arguments SHA-256
```

This preserves the 24-tool contract and prevents grant IDs from becoming bearer
capabilities passed around by models.

### 10.3 Error contract

Freeze stable error codes before cutover. At minimum distinguish:

```text
PERMISSION_REQUIRED
NATIVE_PERMISSION_GRANT_NOT_FOUND
NATIVE_PERMISSION_GRANT_OWNER_MISMATCH
NATIVE_PERMISSION_GRANT_WORKSPACE_MISMATCH
NATIVE_PERMISSION_GRANT_TOOL_MISMATCH
NATIVE_PERMISSION_GRANT_KIND_MISMATCH
NATIVE_PERMISSION_GRANT_ARGUMENT_MISMATCH
NATIVE_PERMISSION_GRANT_EXPIRED
NATIVE_PERMISSION_GRANT_REVOKED
NATIVE_PERMISSION_GRANT_CONSUMED
NATIVE_PERMISSION_GRANT_SET_INCOMPLETE
NATIVE_PERMISSION_GRANT_SET_AMBIGUOUS
NATIVE_EXECUTABLE_CHANGED
NATIVE_PATCH_AUTHORITY_FACTS_CHANGED
ELICITATION_UNSUPPORTED
ELICITATION_DENIED
ELICITATION_TIMEOUT
```

Errors must preserve category, retryability, stable safe details, and redaction.

### 10.4 Mode compatibility

After cutover, existing behavior must remain:

```text
safe:
  denies all intrinsic risky permissions unless independently approved

trusted:
  implicitly permits network, shell expansion, inline scripts
  still requires explicit permission for sensitive env, destructive command,
  long timeout, privileged executable, and generated/ignored patch writes

dangerous:
  implicitly permits all eight Native permissions
  still runs inside the accepted Bubblewrap hard-isolation boundary
  still has no workflow/project/verifier/finalizer authority
```

### 10.5 Network permission must change the plan

A safe-mode network grant is not merely a regex bypass. For that exact invocation:

```text
EffectiveNativePolicy.network = granted
        ↓
SandboxPlan.network = Shared
        ↓
trusted resolver file mounted read-only when required
```

Every other SandboxPlan field must remain identical to safe mode.

### 10.6 Sensitive environment scope

An explicit sensitive-env grant permits only the exact environment object in the
bound tool arguments. It never restores the full parent process environment.

The child environment still starts from the accepted cleared/allowlisted model.

### 10.7 Production metadata

An additive `server_info` object may be introduced only after freezing it in the
MTM-014 contract. Recommended safe fields:

```json
{
  "native_permission_authority": {
    "implementation": "rust",
    "grant_store": "process_local",
    "authority_state": "shadow|authoritative",
    "consent_provider": "unsupported|tui|mcp_elicitation",
    "bubblewrap_actuator": true,
    "workflow_authority_inherited": false
  }
}
```

Do not expose grant counts, raw IDs, argument hashes, owners, or pending request data.

## 11. D5 real target acceptance corpus

Create a dedicated runner and validator, for example:

```text
scripts/run_mtm014_native_permission_target.py
scripts/validate_mtm014_native_permission_target.py
records/evidence/MTM-014/native-permission-target.json
```

The runner must use a candidate binary whose SHA-256 is recorded and must not use
mock Bubblewrap, mock OAuth, or mock operator approval for A4.

### 11.1 Permission cases

1. Safe network request denied before approval.
2. Verified once network approval permits exactly one identical request.
3. Repeating it fails after one-shot consumption.
4. URL/argument mutation fails.
5. Session network grant permits repeated identical requests in one process.
6. Server restart invalidates the session grant.
7. Cross-owner request fails using two real OAuth clients.
8. Cross-workspace request fails using two runtime instances.
9. Multi-risk request with one missing grant consumes none.
10. Multi-risk request with all once grants has one full concurrent winner.
11. Trusted implicit network/shell/inline behavior remains compatible.
12. Trusted sensitive env and destructive command remain gated.
13. Dangerous implicit profile works but private vault/workflow authority remains
    denied.
14. `long_timeout` boundary 30,000/30,001 is enforced.
15. Sensitive env exact binding is enforced.
16. Setuid/setgid fixture is detected and cannot gain real privilege.
17. Generated/ignored patch dry-run succeeds with zero writes.
18. Generated/ignored real patch is denied, approved once, and then denied on replay.
19. Patch mutation, symlink, workspace escape, and stale baseline remain denied.
20. Deny, timeout, EOF, and disconnected approval paths mint no grant.

### 11.2 Isolation non-regression

For safe, trusted, dangerous, and safe+network-grant cases, prove:

- workspace mount behavior;
- private roots hidden;
- toolchains read-only;
- parent secret absent;
- capabilities dropped;
- no-new-privileges;
- nested user namespaces disabled;
- broad `/run` hidden;
- resolver exposure is one trusted read-only target;
- safe without grant has isolated networking;
- safe with network grant changes only networking/resolver fields.

### 11.3 Functional non-regression

Repeat real target checks for:

- ordinary shell command;
- TTY stdin round trip;
- retained output paging;
- timeout;
- explicit kill and descendant cleanup;
- Git;
- curl/DNS;
- SageMath;
- Magma;
- `pdflatex`/`latexmk` finalization path;
- Quick Tunnel startup/owned cleanup if the candidate touches operator composition;
- Rethlas workflow authority non-inheritance.

### 11.4 Evidence hygiene

The target report may contain:

- binary and harness hashes;
- boolean checks;
- stable error codes;
- bounded counts/timings;
- redacted fingerprints where necessary.

It may not contain:

- raw OAuth credentials;
- raw grant IDs;
- raw permission-request nonces;
- command or patch bodies containing secrets;
- full environment values;
- private vault paths/content;
- raw TUI approval transcript.

## 12. Release and rollout strategy

MTM-014 is a material behavior change. Do not overwrite stable `0.4.0` in place.

Recommended candidate identity:

```text
0.5.0-preview.1
```

Use a different version only after explicitly recording the release decision.

Rollout sequence:

```text
stable 0.4.0 remains selected
        ↓
build hash-bound MTM-014 candidate
        ↓
run A0/A1/A3 and real A4 target corpus
        ↓
install candidate side by side
        ↓
temporary selector cutover
        ↓
real OAuth/MCP/TUI permission flow
        ↓
rollback to 0.4.0
        ↓
verify 0.4.0 behavior/state
        ↓
recutover to candidate
        ↓
bounded soak/resource gate
        ↓
only then mark MTM-014 authoritative/completed
```

No persistent workflow/project/proof migration should be required. Restarting the
server intentionally invalidates all temporary grants.

## 13. File-by-file implementation map

Expected files and responsibilities:

### `crates/mtm-contracts/src/enums.rs`

- Keep the frozen eight kinds, two scopes, and two tools.
- Add wire-value tests only when a new stable enum is genuinely necessary.
- Do not add workflow permissions here.

### `crates/mtm-core/src/native_permission.rs`

- Typed request parsing.
- Canonical argument digest.
- Mode profile data.
- Pure intrinsic permission evaluation types.
- `EffectiveNativePolicy` pure derivation.
- No filesystem, Git, clock, randomness, OAuth, process, or Bubblewrap calls.

### `crates/mtm-core/src/command_policy.rs`

- Preserve old production evaluator until cutover.
- Reuse established regex/order facts without creating duplicate conflicting regexes.
- Add mode-neutral classification or move shared pure facts into
  `native_permission.rs` without creating a cycle.

### `crates/mtm-runtime/src/native_permission.rs`

- Process-local grant authority.
- Atomic invocation-level grant matching/consumption.
- Verified consent boundary.
- Stable permission errors.
- No raw arguments retained.

### `crates/mtm-runtime/src/tool_backend.rs`

- OAuth-bound orchestration for request, exec, and patch.
- Never pass raw principal booleans to authority operations.
- Keep Rethlas capability path completely separate.

### `crates/mtm-runtime/src/native_tools.rs`

- Typed exec parsing/fact collection and plan execution.
- No consent UI logic.
- After D4, no mode branch inside Bubblewrap actuation.

### `crates/mtm-runtime/src/workspace.rs`

- PreparedPatch.
- Git-ignore/generated-path fact collection.
- Atomic commit and baseline revalidation.
- Existing workspace/symlink/path protections remain authoritative.

### `crates/mtm-runtime/src/application.rs`

- Own exactly one process-local grant authority.
- Wire exactly one consent provider.
- Restart destroys all grants.

### `crates/mtm-runtime/src/operator.rs`

- Only if TUI consent is selected: bounded redacted prompt and independent operator
  decision.
- Operator session receives no workflow or storage authority.

### `crates/mtm-native/src/bubblewrap.rs`

- Compile validated `SandboxPlan` only.
- No OAuth, grant, permission, mode, or workflow decisions.

### Governance and evidence

```text
docs/adr/0014-rust-native-permission-authority.md
records/iterations/ITER-014.json
records/governance/migration-graph.json
records/governance/project-progress.json
records/governance/authority-inventory.json
records/evidence/MTM-014/*
records/validation/local-validation.json
tests/test_governance.py
scripts/run_checks.py
```

Update authority inventory only at real authority cutover, not during shadow work.

## 14. Commit sequence

The exact number may change if a unit cannot remain independently buildable, but the
following order should be preserved:

1. `docs(mtm014): freeze complete permission semantics [MTM-014]`
2. `feat(mtm014): evaluate complete native permission policy [MTM-014]`
3. `test(mtm014): harden atomic multi-permission grants [MTM-014]`
4. `refactor(mtm014): introduce typed native sandbox plans [MTM-014]`
5. `refactor(mtm014): prepare patches before authority commit [MTM-014]`
6. `test(mtm014): qualify verified native consent [MTM-014]`
7. `feat(mtm014): bridge verified native consent [MTM-014]`
8. `feat(mtm014): enforce native permission authority [MTM-014]`
9. `test(mtm014): qualify native permission target [MTM-014]`
10. `docs(mtm014): complete native permission authority [MTM-014]`

Do not use `perf` commits. No A6 claim is planned.

Every material commit body must contain the required trailers from
`docs/COMMIT_STANDARD.md`.

Authority trailers should reflect reality:

- D3/D4 shadow commits: `rust-shadow -> rust-shadow` for the new permission path;
- consent feasibility without enforcement: still `rust-shadow -> rust-shadow`;
- production enforcement cutover: `rust-shadow -> rust`;
- final qualification/records: `rust -> rust`.

## 15. Validation commands

Use the pinned toolchain environment already established by the repository.

Narrow development loop:

```bash
cargo fmt --all -- --check
cargo test -p mtm-core native_permission -- --nocapture
cargo test -p mtm-runtime native_permission -- --nocapture
cargo clippy -p mtm-core -p mtm-runtime --all-targets -- -D warnings
git diff --check
```

Sandbox-plan loop:

```bash
cargo test -p mtm-native bubblewrap -- --nocapture
cargo test -p mtm-runtime native_tools -- --nocapture
cargo clippy -p mtm-native -p mtm-runtime --all-targets -- -D warnings
```

Governance loop:

```bash
python3 scripts/validate_migration_graph.py
python3 scripts/validate_engineering_graph.py
python3 scripts/validate_record_layout.py
python3 -m unittest tests.test_governance -v
```

Full gate before every accepted delivery or authority claim:

```bash
python3 scripts/run_checks.py
git diff --check
git status --short
```

Real target gate before cutover:

```bash
python3 scripts/run_mtm014_native_permission_target.py
python3 scripts/validate_mtm014_native_permission_target.py
```

The runner must fail closed when its binary or harness hash is stale.

## 16. Stop conditions

Codex must stop and record a blocked result instead of guessing when any of these
occurs:

1. No independently verified human consent path is available.
2. A proposed solution requires changing the public tool set or workflow capability.
3. A proposed solution requires persisting grants in workflow/project SQLite.
4. Bubblewrap cannot express a required policy without widening unrelated mounts or
   privileges.
5. Safe network approval cannot be represented as an invocation-local SandboxPlan.
6. Multi-grant authorization cannot guarantee zero partial one-shot consumption.
7. Patch authorization cannot guarantee zero writes before final authorization.
8. Git-ignore or executable facts cannot be revalidated against TOCTOU mutation.
9. Any target case exposes the private vault, parent secrets, Linux capabilities, or
   workflow authority.
10. Any accepted MTM-013 evidence hash changes.
11. Full local gate fails for reasons not understood and recorded.
12. The implementation requires local `unsafe` without a separately approved
    milestone and safety argument.

## 17. Final MTM-014 acceptance checklist

MTM-014 may be marked completed only when all boxes are true:

```text
[ ] D1 accepted and unchanged
[ ] D2 accepted and unchanged except reviewed atomic multi-grant extension
[ ] D3 complete eight-kind semantics accepted
[ ] D4 SandboxPlan accepted
[ ] Bubblewrap is a pure actuator
[ ] PreparedPatch guarantees no writes before authorization
[ ] verified independent human consent path accepted
[ ] headless unsupported behavior remains fail-closed where applicable
[ ] exact owner/workspace/tool/kind/arguments binding enforced
[ ] once grants atomically consumed
[ ] session grants disappear on restart
[ ] safe/trusted/dangerous compatibility proven
[ ] network grant changes only network/resolver plan
[ ] sensitive-env grant never restores parent env
[ ] destructive grant never widens writable filesystem
[ ] privileged-executable grant never restores privilege
[ ] ignored/generated patch grant does not bypass path/symlink/baseline checks
[ ] cross-owner/workspace/tool/mutation/replay/expiry/revocation corpus passes
[ ] real Bubblewrap A4 passes
[ ] TTY/timeout/kill/Sage/Magma/Git/LaTeX non-regression passes
[ ] Rethlas workflow/finalizer non-inheritance passes
[ ] no raw secrets or grants in evidence
[ ] stable 0.4.0 rollback and preview recutover pass
[ ] bounded A5 resource gate passes
[ ] migration event appended
[ ] final receipt appended
[ ] authority inventory updated only after cutover
[ ] run_checks.py passes
[ ] worktree clean
```

## 18. Initial Codex task prompt

Use the following as the first Codex instruction:

```text
Work only in ~/桌面/tempcoding/MTM-reboot.

Read AGENTS.md, docs/CODE_STANDARD.md, docs/COMMIT_STANDARD.md,
docs/ACCEPTANCE.md, docs/adr/0014-rust-native-permission-authority.md,
records/iterations/ITER-014.json, and
docs/MTM-014-CODEX-IMPLEMENTATION-PLAN.md before changing files.

Preserve the existing uncommitted D3 contract in:
  docs/adr/0014-rust-native-permission-authority.md
  records/iterations/ITER-014.json
  records/validation/local-validation.json

First complete section 6 of the plan only: add governance assertions for the frozen
D3 contract, run the specified gates, and prepare the contract-only commit
`docs(mtm014): freeze complete permission semantics [MTM-014]` with the required
trailers. Do not implement D3 code in that commit. Do not push, publish, install,
change selectors, restart production, alter Bubblewrap, mint safe/trusted grants, or
touch accepted MTM-013 evidence.

After the contract commit is clean and validated, proceed to D3 in the exact order
defined by the plan. Stop and record a blocked result rather than inventing a consent
mechanism or weakening an authority boundary.
```
