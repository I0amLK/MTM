# MTM

Stage E is complete for the current development contract. The E2 action-file
checkpoint keeps schema 7 and uses `mtm-tools-v9`.
All state-changing model actions now have a current-contract interruption policy:
four database-only actions commit atomically, while plans/direct proving/branch/
join/failure/replan/verification actions use explicit restartable enrollment plus
stable private file-effect evidence. `recover_only` never runs an action; corrected
resubmission reuses exact internal bytes or fails closed on drift. Historical or
unmarked unknown work remains unknown rather than being inferred. See
`docs/MTM-016-E2-ACTION-FILE-RECOVERY.md`. Development only; not release-qualified.

The current E2 mechanical checkpoint keeps schema 7 and uses `mtm-tools-v8`.
Branch preparation now uses stable identities plus one database transaction; LaTeX
result metadata and its transition commit together; exact final proof publication is
restartable and a Done reconnect may restore only the derived manual-validation
manifest. Conflicting existing private/final bytes fail closed. See
`docs/MTM-016-E2-MECHANICAL-RECOVERY.md`. Planning/direct-screening/join/verification
file-effect recovery remains pending. Development only: no deployment.

The preceding E2 action checkpoint uses schema 7 and `mtm-tools-v7`. Assessment,
exploration, proof submission/escalation and repair commit their database effects,
domain seal and transition receipt together. Explicitly enrolled interrupted actions
can be reconciled without executing them; caller writes remain retained. Branch
database sealing is also atomic, but preceding branch file effects stay unknown.
See `docs/MTM-016-E2-ACTION-TRANSACTIONS.md`. Development only: no deployment.

The preceding E2 checkpoint keeps schema 6 and uses `mtm-tools-v6`: caller
`proof_manifest` and `reference_audit` writes commit with their accepted-write
checkpoint in a single database transaction. Failed transactions preserve any
earlier retained prefix; recovery never executes the action or rewrites evidence.
Historical opaque journals and action-internal interruptions remain unresolved.
See `docs/MTM-016-E2-DATABASE-WRITES.md`. Development only; no production cutover.

The E2 caller-write checkpoint uses schema 6 and `mtm-tools-v5`. Explicit
`recover_only` may reconcile a proven retained write prefix without replaying
records or executing the action. File evidence and permanent private file locks
distinguish publication from lost acknowledgement; opaque database writes,
entered actions, conflicting bytes and legacy unknown work remain blocked.
See `docs/MTM-016-E2-WRITE-RECOVERY.md`. This development branch is not installed
or release-qualified; no previous candidate evidence qualifies schema 6.

MTM-016 Native environment diagnostics are available with
`cargo xtask native-preflight --record`. The ordinary source check includes the
probe but still runs every test when the environment is blocked. See
`docs/MTM-016-NATIVE-PREFLIGHT.md` for the real-host handoff and its limits.

> Development branch: MTM-016 (`0.6.0-preview.1`, not qualified) is in progress. See
> [the native modernization plan](docs/MTM-016-NATIVE-PLAN.md) and
> `records/iterations/ITER-016.json`. This branch is not release-qualified and
> must not overwrite the installed immutable 0.5.0-preview.2 binary. The release
> section below describes the previously accepted MTM-015 baseline. The development
> [MTM-owned tool contract](docs/MTM-016-TOOL-CONTRACT.md) removes hidden aliases and
> exposes a Rust-built directory with `mtm tool-catalog`.

The current E2 initialization-resume checkpoint uses schema 5 and `mtm-tools-v4`.
New keyed initialization can finish missing input publication and its transactional
database setup after process interruption, without replacing existing inputs,
project snapshots or references. Legacy pending creations are not automatically
enrolled. See `docs/MTM-016-E2-CREATION-RESUME.md`; arbitrary partial step/action
replay, real-host qualification and production deployment remain outside this scope.

The preceding E2 development checkpoint used schema 4 and `mtm-tools-v3`. Optional
`creation_key` preserves one intended start across a lost response; explicit
`recover_only` can resolve a still-unstarted step without executing it. Completed
transition receipts survive failures constructing the next task. Partial writes,
legacy unknown operations and unfinished initialization are never blindly retried.
See `docs/MTM-016-E2-RECOVERY.md`. This is not complete crash reconciliation,
release qualification or an instruction to open production state with this build.

The E1 development checkpoint introduces state schema **3** and `mtm-tools-v2`:
identical `rethlas_step` retries recover a durable non-authorizing submission
receipt rather than applying writes twice. Pending outcomes remain blocked; this
does not yet deduplicate run creation or reconcile interrupted submissions.
Read `docs/MTM-016-SUBMISSION-RECEIPTS.md` before using this development binary.
Do not point it at production data. Schema-2 binaries need an untouched pre-upgrade
copy for rollback; deleting receipts or decrementing a schema version is not rollback.

MTM-016 now has Rust commit-policy checks, authenticated HTTP tests and a
current-binary capability regression and independent 135-case pure-policy tests;
eleven reviewed Python files have been retired and 116 remain. See
`docs/MTM-016-PYTHON-RETIREMENT.md` for coverage and remaining limitations.
Record integrity is now consolidated in `cargo xtask records`, including archived
operator host reports that are not overwritten by subsequent sandbox diagnostics.
See `docs/MTM-016-RECORD-INTEGRITY.md` for the evidence and test boundaries.
Exact-artifact protocol checks are available with `cargo xtask qualify --profile
protocol --binary <artifact> --sha256 <digest> --record`. This selects the actual
artifact for OAuth/capability, Workspace and complete scripted workflow fixtures;
`--profile target` adds a fail-closed Native-host preflight, public Bubblewrap
execution and required compiled LaTeX on that same SHA-bound artifact. The target
profile is still not browser/resource/install/rollback or release qualification.
`--profile resource` accepts an explicit baseline artifact and measures bounded
startup/request/RSS/thread/FD/shutdown non-regression without reading or changing a
selector. Target/resource profiles require a capable Native host. See
`docs/MTM-016-CANDIDATE-GATE.md` before using the development qualification entry.
The development branch also repairs atomic patch permission preservation and numeric
schema bounds. See `docs/MTM-016-POLICY-REGRESSION.md` for the policy-test scope. These
source changes are not installed by this checkout and are not release-qualified.

The development branch also fixes lossless UTF-8 read continuations, explicit Git
repository selection, and executable checks using the requested PATH. These have
Rust regressions and a real-binary OAuth/MCP workspace smoke; see
`docs/MTM-016-WORKSPACE-REPAIR.md`. Complex shell semantics and target qualification
remain open. The installed preview.2 is not changed by this checkout.

MTM is a Rust-native mathematical research runtime with capability-gated workflows,
isolated Native tools, OAuth/MCP access, private workflow state, verifier/finalizer
gates, and a single operational CLI/TUI.

The development source gate includes a Rust-owned current-binary capability suite:
`cargo xtask capability --record`. Its disposable OAuth/socket tests cover 500
assessment first hops, negative capability cases and restart; see
[the exact scope](docs/MTM-016-CAPABILITY-REGRESSION.md). This is not release or
real-web-client qualification.

MTM was migrated from the Re-CTM 0.3.0 compatibility baseline, but it is now a
separate project with its own executable, configuration namespace, and runtime data.

Repository: <https://github.com/I0amLK/MTM>

## Current release

MTM-015 is qualified as **0.5.0-preview.2** with exact binary SHA-256
`2164c84701b191b06a66a5d28ba595697d355f9a3bdc78ca31ea455d49793d6a`.
Both ordinary `mtm` command entries select that immutable release. Qualified
**0.5.0-preview.1** remains the direct selector rollback and the immutable **0.4.0**
stable binary remains preserved as the earlier stable rollback. This is a preview,
not a new stable cut.

Preview.2 retains the qualified MTM-014 Native permission authority and adds the
MTM-015 capability-reliability repairs: non-overwriting persistent secret creation,
redacted capability diagnostics, bounded same-run recovery, permanent 500-round
current-source capability regression, and RFC 9728 path-aware OAuth protected-resource
metadata for the public `/mcp` endpoint. The exact candidate passed target and
installed-endpoint qualification, five clean real Quick Tunnel compact capability
roundtrips with zero normal `CAPABILITY_INVALID`, actual preview.1 rollback/preview.2
recutover, and a bounded post-recutover permission soak.

See [the preview.2 release contract](docs/releases/0.5.0-preview.2.md) and the exact
qualification/deployment receipts under `records/evidence/MTM-015/`. Existing
running sessions are not restarted by selector changes. On the qualified target,
restart the desired TUI with `mtm tui --quick-tunnel --native-mode dangerous` to
adopt the current selection. Magma functional use remains host-license dependent
and is not counted as a pass when the host installation rejects its license.

## Highlights

- Single Rust executable: `mtm`.
- 24 public MCP tools; this development branch removes the 11 historical hidden aliases.
- OAuth DCR, PKCE, bearer-token validation, legacy/modern MCP, and HTTP gateway.
- Capability-gated Rethlas workflow with private vault, verifier, repair, and
  mechanical finalizer.
- Native command lifecycle with bounded output, TTY, timeout/kill provenance, and
  Bubblewrap isolation on Linux.
- File, Git, image, research, LaTeX, TUI, and Quick Tunnel integration.
- No Python runtime dependency for MTM itself.
- MTM and Re-CTM can be installed on the same machine without sharing an executable,
  installation root, environment-variable namespace, or default runtime-data root.

## Platform and prerequisites

The current release is qualified on Linux x86_64. Other platforms may compile, but
they do not yet have the same target acceptance evidence.

Build requirements:

- Rust 1.85 or newer; Rust 1.98.0 is the tested release toolchain.
- Cargo.
- Git.

Runtime requirements:

- `curl` — required by the bounded research adapter.
- `bubblewrap` / `bwrap` — strongly recommended and required for the validated Linux
  Native isolation path used by `dangerous` mode.
- `latexmk` and `pdflatex` — required for the fully compiled verifier/finalizer path
  when LaTeX policy is `required`.
- `cloudflared` — optional; required only for `--quick-tunnel`.
- SageMath, Magma, or other CAS installations are optional and exposed through the
  generic read-only toolchain-root policy when configured.

Useful checks:

```bash
rustc --version
cargo --version
command -v curl
command -v bwrap
command -v latexmk
command -v pdflatex
command -v cloudflared   # optional
```

## Install

### Directly from GitHub

```bash
cargo install --git https://github.com/I0amLK/MTM.git --locked --bin mtm mtm-cli
```

Cargo normally installs the executable into `~/.cargo/bin`. Make sure that directory
is on `PATH`:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

Verify the installation:

```bash
mtm --version
mtm release-info
mtm check-config
```

Expected command identity:

```text
mtm 0.5.0-preview.2
```

MTM 0.5.0-preview.2 uses workflow protocol 3 as the production default for new runs
after the accepted MTM-011 cutover qualification. Protocol 2 remains available as an
explicit rollback selection:

```bash
MTM_WORKFLOW_PROTOCOL_VERSION=2 mtm tui --quick-tunnel --native-mode dangerous
```

Existing protocol-2/3 runs remain resumable and the final mathematical artifact remains
`proof_verified.tex`; changing the new-run default does not rewrite existing run state.

### Install from a local clone

```bash
git clone https://github.com/I0amLK/MTM.git
cd MTM
cargo install --path crates/mtm-cli --locked --force
```

## Update

For an installation made directly from GitHub:

```bash
cargo install --git https://github.com/I0amLK/MTM.git --locked --bin mtm mtm-cli --force
mtm --version
mtm check-config
```

For a local clone:

```bash
cd MTM
git pull --ff-only
cargo install --path crates/mtm-cli --locked --force
mtm --version
```

`--force` replaces the installed `mtm` binary only. MTM does not install or replace
the `re-ctm` executable.

## Start MTM

### Recommended interactive launch

```bash
mtm tui --quick-tunnel --native-mode dangerous
```

This starts the operator TUI, enables the validated Bubblewrap-backed Native path,
shows each tool once when it starts, reports failures, suppresses routine successful
completion/trace/argument-key noise, and attempts to create an owned Cloudflare Quick
Tunnel. If `cloudflared` is not available, start locally without the tunnel:

```bash
mtm tui --native-mode dangerous
```

For diagnostic sessions, `--verbose` restores the detailed redacted lifecycle view
with tool start/done/error lines, trace identifiers, and argument-key names. Argument
values and secrets are never printed:

```bash
mtm tui --verbose --native-mode dangerous
```

### Conservative local launch

```bash
mtm tui --native-mode safe
```

### Run the HTTP/MCP server directly

```bash
mtm serve \
  --host 127.0.0.1 \
  --port 8000 \
  --workspace "$PWD" \
  --native-mode safe
```

### Inspect configuration and Native isolation

```bash
mtm check-config
mtm attest-native --workspace "$PWD" --native-mode dangerous
```

When no OAuth operator password is configured, an interactive launch generates one
and prints it to the local terminal after the server has successfully bound. For
background services, configure a password explicitly instead of relying on terminal
output.

## Configuration

MTM uses only the `MTM_*` environment-variable namespace. It intentionally does not
consume Re-CTM's `RE_CTM_*` variables.

Important settings:

| Variable | Purpose | Default |
| --- | --- | --- |
| `MTM_WORKSPACE` | Native/project workspace | current directory |
| `MTM_DATA_ROOT` | Runtime state root | `~/.mtm` |
| `MTM_PRIVATE_ROOT` | Private workflow/vault root | `$MTM_DATA_ROOT/private` |
| `MTM_DEBUG_ROOT` | Debug/event root | `$MTM_DATA_ROOT/debug` |
| `MTM_NATIVE_MODE` | `safe`, `trusted`, or `dangerous` | `safe` |
| `MTM_NATIVE_EXEC_BACKEND` | `bubblewrap` or `disabled` | auto-detect on Linux |
| `MTM_NATIVE_EXEC_ALLOW_ROOTS` | Extra read-only toolchain roots | empty |
| `MTM_LATEX_POLICY` | `static_only`, `if_available`, or `required` | `required` |
| `MTM_WORKFLOW_PROTOCOL_VERSION` | Optional explicit new-run workflow protocol: `2` or `3` | `3` |
| `MTM_OAUTH_PASSWORD` | Operator password for OAuth authorization | generated interactively if omitted |
| `MTM_SERVER_URL` | Fixed external OAuth/MCP base URL | dynamic loopback origin |
| `MTM_ALLOWED_ORIGINS` | Additional allowed browser origins | empty |
| `MTM_TOKEN_SECRET` | Hex-encoded OAuth signing secret | owner-only generated file |
| `MTM_CAPABILITY_SECRET` | Hex-encoded L2 capability secret | derived/generated |
| `MTM_THEOREM_SEARCH_URL` | Fixed theorem-search endpoint | LeanSearch endpoint |
| `MTM_THEOREM_SEARCH_TIMEOUT_SECONDS` | Research timeout | `30` |
| `MTM_DEBUG` | Enable debug event recording | off |
| `MTM_TRACE_PAYLOADS` | Permit configured payload tracing | off |

Example background configuration:

```bash
export MTM_OAUTH_PASSWORD='replace-with-a-long-random-secret'
export MTM_NATIVE_MODE='dangerous'
export MTM_LATEX_POLICY='required'

mtm serve --host 127.0.0.1 --port 8000 --workspace "$PWD"
```

## MTM and Re-CTM can coexist

The two projects deliberately use different namespaces:

```text
MTM
  command:      mtm
  config:       MTM_*
  default data: ~/.mtm

Re-CTM
  command:      re-ctm
  config:       RE_CTM_*
  default data: ~/.re-ctm
```

MTM provides no `re-ctm` compatibility alias. Installing or updating MTM must not
replace the Re-CTM executable, and installing Re-CTM must not replace `mtm`.

You can verify both installations independently:

```bash
mtm --version
re-ctm --version
```

## Native security model

Rust and Bubblewrap protect different layers.

Rust owns:

- typed capability and authority boundaries;
- command policy;
- process ownership and lifecycle;
- bounded output and timeout/kill provenance;
- workflow state, verifier/finalizer permits, and private-vault access rules.

Bubblewrap remains the Linux operating-system isolation actuator for arbitrary Native
commands. It provides namespace/mount isolation and read-only toolchain exposure; it
does not grant workflow, storage, verifier, or finalizer authority.

`dangerous` Native mode therefore does **not** imply Rethlas/workflow authority.

## Engineering and acceptance

The Rust rewrite was accepted through eight recorded milestones. The repository keeps
the migration graph, implementation graph, frozen Python/Rust differential corpora,
real target evidence, rollback drills, soak results, and bounded A6 performance
evidence.

Key checks include:

- 135-case pure policy differential.
- Native lifecycle/isolation target checks with Bubblewrap, TTY, SageMath, Magma,
  timeout/kill, private-root denial, and Quick Tunnel ownership.
- 52-operation storage/capability differential and SQLite migration/rollback checks.
- 44-record OAuth/MCP differential and real Firefox PKCE flow.
- 82-checkpoint workflow/vault/verifier/finalizer differential.
- 18-checkpoint full runtime composition differential, with only the intentional
  product-identity transition from Re-CTM to MTM normalized for comparison.
- Real LaTeX/finalizer, research, packaging, TUI, Quick Tunnel, rollback, and soak
  validation.

The performance claim is deliberately narrow: it applies only to the recorded
authenticated loopback OAuth/MCP mixed workload under eight concurrent clients. It is
not a general claim about external research, CAS workloads, LaTeX, or mathematical
proof-generation time.

Run the complete local gate from a source checkout with:

```bash
python3 scripts/run_checks.py
```

See also:

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/ACCEPTANCE.md`](docs/ACCEPTANCE.md)
- [`docs/MIGRATION_PLAN.md`](docs/MIGRATION_PLAN.md)
- [`records/governance/migration-graph.json`](records/governance/migration-graph.json)
- [`records/governance/engineering-graph.json`](records/governance/engineering-graph.json)
- [`records/README.md`](records/README.md) — governance, iteration, evidence, and validation record layout

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
