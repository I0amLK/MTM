# MTM

MTM is a Rust-native mathematical research runtime with capability-gated workflows,
isolated Native tools, OAuth/MCP access, private workflow state, verifier/finalizer
gates, and a single operational CLI/TUI.

MTM was migrated from the Re-CTM 0.3.0 compatibility baseline, but it is now a
separate project with its own executable, configuration namespace, and runtime data.

Repository: <https://github.com/I0amLK/MTM>

## Highlights

- Single Rust executable: `mtm`.
- 24 public MCP tools plus 11 hidden compatibility aliases.
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
mtm 0.4.0-preview.3
```

MTM 0.4.0-preview.3 uses workflow protocol 3 as the production default for new runs
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
- [`migration-graph.json`](migration-graph.json)
- [`engineering-graph.json`](engineering-graph.json)

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
