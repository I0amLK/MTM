# MTM-reboot architecture

## Functional architecture first

The target architecture preserves Re-CTM's functional planes rather than mirroring
its Python files one-for-one.

```text
client / operator
        │
        ▼
OAuth + MCP gateway
        │
        ├──────────────► Native authority ─► isolated worker
        │
        └──────────────► Workflow transition kernel
                                │
                   ┌────────────┼────────────┐
                   ▼            ▼            ▼
              capability     state store   private vault
                   │                         │
                   └────────────┬────────────┘
                                ▼
                       mechanical finalizer
```

## Intentional choke points

- Native isolation remains an explicit process/security choke point.
- Workflow transition planning remains a single logical authority.
- Final artifact and VERIFIED/CONDITIONAL publication remain a single mechanical
  authority.
- Contract types are high fan-in by design, but contain stable facts only.

## Avoided accidental hubs

- The CLI does not import every implementation component directly.
- The workflow kernel returns transition plans instead of performing transport,
  arbitrary process, or long-lived network work itself.
- Storage exposes transactions and typed repositories rather than becoming a general
  utility module.
- Observability receives redacted events and cannot authorize or mutate behavior.

The machine-audited target graph is [`engineering-graph.json`](../engineering-graph.json).

## Implemented through MTM-006

The current Rust graph now has six implemented authority components:

```text
                    mtm-contracts
                 ▲       ▲        ▲
                 │       │        │
            mtm-core  mtm-storage │
              ▲          ▲        │
              │          │        │
         mtm-native  mtm-workflow │
                              mtm-gateway
```

`mtm-native` keeps two intentionally separate runtime choke points:

```text
command manager ── bounded helper-v1 request ──► Bubblewrap helper process
```

The command manager owns command ids, TTY, output paging and termination provenance.
The helper owns namespace construction, environment clearing, read-only toolchain
mount validation and attestation. Neither component can read or write workflow state,
authenticate a client, or publish a verified artifact.

`mtm-storage` owns the schema-2 SQLite boundary, migrations, typed repositories,
project/claim/reference provenance, optimistic promotion and capability signing plus
registry validation. Its authority rules are:

```text
one connection mutex per store
        +
BEGIN IMMEDIATE for every multi-step write
        +
no network, child process, model, LaTeX, or vault I/O inside transactions
        +
one deployed production writer
```

Python and Rust are compared only on independent copies. The current Re-CTM Python
runtime remains the deployed writer; `mtm-storage` is authoritative only inside the
new project until the gateway and workflow composition milestones make a separately
accepted cutover possible.

`mtm-gateway` owns OAuth DCR/PKCE/code/token behavior, HTTP routing and Origin/CORS
policy, legacy/modern MCP envelopes, mirror-header checks, and tool dispatch. It
accepts a tool catalog only when the public order, hidden aliases, and both frozen
definition hashes match Re-CTM 0.3.0 exactly. The gateway calls a `ToolBackend` trait;
it cannot implement Native/workflow semantics, write workflow state, access the
private vault, or publish verified artifacts.

During migration, conformance tooling still regenerates the catalog independently
from the frozen source files. The MTM-007 release binary now embeds the separately
verified catalog and methodology assets; Rust validates the immutable catalog hashes
at startup and never invokes Python to build its production catalog.

`mtm-workflow` owns one deterministic transition authority, the logical private
vault, verifier computation, repair/escalation, and the mechanical finalizer. It
depends directly on `mtm-storage` deliberately: a validated L2 capability becomes a
private-field `CapabilityClaims` value rather than being converted back to an
untrusted role/state string. `FinalizationPermit` is crate-private to the verifier
module and has a private constructor; sibling modules cannot mint it. The vault
re-hashes the current proof before publishing `proof_verified.tex`, so verifier
approval cannot be replayed after draft mutation.

The workflow library has no network, async-runtime, Native-process, or gateway
dependency. MTM-007 keeps production `latexmk`/`pdflatex` and fixed-provider HTTPS
research in `mtm-runtime` behind the `LatexGate` and `ResearchProvider` traits; the
workflow crate therefore gains functionality without acquiring process or network
authority. This intentionally keeps the authority graph stronger even though it adds
explicit composition edges in `mtm-runtime`.

## Implemented slice after MTM-007

Seven of the eight workspace crates are now implemented, while `mtm-contracts`
remains the stable bootstrap contract floor:

```text
mtm-contracts
      ↑
   mtm-core
   ├── mtm-storage
   ├── mtm-native
   ├── mtm-gateway
   └── mtm-workflow
          ↑
      mtm-runtime
          ↑
        mtm-cli
```

`mtm-runtime` is the only allowed broad composition root. `mtm-cli` depends only on
contracts/runtime plus serialization and therefore cannot become a second authority
source. `OperatorSession` receives redacted events and owns no store, capability,
vault, or workflow object. Deployed Re-CTM traffic remains Python until the dedicated
MTM-008 authority-transfer commit.

MTM-008 adds a separate deployment authority graph. A user-visible `re-ctm` symlink
is an atomic selector whose only accepted sources are a hash-verified Rust release or
the recorded Python rollback release. Python production retirement is forbidden until
wheel restoration, command rollback, Rust recutover, soak, and A6 qualification have
all passed. Historical Python source remains a non-production reference after
retirement.
