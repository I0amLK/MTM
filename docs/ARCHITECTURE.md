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

## Implemented through MTM-004

The current Rust graph now has four implemented lower-level components:

```text
             mtm-contracts
              ▲         ▲
              │         │
           mtm-core  mtm-storage
              ▲
              │
         mtm-native
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

## Implemented slice after MTM-002

`mtm-contracts` and `mtm-core` now form the implemented bottom of the dependency DAG:

```text
mtm-contracts
      ▲
      │
  mtm-core
```

They own only stable wire facts and pure bounded policy. They have no database,
process, network, workflow-transition, vault, or finalizer authority. The standalone
CLI evaluator exists solely for golden and differential testing against the frozen
Python source. This keeps the first Rust authority boundary coherent without making
the CLI or conformance harness a production composition root.
