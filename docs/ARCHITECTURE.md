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
