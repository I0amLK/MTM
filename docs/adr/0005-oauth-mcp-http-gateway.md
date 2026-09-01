# ADR-0005: OAuth, MCP, and HTTP gateway authority

## Status

Accepted for `MTM-005`.

## Context

Re-CTM's public boundary combines OAuth dynamic client registration, Authorization
Code + PKCE, signed bearer tokens, fixed or reverse-proxy-derived issuer origins,
HTTP/CORS policy, two MCP protocol eras, an exact public tool catalog, hidden legacy
aliases, and dispatch into Native or workflow authorities. Migrating this boundary
must not accidentally move workflow semantics, weaken authentication, or create a
second state writer.

## Decision

`mtm-gateway` owns only the public transport and authentication boundary:

- OAuth DCR, PKCE S256, single-use codes, three token endpoint authentication modes,
  HMAC access tokens, metadata, and bearer validation;
- loopback-only dynamic issuer discovery and fixed-origin precedence;
- HTTP request limits, content types, Origin/CORS rules, OAuth challenge headers, and
  modern HTTP status mapping;
- legacy MCP (`2025-11-25`, `2025-06-18`) and modern MCP (`2026-07-28`), including
  `_meta`, mirror headers, notifications, discovery, list, and call envelopes;
- a `ToolCatalog` that fails closed unless all 24 public names, 11 hidden aliases,
  public catalog hash, and all-definition hash match the frozen Re-CTM 0.3.0 facts;
- a `ToolBackend` trait for dispatch. The gateway cannot implement the called tool.

OAuth uses its separate OAuth database, as in the source implementation. The gateway
does not depend on `mtm-storage`, `mtm-native`, or the future workflow crate and cannot
write workflow state, read the private vault, or finalize an artifact.

During migration, target and conformance tools generate the catalog snapshot from the
frozen source files and Rust verifies its immutable hashes. Bundling that verified
asset belongs to the distribution milestone; the production gateway will never invoke
Python to construct its catalog.

## Evidence

- 44 deterministic source/Rust records with zero differences;
- exact public and all-definition SHA-256 checks;
- eight Rust unit/security tests for OAuth, PKCE, catalog, MCP, Origin, and issuer
  boundaries;
- 15 implementation-hash-bound target checks using the real Rust server and Firefox,
  including browser form submission, DCR/PKCE/token exchange, code reuse denial,
  legacy/modern MCP, hidden aliases, CORS, mirror headers, and fixed/dynamic origins;
- source Re-CTM OAuth/MCP/HTTP test modules passed before acceptance.

## Consequences

The new project has one Rust gateway authority, but deployed traffic remains on the
Python runtime. Rollback is routing-only because no workflow database or artifact
format changed. `MTM-006` may compose the gateway with Rust workflow semantics only
after its own trace-replay and finalizer gates pass.
