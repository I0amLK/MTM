# MTM-reboot code standard

## 1. Governing order

Every decision is made in this order:

1. user-visible functionality, compatibility, mathematical correctness, and security;
2. recorded, tested, reviewable, and reversible implementation;
3. measured performance and structural optimization.

Rust is an implementation choice, not acceptance evidence. Fewer files, fewer edges,
fewer allocations, or lower latency do not compensate for changed behavior.

## 2. Scope discipline

- One commit and one review unit address one `MTM-NNN` milestone.
- Do not mix migration with unrelated cleanup, mass renaming, or formatting.
- Do not create a crate until its milestone is approved.
- Move the smallest coherent authority boundary, not arbitrary line ranges.
- A large file is an investigation signal, not an instruction to split it.
- Every behavior-changing proposal records explicit non-goals and rollback.

## 3. Rust rules

- `unsafe_code = "forbid"` is the workspace default.
- Any future `unsafe` exception requires a separate approved milestone, a safety
  argument, target tests, and a narrowly scoped module-level allowance.
- Production code must not use `unwrap`, `expect`, `panic!`, `todo!`, or
  `unimplemented!` on reachable input or runtime paths.
- Protocol, persistence, and cross-crate data use named types; raw unvalidated maps
  stop at the outer boundary.
- Unknown enum values, malformed JSON, future database versions, invalid paths, and
  stale capabilities fail closed.
- Secret-bearing types must not implement display output that reveals raw contents.
- Errors preserve stable code, category, retryability, and safe structured details.
- Resource ownership is explicit. Child processes, threads/tasks, files, locks, and
  transactions have bounded shutdown behavior.
- Locks are not held across external commands, network calls, model turns, LaTeX,
  or other unbounded work.
- SQLite transactions do not contain external I/O.
- Async is used only where concurrency or cancellation requires it; pure and local
  code stays synchronous.

## 4. Authority and shadow rules

For each component exactly one implementation may produce production side effects.

Allowed migration states:

```text
Python authoritative + Rust read-only shadow
Rust authoritative + Python bounded rollback
```

Forbidden states:

```text
Python and Rust both write production SQLite
two workflow engines both commit transitions
two finalizers can publish proof_verified.tex
authorization accepts the more permissive implementation
shadow execution makes network, file, process, or persistence side effects
```

Shadow comparison must use copied inputs and disposable state. Every mismatch is
classified before cutover as a Python bug, Rust bug, intentional approved contract
change, or unresolved nondeterminism.

## 5. Crate boundaries

The target dependency direction is:

```text
contracts
   ↓
core
   ├── storage
   ├── native
   ├── gateway
   └── workflow
          ↓
       runtime
          ↓
         cli
```

This is a dependency DAG, not a promise to create all crates immediately.

- `contracts` owns stable wire values and error/schema facts.
- `core` owns pure policy and authority-neutral domain types.
- `storage` owns SQLite schemas and transaction mechanics.
- `native` owns child processes, TTY, toolchains, and isolation.
- `gateway` owns OAuth/MCP/HTTP boundary behavior.
- `workflow` owns deterministic transition planning, verifier/finalizer gates, and
  project semantics without directly owning transport.
- `runtime` is the composition root and only orchestration layer.
- `cli` presents commands and never becomes a second authority source.

Crates may not depend upward or create a cycle merely to share helpers. Shared facts
move downward only when they are stable contracts rather than implementation details.

## 6. Data and persistence

- Preserve source database files until a migration milestone explicitly changes them.
- Production databases are never dual-written by Python and Rust.
- Every schema change is versioned, transactional, forward-incompatible fail-closed,
  and tested against copied historical databases.
- Immutable claim revisions, proof manifests, reference audits, and final artifacts
  remain immutable under retries.
- Serialization used in signatures, hashes, manifests, or comparison fixtures is
  deterministic and versioned.

## 7. Security

- L0 OAuth, L1 Native, L2 workflow capability, and project/finalizer authority remain
  independent.
- Native `dangerous` never grants workflow or project authority.
- The private vault is absent from arbitrary native command namespaces.
- Capability handles remain opaque and are compared with constant-time primitives
  where secret equality matters.
- Generated OAuth keys, tokens, capabilities, private problem/proof text, and secret
  environment values never enter logs, receipts, or public artifacts.
- Security check order is behavior. Reordering requires negative tests.

## 8. Testing

- Fixes add regression tests with the implementation.
- Pure functions get unit and property tests.
- Protocol and persistence behavior get golden and differential tests.
- Permission, path, capability, transaction, and finalization work includes negative
  tests.
- Mocks do not prove browser, Bubblewrap, CAS, external network, or real LaTeX behavior.
- Every milestone runs its acceptance commands and the complete local gate.

## 9. Performance

- Performance is considered only after functional parity and safety gates pass.
- Benchmarks record environment, input size, warmup, repetitions, median, p95/p99,
  RSS, threads/processes, and resource bounds.
- A Rust implementation without an equivalent baseline cannot use a performance
  claim or `perf` commit type.
- A regression may block cutover even when correctness tests pass.

## 10. Completion

A milestone completes only when its acceptance levels pass, records are appended,
authority is explicit, rollback is proven or documented, and all remaining manual
checks remain honestly pending.
