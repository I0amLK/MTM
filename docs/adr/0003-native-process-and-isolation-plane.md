# ADR 0003: Preserve the Native process and Bubblewrap choke points in Rust

Status: accepted for `MTM-003`

## Context

The source runtime separates two different responsibilities:

1. a long-lived command manager owns command ids, TTY input, output retention,
   polling, timeout, explicit kill, and parent-shutdown provenance;
2. a separate helper process validates a bounded JSON request and creates the
   Bubblewrap namespace in which arbitrary Native commands execute.

Combining these responsibilities merely because Rust can own both would remove an
intentional security boundary. Replacing them one file at a time would also create
fine-grained Python/Rust calls across live process state.

## Decision

- `mtm-native` owns a Rust `CommandManager` with one process group per command,
  bounded head-plus-rolling-tail output, retained paging, TTY input, timeout, kill,
  and shutdown provenance.
- `mtm-native-helper` remains a separate executable using the source
  `re-ctm-native-helper-v1` protocol. It clears the parent environment, constructs
  the Bubblewrap namespace, validates read-only toolchain roots, and emits bounded
  structured results.
- The command manager may launch a Bubblewrap command, but it does not absorb the
  helper's request validation or attestation authority.
- TTY support uses the target's `script(1)` pseudo-terminal wrapper rather than an
  `unsafe` Rust PTY implementation. Python/Rust lifecycle differential tests and a
  real isolated TTY round trip are required before accepting that adapter.
- Quick Tunnel remains an explicit owned-child adapter. Close is idempotent, emits
  one terminal event, and terminates only the child process group created by the
  current session.
- `mtm-native` is authoritative for the new MTM-reboot Native component after A0–A5,
  while Re-CTM's Python runtime remains the deployed production authority until a
  later composition/cutover milestone.

## Evidence

- The frozen Python/Rust Native corpus compares exact toolchain and Bubblewrap
  construction plus semantic command lifecycle results with zero mismatches.
- The current Linux target passes real Bubblewrap attestation, private-root denial,
  parent-environment clearing, generic explicit tool execution, read-only mounts,
  SageMath, Magma, timeout, TTY, explicit kill, and Quick Tunnel ownership checks.
- Python and Rust helper responses match for attest, normal execute, and timeout
  after removing only elapsed-time fields.

## Consequences

- The separate helper bridge remains an intentional graph edge and security choke
  point.
- No SQLite, OAuth, MCP, workflow, vault, or finalizer authority moves in this
  milestone.
- Other operating systems and proprietary toolchain layouts remain later target
  acceptance work; one passing Linux target is not universal evidence.
