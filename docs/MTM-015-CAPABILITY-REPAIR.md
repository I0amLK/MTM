# MTM-015 capability reliability repair candidate

Status: registered MTM-015 source candidate in progress; locally qualified, but not a qualified release, deployment, or completed milestone.

Target qualification is intentionally two-phase. The source repair is frozen at
`94e7bde4a9a0db30fe6459ce4352e3d6661c7384`; a separately committed runner and
validator must execute from a clean tree before `records/evidence/MTM-015/target-qualification.json`
may exist. The runner builds into an isolated target directory and does not install or
select the candidate binary.

The committed target harness at `e4bc7d447eb4e2d3c0b0a14c1f3f4bf08b2ccb36`
has now passed 14/14 checks for candidate SHA-256
`7f869fc867a7c2575ad68d65956bc34f2cda26bc42b4878c20ff0d75cc42decd`.
This includes same-key restart continuity, deliberate changed-key rejection for the same
OAuth owner with zero writes, redacted signature-stage diagnostics, required-LaTeX full
and compact workflows, copied-state compatibility, bounded resource non-regression, and
a 60-second permission soak. It still does not claim a real web client, an installed
MTM-015 endpoint, or selector cutover.
Base: `3254e54465f9f10a449f3a6d5877c846a4319773` (`0.5.0-preview.1`).

## Scope and invariants

The candidate changes secret-file initialization, opt-in diagnostics, operator
outcome classification, a JSON ownership/copy path, and regression tooling. It does
not add a crate, public MCP tool, hidden alias, workflow state, database schema,
model provider, or background agent. Signature/registry/owner/run/role/epoch/state
checks and their order remain unchanged. Native permission is not workflow authority.
No invalid token authorizes a write. No submission is automatically replayed by
the server. Historical receipts, frozen harness bytes, production data and binary
selectors are not rewritten.

## R1: non-overwriting secret initialization

The previous `exists -> generate -> rename -> return local candidate` sequence can
return different keys to simultaneous first starters. Ordinary restart with an
existing unchanged key is not this race. This candidate creates a unique owner-only
same-directory staging file with `create_new`, fully writes and fsyncs it, then uses
`hard_link` as the non-overwriting publication step and reads the persisted winner
even after losing the race. The staging name is removed on both winning and losing
paths. `tempfile` remains a test-only dependency, so the runtime dependency boundary
does not widen. Invalid, empty, and symlink key files are rejected, not silently
regenerated. Concurrent application processes sharing a state database still need to
obey the project's single-writer deployment policy.

The repair prevents this specific first-creation race. It does NOT establish that
this race caused the user-reported same-run failure, and does not reconcile running
processes that already hold different keys. Do not delete/regenerate production
keys as a diagnostic shortcut. Filesystem directory protections remain a prerequisite;
the regular-file check is not a defense against a malicious process with the same
OS user modifying the private directory.

## R2: diagnostic evidence, not guesswork

`MTM_DEBUG=1 mtm tui --verbose ...` enables a separately classified diagnostic event
through the existing observer. It reports only the complete token SHA-256, byte
length, domain-separated HMAC signer identifier, random authority-instance identifier,
trace identifier, and failure stage. No key, token body/signature, proof, or raw tool
arguments are written by the new diagnostic path. Existing audit events are retained.
Diagnostics are off by default; normal conformance events are unchanged when off.
A `serve` application without an event observer does not acquire an implicit logger.

Interpret comparisons only when issuance and submission have been correctly paired:

* Different bytes: changed token OR different token selection OR a missing issuance
  record. This alone does not identify an HTTP, model, or serialization defect.
* Same bytes, different signer identifiers: investigate endpoint/instance/key
  configuration. The same key can legitimately have different instance identifiers.
* Same bytes and signer: inspect the failure stage and exact binary. INVALID also
  covers unsupported/malformed signed payloads and claims, not just bad HMACs.

Unsigned context is not treated as trusted identity. The existing owner/run check
still determines whether a fresh task may be returned. Diagnostic identifiers are
correlation data, never substitute credentials.

## R3: distinguish authorization, submission and transport outcomes

Compact output retains low-level capability denials but labels them
`authorization check denied`, with a trace, rather than calling them runtime crashes.
A returned fresh task generates `tool.call_submission_rejected`, not an unconditional
`tool.call_finished`. The operator is told that the original logical submission was
not applied and must be resubmitted. A fresh-token notice is emitted only when a
nonempty capability is actually present and zero logical writes/no retained writes
are reported. Genuine final failures include their safe error code. Other security
denials are not suppressed. No unbounded correlation cache or event worker is added.

`writes_applied=0` means no logical writes from that submission; it does not mean
that capability issuance, audit records, or every database/file operation is absent.
Nor does a failed authorization imply that a theorem is false or a proof has a gap.

## R4: bounded caller recovery

`scripts/capability_recovery.py` is a reusable test/client helper, not a new server
protocol and not an automatic patch to a web-model client. Its callback must be bound
to one endpoint and OAuth owner. Cursors are task/run scoped. It adopts a fresh
same-run task only for the existing INVALID + recoverable + retryable + zero-write
contract. It rebuilds arguments from that task, permits one retry, and stops after a
second rejection. State, role/domain/epoch or task-contract changes require inspection,
not blind replay. Retained/unknown writes, revoked tokens, and cross-run responses
are not automatically retried. Other runs and branches are not globally discarded.
Client-side replacement does not assert server-side revocation of every old token.

## R5: permanent current-binary gate

`scripts/check_capability_current.py --build --samples 500` rebuilds the current CLI
and runs the unmodified MTM-013 mutation/truncation/fresh-resubmission/cross-run/
cross-owner/revocation corpus on disposable loopback state. It then runs 500 fresh
run/first-transition roundtrips with programmatically copied envelopes. Any INVALID
or refresh on that normal path fails the gate. It uses the existing target directory
rather than creating a second permanent build tree. The script is unconditionally
wired into the Rust-available branch of `run_checks.py`; a different milestone does
not skip it. A build failure does not fall back to an old executable.

This is NOT 500 consecutive research steps in one run, and NOT a web-model, tunnel,
LaTeX, or target deployment test. These target tests remain required. Counts, binary
and source hashes go to a regenerable record under `records/validation/`, not over a
historical accepted receipt. Frozen harness stdout/errors are not dumped into evidence.

## R6: JSON ownership optimization

`tool_result` moves its owned structured payload into the response instead of deep
cloning it. Wire fields, error flags, image extraction and summary text remain the
same. Added tests cover a large nested payload, image output, error output, and
nonobject normalization. No speedup, RSS improvement, or research-efficiency result is
claimed until parity and measured A5/A6 evidence exist.

## Required validation before any deployment

Run format, warnings-denied Clippy, complete workspace tests, the current-binary gate,
and the original local gate. Do not bypass old qualification checks merely because
source hashes changed. Register/validate the new milestone's governance records and
obtain fresh candidate evidence instead of relabeling historical receipts.

Real acceptance must additionally bind the actual running binary and endpoint;
compare issued/submitted fingerprints under loopback and the actual web client;
exercise same-key restart, deliberate changed-key rejection, independent instances,
cross-run/owner, expired/stale/revoked tokens, and concurrent interleaved logs; verify
compact/full proof workflows with required LaTeX; and perform copied-state rollback
and recutover. Never record raw capabilities. Deliberate corruption must remain denied.
A normal-loop zero failure count is bounded evidence, not a proof of zero population
failure probability.

## Rollback and release decision

This bundle only changes source files. It never switches binaries. `apply_mtm015.py
--reverse` can reverse its exact output before subsequent edits/formatting. It refuses
to overwrite later user changes. After additional edits, use a reviewed Git diff or
revert a dedicated commit rather than a forced reset. Keep the previous qualified
binary and its key/state configuration. Do not replace an immutable release under
its old qualified name. No version bump or stable/RC publication is performed here.

Tokio blocking isolation, SQLite reader-pool changes, compatibility removals, broad
validation-framework restructuring and research-efficiency claims are deferred until
this reliability work has passed its own gates. The verifier/finalizer remains a
workflow review/publication gate, not a newly added formal mathematical proof kernel.
