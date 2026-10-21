# MTM-020: minimal domain ID entropy patch

The operator approved verification followed by the one-line patch on 2026-10-21.
Only WorkflowEngine::ensure_domain changes in production: token_hex(3) becomes
token_hex(16), widening the random suffix from 24 to 128 bits. Role, state and
epoch prefixes, uniqueness constraints, failure behavior and existing-domain reuse
remain unchanged. No run ID prefix, retry, schema migration, dependency, tool or
capability format change is introduced. MTM-019 TUI changes remain separate.

## Verification

A deterministic regression first runs against the unchanged 24-bit code. Two
independent runs share a three-byte random suffix. The first receives its assess
task; the second fails with SQLITE_ERROR and the domains.domain_id unique
constraint. The same test passes after widening the suffix: the full 128-bit IDs
differ even though their trailing three bytes are identical.

The older forced-collision recovery test continues to force a full-width collision.
Its test ID source is adapted for the 16-byte domain request and the existing
16-byte step execution request. It still checks the completed receipt, zero-write
replay, preserved other-run domain and separate next-task recovery. Increasing
entropy does not remove uniqueness checks or promise recovery from a deliberately
broken random source.

A separate compatibility test inserts a legacy six-hex-character domain into a
disposable database, issues its capability, reopens the database, submits that old
capability, obtains a new full-width domain and replays the exact completed receipt
without repeating writes. Existing domain IDs and capabilities are not rewritten.

The real socket/OAuth 500-round capability gate is run without weakening its
assertions. Full source validation retains all failures, including the previously
observed readiness test's dependency on unavailable historical target artifacts.
An initial compatibility fixture incorrectly used assessor instead of the actual
generator role; its failed log is retained and only that fixture is corrected.

This proves one reproducible cause of initial-assessment failure and mitigates
random collisions. It does not retrospectively attribute the earlier uncaptured
223-round failure to that cause or claim mathematically impossible collisions.

## Boundaries and rollback

The patch uses the existing host tool cache at target/mtm-tool, explicitly selected
for every Cargo command; the unavailable /workspace mount is not synthesized.
All test databases, authentication and workspaces are disposable. No installed
binary, running service, operator database, historical receipt or acceptance count
is changed. No release, deployment or performance claim follows.

Rollback restores token_hex(3) and the related test source while retaining these
observations; no database rollback is required. Detailed results live under
records/evidence/MTM-020/ and records/iterations/ITER-020.json.
