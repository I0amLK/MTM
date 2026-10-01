# MTM-017: evidenced correction after a denied caller write

## Scope and diagnosis

The operator requested this combined source repair through CTM on 2026-09-30.
It preserves the strict flat-schema repair described in
`MTM-017-STEP-SCHEMA-COMPATIBILITY.md`. No installation, service restart, live
database inspection, live proof read, state reset, publication or credential
change is part of this repair. Tests use synthetic disposable state only.

The submission backend first authorizes `commit:workflow`, then reserves and
activates a durable receipt. Each caller write separately checks its resource
ACL before any write effect. A `ROLE_ACCESS_DENIED` at this boundary previously
escaped without a correction result, so the receipt remained pending and the
outer handler returned `RESULT_UNKNOWN`. The same request could already have
completed earlier writes. Neither the denial nor a zero-write assumption is a
safe substitute for durable prefix evidence.

The observed old installed executable had SHA-256
`a7fa07d0401566bf8fa0eca1b3e7e921203d5970df109f435c324e90a9df9849`.
It was not the earlier source-only schema repair artifact. The observed
denial/unknown sequences with traces `9QRshT8_xuIN7zCZC46vdQ` and
`seDyiQLCHny6af2E5EQ-pw` are consistent with the source defect, but their exact
run, resource and retained prefix remain unidentified. The isolated unknown
traces `-lVUIu_VJV8H0p7NPXe2Xw` and `ARyEVy3-1JuVl7yIzRjywA` do not establish
this cause. `Hw5xiqGmBZqcZxXA0_THCw` was an inspect denial and is not evidence
of a permission bug. The user subsequently supplied the safe
`INVALID_PROOF_FACTS` message `the final fact must state the proof target` and
failed resource `proof_manifest`. This identifies final-target equality as the
violated constraint, without requiring proof content.

A later owner-status observation of the identified run showed assemble/active,
sequence 2, and a pending commit-ready `proof_submitted` atomic action with an
accepted caller-write lower bound of zero. It advertised atomic-action recovery,
but not caller-write reconciliation or automatic retry. A failed manifest write
returns before commit is armed, so these observations cannot be attributed to
the same request. No original submission was available and no live recovery was
attempted. No historical failure is relabelled as passed.

## Minimal behavior repair

Only a caller-write error with category Permission and code
`ROLE_ACCESS_DENIED` is newly eligible for the existing correction path. The
global Validation/Conflict predicate and commit-stage handler are unchanged.
Other permission failures, including invalid/expired/revoked capabilities,
owner mismatch and authority drift, do not acquire this exception.

Eligibility does not prove completion. Before issuing a fresh task or revoking
the submitted capability, `record_submission_outcome` must verify the enrolled
journal is Between and its durable accepted-write count equals the reported
prefix exactly. Outstanding File/Opaque effects, corrupt journals and count
mismatches cannot be completed through an error classification. Failure to
record an evidenced outcome still returns `RESULT_UNKNOWN`.

A completed denial returns unsuccessful correction status, the failed write
index/resource, and an explicit retained prefix length. Corrected submission
must use the returned current capability and omit already retained writes.
Identical replay returns its non-authorizing historical receipt with zero new
writes, including after restart; `ROLE_ACCESS_DENIED` keeps its Permission
category on replay. Owner/run/workspace binding, request idempotency, role
firewalls and the existing receipt limits remain in force.

This prevents false-unknown classification for future evidenced denials. It
does not clear or certify old pending submissions. Existing unknown work still
requires the exact original submission and the existing evidence-based
`recover_only` flow; recovery must not replay writes or execute a missing action.
No data deletion or production reset is needed or authorized.

## Missing-manifest prerequisite after a failed write

A separate disposable real-MCP diagnostic reproduced this sequence before its
repair: reject the explicit fact target while retaining the proof file; use the
fresh capability for zero-write `proof_submitted`; receive `RESULT_UNKNOWN`
with cause `PROOF_MANIFEST_NOT_FOUND`, leaving assemble/commit-ready/
`proof_submitted`/accepted-writes-zero. Its retained log is
`target/mtm-tool/submission-missing-manifest-diagnostic.log`. This establishes a
possible mechanism, not the request history of the live run.

The required-manifest read in `commit_proof_submitted` occurs before transition
effects. Only its exact NotFound/`PROOF_MANIFEST_NOT_FOUND` error is mapped to a
Validation correction with guidance to write the missing manifest and preserve
the earlier proof. The error code is retained. Storage/direct-read NotFound
semantics and every other missing/corrupt/input/IO/SQL error are unchanged.
Durable Between/count proof is still required to complete the correction. No
general NotFound recovery or automatic atomic-action retry is introduced.

The regression now verifies this sequential omission yields a completed
zero-write correction, unchanged state/sequence and no pending receipt; after
restart, exact replay remains non-authorizing, and writing only a valid manifest
continues using the retained proof. Separate injected atomic transition failures
remain unknown until explicit evidenced recovery without action execution.

## Fact guidance, without weaker validation

`INVALID_PROOF_FACTS` is an existing correctable validation error, not a proven
validator defect. The task's optional fact schema previously omitted several
enforced requirements. It now discloses unique ASCII keys and their bound,
ordered predecessor requirements and bounds, glossary/intuition/text UTF-8 byte
limits, the whitespace-normalized final-target equality, and verbatim inclusion
of declared statements/proofs in the final verified proof. JSON Schema character
limits are not presented as equivalent to UTF-8 byte limits.

The fact validator, fact promotion, predecessor resolution, finalizer and role
ACL implementation are unchanged. Omitting the optional breakdown continues to
use the whole verified proof as one target fact; it does not bypass proof
verification or grant intermediate facts.

There is no new dependency, runtime language, public tool, state schema or
workflow protocol. This is the same schema-8 / protocol-3 / `mtm-tools-v10`
preview version; artifact hashes distinguish the combined repair.

## Verification and remaining acceptance

New disposable real OAuth/MCP tests cover a denied first write, retained memory,
retained proof-file plus manifest-database writes, exact replay/restart,
correction without duplicate writes, foreign-owner/request-change rejection,
and unchanged guarded reads. A malformed explicit fact target remains a
correctable `INVALID_PROOF_FACTS`, preserving the earlier proof write. Storage
regressions reject a denial summary for Opaque/File/corrupt journals or an
incorrect prefix count. The old unknown regression now injects an actual file
publication/checkpoint failure rather than treating a resource denial as
evidence of uncertainty. Other capability and action tests remain in the full
source gate.

The initial focused run retained two test-fixture failures in
`target/mtm-tool/submission-correction-focused.log`: it incorrectly tried an
assembler proof read and submitted the instructional placeholder as a compilable
proof. The tests now preserve the assembler read denial, independently observe
only disposable test files/database rows, and reuse the existing valid lifecycle
proof fixture. No role or LaTeX check was weakened to make them pass.

The first combined source run is retained in
`target/mtm-tool/submission-correction-source-check.log`. It found one additional
legacy E2 fixture that used a role denial to manufacture an unknown result.
That fixture now injects a transaction failure beginning the second legal write,
preserving a durable Between checkpoint after exactly one write. It still
requires missing-receipt recovery to execute nothing, explicit recovery to
preserve unchanged first-write content, the second record to remain absent, and
no workflow transition. The failure was not suppressed or converted into a pass;
the revised source receives a separate full gate.

The second full run is retained as `submission-correction-source-check-r2.log`;
it found an over-specific test assumption that the task's default assessment
template contained one write. The final fixture explicitly selects one valid
server-issued first record before adding the interrupted second record. Exact
prefix/content/sequence assertions remain unchanged. The final focused E2 suite
is rerun on that exact input before the final full gate.

The final `cargo xtask check` passed on 2026-09-30: format, workspace all-target
Clippy, 721 passed / 0 failed / 1 inherited ignored, record/architecture/
retirement checks and diff checks. This includes the current-binary
500-assessment capability regression. The before/after `mtm-rust-source-v1`
identity was
`eb4a852f1f334c131fdd26fd6a88eb07e4fb77be3272e405450c69540a7bd136`.
The final log `target/mtm-tool/submission-correction-source-check-final.log`
has SHA-256
`98987295fcca6e8ae6f0de261c48d9b27111beff570641574863d76e10aba3fa`.
Independent source/result review found no remaining blocking findings.
These checks do not establish refreshed external connector acceptance,
resolve unidentified live traces, or extend any sealed release qualification.
The user will install the combined build separately. Verify its exact hash and
rediscovered catalog, then test a disposable run using the current task contract
and check receipt/state progression. The unchanged preview version alone cannot
identify this patch.

The final optimized build is preserved at
`target/mtm-tool/submission-correction-release-20260930-1740/mtm`, SHA-256
`1144b249d9621e762d5142a63816290f3b5132ecc52924f88c3e1b94f8a2610e`.
It is a regular, single-link 13,880,856-byte file with mode 0500. `release-info`
confirms Linux x86_64, 24 tools, schema 8, protocol 3, `mtm-tools-v10` and
`0.6.0-preview.2`. The catalog is byte-identical to the preceding schema-only
repair artifact, with fingerprint
`7dc1cc9f60f7281ca8a23f949e4ec67d2977609e690e0bc0f9ad20fe2e60a7a5`;
the binary hash distinguishes this additional submission repair. Build output is
retained in `target/mtm-tool/submission-correction-release-build.log`. No
installation or live-run recovery was performed.

Rollback is to revert this source repair and rebuild; there is no storage schema
migration. Old binaries can read the unchanged receipt schema, but retain their
old denial classification behavior. Preserve all prior artifacts and evidence.
