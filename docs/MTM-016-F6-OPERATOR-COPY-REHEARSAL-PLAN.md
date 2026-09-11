# MTM-016 F6: copied-state continuation after successful preinspection

## Completed checkpoint

At `7a49ae328aadcd6b9420991f7549b40ce8fd5347` the operator supplied a
successful synthetic isolation transcript and the real copied-archive
preinspection summary. This is an operator-reported observation; the assistant
has not read the private archive or independently obtained the report's bytes.

The archive is `2d448c5ba1a6f61f8139775c254ad85316b05bf82c0ff6c9d8a0f98805893d8e`.
The extraction has 4,523 entries and 26,126,712 file bytes. Both database integrity
checks and foreign-key checks passed at schema 2. There are 133 runs, 34 active
unsealed runs, 88 sealed done runs, and 30 OAuth clients. No run lacks an owner.
All 34 active runs have public OAuth clients, including nine assess runs.
These counts do not prove availability of an eligible current task, successful
owner authentication, migration, or rollback. The remaining eleven runs are not
classified by this summary; do not assign them an inferred status.

## Next rehearsal contract, not executed

1. Use the same immutable archive, never another production capture. Verify its
   hash and provenance and extract into a new owner-private directory. The original
   state directory, live installation selectors, and host network remain absent.
2. Recheck copied database integrity. Select an existing active assess run whose
   original owner still has a public OAuth registration. Keep run and owner IDs
   private. Preserve a fingerprint of all run/owner associations, registrations,
   signing-key bytes and the initial transition sequence. A new DCR owner is not
   a substitute. Absence of a suitable original owner is a blocker.
3. Prepare ordinary private modes only on this working copy. Launch the exact
   frozen candidate with Native disabled and static-only LaTeX, on isolated
   loopback. Verify schema 7 and endpoint identity. Obtain OAuth authorization
   using the preserved public client and registered redirect, a fresh local-only
   operator password and PKCE. Do not follow an external callback. No owner-ID,
   secret-digest or registration rewrite, direct capability minting, or borrowed
   production bearer token is allowed.
4. Obtain the current task through real MCP. Advance the selected old run by one
   explicitly labelled non-mathematical lifecycle rehearsal submission, then stop.
   A conservative full-route request does not claim that the original problem has
   been assessed or proved. Verify exactly one transition, unchanged owner/run
   sets, preserved signing keys, no sealing or final proof, and restart continuity.
5. Stop the candidate before restoring the original archive to a separate clean
   working state. Compare normalized archive bytes and ordinary modes before any
   database open. Never downgrade the migrated database by editing user_version.
   Launch the pinned old runtime on the restored copy, authenticate as the same
   preserved owner, and exercise the same old run with freshly returned authority.
   Verify schema 2, the original starting state, a single new transition, and
   clean shutdown. Production originals and selectors remain unchanged.
6. Only observed success may produce copied-state acceptance evidence. A
   synthetic fixture, preinspection success or a process exit code alone does not
   satisfy the existing Rust release adapter. Neither this rehearsal nor the
   browser equality fixtures supply missing independent corpus trials.

## Draft implementation and validation boundary

`scripts/mtm016-rehearse-operator-copy.sh` and
`scripts/mtm016-run-copy-rehearsal.sh` are uncommitted drafts, not operator entry
points. Their executable entries explicitly stop with `draft_not_validated`.
The first composed syntax/rehearsal tool invocation was blocked by the platform
because its safety status could not be determined. It did not return an execution
receipt; no constituent test result or rehearsal completion is inferred. That
composed trial was not retried or routed through a different executor or the host.

Static review and future synthetic-only validation must settle process ownership,
HTTP request/reply binding, task/run binding, callback validation, strict failure
handling, source provenance, secret hygiene and exact restoration before enabling
any real-archive entry. Draft code does not change the release validator or supply
evidence that those checks passed. Keep the existing production capture and
inspection results; no operator rerun is requested for this checkpoint.
