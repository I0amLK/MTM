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

## Reviewed implementation and ordered host entry

The former drafts stopped at `draft_not_validated`. The first historical composed
trial was blocked by the platform, returned no execution receipt, and is not a
successful test. Following the operator's request to continue, the scripts were
reviewed and revised independently; that historical observation remains unchanged.

`scripts/mtm016-run-copy-rehearsal.sh` now has two bounded modes. `--synthetic`
creates an old-runtime-owned disposable run, then exercises the same extraction,
migration, owner authentication, one transition, restart and original-state
restoration used by the captured-state mode. `--archive-sha256` first runs that
complete synthetic mode and validates its typed report. Only its success permits
locating the previously captured archive by exact SHA. A failed synthetic leg does
not inspect the private capture or run a captured-state leg. No automatic retry,
latest-directory guess, alternative owner or alternative run is used.

From the reviewed checkout, on the capable host:

```sh
bash conformance/mtm016-copy-rehearsal-tests.sh --sqlite /home/lk/miniconda3/bin/sqlite3 &&
bash scripts/mtm016-run-copy-rehearsal.sh --archive-sha256 2d448c5ba1a6f61f8139775c254ad85316b05bf82c0ff6c9d8a0f98805893d8e --sqlite /home/lk/miniconda3/bin/sqlite3
```

The second command performs its own synthetic prerequisite; do not add another
synthetic launch before it. Production clients need not pause. Do not recapture
production, run either binary on the original data directory, or edit files while
the rehearsal runs. Both binaries and helper identities are rechecked, and the
original capture/inspection helpers are pinned without modifying them.

## Verification and limits

The conformance script accepts only an explicit SQLite executable and creates its
own temporary fixtures. It checks nested/duplicate/malformed JSON, HTTP framing and
length, MCP request IDs and boolean outcomes, registered-callback/nonce binding,
preserved-owner selection, exact transition counts, missing/extra/incorrect report
fields, rejection of non-loopback origins, and owned-child shutdown. In captured
mode, a new DCR registration, a new run, and Native tool requests are forbidden.
These primitive tests do not launch the actual candidate and cannot replace the
complete host synthetic leg. A real namespace setup failure is failed, not skipped.

The only durable writable host mount in either leg is its new private `/work`.
Production state, host network, other processes and installation selectors are not
mounted. OAuth tokens, capabilities, raw protocol replies, selected identifiers and
runtime startup logs stay under a private tmpfs scratch directory. The registered
callback is checked but never visited. The owner and registrations are preserved;
no owner rewrite, borrowed live token, direct signing, confidential-secret guessing
or newly registered substitute is permitted. Public-client authentication is a
scripted copied-state test, not a second browser or independent-human test.

The runner checks both databases again, normalizes private modes on the fresh copy
only and compares content before/after that preparation. It checks all run/owner
associations, all OAuth registration fields and the persisted OAuth signing-key
file after candidate restart, original restoration, and baseline continuation.
This key claim concerns the copied persisted key and its normal derived capability
key; it does not certify production secrets supplied exclusively through a live
process environment. Original archive bytes, modes and numeric ownership must
round-trip exactly before the restored database is opened. Mismatches block the
rehearsal; there is no user_version edit or permission relaxation to make it pass.

Native is disabled, LaTeX is static-only, and candidate and baseline endpoint facts
must agree with the selected versions and safe/disabled Native settings. Only one
explicitly non-mathematical assessment transition is submitted per leg. The selected
run must remain active and unsealed, and no final `.tex` is published into the new
workspace. No original proof is replaced. Failure leaves private copies for
diagnosis; shutdown targets only the runner's own child. An outer 240-second
deadline with TERM/KILL escalation bounds each namespace leg. The rehearsal uses
two Tokio workers and a 1 GiB virtual-address limit; these are not resource-gate
measurements or performance claims.

Success prints two `mtm-operator-copy-rehearsal-v1` reports, first with
`synthetic_only=true` and then with `synthetic_only=false`. Each strict 30-field
report still has `release_qualified=false`. Return only those reports or fixed
`MTM_COPY_REHEARSAL_ERROR` / `MTM_COPY_REHEARSAL_DIAGNOSTIC` lines. Private archives,
working databases and raw logs must not be uploaded. A later evidence review is
required before the existing Rust release adapter can validate copied_operator_state.
Neither report supplies missing independent corpus trials.

External semantics reviewed: GNU Bash signal/wait rules and GNU env signal-reset
options; curl's no-redirect, header-file, timeout and size-bound options; SQLite's
json_tree object traversal. References: https://www.gnu.org/software/bash/manual/bash.html,
https://curl.se/docs/manpage.html, https://www.sqlite.org/json1.html. They explain
mechanics, not whether the actual operator archive passed this rehearsal.
