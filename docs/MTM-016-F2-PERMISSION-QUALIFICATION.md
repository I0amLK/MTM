# MTM-016 F2: scripted permission protocol and protected-patch soak

Round 4/5 continues from `529d903`. This is a separate exact-artifact scope,
not a fallback pass for blocked Native/LaTeX/resource profiles.

Use the real disposable OAuth/MCP server, current request-scoped form-elicitation
protocol, and production `apply_patch` authority. Test no-write rejection before
consent, decline/cancel/false approval, challenge and argument binding, duplicate
grant handling, one-shot consumption, session reuse and restart invalidation.
Consent responses are scripted fixture inputs, never independent human evidence.
All patches affect fixture-owned generated paths; no production state is opened.

The dedicated `permissions` profile adds 100 one-shot grant/protected-patch cycles
spread over at least 60 seconds with a 90-second upper bound. Every cycle requires
initial rejection, explicit scripted grant, duplicate-prompt suppression, actual
changed file bytes, and a new challenge after consumption. Measure the same owned
server's RSS/threads/FDs and children after warmup and throughout the cycles.
The fixed local bounds are 8 MiB RSS growth, no extra threads/FDs, no retained
children and clean bounded shutdown. This is not an A5 baseline comparison.

Native execution stays disabled and LaTeX static-only. Protected patch writes
still pass through the production workspace permission authority. This does not
qualify command execution, seven command-risk kinds, TTY/CAS, compiled LaTeX,
network retrieval, a browser UI, or human consent. The full Native command/grant
soak remains pending. No Python file is retired merely because this scope passes.

Reports bind the explicit candidate SHA, exact check set, observed iteration/time
bounds and runtime profile. Missing/duplicate/foreign summaries, changed artifacts,
incomplete loops, leaked scope and non-boolean checks fail closed. General source
and other qualification profiles must clear the dedicated permissions flag.
Keep rejected runs immutable and seal final evidence in `ITER-016.json`.

## Operator entry and measured boundary

```sh
cargo xtask qualify --profile permissions \
  --binary target/mtm016-f1-clean-build/release/mtm \
  --sha256 496f83ba59578a61833d2bef40085bc6e5771a0d5edb0a30d5aeca7bbccc6183 \
  --record
```

No production directory, alternative duration, smaller iteration count or human
override flag is accepted. The candidate is copied to the existing private
SHA-bound snapshot and the normal bounded qualification runner is reused.
Raw tokens, consent handles, arguments and protocol output do not enter reports.

The short boundary regression also runs in ordinary source tests. Only the long
soak requires explicit selection. Each measured cycle inserts after a permanent
unique anchor: the identical patch remains syntactically applicable afterward,
so a new challenge is evidence of consumed authority rather than invalid hunks.
Warmup has five cycles. Resource samples occur between completed requests and
at the end; they are sampled maxima, not continuously monitored peak usage.
Safe and trusted modes both require protected-write consent; dangerous mode's
implicit patch policy is tested separately, without running commands.

Concurrent identical requests must have exactly one successful caller. The other
may see `PERMISSION_REQUIRED` or the prior transaction's changed-file-baseline
rejection. A subsequent sequential request must still be permission-denied.
Both client threads are joined even when one fails. No retry loop can turn an
ambiguous submission into success.

The development observation records preserve the failed incomplete-HTTP-header
fixture, the too-narrow concurrent-rejection expectation and the invalid
post-write replacement hunk. Product checks were not relaxed. The corrected
pilot completed 100 cycles in 86,851 ms with 1,376 KiB sampled RSS growth, flat
threads/FDs and no retained children. This pilot is not a post-commit gate: the
final qualifier must independently recheck the exact candidate and source hash.

Rollback is reverting the dedicated F2 test/maintenance and evidence commits.
No product dependency, public tool, runtime authority, database schema, production
selector or installed artifact is changed by this checkpoint.

The complete source gate passed format, Clippy, four installation unit tests,
six deployment CLI tests, 44 capability/recovery functions (four long/host profile
entries inert), 66 maintenance unit tests and 12 maintenance CLI tests. It remains
failed for the same ten inherited Native/Bubblewrap tests (128 Runtime passes,
one existing ignored target-only test). The byte-preserved composed report and
its unchanged source hash are sealed in the implementation receipt; they are not
relabelled as a complete host pass.

## Post-commit delivery

Commit `569229d` passed the exact permissions qualifier on the retained clean-F1
candidate SHA `496f83ba59578a61833d2bef40085bc6e5771a0d5edb0a30d5aeca7bbccc6183`.
The committed harness and original/private candidate snapshots were unchanged.
All 21 boundary checks and 100 measured changed-byte cycles passed: 86,710 ms
measurement, RSS 13,172 -> 13,992 KiB (820 KiB growth), nine threads and 16 FDs
throughout sampled checkpoints, zero retained children and 10 ms clean shutdown.
The 102,500 ms overall runner also includes setup and the boundary regression;
it is not the measured soak duration. No bound was changed after testing.

The exact report is `records/evidence/MTM-016/candidate-permissions-f2-569229d.json`,
sealed in `MTM016-F2-PERMISSION-DELIVERY`. F2 is complete only for its declared
scripted consent and protected-patch scope. It does not discharge the separate
command-grant soak, host resource comparison or independent browser/human checks.
The failed full source-gate record and development failures remain preserved.
