# MTM-017 exact-artifact qualification

## Scope

This is forward qualification of the schema-8 implementation, not another
MTM-016 deployment. The historical release and its stale lifecycle summaries
were reconciled separately in `docs/MTM-016-LIFECYCLE-RECONCILIATION.md`.

The optimized qualification snapshot was built with
`cargo build --release --locked --offline -p mtm-cli`, Rust 1.98.0, and the
existing `target/mtm-tool` cache. Its Rust source identity is unchanged from
development closeout:
`61922484c1f969365660b052ab878250738542bf25bd870f40b3b6851ef1930d`.

The snapshot SHA-256 is
`20e5178bfb0b31633747b18343c92cc5f7f3e6e72680e586211416a9c25702b0`.
It is retained under `target/mtm017-qualification/` in the digest-addressed
directory created by `cargo xtask dist`. Its own `release-info` and `contract`
commands report schema 8, `mtm-tools-v10`, protocol 3 and 24 public tools.

The package still reports `0.6.0-preview.1`. The released schema-7 artifact has
that same label but a different digest, `f59cbdda...88034`. Therefore this is a
qualification-only snapshot, not an installable replacement under the published
version name. A distinct release version, rebuilt artifact and appropriately
rebound qualification are required before publication. The byte-staging command
does not verify version semantics or authorize installation.

## Completed machine-executed profiles

The current Rust qualifier was invoked with the explicit snapshot path and hash.
The raw reports retain their inherited `MTM-016` runner label and are archived
byte-for-byte under `records/evidence/MTM-017/artifact-*-20e5178.json`. Their
candidate digest and harness source identity, rather than that historical runner
label, identify the actual execution. No old report was relabelled or reused.

| Profile | Executed scope |
|---|---|
| `protocol` | Exact-binary 500 independent assessments, zero normal INVALID/rejections, eight adversarial checks, restart/lifecycle and workspace/Git regressions. |
| `native_commands` | Dangerous-only isolation, seven command risk classes, 32 cycles, TTY/stdin, timeout/kill, descendant cleanup, functional Sage and Magma. |
| `compiled_latex` | Required compiler policy, real latexmk/pdfLaTeX, compact/full/repair flows, exact final artifacts and a rejected shell-escape proof. |
| `resource` | Explicit released schema-7 baseline and schema-8 candidate; three starts and 180 measured requests per artifact, with unchanged non-regression thresholds. |
| `corpus_native` | U16-U20, three repetitions each: 15 passed, zero failed. This is not the complete 90-trial release corpus. |
| `install_sigkill` | External SIGKILL during a disposable installation rollback; journal recovery and selector restoration, not physical power-loss or a production drill. |
| `retrieval` | Real configured external HTTPS research endpoints and rejected cross-domain redirect; no browser or independent mathematical acceptance. |

The resource run was executed after the Native and LaTeX runs had exited, before
the next qualification jobs were started. It makes no A6 performance claim.
The released baseline was also retained under `target/mtm017-baselines/` with
its exact hash; that copy does not recover the missing older 0.5.0 rollback file.

## Remaining boundaries

All seven profiles above completed successfully on this exact snapshot. Their
immutable hashes are recorded in the appended `ITER-017` artifact receipt.
The protocol profile independently repeated 500 assessments on the optimized
binary; it does not borrow the earlier debug-binary capability report. Its
synthetic older-schema fixture is not the schema-7 operator-state upgrade test.

The existing paired upgrade fixture explicitly requires a 0.5.0-preview.2,
schema-2 baseline. It cannot establish the required schema-7 to schema-8 upgrade
by changing only the baseline path. A dedicated reviewed paired fixture and
separately authorized operator-state copy remain required. No live workflow or
OAuth database has been opened or copied for these qualifications.

Real-client observations, independent mathematical review and the remaining
corpus cases are separate from scripted fixtures. The frozen MTM-016 release
manifest and cutover driver must not be repointed at this artifact. Publication,
deployment authorization, the missing older rollback artifact and the complete
schema-8 release decision remain explicit outstanding work. No installed
selector, live session or production state has been changed in these runs.
