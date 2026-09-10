# MTM-016 F6 capable-host Native and compiled-LaTeX qualification

## Scope

F6 adds two explicit exact-candidate qualification profiles for the remaining
real-host gates. They reuse the existing Rust `cargo xtask qualify` authority:

- candidate bytes are SHA-256 selected and copied to an owner-only temporary
  executable before any launch;
- Native preflight must positively prove the host is suitable before the profile
  runner starts;
- the candidate is exercised through its public loopback OAuth/MCP boundary;
- the runner output is bounded and only a strict structured summary is retained;
- candidate bytes and harness source identity are checked again after the run;
- a successful receipt is still evidence for one gate, not release authorization.

No Python implementation, model API, background agent runtime, production selector,
production database, production key, or browser-human claim is introduced here.

## Frozen candidate

The current MTM-016 release-input candidate remains:

```text
target/mtm016-f5-frozen/mtm-0.6.0-preview.1-46c1441b824d6cc311a276ff34fda888c36223ebf5c98f8ca65ce26570df9724/mtm
SHA-256: 46c1441b824d6cc311a276ff34fda888c36223ebf5c98f8ca65ce26570df9724
source commit: cc17b1688a2deda7db3dde4b2dbf63199bf48b13
```

Do not substitute another build with the same version label. The profiles select
the exact bytes above.

## Native command profile

`native_commands` requires a capable Linux Bubblewrap host and exercises:

- safe, trusted, and dangerous Native modes;
- all seven command permission kinds in the frozen order:
  `sensitive_env`, `destructive_command`, `shell_expansion`, `inline_script`,
  `network`, `long_timeout`, and `privileged_executable`;
- each permission kind as deny -> scripted once-grant -> successful execution ->
  re-challenge, so a consumed grant cannot be silently reused;
- 32 additional exact-once long-timeout grant cycles;
- TTY plus stdin round-trip through `write_stdin`;
- timeout TERM/KILL lifecycle;
- process-group descendant cleanup using a delayed workspace side-effect probe;
- functional Sage evaluation returning `42`;
- functional Magma evaluation returning `42`.

The permission form responses are scripted test responses. They validate Native
command grant mechanics only and never satisfy the independent browser/human-consent
gate.

Required host commands include `bwrap`, `curl`, `git`, `script`, `cat`, `sh`,
`sleep`, `printf`, `rm`, `sage`, and `magma`.

## Compiled-LaTeX profile

`compiled_latex` requires the same positively attested Bubblewrap host plus
`latexmk` and `pdflatex`. It exercises:

- direct functional `latexmk` discovery;
- direct `pdflatex` compilation with `-no-shell-escape`;
- required-LaTeX compact workflow finalization;
- required-LaTeX full workflow finalization;
- required-LaTeX repair workflow finalization;
- exact final `.tex` artifact byte checks for all three routes;
- an unsafe `\\write18` proof that must route to repair and must not create either
  a final artifact or its delayed shell side-effect file.

The workflow submissions are fixed scripted mathematical fixtures. This proves the
runtime/LaTeX gate, not independent mathematical correctness.

## Operator commands

Run from the repository root on the capable host:

```bash
export CANDIDATE='target/mtm016-f5-frozen/mtm-0.6.0-preview.1-46c1441b824d6cc311a276ff34fda888c36223ebf5c98f8ca65ce26570df9724/mtm'
export CANDIDATE_SHA='46c1441b824d6cc311a276ff34fda888c36223ebf5c98f8ca65ce26570df9724'

sha256sum "$CANDIDATE"
cargo xtask native-preflight --record
cargo xtask qualify --profile native_commands --binary "$CANDIDATE" --sha256 "$CANDIDATE_SHA" --record
cargo xtask qualify --profile compiled_latex --binary "$CANDIDATE" --sha256 "$CANDIDATE_SHA" --record
```

Expected successful validation reports are:

```text
records/validation/mtm016-native-preflight.json
records/validation/candidate-native-commands.json
records/validation/candidate-compiled-latex.json
```

Do not hand-edit these JSON files. Return the complete command stdout/stderr and the
three generated reports for repository-side hash sealing and release-input update.

## Failure handling

Any nonzero result is evidence, not permission to weaken the profile. In particular:

- missing Sage or Magma is a missing real-host prerequisite, not a pass with a skip;
- failed Bubblewrap preflight blocks both profiles before candidate launch;
- a TTY, timeout, descendant, permission, CAS, or LaTeX failure remains failed;
- no browser or production-state action is authorized by these commands.

After a successful real-host run, the receipts must pass the same Rust summary
validators again and their harness source lineage must match a committed source
identity before `release-check` may mark the corresponding gate validated.
