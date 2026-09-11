# MTM-016 F6: independent Native corpus U16-U20

This checkpoint adds `cargo xtask qualify --profile corpus_native` for the
unchanged frozen candidate and corpus definition. It is not a rerun or relabelling
of the previously sealed Native command/CAS gate. No production path, selector,
new dependency, product implementation or first-party Python launcher is added.

## Executed scope

The new profile executes five tasks three times. Each task/repeat constructs a
fresh temporary workspace, server process, signing key and OAuth client. U20
additionally uses separate safe, trusted and dangerous instances. Trial IDs are
random public evidence identifiers, not tokens or capability fingerprints.

| Task | Actual assertions |
| --- | --- |
| U16 | Direct argv retains literal shell metacharacters with exact stdout. |
| U17 | Compound commands and direct argv agree on nested cwd and the minimal PATH; a statically missing executable prevents launch. |
| U18 | A real owned TTY accepts stdin, obeys the requested output bound and terminates through kill_command. |
| U19 | Timeout and explicit kill each terminate a ready command with descendants; delayed descendant writes remain absent and child processes are reaped. |
| U20 | A normal safe command uses a separate network namespace; network requests are denied without an exact grant, cross-owner/changed arguments do not consume it, the approved request reaches an owned loopback endpoint once, and trusted/dangerous networking also reaches that endpoint. |

U20 follows the current authoritative implementation in
`crates/mtm-runtime/src/native_tools.rs::prepare_authority_exec`: a safe invocation
requiring Network is prepared with a shared network namespace but cannot launch
until the required explicit grant is validated. Safe invocations without that
permission remain isolated. A draft assumption that even an explicitly granted
network command must stay isolated was corrected during source review, before
any Native trial was accepted. Neither the product nor its grant semantics changed.
The owned endpoint has no external destination, redirects, credentials, or access
to production services. Its request/response sizes, read deadline and lifetime
are bounded; its thread is joined on success and failure.

The profile records all fifteen rows, including failures, without retrying a row
or replacing a failed task with another one. Every passed row requires isolation,
private-vault exclusion, process cleanup and the full task-specific check set.
Scripted permission responses are mechanics evidence only: human consent and
independent mathematical research remain explicitly untested.

## Qualification and evidence

The existing exact-artifact runner provides native preflight, a private executable
snapshot, before/after artifact and harness identities, bounded child capture and
clean exit verification. `candidate-corpus-native.json` is a separate regenerable
report; it never overwrites the original portable corpus or old Native evidence.
The corpus definition is hashed both in the compiled fixture and from the current
file. Unknown fields, duplicate JSON keys, missing rows, duplicate task/repeat
cells, reused trial IDs, wrong task/scenario pairs, missing checks, forged totals,
scope changes and foreign-profile summaries fail validation. Sealed receipts reuse
the same validator rather than trusting a top-level passed flag.

The new `mtm-usability-corpus-aggregate-v2` accepts exactly one hash-bound historical
48/42 v1 base and one fully validated native batch. Its reviewed scope is only
63 passed / 0 failed / 27 blocked and `complete=false`. The existing v1 adapter is
unchanged. The v2 adapter verifies immutable paths/hashes, the complete batch
receipt and committed harness lineage. It cannot recursively add itself, import
the old broad Native gate, substitute research/browser results, or close the
release gate. No v2 observation is created until real Native executions pass.

## Host sequence and remaining work

Adding test/maintenance source changes the source identity. The old host source
report remains preserved but no longer qualifies the new source tree. Refresh
`cargo xtask check --record` on the host before the new Native profile. All ordinary
source, capability and qualification runners clear `MTM_TEST_NATIVE_CORPUS_PROFILE`;
the optional test entry is inert without its exact explicit flag and candidate.

Run from the reviewed committed checkout, using the host-owned Cargo cache:

```sh
cargo xtask check --record &&
cargo xtask qualify --profile corpus_native \
  --binary target/mtm016-f5-frozen/mtm-0.6.0-preview.1-46c1441b824d6cc311a276ff34fda888c36223ebf5c98f8ca65ce26570df9724/mtm \
  --sha256 46c1441b824d6cc311a276ff34fda888c36223ebf5c98f8ca65ce26570df9724 --record
```

Do not parallelize compilation with qualification, weaken isolation, install the
candidate, alter resource limits or recapture production state. Retain failures.
Only after successful host reports are checked and sealed may the release inputs
reference a new partial aggregate. U21-U25 research, U26-U28 browser/human and U29
copied-state repeats remain separate work; one successful copied-state gate is not
three corpus trials. All partial reports retain `release_qualified=false`.
