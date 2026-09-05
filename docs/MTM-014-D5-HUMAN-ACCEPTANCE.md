# MTM-014 D5A: independent client consent acceptance

This remains the reproducible operator runbook. D5A human consent was accepted on
2026-09-05 using MCP Inspector 2.5.0 in modern MCP 2026-07-28 mode over a real
Cloudflare Quick Tunnel. The redacted accepted receipt is
`records/evidence/MTM-014/elicitation-capability.json`. The MRTR and capacity runners
still use scripted responses and establish A3 only; neither runner can replace the
accepted human-UI observation.

## Current boundary

The selected provider is MCP 2026-07-28 MRTR form elicitation. The application must
own the approval UI, keep responses outside model-supplied tool arguments, and
prevent model output from fabricating the second round. A client capability
declaration is not proof of that UI behavior, and `clientInfo` is self-reported,
not an authenticated security attestation. Inspect and record the actual client
version and its observed behavior rather than assuming support from a product name.

The server validates OAuth identity, exact request binding, expiry and replay. It
does not cryptographically attest a physical click. D5A qualification therefore
requires an operator-observed, trusted client path in addition to the protocol tests.
An arbitrary caller holding OAuth credentials is not proved to be a human merely
because it sends `approved=true`. Do not describe the protocol as providing that
guarantee.

## Isolated candidate only

Keep the installed stable selector and existing sessions unchanged. In the repository,
read `AGENTS.md` and use the pinned toolchain through `rust-toolchain.toml`; build
the candidate with `cargo build --locked -p mtm-cli --bin mtm` and record the SHA-256
of `target/debug/mtm`. Its package version alone is not stable-artifact identity.

Use a dedicated temporary workspace and data root, never the production database or
vault. A local terminal launch example follows. This is for the operator to run;
it does not install, publish or select a release.

```bash
cd ~/桌面/tempcoding/MTM-reboot
umask 077
test_root=$(mktemp -d "${TMPDIR:-/tmp}/mtm014-human.XXXXXX")
mkdir -p "$test_root/workspace"
sha256sum target/debug/mtm
env -u MTM_OAUTH_PASSWORD -u MTM_TOKEN_SECRET -u MTM_CAPABILITY_SECRET \
  MTM_WORKSPACE="$test_root/workspace" \
  MTM_DATA_ROOT="$test_root/data" \
  MTM_PRIVATE_ROOT="$test_root/data/private" \
  MTM_DEBUG_ROOT="$test_root/data/debug" \
  MTM_SERVER_URL= MTM_DEBUG=0 MTM_TRACE_PAYLOADS=0 \
  MTM_NATIVE_EXEC_BACKEND=bubblewrap MTM_NATIVE_EXEC_ALLOW_ROOTS= \
  MTM_LATEX_POLICY=static_only \
  target/debug/mtm tui --host 127.0.0.1 --port 0 \
    --workspace "$test_root/workspace" --native-mode safe
```

Use the endpoint printed by that process with an actual form-capable client. A
remote-only client needs a separately operator-approved tunnel; do not reuse test
harness passwords or publish a port simply to obtain a passing result. Never copy
the generated OAuth key into repository records, screenshots, or chat messages.
Stop the test process after the exercise. Keep any sensitive temporary data private;
only reviewed, redacted summaries may enter repository evidence.

## Exercise and observe

Use a harmless permission request, for example `inline_script` for the exact
`exec_command` arguments `{"cmd":"sh -c 'printf mtm014-human'"}`. The request itself
does not run the command. Do not put `inputResponses`, `approved`, or `requestState`
in model-generated arguments. The client must own the MRTR continuation.

| Observation | Required evidence |
|---|---|
| First request | The real client displays the form from `input_required`; there is no grant before a human decision. |
| Accept | The operator verifies the action in client-owned context, then actively confirms; exactly one bound grant is reported. |
| Decline / cancel / unchecked confirmation | Separate fresh requests mint no grant. |
| Abandon prompt | No grant is created while the prompt is unanswered; a late reply after challenge expiry is rejected. |
| Replay / mutation | A used continuation cannot grant again; changing the exact original request cannot reuse its consent. |
| Client unsupported | Legacy, missing-form or URL-only support remains unsupported; the model is never asked to supply approval JSON. |
| Redaction | Record outcomes and fingerprints only, not raw state, grant IDs, credentials, prompts or tool bodies. |

The argument fingerprint binds bytes but is not an explanation of what those bytes
do. The operator must be able to associate the form with the exact originating
action using trusted client-owned context. If only an unexplained hash is visible,
record informed-consent usability as unresolved, not accepted.

An ordinary HTTP connection ending between MRTR rounds is normal and is not a
semantic cancellation. Distinguish explicit client `cancel`, closing/abandoning a
prompt, and transient network reconnect. Reconnect within the bound challenge TTL
may permit a correctly correlated retry; abandonment alone must never mint a grant.
Do not claim an automatic disconnect revocation that the implementation lacks.

## Evidence and stop conditions

Only after the operator actually observes the required UI behavior, prepare the
redacted `records/evidence/MTM-014/elicitation-capability.json` with the exact tested
binary/source identity, client/version, transport, each actual result, observer
confirmation, and the trust-boundary limitations above. Bind the reviewed report
hash in `ITER-014.json`; a self-authored `human=true` field is not independent proof.
Missing observations, unexpected auto-approval, inability to identify the action, or
client incompatibility leave D5A pending/blocked. Preserve failed evidence.

Do not test grant-backed public command execution as though it were already enabled:
the candidate authority executor is still unreachable from public dispatch. D5B
cutover, complete real-target A4, Magma functional licensing, preview identity,
installation, rollback/recutover and soak remain separate gates.

## Reproduce automated capacity evidence

```bash
python3 scripts/run_mtm014_capacity_validation.py
python3 scripts/validate_mtm014_capacity_validation.py
python3 -m unittest tests.test_mtm014_capacity_evidence -v
```

The runner prints a redacted report; it never overwrites accepted evidence. The
validator compares the recorded snapshot with the current candidate binary and
implementation/harness digest. Later source changes make that comparison stale;
collect a new, separately named receipt rather than rewriting accepted history.
These commands cannot complete the human UI gate or allow cutover.
