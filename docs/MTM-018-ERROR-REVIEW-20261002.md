# MTM-018: source-only error review, 2026-10-02

## Input and scope

The operator requested investigation and direct fixes in the MTM2 checkout.
The supplied `mtm-error-summary(1).json` has SHA-256
`385c937c0b449e3e7bb41eec23160266c538166f6b0bf133a3b976527d9e6649`.
Its MTM-001 through MTM-006 names are **report issue IDs**, not this
repository's migration milestone IDs. The original report is not a complete
request log and is not evidence of an incident rate.

Base commit: `a3ab170cbe6e46b3685a7be40ca923c92a5dae16`.
The checkout was clean before this work. This follow-up does not reopen or
relabel the accepted MTM-018 integration receipt, build, or live-client smoke.

| Report issue | Source review disposition |
|---|---|
| MTM-001 reauthentication | Root cause remains unknown; no server authentication logs were supplied. No OAuth change. |
| MTM-002 absolute paths | Runtime rejection is correct, but the model-visible tool/schema descriptions did not clearly state that path/workdir are workspace-relative while server_info.workspace is only informational. Treat as a tool self-description/usability defect; keep the path authority boundary unchanged. |
| MTM-003 paper lookup | Correct rejection of mixed natural-language input in an exact-identifier operation. No change. |
| MTM-004 source appendix | Product defect reproduced: static checks counted document wrappers and bibliography inside literal Verbatim text. Fixed. |
| MTM-005 shell probe | Product defect reproduced: scalar expansion triggered the fallback splitter, producing `pwd;` and `true;` as executable candidates and omitting later commands. Fixed within the bounded grammar below. |
| MTM-006 source locator | Correct exact-snapshot validation; the successful 101-write prefix and correction receipt are not evidence of data loss. No workflow/receipt change. |
| ENV-001 missing engine/packages | Execution-environment limitation, not an RPC defect. No TeX packages or fonts were installed by this fix. |

## LaTeX repair and boundaries

`latex_scan.rs` builds a lexical checking view while leaving the original compiler
input unchanged. It masks comments and supported literal text without changing
line breaks. The same static checker is used by proof submission and the runtime
LaTeX gate. Compilation, `-no-shell-escape`, isolated helper execution, verification
and finalization authority remain unchanged.

Supported literal forms are `verbatim`, `verbatim*`, `Verbatim`, `Verbatim*`, and
inline `verb`/`verb*`. Environment headers must start on their own line outside a
braced argument and end with a newline. Inline delimiters are non-letter printable
ASCII, with a matching delimiter on the same line. The first raw environment end
marker terminates the masked range, including after a literal percent or slash;
active text after it must still be checked.

Uppercase Verbatim supports a bounded formatting allowlist: frame, numbers,
standard fontsize commands, showspaces/showtabs/resetmargins/samepage booleans,
tabsize, gobble and literal numbersep/framesep/framerule/xleftmargin/xrightmargin
dimensions. Global fvset accepts the same subset when literal text is present.
Unknown or executable options, macro/environment reconfiguration, alternate key
configuration, catcode changes and conditional tokenization are conservatively
rejected when combined with supported literal text. Errors explicitly identify
unsupported literal configuration. This is not a complete TeX interpreter and
does not certify arbitrary package/macro expansion or replace isolation.

Negative tests also exposed a separate preexisting static-check omission:
regex word boundaries did not recognize operations such as `openout1` or
`openin1`, although TeX control words end before the digit. The operation checks
now use a control-word boundary and still distinguish longer command names.
This is a source/test finding, not an additional incident claimed from the report.

## Native repair and boundaries

Executable collection retains quote-aware list boundaries when scalar parameters
occur in arguments. Simple newline-separated lists and bounded for/do/done loops
are supported. Loop variables and their iteration lists are not executables;
command -v/-V queries do not execute the names they describe. Actual commands
before, inside and after the loop remain candidates for resolution/revalidation.

Direct argv still names an external executable. An explicit path ending in
`command` is not the shell builtin. Existing external wrapper target collection
is retained. Dynamic executable names and missing actual executables still fail
resolution. Command -p execution is rejected rather than inspecting a file using
the wrong PATH semantics; -p combined with a name query is supported.

This is deliberately not a complete shell parser. Command substitution,
heredocs, redirects and other compound syntax are not reclassified as literal
query arguments; they retain the previous collection path. Malformed supported
loops fail closed. The stricter shared literal-only risk classifier is unchanged,
as are executable metadata revalidation, Bubblewrap and workflow authority.

## Validation evidence

Reproduction was performed on synthetic source and argument fixtures, not by
replaying the user's historical proof runs or verifier submissions. Initial
regressions failed with the two original signatures before implementation.
The real compiler fixture is
`crates/mtm-runtime/tests/fixtures/verbatim-appendix.tex`; it is passed to the same
static checker in a unit test and separately compiled with host pdflatex using
`-no-shell-escape -halt-on-error`.

Diagnostic logs, including failures and the zero-test resolver filter attempt,
are retained under `target/mtm-tool/error-review-20261002/`. The corrected resolver
filter is `native_permission::resolver_tests`; a zero-test run is not acceptance.
Final counts, command outcomes and content hashes are recorded separately in
`records/evidence/MTM-018/error-review-20261002.json` after validation completes.
The host compiler sanity check is not an exact-artifact workflow/LaTeX release
qualification, and profile-gated source tests are not claimed as real-client trials.

All Cargo commands use the existing dedicated `target/mtm-tool` cache with its
host checkout path, explicit host Cargo/Rustup homes and auto-install disabled
for validation. A preliminary version probe, before those explicit homes were
selected, caused Rustup to auto-install the pinned compiler in the CTM session's
private home; it did not change repository toolchain configuration. No operator
build cache or historical candidate was cleaned.

## Rollback and deployment

Revert only this follow-up's hunks in native_permission.rs, shell_segments.rs,
latex.rs and native_resolver_tests.rs; remove the newly added scanner/candidate
modules, their tests and the synthetic fixture. Preserve diagnostic evidence and
append a superseding disposition rather than rewriting historical acceptance.
No database migration or state rollback is required.

No package version, tool count, v11 contract, schema 8, workflow protocol 3,
OAuth, capability, finalizer, production state or installed selector is changed.
There is no commit, push, installation or service restart in this operation.
Source validation does not deploy these changes into an already running service.
