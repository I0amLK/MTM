# MTM-owned tool contract: implementation checkpoint

This is a development contract under MTM-016, not a release qualification receipt.
The working binary is identified as `0.6.0-preview.1`; the installed, previously
qualified `0.5.0-preview.2` is not changed by this work.

## Single current authority

`crates/mtm-gateway/src/catalog/` defines the 24 supported tool identities,
descriptions, annotations and input schemas in Rust. The typed `ToolId` table
generates the public names and is also the runtime dispatch discriminator.
The old embedded Base64 directory, frozen Re-CTM catalog hashes, gateway shadow
binary and its feature-gated principal constructor have been removed.

The optional gateway fixture server can validate a supplied **current** snapshot,
but cannot use it to replace a description/schema, add an alias, or create a new
authority. The product CLI builds the directory directly; no Python export or
adjacent reference checkout participates in this path.

The common envelope version is `mtm-tools-v1`. Operation-specific schemas keep
their fields visible at the top level for clients, while strict operation branches
reject irrelevant fields. This checkpoint does not claim all boundary JSON maps
have already been replaced with typed Rust request structures.

## Intentional public changes

| Area | Current development behavior |
|---|---|
| Legacy aliases | All eleven former hidden Rethlas names have no catalog entry or runtime dispatch arm. Use the six public facades instead. |
| `exec_command` | Both `argv` and `cmd` are advertised, with exactly one required. Empty non-program arguments are valid; an empty program is not. |
| `search_text` | A file target is supported, with file-only scope and the existing directory/filter path preserved. |
| Rethlas guidance | Step, inspect and retrieve share task-domain/branch lifecycle rules, zero-write correction limits and uncertain-transport handling. |
| `server_info` | Publishes `native_tool_count`, `native_tools`, `hidden_alias_count=0` and `tool_contract_version`; former `ctm_native_*` and hidden-alias inventory fields are retired. |
| `mtm contract` | Reports the current Rust-authoritative protocol-3 contract, not the historical migration baseline. |
| `mtm tool-catalog` | Emits the current public directory without opening a server or materializing secrets. |
| `mtm status` | Reports compiled identity only; explicitly does not claim installed-selector or release-qualification verification. |

Old generic Python conformance drivers are historical migration machinery, not
the acceptance authority for this intentional contract change. Their useful
security and protocol coverage must still be mapped to independent Rust suites
before those drivers are deleted. The separate `mtm-gateway-server` fixture binary
is not removed by this checkpoint.

## Boundaries retained

No workflow transition, role ACL, signing format, key material, state schema,
reference provider, Native isolation policy or finalizer implementation changes
here. Shared logical read/search/export implementations remain behind the public
facades. Only obsolete external entry points and unused alias wrappers are removed.
Shell-program argument semantics and schema validation remain separate from
execution authorization; passing an input schema is never a permission grant.

An uncertain transport result is not a zero-write result. A run identifier alone
never grants workflow authority. Updating descriptions is not evidence that the
previous signature mismatch has been explained, or that client retries are now
automatically correct. Persistent workflow idempotency remains stage E work.

## Verification and limitations

Rust catalog tests cover every public tool and facade operation, malformed input,
cross-operation field misuse, current-snapshot integrity and absence of all eleven
retired aliases. CLI integration tests run the actual built binary with its
inherited environment cleared and compare the published identity and directory.
Existing OAuth tests, storage tests and workflow tests remain in the Rust suite.

A previous authenticated dispatcher test proposal was not applied; its historical
receipt is retained. A later Rust HTTP suite now exercises the real router, DCR,
authorization form, PKCE exchange and authenticated dispatch against a counting
test backend. All eleven retired aliases are rejected before that backend. This
is more than catalog membership, but is explicitly not a socket/browser test,
Native execution or a complete Rethlas run. Web-client flow acceptance remains
pending. The identified nested Bubblewrap limitation still affects the same ten
inherited runtime tests; no suppression or new ignore attribute was added.

Use `cargo xtask check --record` for current source checks. A failed host test keeps
the aggregate false. Use `cargo xtask audit --strict` to check retirement completion;
the remaining Python maintenance files and Rust legacy markers still make it fail.

Historical evidence, rejected attempts, baseline records and legal notices remain
unchanged. Before deployment, complete client schema usability, full research,
real Native, LaTeX, copied-state and rollback qualifications on the exact candidate.
