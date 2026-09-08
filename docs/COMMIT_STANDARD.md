# MTM-reboot commit standard

## Subject

```text
<type>(<scope>): <imperative summary> [MTM-NNN]
```

Allowed types:

```text
docs test build feat fix refactor perf chore
```

Examples:

```text
docs(governance): establish migration records and gates [MTM-001]
test(contracts): freeze OAuth and MCP golden fixtures [MTM-002]
feat(native): add read-only Rust process shadow [MTM-003]
refactor(workflow): switch transition authority to Rust [MTM-006]
```

`perf` is allowed only after A6 evidence exists.

## Required body trailers

Every material migration commit includes:

```text
Milestone: MTM-NNN
Authority-Before: none|python|rust-shadow|rust|retired
Authority-After: none|python|rust-shadow|rust|retired
Acceptance: A0[,A1,...]
Receipt: records/iterations/ITER-NNN.json
Rollback: <exact rollback action>
Manual-Pending: <pending target/browser/CAS/LaTeX work or none>
```

## Commit size and ordering

- A commit is independently reviewable and leaves the branch buildable.
- Contract fixtures precede or accompany the code that depends on them.
- Shadow implementation precedes authority cutover.
- Authority cutover and Python deletion are separate commits.
- Formatting-only changes do not share a commit with semantic changes.
- Generated validation evidence is committed only when the project record declares it
  an acceptance artifact.

## Forbidden messages

```text
cleanup
rust rewrite
misc fixes
performance improvements
WIP
```

These do not identify the milestone, authority change, or evidence.

The local commit-msg validator is Rust (MTM-016):

```bash
cargo xtask commit-message <message-file>
```

The Git hook is a minimal shell bootstrap into Cargo, not a second policy
implementation. It uses `--locked --offline` and fails closed if the Rust tools
are unavailable. Build the maintenance binary once before using the hook.
Duplicate required trailers, malformed/duplicate acceptance levels and receipts
that do not name the subject's milestone are now rejected explicitly.
