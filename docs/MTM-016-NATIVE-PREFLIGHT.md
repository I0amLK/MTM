# MTM-016: Native environment preflight

This is maintenance diagnostics, not an isolation bypass, a second Native
authority, or a release qualifier. The current environment is where the command
runs: executing it inside MTM cannot turn that environment into the Linux host.

## Commands and result ownership

```sh
cargo xtask native-preflight --record
cargo xtask check --record
```

The first writes `records/validation/mtm016-native-preflight.json` and exits
nonzero if prerequisites are missing, blocked or inconclusive. The second embeds
a newly measured preflight under `native_environment` in the existing source
report, then still executes formatting, Clippy, every workspace test, and diff
checks. A blocked probe does not skip a test or relabel a failed test as passed.
Successful tests plus an unknown/blocked probe also cannot make the aggregate
green. `source_tests_passed` is null in the standalone diagnostic, not true.

These are regenerable current observations. Historical accepted/rejected evidence
is neither replaced nor used as an environment waiver. The iteration ledger
records the actual failed names and counts separately; attribution stays open
until the same source is exercised on a capable host.

## Two bounded active probes

The maintenance executable starts a fresh, single-threaded child that calls
`unshare(CLONE_NEWUSER)` through the existing safe Rust nix wrapper. It records
the syscall errno symbol and number, not a guessed errno extracted from arbitrary
logs. No UID/GID mapping is written, no namespace is joined with setns, and no
user-supplied program can be passed to this child.

A separate Bubblewrap probe uses a fixed policy: new user/mount/PID/IPC/UTS/network
namespaces, dropped capabilities, no new privileges, a cleared environment,
`--disable-userns`, `--new-session` and `--die-with-parent`. It mounts only the
fixed system binary/library directories and the maintenance executable read-only.
It does not mount the workspace, home, secrets, data root or research vault.
The child checks namespace changes, capability state, environment and the refusal
to create another user namespace. Missing observations fail closed.

Both children have a five-second capture deadline, at most 16 KiB retained per
output stream, nonblocking bounded draining and bounded direct-child cleanup.
Timeout, output overflow, unclosed pipes, failure to reap, malformed JSON, unknown
protocol and changed executable identity cannot produce a passing probe. Error
paths do not publish raw stdout/stderr, command text, environment values or
namespace identifiers. The owned fixed Bubblewrap child uses its own PID namespace
and parent-death behavior; this is not a general process-tree supervisor.

The only dependency addition is an xtask reference to the already pinned nix
crate with its Linux sched feature. There is no new product dependency, crate,
Python subprocess, daemon or arbitrary native-command interface.

## Passive observations are not root-cause proof

The report includes shapes of UID/GID mappings, equality to the *visible* PID 1
user namespace, NoNewPrivs/capability/seccomp observations and readable namespace
limits. Missing proc files remain null. It does not publish host identities or
pretend to measure nesting depth, namespace occupancy or ancestor quotas.

In particular, a positive `max_user_namespaces` read inside a namespace does not
prove that a child can be created. Linux also accounts usage against ancestor
namespaces. Bubblewrap documents `--disable-userns` as setting an outer namespace
limit to one and then entering a further namespace that cannot raise it.
Consequently, ENOSPC can be consistent with intentionally disabled nesting even
when the current visible limit is large. The result is deliberately named
`namespace_limit_or_depth`, not "host namespace resources exhausted".

EPERM/EACCES are reported as permission-or-policy denial, not a diagnosis of a
specific LSM or seccomp rule. EINVAL/ENOSYS remain support-or-context failures.
Unexpected errno values, unknown Bubblewrap output, missing executable, timeout
and incomplete capture remain separate nonpassing observations.

Primary references for these semantics:

- Linux kernel: <https://docs.kernel.org/admin-guide/sysctl/user.html>
- Linux man-pages project: <https://www.man7.org/linux/man-pages/man2/unshare.2.html>
- Bubblewrap manual: <https://github.com/containers/bubblewrap/blob/main/bwrap.xml>

## Real-host handoff before stage E

Run in an ordinary Linux host terminal, in the same development checkout, not
through MTM exec_command and not by removing its namespace restrictions:

```sh
cd ~/桌面/MTM/mtm-native-016
git rev-parse HEAD
cargo xtask native-preflight --record
cargo xtask check --record
```

Run the final command even if standalone preflight was nonzero, so that the full
test outcome remains recorded. Do not use `|| true`, add ignores, remove
`--disable-userns`, change sysctls automatically, or install the development
candidate just to collect this evidence. A preflight failure can also be a probe
implementation or unsupported-environment issue; inspect both layers.

The formerly failing Runtime tests must actually run and pass on the capable host.
An existing ignored manual test is still manual work, not a new pass. This closes
the current test-environment attribution only after the actual result is reviewed.
Stage F must independently requalify the final exact product binary, real Native
policy/TTY/tools/vault, full workflow/LaTeX, copied state, resources and rollback.
Unit tests and the minimal preflight cannot substitute for those checks.
