# MTM-010 Native resolver compatibility stabilization

## 1. Trigger

Real web-driven MTM 0.4.0-preview.1 tests showed that network-enabled Native
Bubblewrap commands could establish HTTPS connections to direct IP addresses but
failed ordinary hostnames with `curl` exit code 6. Inside the sandbox,
`/etc/resolv.conf` was the host symlink to
`../run/systemd/resolve/stub-resolv.conf`, while that target file was absent because
MTM intentionally does not expose the host `/run` tree.

This is a Native isolation compatibility defect, not a workflow-protocol defect. It
is therefore separated from MTM-009, whose accepted non-goals explicitly exclude a
Native sandbox redesign.

## 2. Required behavior

For a network-enabled Native command:

1. the existing read-only `/etc` mount remains authoritative;
2. if host `/etc/resolv.conf` is a regular file, no extra mount is added;
3. if it resolves to a trusted runtime resolver file outside the existing system
   roots, only that exact regular file is mounted read-only at its canonical path;
4. only empty destination parent directories required for that file are created;
5. the host `/run` tree is never mounted broadly;
6. Safe mode continues to use `--unshare-net`, so resolver visibility never grants
   network access;
7. forbidden paths, the private vault, credentials and unrelated service state remain
   hidden.

## 3. Trusted resolver targets

The first implementation may recognize only well-known runtime resolver locations
needed by common Linux resolver managers, such as files below:

- `/run/systemd/resolve/`;
- `/run/NetworkManager/`;
- `/run/resolvconf/`.

The resolved target must be a regular file. Symlinks resolving outside the explicit
trusted prefixes fail closed rather than causing an arbitrary host file to be
mounted. Broad directories are never accepted as resolver targets.

## 4. Tests

### A0/A1

- command construction adds no resolver mount for a regular `/etc/resolv.conf`;
- a supported runtime symlink produces one exact read-only file bind;
- an unsafe target is rejected or omitted fail-closed;
- command construction never adds `--ro-bind /run /run` or equivalent;
- Safe mode still contains `--unshare-net`;
- dangerous/network-enabled mode does not add `--unshare-net`.

### A3/A4

- real Bubblewrap target shows a readable `/etc/resolv.conf` and successful hostname
  lookup in network-enabled mode;
- Safe mode remains unable to reach the network;
- private workspace exclusions and `/home/lk/.ssh` remain hidden;
- the ten-case real webpage corpus is rerun without DoH and without `curl --resolve`.

### A5

The extra resolver-file mount must not create a persistent child, fd/thread growth,
or writable host path. No performance claim is attached to MTM-010.

## 5. Rollback

Revert the resolver-file mount helper and return to the previously accepted
Bubblewrap mount list. No SQLite state, workflow capability, proof artifact or
project state changes are involved.

