# MTM-019: fixed operator TUI header

## Approved scope

The operator requested a fixed header on 2026-10-21, explicitly including the
current OAuth password and temporary Quick Tunnel URL. This supersedes only the
MTM-012 line-only presentation non-goal. It does not authorize deployment, an
installed-selector change, a live restart, or production-state access.

An ANSI-capable interactive stderr uses an alternate screen. Version, protocol,
Native mode, public/local MCP endpoints and the current password remain above the
bounded latest-event area. Both generated and externally configured passwords
are visible in this owner-operated terminal, by explicit request. They are never
placed in event JSON, the event queue, debug files, validation output or receipts.
Keep the terminal private when screen sharing or using terminal-recording software.

Tunnel callbacks update the public endpoint in place; disconnect/unavailable/closed
states remove the live endpoint from the header. Historical endpoint events remain
ordinary log lines. Compact/verbose filtering and argument-value redaction stay
unchanged. No OAuth, MCP tool, capability, schema, workflow, proof or finalizer
semantics change. Temporary tunnels remain temporary; no domain is introduced.

## Terminal and resource ownership

The CLI owns the renderer; runtime operator formatting accepts optional output
callbacks without gaining terminal or credential ownership. Reuse the already
locked rustix 1.1.4 safe terminal API; add unicode-width 0.2.2 for cell-aware wrapping.
There is no new crate, terminal framework, raw mode or unsafe code.

One joined resize worker checks size every 150 ms and redraws only on change.
Events are serialized through one mutex. The queue retains at most 256 event lines,
each bounded to 2048 input characters. Terminal controls and directional overrides
are escaped. The password is outside the queue and has no Debug/Display formatter.
Passwords longer than 4096 characters produce an explicit hint, never a misleading
partial password. Terminals too small for the full header show an enlargement hint.
Rendering reserves the final column to avoid wrap-induced scrolling.

Echo is disabled while the screen is active, but canonical input and signal handling
remain enabled. Normal return, errors after activation, Ctrl+C and Unix SIGTERM
restore terminal attributes, cursor and the prior screen; SIGKILL cannot be handled.
The server's existing shutdown path now also accepts SIGTERM to reach that cleanup.
Redirected stderr, missing/dumb TERM or unavailable size use the old plain format;
externally configured passwords remain hidden in that fallback.

## Validation and rollback

Pure rendering tests cover fixed header placement, queue overflow, tunnel-state
replacement, narrow/wide/undersized resize, Unicode cells, control injection and
oversized credentials. CLI integration tests use real PTYs and disposable servers,
OAuth DCR/PKCE and authenticated tools. A synthetic cloudflared child tests URL
changes and disconnect without contacting Cloudflare. Generated/configured keys,
compact/verbose output, redaction, debug files, plain redirected/dumb output and
SIGINT/SIGTERM restoration are checked. These tests are not real browser, external
tunnel, production database, release or independent mathematical acceptance.

The host checkout cannot create /workspace (permission denied). Its one tool cache
is therefore addressed at the documented host-side target/mtm-tool path. The first
focused command accidentally used the newly empty target/debug after the mkdir
failed; only those newly created products were moved into target/mtm-tool. No
preexisting operator cache, frozen candidate or production binary was touched.
All subsequent Cargo commands explicitly use this host tool cache. This observation
is retained rather than silently claiming use of the inaccessible mount path.

Rollback removes only this milestone's terminal module, operator callbacks, signal
extension, dependencies and related tests/docs. No database rollback is needed.
The installed MTM binary and existing running sessions remain unchanged.

Full source validation results are recorded separately under records/evidence/MTM-019/.
Human visual acceptance in the desired terminal and a real external Quick Tunnel
remain pending; no release, deployment or performance claim follows.
