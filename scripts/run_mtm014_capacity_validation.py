#!/usr/bin/env python3
"""Real loopback OAuth/MCP capacity test with scripted (not human) consent."""
from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import run_mtm014_mrtr_permission_validation as wire
from mtm008_runtime_harness import free_port, oauth_token, runtime_environment, wait_for_port
from validate_mtm014_capacity_validation import CHECKS, ROOT, SCOPES, current_identity, validate


def run() -> dict[str, Any]:
    identity = current_identity()
    checks = dict.fromkeys(sorted(CHECKS), False)
    with tempfile.TemporaryDirectory(prefix="mtm014-capacity-") as temporary:
        root = Path(temporary)
        workspace = root / "workspace"
        workspace.mkdir()
        port = free_port()
        environment = runtime_environment(workspace, root / "data", "rust")
        process = subprocess.Popen(
            [str(wire.BINARY), "serve", "--host", "127.0.0.1", "--port", str(port),
             "--workspace", str(workspace), "--native-mode", "safe", "--latex-policy", "static_only"],
            cwd=ROOT, env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True,
        )
        try:
            wait_for_port(port, process)
            base = f"http://127.0.0.1:{port}"
            owner = oauth_token(port, base, "capacity-owner")
            other = oauth_token(port, base, "capacity-other")
            request = wire.permission_request(command="sh -c 'printf capacity'")

            def call(token: str, args: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
                status, payload = wire.modern_tool_call(
                    port, token, "request_permissions", args,
                    capabilities={"elicitation": {"form": {}}}, **kwargs,
                )
                if status != 200:
                    raise RuntimeError("unexpected HTTP status")
                return payload

            states = [wire.input_required(call(owner, request))[0] for _ in range(32)]
            checks["form_challenge_returned"] = len(set(states)) == 32
            full = call(owner, request)
            checks["owner_capacity_enforced"] = (
                wire.result(full).get("isError") is True
                and wire.tool_error_code(full) == "ELICITATION_CAPACITY_EXCEEDED"
            )
            checks["capacity_retryable"] = wire.structured(full).get("error", {}).get("retryable") is True
            text = json.dumps(full)
            checks["capacity_error_redacted"] = all(
                value not in text for value in [owner, other, request["arguments"]["cmd"], *states]
            )
            other_state, _ = wire.input_required(call(other, request))
            checks["other_owner_not_blocked"] = bool(other_state)
            attacked = call(other, request, request_state=states[0], input_responses=wire.consent_response())
            checks["cross_owner_rejected"] = wire.tool_error_code(attacked) == "ELICITATION_OWNER_MISMATCH"
            declined = call(owner, request, request_state=states[0], input_responses={
                wire.CONSENT_KEY: {"action": "decline"},
            })
            checks["original_challenge_survives_cross_owner_attempt"] = (
                wire.structured(declined).get("status") == "denied"
                and wire.structured(declined).get("grant_id") is None
            )
            replacement, _ = wire.input_required(call(owner, request))
            checks["decline_releases_slot"] = replacement not in states
            oversized = dict(request, reason="capacity-sensitive-canary-" + "x" * 1024)
            rejected = call(other, oversized)
            checks["oversized_reason_rejected"] = wire.tool_error_code(rejected) == "NATIVE_PERMISSION_REQUEST_TOO_LARGE"
            checks["oversized_error_redacted"] = "capacity-sensitive-canary" not in json.dumps(rejected)
            false = call(other, request, request_state=other_state, input_responses=wire.consent_response(False))
            checks["false_confirmation_mints_no_grant"] = (
                wire.structured(false).get("status") == "denied"
                and wire.structured(false).get("grant_id") is None
            )
            fresh, _ = wire.input_required(call(other, request))
            checks["denied_request_can_prompt_again"] = fresh != other_state
        finally:
            checks["server_exits_cleanly"] = wire.close(process) == 0
    if identity != current_identity():
        raise RuntimeError("source or binary changed during validation")
    report = {**SCOPES, **identity, "checks": checks, "check_count": len(checks),
              "ok": all(value is True for value in checks.values())}
    validate(report)
    return report


def main() -> int:
    try:
        report = run()
    except Exception:
        # Helper exceptions can contain raw MCP envelopes: never print them.
        print(json.dumps({"ok": False, "error": "capacity integration failed; no raw response retained"}))
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
