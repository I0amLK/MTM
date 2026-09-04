#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

try:
    from scripts.run_mtm005_target_validation import implementation_sha256
except ModuleNotFoundError:
    from run_mtm005_target_validation import implementation_sha256


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "records/evidence/MTM-005/target-validation.json"
REQUIRED_CHECKS = {
    "dynamic_loopback_metadata",
    "trusted_loopback_forwarded_origin",
    "oauth_registration_not_blocked_by_mcp_origin_gate",
    "real_firefox_authorization_page_and_form",
    "browser_code_pkce_exchange",
    "authorization_code_single_use",
    "mcp_requires_bearer_and_advertises_resource_metadata",
    "legacy_exact_public_catalog",
    "modern_mcp_shape_and_mirror_headers",
    "public_and_hidden_dispatch_boundary",
    "mcp_origin_gate_and_cors",
    "modern_http_error_statuses_and_duplicate_headers",
    "gateway_owned_process_shutdown",
    "fixed_origin_ignores_forwarded_attacker",
    "fixed_gateway_shutdown",
}
FORBIDDEN_KEYS = {
    "password",
    "client_id",
    "client_secret",
    "authorization_code",
    "access_token",
    "refresh_token",
    "token",
    "tool_arguments",
    "tool_result",
}


def validate() -> dict[str, object]:
    payload = json.loads(REPORT.read_text(encoding="utf-8"))
    if payload.get("project") != "MTM-reboot" or payload.get("milestone") != "MTM-005":
        raise ValueError("target evidence belongs to a different project or milestone")
    if payload.get("passed") is not True:
        raise ValueError("MTM-005 target evidence is not passing")
    expected_hash = implementation_sha256()
    if payload.get("implementation_sha256") != expected_hash:
        raise ValueError("MTM-005 target evidence is stale for the current implementation")
    checks = payload.get("checks")
    if not isinstance(checks, list):
        raise ValueError("target evidence checks must be an array")
    by_name = {
        str(item.get("name")): item
        for item in checks
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    missing = REQUIRED_CHECKS - set(by_name)
    if missing:
        raise ValueError(f"target evidence is missing checks: {sorted(missing)}")
    failed = sorted(name for name in REQUIRED_CHECKS if by_name[name].get("passed") is not True)
    if failed:
        raise ValueError(f"target evidence contains failed checks: {failed}")
    if by_name["legacy_exact_public_catalog"].get("tool_count") != 24:
        raise ValueError("target evidence did not validate exactly 24 public tools")
    browser = payload.get("environment", {}).get("browser")
    if browser != "firefox":
        raise ValueError("target evidence did not use the installed Firefox browser")
    if payload.get("sensitive_content_omitted") is not True:
        raise ValueError("target evidence does not assert redaction")
    leaked_keys = sorted(_find_forbidden_keys(payload))
    if leaked_keys:
        raise ValueError(f"target evidence contains forbidden sensitive keys: {leaked_keys}")
    serialized = json.dumps(payload, ensure_ascii=False)
    for literal in (
        "operator-password",
        "client-public-fixed",
        "secret-basic-fixed",
        "code-public-fixed",
        "Bearer eyJ",
    ):
        if literal in serialized:
            raise ValueError("target evidence contains a known sensitive literal")
    return {
        "implementation_sha256": expected_hash,
        "required_check_count": len(REQUIRED_CHECKS),
        "environment": {
            "platform": payload.get("environment", {}).get("platform"),
            "release": payload.get("environment", {}).get("release"),
            "machine": payload.get("environment", {}).get("machine"),
            "browser": browser,
        },
    }


def _find_forbidden_keys(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).casefold() in FORBIDDEN_KEYS:
                found.add(str(key))
            found.update(_find_forbidden_keys(item))
    elif isinstance(value, list):
        for item in value:
            found.update(_find_forbidden_keys(item))
    return found


def main() -> int:
    try:
        summary = validate()
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, indent=2))
        return 1
    print(json.dumps({"ok": True, "summary": summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
