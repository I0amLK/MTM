#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

try:
    from scripts.run_mtm007_target_validation import (
        CAPABILITY_SECRET,
        OPERATOR_PASSWORD,
        TOKEN_SECRET,
        implementation_sha256,
    )
except ModuleNotFoundError:
    from run_mtm007_target_validation import (  # type: ignore[no-redef]
        CAPABILITY_SECRET,
        OPERATOR_PASSWORD,
        TOKEN_SECRET,
        implementation_sha256,
    )


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "records/evidence/MTM-007/target-validation.json"
REQUIRED_CHECKS = {
    "release_binary_has_no_python_runtime",
    "cargo_install_path_distribution",
    "bubblewrap_runtime_attestation",
    "native_command_through_public_tool",
    "real_research_provider",
    "real_latex_finalization_through_public_tools",
    "verified_workspace_artifact_delivery",
    "tui_observer_non_authoritative_and_redacted",
    "graceful_sigint_shutdown",
    "quick_tunnel_public_metadata",
    "quick_tunnel_owned_shutdown",
    "resource_non_regression",
}


def validate() -> dict[str, object]:
    payload = json.loads(REPORT.read_text(encoding="utf-8"))
    if payload.get("project") != "MTM-reboot" or payload.get("milestone") != "MTM-007":
        raise ValueError("target evidence belongs to a different project or milestone")
    if payload.get("passed") is not True:
        raise ValueError("MTM-007 target evidence is not passing")
    expected = implementation_sha256()
    if payload.get("implementation_sha256") != expected:
        raise ValueError("MTM-007 target evidence is stale for the current implementation")
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
    serialized = json.dumps(payload, ensure_ascii=False).lower()
    for forbidden in (
        OPERATOR_PASSWORD.lower(),
        TOKEN_SECRET.lower(),
        CAPABILITY_SECRET.lower(),
        "access_token",
        "client_secret",
        "begin{proof}",
    ):
        if forbidden in serialized:
            raise ValueError("target evidence contains forbidden sensitive or proof content")
    environment = payload.get("environment")
    if not isinstance(environment, dict):
        raise ValueError("target evidence environment is missing")
    for executable in ("bwrap", "latexmk", "pdflatex", "cloudflared", "curl"):
        if not environment.get(executable):
            raise ValueError(f"target evidence does not identify {executable}")
    return {
        "implementation_sha256": expected,
        "required_check_count": len(REQUIRED_CHECKS),
        "environment": {
            "platform": environment.get("platform"),
            "release": environment.get("release"),
            "machine": environment.get("machine"),
        },
    }


def main() -> int:
    try:
        summary = validate()
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        return 1
    print(json.dumps({"ok": True, "summary": summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
