#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

try:
    from scripts.run_mtm003_target_validation import implementation_sha256
except ModuleNotFoundError:
    from run_mtm003_target_validation import implementation_sha256


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "mtm003-target-validation.json"
REQUIRED_CHECKS = {
    "bubblewrap_attestation",
    "safe_workspace_read",
    "private_vault_and_parent_env_denial",
    "explicit_generic_toolchain_execution",
    "toolchain_mount_read_only",
    "toolchain_plan_discovers_target_cas",
    "dangerous_plan_attestation",
    "sagemath_execution",
    "magma_execution",
    "helper_timeout_provenance",
    "python_rust_helper_protocol_parity",
    "isolated_tty_round_trip",
    "isolated_process_group_kill",
    "real_quick_tunnel_lifecycle",
}


def validate() -> dict[str, object]:
    payload = json.loads(REPORT.read_text(encoding="utf-8"))
    if payload.get("project") != "MTM-reboot" or payload.get("milestone") != "MTM-003":
        raise ValueError("target evidence belongs to a different project or milestone")
    if payload.get("passed") is not True:
        raise ValueError("MTM-003 target evidence is not passing")
    expected_hash = implementation_sha256()
    if payload.get("implementation_sha256") != expected_hash:
        raise ValueError("MTM-003 target evidence is stale for the current implementation")
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
    environment = payload.get("environment")
    if not isinstance(environment, dict):
        raise ValueError("target evidence environment must be an object")
    missing_tools = [name for name in ("bwrap", "sage", "magma", "cloudflared") if not environment.get(name)]
    if missing_tools:
        raise ValueError(f"target evidence lacks required executables: {missing_tools}")
    return {
        "implementation_sha256": expected_hash,
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
