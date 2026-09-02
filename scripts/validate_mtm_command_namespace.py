#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

try:
    from scripts.run_mtm_command_namespace_cutover import (
        MTM_BIN,
        MTM_STATE_ROOT,
        RE_CTM_BIN,
        RE_CTM_TOOL_ROOT,
        REPORT,
        implementation_sha256,
    )
except ModuleNotFoundError:
    from run_mtm_command_namespace_cutover import (
        MTM_BIN,
        MTM_STATE_ROOT,
        RE_CTM_BIN,
        RE_CTM_TOOL_ROOT,
        REPORT,
        implementation_sha256,
    )


REQUIRED = {
    "mtm_command_unique",
    "re_ctm_command_unique",
    "mtm_identity",
    "re_ctm_identity",
    "mtm_release_info",
    "re_ctm_server_probe",
    "mtm_sessions_restarted",
    "old_mtm_selector_released",
    "distinct_install_roots",
}


def validate() -> dict[str, object]:
    payload = json.loads(REPORT.read_text(encoding="utf-8"))
    if payload.get("project") != "MTM-reboot" or payload.get("phase") != "command_namespace_separation":
        raise ValueError("command-namespace evidence identity is invalid")
    if payload.get("passed") is not True or payload.get("implementation_sha256") != implementation_sha256():
        raise ValueError("command-namespace evidence is failed or stale")
    checks = payload.get("checks")
    if not isinstance(checks, list):
        raise ValueError("command-namespace checks are missing")
    by_name = {str(item.get("name")): item for item in checks if isinstance(item, dict)}
    if REQUIRED - set(by_name):
        raise ValueError("command-namespace evidence is incomplete")
    if any(by_name[name].get("passed") is not True for name in REQUIRED):
        raise ValueError("command-namespace evidence contains a failed check")
    if not MTM_BIN.is_symlink() or not RE_CTM_BIN.exists():
        raise ValueError("both project commands are not installed")
    if MTM_BIN.resolve() == RE_CTM_BIN.resolve():
        raise ValueError("MTM and Re-CTM resolve to the same executable")
    if MTM_STATE_ROOT.resolve() == RE_CTM_TOOL_ROOT.resolve():
        raise ValueError("MTM and Re-CTM share an installation root")
    serialized = json.dumps(payload, ensure_ascii=False).lower()
    for forbidden in ("access_token", "client_secret", "oauth operator key:", "capability_secret"):
        if forbidden in serialized:
            raise ValueError(f"command-namespace evidence contains forbidden content: {forbidden}")
    return {
        "implementation_sha256": implementation_sha256(),
        "required_check_count": len(REQUIRED),
        "mtm_target": str(MTM_BIN.resolve()),
        "re_ctm_target": str(RE_CTM_BIN.resolve()),
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
