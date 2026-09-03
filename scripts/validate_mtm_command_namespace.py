#!/usr/bin/env python3
from __future__ import annotations

import json
import hashlib
from pathlib import Path

try:
    from scripts.run_mtm_command_namespace_cutover import (
        LEGACY_SHARED_DATA_ROOT,
        MTM_BIN,
        MTM_DATA_ROOT,
        MTM_STATE_ROOT,
        RE_CTM_BIN,
        RE_CTM_TOOL_ROOT,
        REPORT,
        implementation_sha256,
    )
    from scripts.validate_mtm011_preview_release import validate as validate_mtm011_preview_release
    from scripts.validate_mtm012_preview_release import validate as validate_mtm012_preview_release
except ModuleNotFoundError:
    from run_mtm_command_namespace_cutover import (
        LEGACY_SHARED_DATA_ROOT,
        MTM_BIN,
        MTM_DATA_ROOT,
        MTM_STATE_ROOT,
        RE_CTM_BIN,
        RE_CTM_TOOL_ROOT,
        REPORT,
        implementation_sha256,
    )
    from validate_mtm011_preview_release import validate as validate_mtm011_preview_release
    from validate_mtm012_preview_release import validate as validate_mtm012_preview_release


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
    "distinct_runtime_data_roots",
}

ROOT = Path(__file__).resolve().parents[1]
PREVIEW_REPORT = ROOT / "mtm009-preview-release.json"
PREVIEW_VERSION = "0.4.0-preview.1"
MTM011_PREVIEW_VERSION = "0.4.0-preview.2"
MTM012_PREVIEW_VERSION = "0.4.0-preview.3"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def validate_preview_namespace() -> dict[str, object]:
    payload = json.loads(PREVIEW_REPORT.read_text(encoding="utf-8"))
    if payload.get("project") != "MTM-reboot" or payload.get("phase") != "mtm009_preview_release":
        raise ValueError("MTM-009 preview namespace evidence identity is invalid")
    if payload.get("passed") is not True or payload.get("version") != PREVIEW_VERSION:
        raise ValueError("MTM-009 preview namespace evidence is not accepted")
    if payload.get("milestone_status") != "in_progress":
        raise ValueError("preview release may not claim MTM-009 completion")
    if payload.get("workflow_protocols", {}).get("production_default") != 2:
        raise ValueError("preview release changed the production workflow default")
    if payload.get("workflow_protocols", {}).get("preview_opt_in") != 3:
        raise ValueError("preview release does not expose protocol 3 as the recorded opt-in")
    if payload.get("workflow_protocols", {}).get("protocol3_default_cutover_allowed") is not False:
        raise ValueError("preview evidence improperly authorizes protocol-3 default cutover")
    expected_target = Path(str(payload.get("production_command_target") or ""))
    if not expected_target.is_absolute() or not expected_target.is_file():
        raise ValueError("preview release target is missing")
    if not MTM_BIN.is_symlink() or MTM_BIN.resolve() != expected_target.resolve():
        raise ValueError("MTM command does not select the recorded preview release")
    expected_sha = str(payload.get("binary_sha256") or "")
    if sha256_file(expected_target) != expected_sha:
        raise ValueError("preview release binary hash mismatch")
    rollback = payload.get("rollback", {})
    rollback_target = Path(str(rollback.get("target") or ""))
    if not rollback_target.is_file() or sha256_file(rollback_target) != rollback.get("sha256"):
        raise ValueError("preview rollback target is unavailable or has drifted")
    if rollback.get("real_rollback_and_recutover_passed") is not True:
        raise ValueError("preview rollback drill is missing")
    if not RE_CTM_BIN.exists() or MTM_BIN.resolve() == RE_CTM_BIN.resolve():
        raise ValueError("MTM and Re-CTM commands are not independently installed")
    if MTM_STATE_ROOT.resolve() == RE_CTM_TOOL_ROOT.resolve():
        raise ValueError("MTM and Re-CTM share an installation root")
    if not MTM_DATA_ROOT.is_dir() or MTM_DATA_ROOT.is_symlink():
        raise ValueError("MTM runtime data root is missing or unsafe")
    if MTM_DATA_ROOT.resolve() == LEGACY_SHARED_DATA_ROOT.resolve():
        raise ValueError("MTM and Re-CTM share a runtime data root")
    serialized = json.dumps(payload, ensure_ascii=False).lower()
    for forbidden in ("access_token", "client_secret", "oauth operator key:", "capability_secret"):
        if forbidden in serialized:
            raise ValueError(f"preview release evidence contains forbidden content: {forbidden}")
    return {
        "evidence": "mtm009_preview_release",
        "mtm_version": PREVIEW_VERSION,
        "mtm_target": str(MTM_BIN.resolve()),
        "mtm_sha256": expected_sha,
        "re_ctm_target": str(RE_CTM_BIN.resolve()),
        "mtm_data_root": str(MTM_DATA_ROOT.resolve()),
        "existing_sessions_restarted_for_preview": payload.get("live_sessions", {}).get(
            "existing_sessions_restarted_for_preview"
        ),
    }


def validate_mtm011_preview_namespace() -> dict[str, object]:
    summary = validate_mtm011_preview_release()
    if not RE_CTM_BIN.exists() or MTM_BIN.resolve() == RE_CTM_BIN.resolve():
        raise ValueError("MTM and Re-CTM commands are not independently installed")
    if MTM_STATE_ROOT.resolve() == RE_CTM_TOOL_ROOT.resolve():
        raise ValueError("MTM and Re-CTM share an installation root")
    if not MTM_DATA_ROOT.is_dir() or MTM_DATA_ROOT.is_symlink():
        raise ValueError("MTM runtime data root is missing or unsafe")
    if MTM_DATA_ROOT.resolve() == LEGACY_SHARED_DATA_ROOT.resolve():
        raise ValueError("MTM and Re-CTM share a runtime data root")
    return {
        "evidence": "mtm011_preview_release",
        "mtm_version": MTM011_PREVIEW_VERSION,
        "mtm_target": str(MTM_BIN.resolve()),
        "mtm_sha256": summary["binary_sha256"],
        "production_default_workflow_protocol": 3,
        "rollback_workflow_protocol": 2,
        "real_rollback_and_recutover_passed": summary["real_rollback_and_recutover_passed"],
        "re_ctm_target": str(RE_CTM_BIN.resolve()),
        "mtm_data_root": str(MTM_DATA_ROOT.resolve()),
    }


def validate() -> dict[str, object]:
    if MTM_BIN.is_symlink() and f"/releases/{MTM012_PREVIEW_VERSION}/" in str(MTM_BIN.resolve()):
        summary = validate_mtm012_preview_release()
        if not RE_CTM_BIN.exists() or MTM_BIN.resolve() == RE_CTM_BIN.resolve():
            raise ValueError("MTM and Re-CTM commands are not independently installed")
        return {
            "evidence": "mtm012_preview_release",
            "mtm_version": MTM012_PREVIEW_VERSION,
            "mtm_target": str(MTM_BIN.resolve()),
            "mtm_sha256": summary["binary_sha256"],
            "production_default_workflow_protocol": summary[
                "production_default_workflow_protocol"
            ],
            "rollback_workflow_protocol": summary["rollback_workflow_protocol"],
            "real_rollback_and_recutover_passed": summary[
                "real_rollback_and_recutover_passed"
            ],
            "re_ctm_target": str(RE_CTM_BIN.resolve()),
            "mtm_data_root": str(MTM_DATA_ROOT.resolve()),
        }
    if MTM_BIN.is_symlink() and f"/releases/{MTM011_PREVIEW_VERSION}/" in str(MTM_BIN.resolve()):
        return validate_mtm011_preview_namespace()
    if MTM_BIN.is_symlink() and f"/releases/{PREVIEW_VERSION}/" in str(MTM_BIN.resolve()):
        return validate_preview_namespace()
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
    if not MTM_DATA_ROOT.is_dir() or MTM_DATA_ROOT.is_symlink():
        raise ValueError("MTM runtime data root is missing or unsafe")
    if MTM_DATA_ROOT.resolve() == LEGACY_SHARED_DATA_ROOT.resolve():
        raise ValueError("MTM and Re-CTM share a runtime data root")
    serialized = json.dumps(payload, ensure_ascii=False).lower()
    for forbidden in ("access_token", "client_secret", "oauth operator key:", "capability_secret"):
        if forbidden in serialized:
            raise ValueError(f"command-namespace evidence contains forbidden content: {forbidden}")
    return {
        "implementation_sha256": implementation_sha256(),
        "required_check_count": len(REQUIRED),
        "mtm_target": str(MTM_BIN.resolve()),
        "re_ctm_target": str(RE_CTM_BIN.resolve()),
        "mtm_data_root": str(MTM_DATA_ROOT.resolve()),
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
