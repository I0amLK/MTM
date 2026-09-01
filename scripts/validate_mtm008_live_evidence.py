#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

try:
    from scripts.mtm008_deployment import load_manifest, sha256_file
    from scripts.run_mtm008_live_cutover import (
        BIN_LINK,
        PYTHON_TOOL_ROOT,
        REPORT,
        STATE_ROOT,
        implementation_sha256,
    )
except ModuleNotFoundError:
    from mtm008_deployment import load_manifest, sha256_file
    from run_mtm008_live_cutover import (
        BIN_LINK,
        PYTHON_TOOL_ROOT,
        REPORT,
        STATE_ROOT,
        implementation_sha256,
    )


REQUIRED_CHECKS = {
    "candidate_commit_clean",
    "rollback_wheel_persisted",
    "python_sessions_stopped",
    "live_rust_cutover",
    "live_python_rollback",
    "live_rust_recutover",
    "sessions_restarted_on_rust",
    "session_logs_secret_free",
    "no_python_re_ctm_process",
    "live_command_release_identity",
}


def validate() -> dict[str, object]:
    payload = json.loads(REPORT.read_text(encoding="utf-8"))
    if payload.get("project") != "MTM-reboot" or payload.get("milestone") != "MTM-008":
        raise ValueError("live evidence belongs to another project or milestone")
    if payload.get("phase") != "live_cutover" or payload.get("passed") is not True:
        raise ValueError("MTM-008 live cutover evidence is not passing")
    if payload.get("implementation_sha256") != implementation_sha256():
        raise ValueError("MTM-008 live cutover evidence is stale")
    checks = payload.get("checks")
    if not isinstance(checks, list):
        raise ValueError("live checks must be an array")
    by_name = {
        str(item.get("name")): item
        for item in checks
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    missing = REQUIRED_CHECKS - set(by_name)
    if missing:
        raise ValueError(f"live evidence is missing checks: {sorted(missing)}")
    failed = sorted(name for name in REQUIRED_CHECKS if by_name[name].get("passed") is not True)
    if failed:
        raise ValueError(f"live evidence contains failed checks: {failed}")
    manifest_path = STATE_ROOT / "deployment" / "deployment-v1.json"
    manifest = load_manifest(manifest_path)
    if manifest.get("state") not in {"rust_active", "rust_active_python_retired"}:
        raise ValueError("live deployment manifest does not select Rust")
    release = manifest.get("release", {})
    release_path = Path(str(release.get("path") or ""))
    if not BIN_LINK.is_symlink() or BIN_LINK.resolve() != release_path.resolve(strict=True):
        raise ValueError("live command does not select the recorded Rust release")
    if sha256_file(release_path) != release.get("sha256"):
        raise ValueError("live Rust release hash mismatch")
    wheel = manifest.get("rollback_wheel")
    if not isinstance(wheel, dict):
        raise ValueError("live deployment has no rollback wheel")
    wheel_path = Path(str(wheel.get("path") or ""))
    if not wheel_path.is_file() or sha256_file(wheel_path) != wheel.get("sha256"):
        raise ValueError("live rollback wheel is missing or changed")
    if manifest.get("state") == "rust_active" and not PYTHON_TOOL_ROOT.is_dir():
        raise ValueError("authoritative phase must retain the Python rollback tool root")
    serialized = json.dumps(payload, ensure_ascii=False).lower()
    for forbidden in ("access_token", "client_secret", "oauth_password", "capability_secret"):
        if forbidden in serialized:
            raise ValueError(f"live evidence contains forbidden content: {forbidden}")
    return {
        "implementation_sha256": implementation_sha256(),
        "required_check_count": len(REQUIRED_CHECKS),
        "release_sha256": release.get("sha256"),
        "deployment_state": manifest.get("state"),
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
