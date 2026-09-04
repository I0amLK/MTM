#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

try:
    from scripts.mtm008_deployment import (
        load_manifest,
        processes_using,
        run_json,
        sha256_file,
        verify_active_rust,
        manifest_layout,
    )
except ModuleNotFoundError:
    from mtm008_deployment import (
        load_manifest,
        processes_using,
        run_json,
        sha256_file,
        verify_active_rust,
        manifest_layout,
    )


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "records/evidence/MTM-008/retirement.json"
INVENTORY = ROOT / "records/governance/authority-inventory.json"
STATE_ROOT = Path("/home/lk/.local/share/re-ctm-rust")
MANIFEST = STATE_ROOT / "deployment" / "deployment-v1.json"
BIN_LINK = Path("/home/lk/.local/bin/re-ctm")
PYTHON_TOOL_ROOT = Path("/home/lk/.local/share/uv/tools/re-ctm")
HELPER_LINK = Path("/home/lk/.local/bin/re-ctm-native-helper")
QUALIFICATION_COMMIT = "b1601149d3dd555278bcd26ecda02f39a0600860"
REQUIRED_CHECKS = {
    "qualification_commit_exact",
    "candidate_evidence_fresh",
    "live_cutover_evidence_fresh",
    "final_release_matches_qualified_candidate",
    "live_sessions_stopped_for_upgrade",
    "live_sessions_restarted_exact_release",
    "final_status_reports_rust_authority",
    "rollback_wheel_restored_after_retirement",
    "python_tool_root_removed",
    "legacy_python_helper_link_removed",
    "no_python_re_ctm_process",
    "deployment_manifest_retired",
    "rollback_wheel_retained",
    "release_has_no_python_linkage",
    "historical_source_preserved",
    "session_logs_secret_free",
    "legacy_selector_rollback_fails_closed",
}


def implementation_sha256() -> str:
    try:
        from scripts.run_mtm008_python_retirement import implementation_sha256 as calculate
    except ModuleNotFoundError:
        from run_mtm008_python_retirement import implementation_sha256 as calculate

    return calculate()


def validate() -> dict[str, Any]:
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
    if report.get("project") != "MTM-reboot" or report.get("milestone") != "MTM-008":
        raise ValueError("retirement evidence identity is invalid")
    if report.get("phase") != "python_retirement" or report.get("passed") is not True:
        raise ValueError("retirement evidence is not passing")
    expected_hash = implementation_sha256()
    if report.get("implementation_sha256") != expected_hash:
        raise ValueError("retirement evidence is stale for its implementation")
    if report.get("qualification_commit") != QUALIFICATION_COMMIT:
        raise ValueError("retirement evidence is not bound to the qualification commit")
    subprocess.run(
        ["git", "cat-file", "-e", f"{QUALIFICATION_COMMIT}^{{commit}}"],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=True,
    )

    checks = report.get("checks")
    if not isinstance(checks, list):
        raise ValueError("retirement checks must be an array")
    by_name = {
        str(item.get("name")): item
        for item in checks
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    missing = REQUIRED_CHECKS - set(by_name)
    if missing:
        raise ValueError(f"retirement evidence is missing checks: {sorted(missing)}")
    failed = sorted(name for name in REQUIRED_CHECKS if by_name[name].get("passed") is not True)
    if failed:
        raise ValueError(f"retirement evidence contains failed checks: {failed}")

    manifest = load_manifest(MANIFEST)
    layout = manifest_layout(manifest)
    verify_active_rust(layout, manifest)
    if manifest.get("state") != "rust_active_python_retired":
        raise ValueError("deployment manifest does not record Python retirement")
    if PYTHON_TOOL_ROOT.exists() or processes_using(PYTHON_TOOL_ROOT):
        raise ValueError("Python production tool root or process still exists")
    if HELPER_LINK.exists() or HELPER_LINK.is_symlink():
        raise ValueError("legacy Python helper command still exists")
    release = manifest.get("release")
    if not isinstance(release, dict):
        raise ValueError("deployment release is missing")
    release_path = Path(str(release.get("path") or ""))
    if not BIN_LINK.is_symlink() or BIN_LINK.resolve() != release_path.resolve(strict=True):
        raise ValueError("production command does not select the recorded Rust release")
    if sha256_file(release_path) != release.get("sha256"):
        raise ValueError("production release hash changed")
    wheel = manifest.get("rollback_wheel")
    if not isinstance(wheel, dict):
        raise ValueError("rollback wheel is missing")
    wheel_path = Path(str(wheel.get("path") or ""))
    if not wheel_path.is_file() or sha256_file(wheel_path) != wheel.get("sha256"):
        raise ValueError("rollback wheel changed or disappeared")

    status = run_json(BIN_LINK.resolve(), "status")
    release_info = run_json(BIN_LINK.resolve(), "release-info")
    if status.get("production_authority") != "rust" or status.get(
        "milestone_state"
    ) != "authoritative":
        raise ValueError("production status is not the accepted Rust-authoritative build")
    if release_info.get("implementation") != "rust" or release_info.get(
        "python_runtime_required"
    ) is not False:
        raise ValueError("release-info no longer identifies the no-Python Rust runtime")

    if inventory.get("production_authority") != "rust":
        raise ValueError("authority inventory does not identify Rust production authority")
    python_inventory = inventory.get("python_production_runtime")
    if not isinstance(python_inventory, dict) or python_inventory.get("retired") is not True:
        raise ValueError("authority inventory does not record Python retirement")
    if python_inventory.get("active_process_count") != 0:
        raise ValueError("authority inventory records a Python production process")
    if python_inventory.get("legacy_helper_link_removed") is not True:
        raise ValueError("authority inventory does not record helper-link retirement")
    live_sessions = inventory.get("live_sessions")
    if not isinstance(live_sessions, dict) or live_sessions.get("exact_release") is not True:
        raise ValueError("authority inventory does not bind live sessions to the release")
    if live_sessions.get("logs_secret_free") is not True:
        raise ValueError("authority inventory does not confirm secret-free logs")

    serialized = json.dumps({"report": report, "inventory": inventory}, ensure_ascii=False).lower()
    for forbidden in (
        "access_token",
        "client_secret",
        "oauth operator key:",
        "re_ctm_oauth_password",
        "re_ctm_token_secret",
        "re_ctm_capability_secret",
        "begin{proof}",
    ):
        if forbidden in serialized:
            raise ValueError(f"retirement evidence contains forbidden content: {forbidden}")
    if report.get("sensitive_content_recorded") is not False:
        raise ValueError("retirement evidence does not explicitly deny sensitive content")

    return {
        "implementation_sha256": expected_hash,
        "required_check_count": len(REQUIRED_CHECKS),
        "release_sha256": release["sha256"],
        "rollback_wheel_sha256": wheel["sha256"],
        "deployment_state": manifest["state"],
        "live_session_count": live_sessions.get("count"),
    }


def main() -> int:
    try:
        summary = validate()
    except (OSError, ValueError, json.JSONDecodeError, subprocess.CalledProcessError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        return 1
    print(json.dumps({"ok": True, "summary": summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
