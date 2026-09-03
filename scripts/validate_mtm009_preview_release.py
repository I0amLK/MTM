#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HOME = Path("/home/lk")
REPORT = ROOT / "mtm009-preview-release.json"
SIMULATION = ROOT / "conformance" / "mtm009-math-simulation.json"
EVALUATION = ROOT / "mtm009-research-state-math-evaluation.json"
DEPLOYMENT = HOME / ".local" / "share" / "mtm" / "deployment" / "deployment-v1.json"
MTM_BIN = HOME / ".local" / "bin" / "mtm"
RE_CTM_BIN = HOME / ".local" / "bin" / "re-ctm"
VERSION = "0.4.0-preview.1"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def release_info(path: Path) -> dict[str, object]:
    completed = subprocess.run(
        [str(path), "release-info"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10,
        check=True,
    )
    return json.loads(completed.stdout)


def validate() -> dict[str, object]:
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    if report.get("project") != "MTM-reboot" or report.get("phase") != "mtm009_preview_release":
        raise ValueError("preview release evidence identity is invalid")
    if report.get("passed") is not True or report.get("version") != VERSION:
        raise ValueError("preview release evidence is not accepted")
    if report.get("milestone_status") != "in_progress":
        raise ValueError("preview release may not claim MTM-009 completion")
    target = Path(str(report.get("production_command_target") or ""))
    if not MTM_BIN.is_symlink() or MTM_BIN.resolve() != target.resolve(strict=True):
        raise ValueError("installed mtm command does not select the preview release")
    expected_sha = str(report.get("binary_sha256") or "")
    if sha256_file(target) != expected_sha:
        raise ValueError("installed preview binary hash mismatch")
    info = release_info(target)
    required_info = {
        "name": "mtm",
        "version": VERSION,
        "implementation": "rust",
        "production_authority": "rust",
        "python_runtime_required": False,
        "public_tool_count": 24,
        "hidden_alias_count": 11,
        "state_schema_version": 2,
        "workflow_protocol_version": 2,
    }
    for key, expected in required_info.items():
        if info.get(key) != expected:
            raise ValueError(f"preview release-info drifted: {key}")
    protocols = report.get("workflow_protocols", {})
    if protocols.get("production_default") != 2 or protocols.get("preview_opt_in") != 3:
        raise ValueError("preview workflow protocol posture drifted")
    if protocols.get("protocol3_default_cutover_allowed") is not False or protocols.get("real_web_a4") != "pending":
        raise ValueError("preview improperly claims protocol-3 default acceptance")
    # The preview report is historical evidence for the exact installed preview binary.
    # The mutable current-candidate resource report is validated independently by
    # validate_mtm009_research_resource.py and must not retroactively invalidate this
    # already-qualified preview when a later candidate is measured.
    preview_a5 = report.get("a5_resource_evidence", {})
    if (
        preview_a5.get("passed") is not True
        or preview_a5.get("implementation_sha256") != expected_sha
        or preview_a5.get("performance_claim") is not False
        or not isinstance(preview_a5.get("sha256"), str)
        or len(str(preview_a5.get("sha256"))) != 64
    ):
        raise ValueError("historical preview A5 evidence binding is incomplete")
    simulation = json.loads(SIMULATION.read_text(encoding="utf-8"))
    if simulation.get("official_a4_eligible") is not False:
        raise ValueError("simulation may not qualify as A4")
    evaluation = json.loads(EVALUATION.read_text(encoding="utf-8"))
    if evaluation.get("status") == "pending_web_runs":
        real_web_a4 = "pending"
    elif (
        evaluation.get("status") == "complete"
        and evaluation.get("decision") == "rejected"
        and evaluation.get("aggregate", {}).get("release_gate_passed") is False
    ):
        real_web_a4 = "complete_rejected"
    else:
        raise ValueError("current real-web A4 state is not a recognized bounded preview posture")
    rollback = report.get("rollback", {})
    rollback_target = Path(str(rollback.get("target") or ""))
    if not rollback_target.is_file() or sha256_file(rollback_target) != rollback.get("sha256"):
        raise ValueError("accepted preview rollback target drifted")
    if rollback.get("real_rollback_and_recutover_passed") is not True:
        raise ValueError("real preview rollback/recutover evidence is missing")
    deployment = json.loads(DEPLOYMENT.read_text(encoding="utf-8"))
    if deployment.get("release", {}).get("sha256") != expected_sha:
        raise ValueError("deployment manifest does not bind the preview release hash")
    if deployment.get("previous", {}).get("resolved_target") != str(rollback_target):
        raise ValueError("deployment manifest does not retain the accepted rollback target")
    if not RE_CTM_BIN.exists() or RE_CTM_BIN.resolve() == MTM_BIN.resolve():
        raise ValueError("MTM and Re-CTM command namespaces are not separate")
    tui = report.get("tui_tool_visibility", {})
    if tui.get("passed") is not True or tui.get("argument_values_hidden") is not True:
        raise ValueError("preview TUI visibility/redaction evidence is incomplete")
    progress = json.loads((ROOT / "project-progress.json").read_text(encoding="utf-8"))
    if progress.get("version") != VERSION or progress.get("current_milestone") not in {"MTM-009", "MTM-011"}:
        raise ValueError("project progress does not identify the installed preview")
    return {
        "version": VERSION,
        "binary_sha256": expected_sha,
        "production_default_workflow_protocol": 2,
        "protocol3_opt_in": True,
        "protocol3_default_cutover_allowed": False,
        "state_schema_version": 2,
        "public_tools": 24,
        "hidden_aliases": 11,
        "final_artifact": report.get("final_artifact"),
        "real_web_a4": real_web_a4,
        "existing_sessions_restarted_for_preview": report.get("live_sessions", {}).get("existing_sessions_restarted_for_preview"),
    }


def main() -> int:
    try:
        summary = validate()
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, ValueError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, indent=2))
        return 1
    print(json.dumps({"ok": True, "summary": summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
