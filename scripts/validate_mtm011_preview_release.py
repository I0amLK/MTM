#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HOME = Path("/home/lk")
VERSION = "0.4.0-preview.2"
REPORT = ROOT / "records/evidence/MTM-011/preview-release.json"
EVALUATION = ROOT / "records/evidence/MTM-011/protocol3-cutover-evaluation.json"
POST_A5 = ROOT / "records/evidence/MTM-011/cutover-resource.json"
DEPLOYMENT = HOME / ".local" / "share" / "mtm" / "deployment" / "deployment-v1.json"
MTM_BIN = HOME / ".local" / "bin" / "mtm"
CARGO_MTM_BIN = HOME / ".cargo" / "bin" / "mtm"
RE_CTM_BIN = HOME / ".local" / "bin" / "re-ctm"
EXPECTED_A4_CANDIDATE_SHA256 = "5cebde6458f29012f3da72564ad6a940cc319aae162f9695070474b77d83b036"
A4_CANDIDATE_ARCHIVE = (
    HOME / ".local" / "share" / "mtm" / "evidence"
    / f"mtm011-a4-candidate-{EXPECTED_A4_CANDIDATE_SHA256[:12]}" / "mtm"
)
EXPECTED_EVALUATION_SHA256 = "1820027a361604fd77da2e303e1c7c43ab6f25edd7a7401cc6176705c280bd05"
EXPECTED_POST_A5_SHA256 = "fc9ad093e0abb91d4b90fb05f9c2b280d359557938d701da81dcd5789bdf6f8d"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
    if report.get("project") != "MTM-reboot" or report.get("phase") != "mtm011_preview_release":
        raise ValueError("MTM-011 preview release evidence identity is invalid")
    if report.get("passed") is not True or report.get("version") != VERSION:
        raise ValueError("MTM-011 preview release evidence is not accepted")
    if report.get("milestone_status") != "in_progress":
        raise ValueError("preview release may not claim MTM-011 completion before final receipt")
    if sha256_file(EVALUATION) != EXPECTED_EVALUATION_SHA256:
        raise ValueError("accepted MTM-011 evaluation SHA drifted")
    if sha256_file(POST_A5) != EXPECTED_POST_A5_SHA256:
        raise ValueError("post-cutover A5 evidence SHA drifted")

    target = Path(str(report.get("production_command_target") or ""))
    if not MTM_BIN.is_symlink() or MTM_BIN.resolve() != target.resolve(strict=True):
        raise ValueError("installed mtm command does not select preview.2")
    shell_alias = report.get("shell_command_alias")
    if not isinstance(shell_alias, dict):
        raise ValueError("preview.2 shell command alias evidence is missing")
    if not CARGO_MTM_BIN.is_symlink() or CARGO_MTM_BIN.resolve() != MTM_BIN.resolve():
        raise ValueError("~/.cargo/bin/mtm does not follow the production MTM selector")
    if shell_alias.get("path") != str(CARGO_MTM_BIN):
        raise ValueError("preview.2 shell command alias path drifted")
    if shell_alias.get("a4_candidate_archive") != str(A4_CANDIDATE_ARCHIVE):
        raise ValueError("preview.2 A4 candidate archive path drifted")
    if shell_alias.get("a4_candidate_sha256") != EXPECTED_A4_CANDIDATE_SHA256:
        raise ValueError("preview.2 A4 candidate archive hash binding drifted")
    if not A4_CANDIDATE_ARCHIVE.is_file() or sha256_file(A4_CANDIDATE_ARCHIVE) != EXPECTED_A4_CANDIDATE_SHA256:
        raise ValueError("MTM-011 A4 candidate archive is unavailable or drifted")
    expected_sha = str(report.get("binary_sha256") or "")
    if sha256_file(target) != expected_sha:
        raise ValueError("installed preview.2 binary hash mismatch")
    info = release_info(target)
    required = {
        "name": "mtm",
        "version": VERSION,
        "implementation": "rust",
        "production_authority": "rust",
        "python_runtime_required": False,
        "public_tool_count": 24,
        "hidden_alias_count": 11,
        "state_schema_version": 2,
        "workflow_protocol_version": 3,
    }
    for key, expected in required.items():
        if info.get(key) != expected:
            raise ValueError(f"preview.2 release-info drifted: {key}")

    protocols = report.get("workflow_protocols", {})
    if protocols.get("production_default") != 3 or protocols.get("rollback_override") != 2:
        raise ValueError("preview.2 workflow protocol posture drifted")
    if protocols.get("protocol3_default_cutover_allowed") is not True:
        raise ValueError("preview.2 report does not bind accepted cutover authority")
    probes = report.get("runtime_probes", {})
    if probes != {
        "preview2_default_after_cutover": 3,
        "preview2_explicit_protocol2": 2,
        "preview1_default_during_rollback": 2,
        "preview2_default_after_recutover": 3,
    }:
        raise ValueError("preview.2 runtime default/rollback probes are incomplete")
    rollback = report.get("rollback", {})
    rollback_target = Path(str(rollback.get("target") or ""))
    if not rollback_target.is_file() or sha256_file(rollback_target) != rollback.get("sha256"):
        raise ValueError("preview.1 rollback target is unavailable or drifted")
    if rollback.get("real_rollback_and_recutover_passed") is not True:
        raise ValueError("preview.2 real rollback/recutover evidence is missing")

    deployment = json.loads(DEPLOYMENT.read_text(encoding="utf-8"))
    if deployment.get("release", {}).get("sha256") != expected_sha:
        raise ValueError("deployment manifest does not bind preview.2")
    if deployment.get("previous", {}).get("resolved_target") != str(rollback_target.resolve(strict=True)):
        raise ValueError("deployment manifest does not retain preview.1 rollback")
    actions = [item.get("action") for item in deployment.get("history", []) if isinstance(item, dict)]
    for action in ("preview2_cutover", "preview2_rollback", "preview2_recutover"):
        if action not in actions:
            raise ValueError(f"deployment history is missing {action}")
    if not RE_CTM_BIN.exists() or RE_CTM_BIN.resolve() == MTM_BIN.resolve():
        raise ValueError("MTM and Re-CTM command namespaces are not separate")
    if report.get("existing_runs_rewritten") is not False:
        raise ValueError("preview.2 release improperly claims existing run mutation")
    return {
        "version": VERSION,
        "binary_sha256": expected_sha,
        "production_default_workflow_protocol": 3,
        "rollback_workflow_protocol": 2,
        "real_rollback_and_recutover_passed": True,
        "shell_command_alias": str(CARGO_MTM_BIN),
        "a4_candidate_archive_sha256": EXPECTED_A4_CANDIDATE_SHA256,
        "state_schema_version": 2,
        "public_tools": 24,
        "hidden_aliases": 11,
        "final_artifact": report.get("final_artifact"),
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
