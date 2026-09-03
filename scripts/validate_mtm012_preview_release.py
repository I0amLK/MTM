#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HOME = Path("/home/lk")
VERSION = "0.4.0-preview.3"
REPORT = ROOT / "mtm012-preview-release.json"
TUI_REPORT = ROOT / "mtm012-tui-validation.json"
DEPLOYMENT = HOME / ".local" / "share" / "mtm" / "deployment" / "deployment-v1.json"
MTM_BIN = HOME / ".local" / "bin" / "mtm"
CARGO_ALIAS = HOME / ".cargo" / "bin" / "mtm"
RE_CTM_BIN = HOME / ".local" / "bin" / "re-ctm"
EXPECTED_TUI_SHA256 = "be9a9317988afc7a727a7f4bba00f7dcf0119394773c0825b4526a77f9aa868b"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
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
    if report.get("project") != "MTM-reboot" or report.get("phase") != "mtm012_preview_release":
        raise ValueError("MTM-012 preview release evidence identity is invalid")
    if report.get("passed") is not True or report.get("version") != VERSION:
        raise ValueError("MTM-012 preview release evidence is not accepted")
    if sha256_file(TUI_REPORT) != EXPECTED_TUI_SHA256:
        raise ValueError("MTM-012 TUI A4 report SHA drifted")

    target = Path(str(report.get("production_command_target") or ""))
    if not MTM_BIN.is_symlink() or MTM_BIN.resolve() != target.resolve(strict=True):
        raise ValueError("installed mtm selector does not select preview.3")
    if not CARGO_ALIAS.is_symlink() or CARGO_ALIAS.resolve() != target.resolve(strict=True):
        raise ValueError("login-shell-preferred mtm path does not select preview.3")
    expected_sha = str(report.get("binary_sha256") or "")
    if sha256_file(target) != expected_sha:
        raise ValueError("installed preview.3 binary hash mismatch")
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
            raise ValueError(f"preview.3 release-info drifted: {key}")

    tui = report.get("tui_a4", {})
    if (
        tui.get("report_sha256") != EXPECTED_TUI_SHA256
        or tui.get("check_count") != 20
        or tui.get("raw_tui_log_recorded") is not False
        or tui.get("generated_operator_key_recorded") is not False
    ):
        raise ValueError("preview.3 TUI A4 binding is incomplete")
    probes = report.get("runtime_probes", {})
    if probes != {
        "preview2_default_during_rollback": 3,
        "preview3_default_after_cutover": 3,
        "preview3_default_after_recutover": 3,
        "preview3_explicit_protocol2": 2,
    }:
        raise ValueError("preview.3 runtime/default rollback probes are incomplete")
    rollback = report.get("rollback", {})
    rollback_target = Path(str(rollback.get("target") or ""))
    if not rollback_target.is_file() or sha256_file(rollback_target) != rollback.get("sha256"):
        raise ValueError("preview.2 rollback target is unavailable or drifted")
    if rollback.get("real_rollback_and_recutover_passed") is not True:
        raise ValueError("preview.3 selector rollback/recutover evidence is missing")

    deployment = json.loads(DEPLOYMENT.read_text(encoding="utf-8"))
    if deployment.get("release", {}).get("sha256") != expected_sha:
        raise ValueError("deployment manifest does not bind preview.3")
    if deployment.get("previous", {}).get("resolved_target") != str(rollback_target.resolve(strict=True)):
        raise ValueError("deployment manifest does not retain preview.2 rollback")
    actions = [item.get("action") for item in deployment.get("history", []) if isinstance(item, dict)]
    for action in ("preview3_tui_cutover", "preview3_tui_rollback", "preview3_tui_recutover"):
        if action not in actions:
            raise ValueError(f"deployment history is missing {action}")
    if not RE_CTM_BIN.exists() or RE_CTM_BIN.resolve() == MTM_BIN.resolve():
        raise ValueError("MTM and Re-CTM command namespaces are not separate")
    if report.get("existing_runs_rewritten") is not False:
        raise ValueError("preview.3 release improperly claims existing run mutation")
    return {
        "version": VERSION,
        "binary_sha256": expected_sha,
        "production_default_workflow_protocol": 3,
        "rollback_workflow_protocol": 2,
        "selector_rollback_version": "0.4.0-preview.2",
        "real_rollback_and_recutover_passed": True,
        "tui_check_count": 20,
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
