#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
HOME = Path("/home/lk")
REPORT = ROOT / "records/evidence/MTM-013/stable-release.json"
DEPLOYMENT = HOME / ".local" / "share" / "mtm" / "deployment" / "deployment-v1.json"
SELECTOR = HOME / ".local" / "bin" / "mtm"
CARGO_COMMAND = HOME / ".cargo" / "bin" / "mtm"
VERSION = "0.4.0"
EXPECTED_BINARY_SHA256 = "3312ca75a1de8707e740963cc0add4b09430dccc9dc63a3145e4456ff2b0cdf3"
ROLLBACK_SHA256 = "545ab9ef8cc01edf804581cb52c2b1a4158d03bd8a25ea00c7785039167f3659"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def release_info(path: Path) -> dict[str, Any]:
    completed = subprocess.run(
        [str(path), "release-info"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10,
        check=True,
    )
    value = json.loads(completed.stdout)
    if not isinstance(value, dict):
        raise ValueError("release-info returned a non-object")
    return value


def validate(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("schema_version") != "1.0.0" or payload.get("milestone") != "MTM-013":
        raise ValueError("unexpected stable release evidence identity")
    if payload.get("phase") != "stable_0_4_0_release" or payload.get("version") != VERSION:
        raise ValueError("stable release evidence phase/version drifted")
    if payload.get("passed") is not True or payload.get("binary_sha256") != EXPECTED_BINARY_SHA256:
        raise ValueError("stable release evidence is not accepted or binary-bound")
    target = Path(str(payload.get("production_command_target") or ""))
    if not SELECTOR.is_symlink() or SELECTOR.resolve(strict=True) != target.resolve(strict=True):
        raise ValueError("stable selector is not active")
    if sha256_file(target) != EXPECTED_BINARY_SHA256:
        raise ValueError("installed stable release hash drifted")
    if not CARGO_COMMAND.is_file() or sha256_file(CARGO_COMMAND) != EXPECTED_BINARY_SHA256:
        raise ValueError("login-shell stable command does not match the qualified artifact")
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
    for executable in (target, CARGO_COMMAND):
        info = release_info(executable)
        for key, expected in required.items():
            if info.get(key) != expected:
                raise ValueError(f"stable command identity drifted: {key}")
    probes = payload.get("runtime_probes", {})
    if probes != {
        "stable_default_after_cutover": 3,
        "stable_explicit_protocol2": 2,
        "preview3_default_during_rollback": 3,
        "stable_default_after_recutover": 3,
    }:
        raise ValueError("stable runtime rollback probes are incomplete")
    rollback = payload.get("rollback", {})
    rollback_target = Path(str(rollback.get("selector_target") or ""))
    if not rollback_target.is_file() or sha256_file(rollback_target) != ROLLBACK_SHA256:
        raise ValueError("preview.3 selector rollback target drifted")
    cargo_backup = Path(str(rollback.get("cargo_backup", {}).get("path") or ""))
    if not cargo_backup.is_file() or sha256_file(cargo_backup) != rollback.get("cargo_backup", {}).get("sha256"):
        raise ValueError("preview.3 cargo rollback backup drifted")
    if rollback.get("real_rollback_and_recutover_passed") is not True:
        raise ValueError("stable release lacks real rollback/recutover evidence")
    deployment = json.loads(DEPLOYMENT.read_text(encoding="utf-8"))
    if deployment.get("release", {}).get("sha256") != EXPECTED_BINARY_SHA256:
        raise ValueError("deployment manifest does not bind the stable release")
    actions = [item.get("action") for item in deployment.get("history", []) if isinstance(item, dict)]
    for action in ("stable_0_4_0_cutover", "stable_0_4_0_rollback", "stable_0_4_0_recutover"):
        if action not in actions:
            raise ValueError(f"deployment history is missing {action}")
    if payload.get("existing_runs_rewritten") is not False:
        raise ValueError("stable release improperly claims existing-run mutation")
    return {
        "report_sha256": sha256_file(REPORT),
        "binary_sha256": EXPECTED_BINARY_SHA256,
        "version": VERSION,
        "production_default_workflow_protocol": 3,
        "rollback_workflow_protocol": 2,
        "real_rollback_and_recutover_passed": True,
    }


def main() -> int:
    try:
        summary = validate(json.loads(REPORT.read_text(encoding="utf-8")))
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, ValueError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, indent=2))
        return 1
    print(json.dumps({"ok": True, "summary": summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
