#!/usr/bin/env python3
"""Validate MTM-015 preview.2 release and selector rollback/recutover evidence."""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

import mtm014_release_support as release_support
from mtm008_deployment import load_manifest
from validate_mtm015_candidate_stage import validate as validate_stage
from validate_mtm015_target_qualification import validate as validate_target
from validate_mtm015_web_client import validate as validate_web


ROOT = Path(__file__).resolve().parents[1]
HOME = Path("/home/lk")
STATE_ROOT = HOME / ".local/share/mtm"
REPORT = ROOT / "records/evidence/MTM-015/preview-release.json"
TARGET = ROOT / "records/evidence/MTM-015/target-qualification.json"
STAGE = ROOT / "records/evidence/MTM-015/candidate-stage.json"
WEB = ROOT / "records/evidence/MTM-015/web-client.json"
MANIFEST = STATE_ROOT / "deployment/deployment-v1.json"
SELECTOR = HOME / ".local/bin/mtm"
CARGO_ENTRY = HOME / ".cargo/bin/mtm"
VERSION = "0.5.0-preview.2"
CANDIDATE_SHA = "2164c84701b191b06a66a5d28ba595697d355f9a3bdc78ca31ea455d49793d6a"
PREVIOUS_VERSION = "0.5.0-preview.1"
PREVIOUS_SHA = "2b2cd48bea965fd21c5c54d3be3ead6917eaf40870e9aa801c48bb9484209036"
STABLE_SHA = "3312ca75a1de8707e740963cc0add4b09430dccc9dc63a3145e4456ff2b0cdf3"
INSTALLED = STATE_ROOT / f"releases/{VERSION}/mtm"
PREVIOUS = STATE_ROOT / f"releases/{PREVIOUS_VERSION}/mtm"
STABLE = STATE_ROOT / "releases/0.4.0/mtm"
CHECK_NAMES = {
    "target_evidence_valid",
    "candidate_stage_valid",
    "web_client_valid",
    "immutable_release_installed",
    "preview2_cutover_smoke",
    "preview1_rollback_smoke",
    "preview2_recutover_smoke",
    "post_recutover_soak",
    "both_entries_agree",
    "deployment_manifest_consistent",
    "stable_artifact_preserved",
}
HYGIENE = {
    "raw_capability_recorded": False,
    "raw_oauth_token_recorded": False,
    "raw_secret_recorded": False,
    "raw_logs_recorded": False,
}


def require(value: Any, label: str) -> None:
    if not value:
        raise ValueError(label)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(payload: dict[str, Any] | None = None, *, deployed: bool = True) -> dict[str, Any]:
    payload = payload or json.loads(REPORT.read_text(encoding="utf-8"))
    required = {
        "schema_version", "milestone", "phase", "version", "ok", "recorded_at",
        "release_commit", "candidate_binary_sha256", "target_evidence_sha256",
        "candidate_stage_sha256", "web_client_sha256", "previous_version",
        "previous_sha256", "stable_sha256", "release_path", "checks", "check_count",
        "rollback", "post_recutover_soak", "existing_sessions_restarted",
        "production_state_rewritten", "performance_claim", "evidence_hygiene",
        "harness_sha256",
    }
    require(set(payload) == required, "release_fields")
    for key, expected in {
        "schema_version": "1.0.0",
        "milestone": "MTM-015",
        "phase": "preview_release",
        "version": VERSION,
        "ok": True,
        "candidate_binary_sha256": CANDIDATE_SHA,
        "previous_version": PREVIOUS_VERSION,
        "previous_sha256": PREVIOUS_SHA,
        "stable_sha256": STABLE_SHA,
        "release_path": str(INSTALLED),
        "existing_sessions_restarted": False,
        "production_state_rewritten": False,
        "performance_claim": False,
    }.items():
        require(payload.get(key) == expected, f"release_{key}")
    require(re.fullmatch(r"[0-9a-f]{40}", str(payload["release_commit"])) is not None,
            "release_commit")
    require(payload["target_evidence_sha256"] == digest(TARGET), "target_evidence_binding")
    require(payload["candidate_stage_sha256"] == digest(STAGE), "stage_evidence_binding")
    require(payload["web_client_sha256"] == digest(WEB), "web_evidence_binding")
    target = validate_target()
    stage = validate_stage()
    web = validate_web()
    require(target["binary_sha256"] == CANDIDATE_SHA, "target_binary")
    require(stage["candidate_binary_sha256"] == CANDIDATE_SHA, "stage_binary")
    require(web["candidate_binary_sha256"] == CANDIDATE_SHA, "web_binary")
    checks = payload["checks"]
    require(isinstance(checks, dict) and set(checks) == CHECK_NAMES, "release_check_set")
    require(all(value is True for value in checks.values()), "release_checks")
    require(payload["check_count"] == len(CHECK_NAMES), "release_check_count")
    require(payload["evidence_hygiene"] == HYGIENE, "release_hygiene")
    rollback = payload["rollback"]
    require(rollback == {
        "previous_path": str(PREVIOUS),
        "previous_version": PREVIOUS_VERSION,
        "previous_sha256": PREVIOUS_SHA,
        "real_rollback_and_recutover_passed": True,
    }, "rollback_receipt")
    require(release_support.soak_ok(payload["post_recutover_soak"]), "release_soak")
    require(INSTALLED.is_file() and digest(INSTALLED) == CANDIDATE_SHA,
            "installed_release_hash")
    require(PREVIOUS.is_file() and digest(PREVIOUS) == PREVIOUS_SHA, "previous_release_hash")
    require(STABLE.is_file() and digest(STABLE) == STABLE_SHA, "stable_release_hash")
    release_support.identity(INSTALLED, VERSION)

    harness = payload["harness_sha256"]
    expected_harness = {
        "scripts/release_mtm015_preview.py",
        "scripts/validate_mtm015_preview_release.py",
        "scripts/mtm008_deployment.py",
        "scripts/mtm014_release_support.py",
    }
    require(set(harness) == expected_harness, "release_harness_files")
    for path, expected in harness.items():
        require(digest(ROOT / path) == expected, f"release_harness_drift:{path}")
    require(
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", payload["release_commit"], "HEAD"],
            cwd=ROOT,
            check=False,
        ).returncode == 0,
        "release_commit_not_ancestor",
    )

    deployment = load_manifest(MANIFEST)
    require(deployment.get("release", {}).get("path") == str(INSTALLED),
            "deployment_release_path")
    require(deployment.get("release", {}).get("sha256") == CANDIDATE_SHA,
            "deployment_release_hash")
    require(deployment.get("previous", {}).get("resolved_target") == str(PREVIOUS),
            "deployment_previous_path")
    actions = {
        item.get("action") for item in deployment.get("history", []) if isinstance(item, dict)
    }
    require({
        "mtm015_preview2_cutover",
        "mtm015_preview1_rollback",
        "mtm015_preview2_recutover",
    } <= actions, "deployment_history")
    require(deployment.get("state") == "rust_active", "deployment_state")
    if deployed:
        for entry in (SELECTOR, CARGO_ENTRY):
            require(entry.is_symlink() and entry.resolve(strict=True) == INSTALLED,
                    "deployed_selector")
            require(digest(entry) == CANDIDATE_SHA, "deployed_selector_hash")
            release_support.identity(entry, VERSION)
    return {
        "version": VERSION,
        "binary_sha256": CANDIDATE_SHA,
        "rollback_recutover_passed": True,
        "web_client_qualified": True,
        "deployment_checked": deployed,
    }


def main() -> int:
    try:
        summary = validate()
    except Exception as error:
        print(json.dumps({"ok": False, "error": str(error)}))
        return 1
    print(json.dumps({"ok": True, "summary": summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
