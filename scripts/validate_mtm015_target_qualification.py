#!/usr/bin/env python3
"""Validate MTM-015 target evidence without replaying target side effects."""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "records/evidence/MTM-015/target-qualification.json"
IMPLEMENTATION_COMMIT = "94e7bde4a9a0db30fe6459ce4352e3d6661c7384"
VERSION = "0.5.0-preview.1"
CHECK_NAMES = {
    "committed_rust_scope",
    "candidate_release_identity",
    "permanent_capability_gate",
    "persisted_secret_owner_only",
    "same_key_restart_reuses_authority",
    "changed_key_same_owner_rejects_old_capability",
    "diagnostic_signature_stage_redacted",
    "qc_required_latex",
    "compact_required_latex",
    "copied_existing_state",
    "resource_non_regression",
    "permission_soak",
    "selectors_unchanged",
    "stable_rollback_artifact_preserved",
}
HYGIENE = {
    "raw_capability_recorded": False,
    "raw_oauth_token_recorded": False,
    "raw_secret_recorded": False,
    "raw_proof_recorded": False,
    "raw_logs_recorded": False,
}


def require(value: Any, label: str) -> None:
    if not value:
        raise ValueError(label)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = payload or json.loads(REPORT.read_text(encoding="utf-8"))
    required = {
        "schema_version", "milestone", "phase", "version", "ok", "recorded_at",
        "implementation_commit", "qualification_commit", "binary_sha256",
        "rollback_binary_sha256", "stable_sha256", "checks", "check_count",
        "secret_reliability", "proof_facts", "copied_state", "resource", "soak",
        "required_tools", "harness_sha256", "web_client_tested",
        "installed_running_endpoint_tested", "selector_changed",
        "production_state_rewritten", "performance_claim", "evidence_hygiene",
    }
    require(set(payload) == required, "target_evidence_fields")
    for key, expected in {
        "schema_version": "1.0.0",
        "milestone": "MTM-015",
        "phase": "target_qualification",
        "version": VERSION,
        "ok": True,
        "implementation_commit": IMPLEMENTATION_COMMIT,
        "web_client_tested": False,
        "installed_running_endpoint_tested": False,
        "selector_changed": False,
        "production_state_rewritten": False,
        "performance_claim": False,
    }.items():
        require(payload.get(key) == expected, f"target_{key}")
    require(
        re.fullmatch(r"[0-9a-f]{40}", str(payload["qualification_commit"])) is not None,
        "qualification_commit",
    )
    for field in ("binary_sha256", "rollback_binary_sha256", "stable_sha256"):
        require(re.fullmatch(r"[0-9a-f]{64}", str(payload[field])) is not None, field)
    checks = payload["checks"]
    require(isinstance(checks, dict) and set(checks) == CHECK_NAMES, "target_check_set")
    require(all(value is True for value in checks.values()), "target_checks")
    require(payload["check_count"] == len(CHECK_NAMES), "target_check_count")
    require(
        payload["secret_reliability"]
        == {
            "persisted_secret_owner_only": True,
            "same_key_restart_reuses_authority": True,
            "changed_key_same_owner_rejects_old_capability": True,
            "secret_fingerprint_recorded": False,
        },
        "secret_reliability",
    )
    require(payload["evidence_hygiene"] == HYGIENE, "evidence_hygiene")
    for facts in payload["proof_facts"].values():
        require(facts["state"] == "done" and facts["verdict"] == "correct", "proof_outcome")
        require(facts["latex_passed"] is True and facts["sealed"] is True, "proof_latex_sealed")
    copied = payload["copied_state"]
    require(copied["server_version"] == VERSION, "copied_state_version")
    require(
        copied["state_schema_version"] == 2 and copied["projects_query_ok"] is True,
        "copied_state_schema",
    )
    require(all(payload["required_tools"].values()), "required_tools")
    harness = payload["harness_sha256"]
    expected_harness = {
        "scripts/run_mtm015_target_qualification.py",
        "scripts/validate_mtm015_target_qualification.py",
        "scripts/check_capability_current.py",
    }
    require(set(harness) == expected_harness, "harness_files")
    for path, expected in harness.items():
        require(digest(ROOT / path) == expected, f"harness_drift:{path}")
    qualification_commit = str(payload["qualification_commit"])
    require(
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", qualification_commit, "HEAD"],
            cwd=ROOT,
            check=False,
        ).returncode
        == 0,
        "qualification_commit_not_ancestor",
    )
    require(
        subprocess.run(
            [
                "git", "diff", "--quiet", IMPLEMENTATION_COMMIT, qualification_commit, "--",
                "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "crates",
            ],
            cwd=ROOT,
            check=False,
        ).returncode
        == 0,
        "qualification_commit_rust_scope_drift",
    )
    require("Bearer " not in json.dumps(payload, sort_keys=True), "raw_bearer_in_evidence")
    return {
        "report_sha256": digest(REPORT),
        "qualification_commit": qualification_commit,
        "binary_sha256": payload["binary_sha256"],
        "check_count": payload["check_count"],
        "web_client_pending": True,
        "installed_endpoint_pending": True,
    }


def main() -> int:
    try:
        summary = validate()
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(json.dumps({"ok": False, "error": str(error)}))
        return 1
    print(json.dumps({"ok": True, "summary": summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
