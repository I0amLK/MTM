#!/usr/bin/env python3
"""Validate the side-by-side MTM-015 content-addressed candidate stage."""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "records/evidence/MTM-015/candidate-stage.json"
TARGET = ROOT / "records/evidence/MTM-015/target-qualification.json"
SELECTOR = Path("/home/lk/.local/bin/mtm")
CARGO_ENTRY = Path("/home/lk/.cargo/bin/mtm")
INSTALLED = Path("/home/lk/.local/share/mtm/releases/0.5.0-preview.1/mtm")
STABLE = Path("/home/lk/.local/share/mtm/releases/0.4.0/mtm")
STABLE_SHA = "3312ca75a1de8707e740963cc0add4b09430dccc9dc63a3145e4456ff2b0cdf3"
CHECK_NAMES = {
    "target_evidence_valid",
    "rebuilt_candidate_matches_target",
    "content_addressed_install_exact",
    "installed_endpoint_identity",
    "installed_endpoint_capability_roundtrip",
    "installed_persisted_secret_owner_only",
    "selectors_unchanged",
    "stable_rollback_artifact_preserved",
}


def require(value: Any, label: str) -> None:
    if not value:
        raise ValueError(label)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = payload or json.loads(REPORT.read_text(encoding="utf-8"))
    target = json.loads(TARGET.read_text(encoding="utf-8"))
    required = {
        "schema_version", "milestone", "phase", "version", "ok", "recorded_at",
        "implementation_commit", "target_qualification_commit", "stage_commit",
        "target_evidence_sha256", "candidate_binary_sha256", "candidate_path",
        "checks", "check_count", "endpoint", "harness_sha256", "web_client_tested",
        "installed_endpoint_tested", "selector_changed", "production_state_rewritten",
        "evidence_hygiene",
    }
    require(set(payload) == required, "candidate_stage_fields")
    require(payload["schema_version"] == "1.0.0", "schema_version")
    require(payload["milestone"] == "MTM-015" and payload["phase"] == "candidate_stage",
            "candidate_stage_identity")
    require(payload["ok"] is True and payload["version"] == "0.5.0-preview.2",
            "candidate_stage_version")
    require(payload["candidate_binary_sha256"] == target["binary_sha256"],
            "target_binary_binding")
    require(payload["target_evidence_sha256"] == digest(TARGET), "target_evidence_binding")
    require(re.fullmatch(r"[0-9a-f]{40}", payload["stage_commit"]) is not None, "stage_commit")
    checks = payload["checks"]
    require(isinstance(checks, dict) and set(checks) == CHECK_NAMES, "stage_check_set")
    require(all(value is True for value in checks.values()), "stage_checks")
    require(payload["check_count"] == len(CHECK_NAMES), "stage_check_count")
    candidate = Path(payload["candidate_path"])
    expected = Path(
        f"/home/lk/.local/share/mtm/candidates/MTM-015/{payload['candidate_binary_sha256']}/mtm"
    )
    require(candidate == expected and candidate.is_file(), "candidate_path")
    require(digest(candidate) == payload["candidate_binary_sha256"], "candidate_binary_drift")
    require(SELECTOR.resolve() == INSTALLED and CARGO_ENTRY.resolve() == INSTALLED,
            "selector_drift")
    require(digest(SELECTOR) == digest(CARGO_ENTRY) == digest(INSTALLED), "selector_bytes")
    require(STABLE.is_file() and digest(STABLE) == STABLE_SHA, "stable_drift")
    require(payload["installed_endpoint_tested"] is True, "installed_endpoint_tested")
    require(payload["web_client_tested"] is False, "web_client_claim")
    require(payload["selector_changed"] is False, "selector_changed")
    require(payload["production_state_rewritten"] is False, "production_state_rewritten")
    require(
        payload["evidence_hygiene"]
        == {
            "raw_capability_recorded": False,
            "raw_oauth_token_recorded": False,
            "raw_secret_recorded": False,
            "raw_logs_recorded": False,
        },
        "evidence_hygiene",
    )
    harness = payload["harness_sha256"]
    require(
        set(harness)
        == {
            "scripts/run_mtm015_candidate_stage.py",
            "scripts/validate_mtm015_candidate_stage.py",
        },
        "stage_harness_files",
    )
    for path, expected_hash in harness.items():
        require(digest(ROOT / path) == expected_hash, f"stage_harness_drift:{path}")
    require(
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", payload["stage_commit"], "HEAD"],
            cwd=ROOT,
            check=False,
        ).returncode == 0,
        "stage_commit_not_ancestor",
    )
    return {
        "report_sha256": digest(REPORT),
        "candidate_binary_sha256": payload["candidate_binary_sha256"],
        "candidate_path": str(candidate),
        "check_count": payload["check_count"],
        "web_client_pending": True,
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
