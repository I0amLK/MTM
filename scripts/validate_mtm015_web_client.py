#!/usr/bin/env python3
"""Validate bounded real-web-client evidence for the exact MTM-015 staged candidate."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from validate_mtm015_candidate_stage import validate as validate_stage


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "records/evidence/MTM-015/web-client.json"
STAGE = ROOT / "records/evidence/MTM-015/candidate-stage.json"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def require(value: Any, label: str) -> None:
    if not value:
        raise ValueError(label)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = payload or json.loads(REPORT.read_text(encoding="utf-8"))
    stage = validate_stage()
    required = {
        "schema_version", "milestone", "phase", "ok", "recorded_at",
        "candidate_binary_sha256", "candidate_stage_sha256", "session_id",
        "session_descriptor_sha256", "public_tunnel_observed",
        "public_metadata_issuer_validated", "explicit_user_confirmation",
        "confirmation_source", "issued_fingerprint_count",
        "submitted_fingerprint_count", "paired_fingerprint_count",
        "invalid_diagnostic_count", "submission_rejection_count",
        "operator_log_sha256", "web_client_tested", "selector_changed",
        "production_state_rewritten", "transport", "harness_sha256",
        "evidence_hygiene",
    }
    require(set(payload) == required, "web_client_fields")
    require(payload["schema_version"] == "1.0.0", "schema_version")
    require(payload["milestone"] == "MTM-015" and payload["phase"] == "web_client",
            "web_client_identity")
    require(payload["ok"] is True, "web_client_ok")
    require(payload["candidate_binary_sha256"] == stage["candidate_binary_sha256"],
            "candidate_binary_binding")
    require(payload["candidate_stage_sha256"] == digest(STAGE), "candidate_stage_binding")
    require(payload["transport"] == "quick_tunnel_oauth_mcp", "web_client_transport")
    require(payload["public_tunnel_observed"] is True, "public_tunnel_observed")
    require(payload["public_metadata_issuer_validated"] is True, "metadata_issuer")
    require(payload["explicit_user_confirmation"] is True, "explicit_user_confirmation")
    require(payload["confirmation_source"] == "conversation_user_confirmation",
            "confirmation_source")
    for key in (
        "issued_fingerprint_count", "submitted_fingerprint_count",
        "paired_fingerprint_count", "invalid_diagnostic_count",
        "submission_rejection_count",
    ):
        require(type(payload[key]) is int and payload[key] >= 0, f"count:{key}")
    require(payload["paired_fingerprint_count"] >= 5, "paired_fingerprint_count")
    require(payload["issued_fingerprint_count"] >= payload["paired_fingerprint_count"],
            "issued_pair_count")
    require(payload["submitted_fingerprint_count"] >= payload["paired_fingerprint_count"],
            "submitted_pair_count")
    require(payload["invalid_diagnostic_count"] == 0, "normal_web_client_invalid")
    require(payload["submission_rejection_count"] == 0, "normal_web_client_rejection")
    for key in ("operator_log_sha256", "session_descriptor_sha256"):
        require(isinstance(payload[key], str) and HEX64.fullmatch(payload[key]) is not None,
                f"digest:{key}")
    require(payload["web_client_tested"] is True, "web_client_tested")
    require(payload["selector_changed"] is False, "selector_changed")
    require(payload["production_state_rewritten"] is False, "production_state_rewritten")
    require(payload["evidence_hygiene"]["raw_capability_recorded"] is False,
            "raw_capability_recorded")
    require(payload["evidence_hygiene"]["raw_oauth_token_recorded"] is False,
            "raw_oauth_token_recorded")
    harness = payload["harness_sha256"]
    require(set(harness) == {
        "scripts/launch_mtm015_web_candidate.py",
        "scripts/record_mtm015_web_client_evidence.py",
        "scripts/validate_mtm015_web_client.py",
    }, "web_client_harness_files")
    for path, expected in harness.items():
        require(digest(ROOT / path) == expected, f"web_client_harness_drift:{path}")
    return {
        "report_sha256": digest(REPORT),
        "candidate_binary_sha256": payload["candidate_binary_sha256"],
        "paired_fingerprint_count": payload["paired_fingerprint_count"],
        "invalid_diagnostic_count": 0,
        "submission_rejection_count": 0,
    }


def main() -> int:
    try:
        summary = validate()
    except (OSError, json.JSONDecodeError, ValueError, KeyError) as error:
        print(json.dumps({"ok": False, "error": str(error)}))
        return 1
    print(json.dumps({"ok": True, "summary": summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
