#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

try:
    from scripts.run_mtm006_target_validation import implementation_sha256
except ModuleNotFoundError:
    from run_mtm006_target_validation import implementation_sha256


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "mtm006-target-validation.json"
REQUIRED_CHECKS = {
    "real_pdflatex_finalization",
    "verified_project_promotion",
    "final_artifact_read_only",
    "model_verdict_cannot_override_server",
    "post_verifier_proof_tamper_denied",
    "tamper_does_not_publish_final_artifact",
    "missing_reference_audit_becomes_server_gap",
    "reference_gap_routes_to_repair",
}


def validate() -> dict[str, object]:
    payload = json.loads(REPORT.read_text(encoding="utf-8"))
    if payload.get("project") != "MTM-reboot" or payload.get("milestone") != "MTM-006":
        raise ValueError("target evidence belongs to a different project or milestone")
    if payload.get("passed") is not True:
        raise ValueError("MTM-006 target evidence is not passing")
    expected_hash = implementation_sha256()
    if payload.get("implementation_sha256") != expected_hash:
        raise ValueError("MTM-006 target evidence is stale for the current implementation")
    checks = payload.get("checks")
    if not isinstance(checks, list):
        raise ValueError("target evidence checks must be an array")
    by_name = {
        str(item.get("name")): item
        for item in checks
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    missing = REQUIRED_CHECKS - set(by_name)
    if missing:
        raise ValueError(f"target evidence is missing checks: {sorted(missing)}")
    failed = sorted(name for name in REQUIRED_CHECKS if by_name[name].get("passed") is not True)
    if failed:
        raise ValueError(f"target evidence contains failed checks: {failed}")
    serialized = json.dumps(payload, ensure_ascii=False).lower()
    for forbidden in (
        "capability_secret",
        "proof version",
        "begin{proof}",
        "client_secret",
        "access_token",
    ):
        if forbidden in serialized:
            raise ValueError(f"target evidence contains forbidden sensitive content: {forbidden}")
    environment = payload.get("environment")
    if not isinstance(environment, dict) or not environment.get("pdflatex"):
        raise ValueError("target evidence does not identify the real LaTeX compiler")
    return {
        "implementation_sha256": expected_hash,
        "required_check_count": len(REQUIRED_CHECKS),
        "environment": {
            "platform": environment.get("platform"),
            "release": environment.get("release"),
            "machine": environment.get("machine"),
            "pdflatex": environment.get("pdflatex"),
        },
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
