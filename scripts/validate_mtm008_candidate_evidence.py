#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

try:
    from scripts.run_mtm008_candidate_validation import REPORT, implementation_sha256
except ModuleNotFoundError:
    from run_mtm008_candidate_validation import REPORT, implementation_sha256


REQUIRED_CHECKS = {
    "release_identity",
    "release_has_no_python_linkage",
    "previous_target_evidence_fresh",
    "immutable_python_rollback_wheel",
    "rollback_wheel_restore",
    "atomic_rust_cutover",
    "python_rollback_drill",
    "rust_recutover_drill",
    "a6_performance_qualification",
    "release_soak",
}


def validate() -> dict[str, object]:
    payload = json.loads(REPORT.read_text(encoding="utf-8"))
    if payload.get("project") != "MTM-reboot" or payload.get("milestone") != "MTM-008":
        raise ValueError("candidate evidence belongs to a different project or milestone")
    if payload.get("phase") != "candidate" or payload.get("passed") is not True:
        raise ValueError("MTM-008 candidate evidence is not passing")
    expected_hash = implementation_sha256()
    if payload.get("implementation_sha256") != expected_hash:
        raise ValueError("MTM-008 candidate evidence is stale for the current implementation")
    checks = payload.get("checks")
    if not isinstance(checks, list):
        raise ValueError("candidate evidence checks must be an array")
    by_name = {
        str(item.get("name")): item
        for item in checks
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    missing = REQUIRED_CHECKS - set(by_name)
    if missing:
        raise ValueError(f"candidate evidence is missing checks: {sorted(missing)}")
    failed = sorted(name for name in REQUIRED_CHECKS if by_name[name].get("passed") is not True)
    if failed:
        raise ValueError(f"candidate evidence contains failed checks: {failed}")
    if payload.get("production_authority_changed") is not False:
        raise ValueError("candidate qualification must not claim a live production cutover")
    serialized = json.dumps(payload, ensure_ascii=False).lower()
    for forbidden in (
        "access_token",
        "client_secret",
        "capability_secret",
        "operator_password",
        "begin{proof}",
    ):
        if forbidden in serialized:
            raise ValueError(f"candidate evidence contains forbidden content: {forbidden}")
    return {
        "implementation_sha256": expected_hash,
        "required_check_count": len(REQUIRED_CHECKS),
        "release_sha256": payload.get("release_binary", {}).get("sha256"),
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
