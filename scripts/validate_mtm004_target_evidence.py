#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "mtm004-target-validation.json"

try:
    from scripts.run_mtm004_target_validation import implementation_sha256
except ModuleNotFoundError:
    from run_mtm004_target_validation import implementation_sha256


REQUIRED_CHECKS = {
    "production_database_read_only_backup",
    "production_copy_python_rust_digest_match",
    "production_copy_mutate_and_exact_rollback",
    "python_token_validated_by_rust",
    "rust_token_validated_by_python",
    "registry_tamper_denied_by_rust",
    "capability_secrets_not_recorded",
    "begin_immediate_serializes_writers",
    "storage_atomicity_and_capability_unit_suite",
    "mtm004_golden_and_migration_conformance",
}

FORBIDDEN_KEYS = {
    "rows",
    "run_id",
    "problem_id",
    "project_id",
    "claim_id",
    "revision_id",
    "last_token",
    "token",
    "statement_tex",
    "proof_sha256",
    "content_sha256",
    "source_uri",
    "database_path",
}


def validate(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    if payload is None:
        payload = json.loads(REPORT.read_text(encoding="utf-8"))
    if payload.get("project") != "MTM-reboot" or payload.get("milestone") != "MTM-004":
        raise ValueError("MTM-004 target report identity is invalid")
    if payload.get("passed") is not True:
        raise ValueError("MTM-004 target report did not pass")
    current = implementation_sha256()
    if payload.get("implementation_sha256") != current:
        raise ValueError("MTM-004 target evidence is stale for the current implementation")
    if payload.get("sensitive_content_omitted") is not True:
        raise ValueError("MTM-004 target report does not attest content omission")
    checks = payload.get("checks")
    if not isinstance(checks, list):
        raise ValueError("MTM-004 target checks must be an array")
    by_name: dict[str, dict[str, Any]] = {}
    for check in checks:
        if not isinstance(check, dict) or not isinstance(check.get("name"), str):
            raise ValueError("MTM-004 target check is invalid")
        name = str(check["name"])
        if name in by_name:
            raise ValueError(f"duplicate MTM-004 target check: {name}")
        if check.get("passed") is not True:
            raise ValueError(f"MTM-004 target check failed: {name}")
        by_name[name] = check
    if set(by_name) != REQUIRED_CHECKS:
        raise ValueError("MTM-004 target check set is incomplete or unexpected")
    if payload.get("check_count") != len(REQUIRED_CHECKS):
        raise ValueError("MTM-004 target check_count is inconsistent")
    digest = by_name["production_copy_python_rust_digest_match"]
    if digest.get("schema_version") != 2 or digest.get("private_content_omitted") is not True:
        raise ValueError("MTM-004 copied production database evidence is incomplete")
    if by_name["production_database_read_only_backup"].get("open_mode") != "sqlite_uri_mode_ro":
        raise ValueError("MTM-004 production database was not opened read-only")
    if by_name["begin_immediate_serializes_writers"].get(
        "waited_for_existing_begin_immediate"
    ) is not True:
        raise ValueError("MTM-004 did not prove BEGIN IMMEDIATE serialization")
    assert_no_sensitive_keys(payload)
    serialized = json.dumps(payload, ensure_ascii=False)
    for forbidden in ("/home/lk/.re-ctm", "PRIVATE-CANARY", "Bearer ", "proof_verified.tex"):
        if forbidden in serialized:
            raise ValueError("MTM-004 target report contains private or secret material")
    return {
        "implementation_sha256": current,
        "required_check_count": len(REQUIRED_CHECKS),
        "environment": {
            key: payload.get("environment", {}).get(key)
            for key in ("platform", "release", "machine", "sqlite_version")
        },
    }


def assert_no_sensitive_keys(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        forbidden = FORBIDDEN_KEYS.intersection(value)
        if forbidden:
            raise ValueError(f"sensitive report key at {path}: {sorted(forbidden)}")
        for key, item in value.items():
            assert_no_sensitive_keys(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            assert_no_sensitive_keys(item, f"{path}[{index}]")


def main() -> int:
    try:
        payload = json.loads(REPORT.read_text(encoding="utf-8"))
        summary = validate(payload)
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        return 1
    print(json.dumps({"ok": True, "summary": summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
