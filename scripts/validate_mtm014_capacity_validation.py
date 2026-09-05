#!/usr/bin/env python3
"""Validate bounded-ledger A3 evidence; this never authorizes D5 cutover."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "records/evidence/MTM-014/capacity-validation.json"
CHECKS = {
    "form_challenge_returned", "owner_capacity_enforced", "capacity_retryable",
    "capacity_error_redacted", "other_owner_not_blocked", "cross_owner_rejected",
    "original_challenge_survives_cross_owner_attempt", "decline_releases_slot",
    "oversized_reason_rejected", "oversized_error_redacted",
    "false_confirmation_mints_no_grant", "denied_request_can_prompt_again",
    "server_exits_cleanly",
}
SCOPES = {
    "schema_version": "1.0.0",
    "milestone": "MTM-014",
    "phase": "bounded_permission_ledger_integration",
    "consent_source": "scripted_test_responses",
    "native_exec_backend": "disabled",
    "real_human_consent_evidence": False,
    "production_exec_or_patch_authority_cutover": False,
    "raw_oauth_token_recorded": False,
    "raw_request_state_recorded": False,
    "raw_grant_id_recorded": False,
    "raw_tool_arguments_recorded": False,
}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def current_identity() -> dict[str, str]:
    binary = Path(os.environ.get("MTM014_BINARY", ROOT / "target/debug/mtm"))
    files = {ROOT / "Cargo.toml", ROOT / "Cargo.lock", ROOT / "rust-toolchain.toml"}
    files.update((ROOT / "crates").rglob("*.rs"))
    files.update((ROOT / "crates").rglob("Cargo.toml"))
    files.update(path for path in (ROOT / "crates/mtm-cli/assets").rglob("*") if path.is_file())
    files.update(ROOT / "scripts" / name for name in (
        "run_mtm014_capacity_validation.py", "validate_mtm014_capacity_validation.py",
        "run_mtm014_mrtr_permission_validation.py", "mtm008_runtime_harness.py",
        "run_mtm007_http_smoke.py",
    ))
    digest = hashlib.sha256()
    for path in sorted(files):
        digest.update(path.relative_to(ROOT).as_posix().encode() + b"\0")
        digest.update(bytes.fromhex(sha256_file(path)))
    return {
        "binary_sha256": sha256_file(binary),
        "implementation_and_harness_sha256": digest.hexdigest(),
    }


def validate(payload: Any, *, identity: dict[str, str] | None = None) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("capacity evidence must be an object")
    expected_keys = set(SCOPES) | {
        "ok", "check_count", "checks", "binary_sha256", "implementation_and_harness_sha256",
    }
    if set(payload) != expected_keys:
        raise ValueError("capacity evidence has missing or unexpected fields")
    for key, expected in SCOPES.items():
        if type(payload[key]) is not type(expected) or payload[key] != expected:
            raise ValueError(f"capacity evidence scope is invalid: {key}")
    checks = payload["checks"]
    if not isinstance(checks, dict) or set(checks) != CHECKS:
        raise ValueError("capacity evidence must contain the exact required check set")
    if payload["ok"] is not True or any(value is not True for value in checks.values()):
        raise ValueError("capacity evidence contains a failed or non-boolean check")
    if type(payload["check_count"]) is not int or payload["check_count"] != len(CHECKS):
        raise ValueError("capacity evidence check count is invalid")
    expected_identity = current_identity() if identity is None else identity
    if set(expected_identity) != {"binary_sha256", "implementation_and_harness_sha256"}:
        raise ValueError("capacity evidence identity binding is incomplete")
    for key, expected in expected_identity.items():
        if not isinstance(expected, str) or re.fullmatch(r"[0-9a-f]{64}", expected) is None:
            raise ValueError("capacity evidence identity digest is invalid")
        if payload.get(key) != expected:
            raise ValueError(f"capacity evidence is stale: {key}")
    return {"check_count": len(CHECKS), "scope": "A3_only", "cutover_allowed": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=REPORT)
    args = parser.parse_args()
    try:
        summary = validate(json.loads(args.report.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        # Do not echo input, filesystem paths, or untrusted exception contents.
        print(json.dumps({"ok": False, "error": "capacity evidence missing, invalid, or stale"}))
        return 1
    print(json.dumps({"ok": True, "summary": summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
