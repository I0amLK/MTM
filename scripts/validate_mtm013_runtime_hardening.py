#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BINARY = ROOT / "target" / "debug" / "mtm"
BINARY = Path(os.environ.get("MTM013_BINARY", DEFAULT_BINARY))
REPORT = Path(os.environ.get("MTM013_HARDENING_REPORT", ROOT / "records/evidence/MTM-013/runtime-hardening.json"))
HARNESS = ROOT / "scripts" / "run_mtm013_runtime_hardening.py"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("schema_version") != "1.0.0" or payload.get("milestone") != "MTM-013":
        raise ValueError("unexpected MTM-013 hardening evidence identity")
    if not BINARY.is_file() or payload.get("binary_sha256") != sha256_file(BINARY):
        raise ValueError("MTM-013 hardening evidence is stale for the current binary")
    if payload.get("harness_sha256") != sha256_file(HARNESS):
        raise ValueError("MTM-013 hardening evidence is stale for the current harness")
    checks = payload.get("checks")
    if not isinstance(checks, dict) or len(checks) < 12 or not all(checks.values()):
        raise ValueError("MTM-013 hardening checks are incomplete or failed")
    if payload.get("raw_capability_recorded") is not False:
        raise ValueError("MTM-013 evidence must not record raw capabilities")
    if payload.get("raw_oauth_token_recorded") is not False:
        raise ValueError("MTM-013 evidence must not record raw OAuth tokens")
    facts = payload.get("facts")
    if not isinstance(facts, dict):
        raise ValueError("MTM-013 hardening facts are missing")
    if facts.get("initial_state") != "assess" or facts.get("advanced_state") != "explore":
        raise ValueError("fresh-capability resubmission did not demonstrate a real transition")
    if facts.get("workflow_protocol_version") != 3:
        raise ValueError("MTM-013 hardening evidence did not exercise protocol 3")
    if facts.get("production_default_workflow_protocol_version") != 3:
        raise ValueError("MTM-013 hardening evidence changed the production protocol default")
    if payload.get("ok") is not True:
        raise ValueError("MTM-013 hardening evidence is not accepted")
    return {
        "report_sha256": sha256_file(REPORT),
        "binary_sha256": payload["binary_sha256"],
        "check_count": len(checks),
        "initial_state": facts["initial_state"],
        "advanced_state": facts["advanced_state"],
    }


def main() -> int:
    try:
        summary = validate(json.loads(REPORT.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, indent=2))
        return 1
    print(json.dumps({"ok": True, "summary": summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
