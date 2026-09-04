#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "records/evidence/MTM-012/tui-validation.json"
HARNESS = ROOT / "scripts" / "run_mtm012_tui_validation.py"
BINARY = ROOT / "target" / "release" / "mtm"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("schema_version") != "1.0.0" or payload.get("milestone") != "MTM-012":
        raise ValueError("unexpected MTM-012 TUI evidence identity")
    if payload.get("version") != "0.4.0-preview.3":
        raise ValueError("MTM-012 evidence is not bound to preview.3")
    if payload.get("harness_sha256") != sha256_file(HARNESS):
        raise ValueError("MTM-012 TUI evidence is stale for the harness")
    if not BINARY.is_file() or payload.get("binary_sha256") != sha256_file(BINARY):
        raise ValueError("MTM-012 TUI evidence is stale for the release binary")
    checks = payload.get("checks")
    if not isinstance(checks, dict) or len(checks) != 20 or not all(checks.values()):
        raise ValueError("MTM-012 TUI evidence does not contain twenty passing checks")
    if payload.get("generated_operator_key_recorded") is not False:
        raise ValueError("MTM-012 evidence must not persist the generated operator key")
    if payload.get("raw_tui_log_recorded") is not False:
        raise ValueError("MTM-012 evidence must not persist raw TUI logs")
    if payload.get("performance_claim") is not False:
        raise ValueError("MTM-012 TUI evidence may not make a performance claim")
    return {
        "report_sha256": sha256_file(REPORT),
        "binary_sha256": payload["binary_sha256"],
        "check_count": len(checks),
        "compact_tool_line_count": payload.get("compact_tool_line_count"),
        "raw_tui_log_recorded": False,
        "generated_operator_key_recorded": False,
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
