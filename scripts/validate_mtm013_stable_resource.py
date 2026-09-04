#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "records/evidence/MTM-013/stable-resource.json"
BINARY = ROOT / "target" / "release" / "mtm"
WRAPPER = ROOT / "scripts" / "run_mtm013_stable_resource.py"
MEASUREMENT = ROOT / "scripts" / "run_mtm009_research_resource.py"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("schema_version") != "1.0.0" or payload.get("milestone") != "MTM-013-stable":
        raise ValueError("unexpected MTM-013 stable resource evidence identity")
    if payload.get("version") != "0.4.0":
        raise ValueError("stable resource evidence uses the wrong version")
    if not BINARY.is_file() or payload.get("implementation_sha256") != sha256_file(BINARY):
        raise ValueError("stable resource evidence is stale for the release binary")
    if payload.get("wrapper_harness_sha256") != sha256_file(WRAPPER):
        raise ValueError("stable resource evidence is stale for the wrapper harness")
    if payload.get("measurement_harness_sha256") != sha256_file(MEASUREMENT):
        raise ValueError("stable resource evidence is stale for the measurement harness")
    checks = payload.get("checks")
    if not isinstance(checks, dict) or len(checks) < 8 or not all(checks.values()):
        raise ValueError("stable resource checks are incomplete or failed")
    protocol2 = payload.get("protocol2")
    protocol3 = payload.get("protocol3")
    if not isinstance(protocol2, dict) or not isinstance(protocol3, dict):
        raise ValueError("stable resource evidence lacks protocol measurements")
    if protocol2.get("protocol") != 2 or protocol3.get("protocol") != 3:
        raise ValueError("stable resource protocol labels drifted")
    if protocol2.get("samples") != 40 or protocol3.get("samples") != 40:
        raise ValueError("stable resource evidence requires 40 samples per protocol")
    if protocol2.get("research_view_bytes") != 0:
        raise ValueError("protocol 2 unexpectedly exposes protocol-3 research state")
    view_bytes = protocol3.get("research_view_bytes")
    if not isinstance(view_bytes, int) or not 0 < view_bytes <= 16_384:
        raise ValueError("protocol-3 stable research view is missing or oversized")
    if payload.get("ok") is not True:
        raise ValueError("stable resource evidence is not accepted")
    return {
        "report_sha256": sha256_file(REPORT),
        "binary_sha256": payload["implementation_sha256"],
        "check_count": len(checks),
        "protocol2_p95_ms": protocol2["latency_ms_p95"],
        "protocol3_p95_ms": protocol3["latency_ms_p95"],
        "protocol2_rss_kib": protocol2["rss_kib_peak_proxy"],
        "protocol3_rss_kib": protocol3["rss_kib_peak_proxy"],
        "protocol3_view_bytes": view_bytes,
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
