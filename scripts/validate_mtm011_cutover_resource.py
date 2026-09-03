#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "mtm011-cutover-resource.json"
HARNESS = ROOT / "scripts" / "run_mtm011_cutover_resource.py"
MEASUREMENT_HARNESS = ROOT / "scripts" / "run_mtm009_research_resource.py"
BINARY = ROOT / "target" / "release" / "mtm"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("schema_version") != "1.0.0" or payload.get("milestone") != "MTM-011-cutover":
        raise ValueError("unexpected MTM-011 cutover resource evidence identity")
    if payload.get("version") != "0.4.0-preview.2":
        raise ValueError("cutover resource evidence version drifted")
    if payload.get("purpose") != "A5 non-regression only; not a performance claim.":
        raise ValueError("resource evidence scope drifted")
    if payload.get("harness_sha256") != sha256_file(HARNESS):
        raise ValueError("cutover resource evidence is stale for the wrapper")
    if payload.get("measurement_harness_sha256") != sha256_file(MEASUREMENT_HARNESS):
        raise ValueError("cutover resource evidence is stale for the measurement harness")
    if not BINARY.is_file() or payload.get("implementation_sha256") != sha256_file(BINARY):
        raise ValueError("cutover resource evidence is stale for the release binary")
    protocol2 = payload.get("protocol2")
    protocol3 = payload.get("protocol3")
    if not isinstance(protocol2, dict) or not isinstance(protocol3, dict):
        raise ValueError("resource evidence requires both protocols")
    if protocol2.get("protocol") != 2 or protocol3.get("protocol") != 3:
        raise ValueError("resource protocol labels are invalid")
    if protocol2.get("samples") != 40 or protocol3.get("samples") != 40:
        raise ValueError("resource evidence requires 40 samples per protocol")
    if protocol2.get("research_view_bytes") != 0:
        raise ValueError("protocol 2 exposed a protocol-3 research view")
    view_bytes = protocol3.get("research_view_bytes")
    if not isinstance(view_bytes, int) or not 0 < view_bytes <= 16_384:
        raise ValueError("protocol-3 research view exceeds the fixed budget")
    checks = payload.get("checks")
    if not isinstance(checks, dict) or len(checks) < 8 or not all(checks.values()):
        raise ValueError("one or more cutover resource checks failed")
    if payload.get("ok") is not True:
        raise ValueError("cutover resource evidence is not accepted")
    return {
        "report_sha256": sha256_file(REPORT),
        "implementation_sha256": payload["implementation_sha256"],
        "protocol2_p95_ms": protocol2["latency_ms_p95"],
        "protocol3_p95_ms": protocol3["latency_ms_p95"],
        "protocol3_view_bytes": view_bytes,
        "protocol2_rss_kib": protocol2["rss_kib_peak_proxy"],
        "protocol3_rss_kib": protocol3["rss_kib_peak_proxy"],
        "check_count": len(checks),
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
