#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

HISTORICAL = {
    "MTM-003": ("records/evidence/MTM-003/target-validation.json", "87d8f99465580565ebca843e7d79b44f3466d775290980fb6762bde3a99880db", 14),
    "MTM-004": ("records/evidence/MTM-004/target-validation.json", "ab52686ea2a8da88e212ef60ce5df780db76ff00d44335cb5194cd03d88e3f56", 10),
    "MTM-005": ("records/evidence/MTM-005/target-validation.json", "43b26b5d5b17356a6f4815a2d62a8140cad3707b177fa629322ce761ba22e6c9", 15),
    "MTM-006": ("records/evidence/MTM-006/target-validation.json", "4b7096f5e51ab07243c3ab1b1e413dbd2460eceb1185e4bfa66776c108f8b7c4", 8),
    "MTM-007": ("records/evidence/MTM-007/target-validation.json", "254090e5110e0ac6ea658d3ed3cfc3538fc0440f236300f5058a876826619e09", 12),
    "MTM-008": ("records/evidence/MTM-008/candidate-validation.json", "7578b74e8d42d6050cbd98d17100f281f7e48b51b341977c41f92f73e960eebf", 10),
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def validate() -> dict[str, object]:
    checked: dict[str, dict[str, object]] = {}
    for milestone, (relative, expected_sha, expected_checks) in HISTORICAL.items():
        path = ROOT / relative
        if not path.is_file():
            raise ValueError(f"historical evidence is missing: {relative}")
        actual_sha = sha256_file(path)
        if actual_sha != expected_sha:
            raise ValueError(f"historical evidence changed: {relative}")
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("project") != "MTM-reboot" or payload.get("milestone") != milestone:
            raise ValueError(f"historical evidence identity changed: {relative}")
        if payload.get("passed") is not True:
            raise ValueError(f"historical evidence is not accepted: {relative}")
        check_count = payload.get("check_count")
        if milestone == "MTM-008":
            checks = payload.get("checks")
            check_count = len(checks) if isinstance(checks, list) else 0
        if check_count != expected_checks:
            raise ValueError(f"historical evidence check count changed: {relative}")
        checked[milestone] = {"path": relative, "sha256": actual_sha, "check_count": check_count}
    return {"historical_milestones": len(checked), "evidence": checked}


def main() -> int:
    try:
        summary = validate()
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, indent=2))
        return 1
    print(json.dumps({"ok": True, "summary": summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
