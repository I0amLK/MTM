#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "records/evidence/MTM-013/public-install.json"
SOURCE_COMMIT = "fcdc0cd09bb0852e46bb8cdc37de3b81ccff27e3"
REPOSITORY = "https://github.com/I0amLK/MTM.git"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("schema_version") != "1.0.0" or payload.get("milestone") != "MTM-013":
        raise ValueError("unexpected public-install evidence identity")
    if payload.get("phase") != "public_git_install" or payload.get("repository") != REPOSITORY:
        raise ValueError("public-install evidence scope drifted")
    if payload.get("source_commit") != SOURCE_COMMIT or payload.get("version") != "0.4.0":
        raise ValueError("public-install evidence is not bound to the stable source")
    checks = payload.get("checks")
    if not isinstance(checks, dict) or len(checks) != 3 or not all(checks.values()):
        raise ValueError("public-install checks are incomplete or failed")
    binary_sha = payload.get("installed_binary_sha256")
    if not isinstance(binary_sha, str) or len(binary_sha) != 64:
        raise ValueError("public-installed binary hash is missing")
    if payload.get("raw_git_credentials_recorded") is not False:
        raise ValueError("public-install evidence records credential material")
    if payload.get("ok") is not True:
        raise ValueError("public-install evidence is not accepted")
    return {
        "report_sha256": sha256_file(REPORT),
        "public_main": payload.get("public_main"),
        "source_commit": SOURCE_COMMIT,
        "installed_binary_sha256": binary_sha,
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
