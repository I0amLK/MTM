#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import run_mtm009_research_resource as base


REPORT = ROOT / "mtm011-research-resource.json"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    base.REPORT = REPORT
    result = base.main()
    if result != 0:
        return result
    payload = json.loads(REPORT.read_text(encoding="utf-8"))
    payload["milestone"] = "MTM-011"
    payload["harness_sha256"] = sha256_file(Path(__file__))
    payload["measurement_harness_sha256"] = sha256_file(Path(base.__file__))
    temporary = REPORT.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    temporary.replace(REPORT)
    print(json.dumps({"ok": payload.get("ok") is True, "report": str(REPORT), "implementation_sha256": payload.get("implementation_sha256")}, indent=2))
    return 0 if payload.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
