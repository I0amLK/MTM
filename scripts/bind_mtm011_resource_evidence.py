#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.validate_mtm011_research_resource import REPORT, validate as validate_resource


EVALUATION = ROOT / "records/evidence/MTM-011/protocol3-cutover-evaluation.json"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def atomic_write(path: Path, payload: dict[str, object]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def main() -> int:
    resource = json.loads(REPORT.read_text(encoding="utf-8"))
    summary = validate_resource(resource)
    evaluation = json.loads(EVALUATION.read_text(encoding="utf-8"))
    if evaluation.get("status") == "complete":
        raise SystemExit("evaluation is already complete and immutable")
    candidate = evaluation["candidate"]
    implementation_sha = summary["implementation_sha256"]
    if candidate.get("binary_sha256") not in {None, implementation_sha}:
        raise SystemExit("resource candidate differs from already-recorded treatment binary")
    candidate["binary_sha256"] = implementation_sha
    evaluation["resource_evidence"] = {
        "path": "records/evidence/MTM-011/research-resource.json",
        "sha256": sha256_file(REPORT),
        "status": "accepted_current_candidate"
    }
    atomic_write(EVALUATION, evaluation)
    print(json.dumps({"ok": True, "binary_sha256": implementation_sha, "resource_sha256": evaluation["resource_evidence"]["sha256"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
