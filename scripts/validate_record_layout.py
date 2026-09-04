#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RECORDS = ROOT / "records"
LAYOUT = RECORDS / "governance" / "record-layout.json"
MILESTONE_RE = re.compile(r"MTM-\d{3}$")
ITERATION_RE = re.compile(r"ITER-\d{3}\.json$")
REQUIRED_GOVERNANCE = {
    "authority-inventory.json",
    "engineering-graph.json",
    "migration-graph.json",
    "project-progress.json",
    "record-layout.json",
    "source-baseline.json",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("schema_version") != "1.0.0" or payload.get("layout_version") != 1:
        raise ValueError("record-layout schema/version is invalid")
    if payload.get("root_json_allowed") is not False:
        raise ValueError("record layout must forbid repository-root JSON records")

    root_json = sorted(path.name for path in ROOT.glob("*.json") if path.is_file())
    if root_json:
        raise ValueError(f"repository-root JSON records are forbidden: {root_json}")

    governance = RECORDS / "governance"
    actual_governance = {path.name for path in governance.glob("*.json") if path.is_file()}
    missing_governance = REQUIRED_GOVERNANCE - actual_governance
    if missing_governance:
        raise ValueError(f"required governance records are missing: {sorted(missing_governance)}")

    iteration_files = sorted((RECORDS / "iterations").glob("*.json"))
    if not iteration_files or any(not ITERATION_RE.fullmatch(path.name) for path in iteration_files):
        raise ValueError("iteration records must use ITER-NNN.json names")

    evidence_root = RECORDS / "evidence"
    milestone_dirs = sorted(path for path in evidence_root.iterdir() if path.is_dir())
    if not milestone_dirs or any(not MILESTONE_RE.fullmatch(path.name) for path in milestone_dirs):
        raise ValueError("evidence directories must use MTM-NNN names")
    for directory in milestone_dirs:
        if any(path.is_dir() for path in directory.iterdir()):
            raise ValueError(f"nested evidence directories are not allowed: {directory}")
        if any(path.suffix != ".json" for path in directory.iterdir() if path.is_file()):
            raise ValueError(f"milestone evidence directory contains a non-JSON file: {directory}")

    relocations = payload.get("relocations")
    if not isinstance(relocations, list) or not relocations:
        raise ValueError("record-layout relocation index is missing")
    legacy_seen: set[str] = set()
    current_seen: set[str] = set()
    evidence_hashes_checked = 0
    for item in relocations:
        if not isinstance(item, dict):
            raise ValueError("record relocation entry must be an object")
        legacy = str(item.get("legacy_path") or "")
        current = str(item.get("current_path") or "")
        kind = str(item.get("kind") or "")
        if not legacy or "/" in legacy or not legacy.endswith(".json"):
            raise ValueError(f"legacy relocation must identify a former root JSON path: {legacy!r}")
        if legacy in legacy_seen or current in current_seen:
            raise ValueError("record relocation paths must be one-to-one")
        legacy_seen.add(legacy)
        current_seen.add(current)
        destination = ROOT / current
        if not current.startswith("records/") or not destination.is_file():
            raise ValueError(f"record relocation destination is missing: {current}")
        if (ROOT / legacy).exists():
            raise ValueError(f"legacy root record still exists: {legacy}")
        if kind == "evidence":
            expected_sha = str(item.get("sha256") or "")
            if not expected_sha or sha256_file(destination) != expected_sha:
                raise ValueError(f"relocated evidence hash drifted: {current}")
            evidence_hashes_checked += 1
        elif kind not in {"governance", "validation"}:
            raise ValueError(f"unsupported record relocation kind: {kind}")

    validation_report = RECORDS / "validation" / "local-validation.json"
    if not validation_report.is_file():
        raise ValueError("canonical local validation report is missing")

    return {
        "root_json_count": 0,
        "governance_record_count": len(actual_governance),
        "iteration_record_count": len(iteration_files),
        "evidence_milestone_count": len(milestone_dirs),
        "relocation_count": len(relocations),
        "evidence_hashes_checked": evidence_hashes_checked,
    }


def main() -> int:
    try:
        payload = json.loads(LAYOUT.read_text(encoding="utf-8"))
        summary = validate(payload)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, indent=2))
        return 1
    print(json.dumps({"ok": True, "summary": summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
