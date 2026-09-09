#!/usr/bin/env python3
"""Resolve the immutable MTM-015 staged artifact for retained browser checks.

Historical target/install acceptance is owned by Rust record integrity. This
bridge verifies the frozen receipt and exact candidate bytes only; it does not
inspect production selectors or re-qualify an installation.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "records/evidence/MTM-015/candidate-stage.json"


def require(value: Any, label: str) -> None:
    if not value:
        raise ValueError(label)


def digest(path: Path) -> str:
    require(path.is_file() and not path.is_symlink(), "regular_artifact_required")
    require(path.stat().st_size <= 512 * 1024 * 1024, "artifact_size_bound")
    value = hashlib.sha256()
    total = 0
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(65536), b""):
            total += len(chunk)
            require(total <= 512 * 1024 * 1024, "artifact_growth_bound")
            value.update(chunk)
    return value.hexdigest()


def validate(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    # Rust owns all historical receipt policy. This residual browser adapter only
    # selects that frozen artifact; it is not a second install/release validator.
    completed = subprocess.run(
        [os.environ.get("CARGO", "cargo"), "xtask", "records"], cwd=ROOT,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, check=True, timeout=60,
    )
    integrity = json.loads(completed.stdout)
    require(integrity.get("ok") is True, "rust_record_integrity")
    stage = integrity["historical_releases"]["mtm015_lifecycle_evidence"]["candidate_stage"]
    require(REPORT.stat().st_size <= 65536, "receipt_size_bound")
    with REPORT.open("rb") as source:
        raw = source.read(65537)
    require(len(raw) <= 65536 and hashlib.sha256(raw).hexdigest() == stage["sha256"],
            "frozen_receipt_binding")
    frozen = json.loads(raw)
    require(payload is None or payload == frozen, "alternate_receipt_not_allowed")
    payload = frozen
    candidate = Path(payload["candidate_path"])
    expected = Path(
        f"/home/lk/.local/share/mtm/candidates/MTM-015/{stage['candidate_binary_sha256']}/mtm"
    )
    require(candidate == expected and candidate.is_file(), "candidate_path")
    require(digest(candidate) == stage["candidate_binary_sha256"], "candidate_binary_drift")
    return {
        "report_sha256": stage["sha256"],
        "candidate_binary_sha256": stage["candidate_binary_sha256"],
        "candidate_path": str(candidate),
        "check_count": payload["check_count"],
        "web_client_pending": True,
        "historical_install_revalidated": False,
        "live_selectors_checked": False,
    }


def main() -> int:
    try:
        summary = validate()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print(json.dumps({"ok": False, "error": "frozen candidate bridge validation failed"}))
        return 1
    print(json.dumps({"ok": True, "summary": summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
