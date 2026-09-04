#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.validate_mtm011_math_evaluation import validate as validate_evaluation


VERSION = "0.4.0-preview.2"
EVALUATION = ROOT / "records/evidence/MTM-011/protocol3-cutover-evaluation.json"
ACCEPTED_EVALUATION_SHA256 = "1820027a361604fd77da2e303e1c7c43ab6f25edd7a7401cc6176705c280bd05"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require_text(path: Path, needle: str) -> None:
    if needle not in path.read_text(encoding="utf-8"):
        raise ValueError(f"{path.relative_to(ROOT)} is missing required cutover text: {needle}")


def main() -> int:
    try:
        evaluation_sha = sha256_file(EVALUATION)
        if evaluation_sha != ACCEPTED_EVALUATION_SHA256:
            raise ValueError("accepted MTM-011 evaluation SHA drifted")
        evaluation = json.loads(EVALUATION.read_text(encoding="utf-8"))
        evaluation_summary = validate_evaluation(evaluation)
        if not evaluation_summary["release_gate_passed"] or evaluation_summary["status"] != "complete":
            raise ValueError("MTM-011 evaluation is not accepted and complete")

        workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
        if workspace["workspace"]["package"]["version"] != VERSION:
            raise ValueError("workspace version is not the MTM-011 cutover preview")

        contracts = ROOT / "crates" / "mtm-contracts" / "src" / "lib.rs"
        require_text(contracts, "pub const WORKFLOW_PROTOCOL_VERSION: u16 = 2;")
        require_text(contracts, "pub const PRODUCTION_WORKFLOW_PROTOCOL_VERSION: u16 = 3;")
        require_text(contracts, "pub const ROLLBACK_WORKFLOW_PROTOCOL_VERSION: u16 = 2;")
        require_text(ROOT / "crates" / "mtm-runtime" / "src" / "config.rs", "unwrap_or(default)")
        require_text(
            ROOT / "crates" / "mtm-runtime" / "src" / "tool_backend.rs",
            "production_default_workflow_protocol_version\":PRODUCTION_WORKFLOW_PROTOCOL_VERSION",
        )
        require_text(
            ROOT / "crates" / "mtm-cli" / "src" / "main.rs",
            "\"workflow_protocol_version\": PRODUCTION_WORKFLOW_PROTOCOL_VERSION",
        )
        if not (ROOT / "docs" / "releases" / f"{VERSION}.md").is_file():
            raise ValueError("cutover release note is missing")

        print(
            json.dumps(
                {
                    "ok": True,
                    "summary": {
                        "milestone": "MTM-011",
                        "version": VERSION,
                        "accepted_evaluation_sha256": evaluation_sha,
                        "historical_source_baseline_protocol": 2,
                        "production_default_workflow_protocol": 3,
                        "rollback_workflow_protocol": 2,
                    },
                },
                indent=2,
            )
        )
        return 0
    except (OSError, KeyError, json.JSONDecodeError, ValueError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, indent=2))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
