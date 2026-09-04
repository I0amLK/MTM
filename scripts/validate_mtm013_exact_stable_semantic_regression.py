#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "records/evidence/MTM-013/exact-stable-semantic-regression.json"
HARNESS = ROOT / "scripts/run_mtm013_exact_stable_semantic_regression.py"
STABLE_BINARY = Path("/home/lk/.local/bin/mtm")
EXPECTED_STABLE_SHA256 = "3312ca75a1de8707e740963cc0add4b09430dccc9dc63a3145e4456ff2b0cdf3"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("schema_version") != "1.0.0" or payload.get("milestone") != "MTM-013":
        raise ValueError("unexpected exact-stable semantic evidence identity")
    if payload.get("phase") != "exact_stable_semantic_regression":
        raise ValueError("exact-stable semantic evidence phase drifted")
    if payload.get("harness_sha256") != sha256_file(HARNESS):
        raise ValueError("exact-stable semantic evidence is stale for the current harness")
    if not STABLE_BINARY.is_file() or sha256_file(STABLE_BINARY) != EXPECTED_STABLE_SHA256:
        raise ValueError("installed stable MTM binary is missing or has drifted")
    if payload.get("binary_sha256") != EXPECTED_STABLE_SHA256 or payload.get("server_version") != "0.4.0":
        raise ValueError("semantic evidence is not bound to stable MTM 0.4.0")
    if payload.get("workflow_protocol_version") != 3:
        raise ValueError("semantic evidence did not exercise workflow protocol 3")
    if payload.get("native_exec_backend") != "disabled_for_semantic_regression":
        raise ValueError("semantic evidence backend scope is not explicit")
    if payload.get("latex_policy") != "static_only":
        raise ValueError("semantic regression must record its static LaTeX scope")
    checks = payload.get("checks")
    if not isinstance(checks, dict) or len(checks) < 9 or not all(checks.values()):
        raise ValueError("one or more exact-stable semantic checks failed")
    qc = payload.get("qc_constituent_matching")
    compact = payload.get("compact_sigma_hermitian")
    if not isinstance(qc, dict) or not isinstance(compact, dict):
        raise ValueError("semantic regression cases are missing")
    if qc.get("workflow_mode") != "full" or qc.get("state") != "done" or qc.get("verdict") != "correct":
        raise ValueError("QC constituent-matching full-flow regression did not complete correctly")
    if qc.get("latex_passed") is not True or qc.get("sealed") is not True:
        raise ValueError("QC constituent-matching regression did not pass finalization gates")
    qc_states = qc.get("observed_states")
    if qc_states != [
        "assess",
        "explore",
        "propose_plans",
        "direct_proving",
        "assemble",
        "verify",
        "done",
    ]:
        raise ValueError("QC full-flow state sequence drifted")
    if compact.get("workflow_mode") != "compact" or compact.get("state") != "done" or compact.get("verdict") != "correct":
        raise ValueError("compact sigma-Hermitian regression did not complete correctly")
    if compact.get("latex_passed") is not True or compact.get("sealed") is not True:
        raise ValueError("compact sigma-Hermitian regression did not pass finalization gates")
    if compact.get("observed_states") != ["assess", "assemble", "verify", "done"]:
        raise ValueError("compact state sequence drifted")
    for case in (qc, compact):
        digest = case.get("artifact_sha256")
        size = case.get("artifact_bytes")
        if not isinstance(digest, str) or len(digest) != 64 or not isinstance(size, int) or size <= 0:
            raise ValueError("verified artifact binding is incomplete")
    if payload.get("raw_oauth_token_recorded") is not False or payload.get("raw_capability_recorded") is not False:
        raise ValueError("semantic evidence must not record raw authority tokens")
    if payload.get("ok") is not True:
        raise ValueError("exact-stable semantic evidence is not accepted")
    return {
        "report_sha256": sha256_file(REPORT),
        "binary_sha256": EXPECTED_STABLE_SHA256,
        "check_count": len(checks),
        "qc_artifact_sha256": qc["artifact_sha256"],
        "compact_artifact_sha256": compact["artifact_sha256"],
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
