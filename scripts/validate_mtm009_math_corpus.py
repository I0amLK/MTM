#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "conformance" / "mtm009-math-corpus.json"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("schema_version") != "1.0.0":
        raise ValueError("unexpected corpus schema_version")
    if payload.get("corpus_id") != "mtm009-web-mathematics-v1":
        raise ValueError("unexpected corpus_id")
    policy = payload.get("treatment_policy")
    if not isinstance(policy, dict) or policy.get("final_artifact") != "proof_verified.tex":
        raise ValueError("corpus must freeze proof_verified.tex as the final artifact")
    cases = payload.get("cases")
    if not isinstance(cases, list) or len(cases) != 8:
        raise ValueError("MTM-009 v1 corpus must contain exactly eight cases")
    ids: set[str] = set()
    orders: Counter[tuple[str, str]] = Counter()
    capabilities: Counter[str] = Counter()
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            raise ValueError(f"cases[{index}] must be an object")
        case_id = case.get("case_id")
        if not isinstance(case_id, str) or not case_id.startswith("M009-C") or case_id in ids:
            raise ValueError(f"invalid or duplicate case_id at index {index}")
        ids.add(case_id)
        order = case.get("pair_order")
        if order not in (["protocol2", "protocol3"], ["protocol3", "protocol2"]):
            raise ValueError(f"{case_id} has invalid pair_order")
        orders[tuple(order)] += 1
        problem = case.get("problem_tex")
        if not isinstance(problem, str) or not (20 <= len(problem) <= 4000):
            raise ValueError(f"{case_id} has invalid problem_tex")
        focus = case.get("research_control_focus")
        if not isinstance(focus, str) or not focus.strip():
            raise ValueError(f"{case_id} requires research_control_focus")
        checks = case.get("evaluator_checks")
        if not isinstance(checks, list) or len(checks) < 3 or not all(
            isinstance(item, str) and item.strip() for item in checks
        ):
            raise ValueError(f"{case_id} requires at least three evaluator checks")
        tags = case.get("capabilities")
        if not isinstance(tags, list) or len(tags) < 2 or not all(
            isinstance(item, str) and item for item in tags
        ):
            raise ValueError(f"{case_id} has invalid capability tags")
        capabilities.update(tags)
    if orders[("protocol2", "protocol3")] != 4 or orders[("protocol3", "protocol2")] != 4:
        raise ValueError("paired order must be balanced 4/4")
    if len(capabilities) < 12:
        raise ValueError("corpus capability coverage is too narrow")
    return {
        "case_count": len(cases),
        "order_counts": {"protocol2_first": 4, "protocol3_first": 4},
        "unique_capabilities": len(capabilities),
        "corpus_sha256": sha256_file(CORPUS),
    }


def main() -> int:
    try:
        payload = json.loads(CORPUS.read_text(encoding="utf-8"))
        summary = validate(payload)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, indent=2))
        return 1
    print(json.dumps({"ok": True, "summary": summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
