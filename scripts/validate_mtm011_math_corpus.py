#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "conformance" / "mtm011-math-corpus.json"
STRUCTURAL = {
    "refuted_target_state_preserved",
    "typed_obstruction_class_preserved",
    "canonical_partial_results_preserved",
}
BEHAVIORAL_APPLICABILITY = {
    "counterexample_probe_on_blocker",
    "focused_retrieval_when_missing_reference",
}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("schema_version") != "1.0.0":
        raise ValueError("unexpected corpus schema_version")
    if payload.get("corpus_id") != "mtm011-protocol3-cutover-v1":
        raise ValueError("unexpected corpus_id")
    policy = payload.get("treatment_policy")
    if not isinstance(policy, dict) or policy.get("final_artifact") != "proof_verified.tex":
        raise ValueError("corpus must freeze proof_verified.tex as final artifact")
    release = payload.get("release_policy")
    if not isinstance(release, dict):
        raise ValueError("release_policy must be an object")
    if release.get("minimum_strict_structural_primary_improvements") != 2:
        raise ValueError("MTM-011 must require exactly two strict structural improvements")
    if release.get("verified_tex_non_regression") is not True:
        raise ValueError("verified .tex non-regression must remain required")
    if release.get("harmful_advice_must_equal_zero") is not True:
        raise ValueError("zero harmful advice must remain required")
    cases = payload.get("cases")
    if not isinstance(cases, list) or len(cases) != 6:
        raise ValueError("MTM-011 v1 corpus must contain exactly six cases")
    ids: set[str] = set()
    orders: Counter[tuple[str, str]] = Counter()
    capabilities: Counter[str] = Counter()
    structural_applicable: Counter[str] = Counter()
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            raise ValueError(f"cases[{index}] must be an object")
        case_id = case.get("case_id")
        if not isinstance(case_id, str) or not case_id.startswith("M011-C") or case_id in ids:
            raise ValueError(f"invalid or duplicate case_id at index {index}")
        ids.add(case_id)
        order = case.get("pair_order")
        if order not in (["protocol2", "protocol3"], ["protocol3", "protocol2"]):
            raise ValueError(f"{case_id} has invalid pair_order")
        orders[tuple(order)] += 1
        problem = case.get("problem_tex")
        if not isinstance(problem, str) or not (40 <= len(problem) <= 6000):
            raise ValueError(f"{case_id} has invalid problem_tex")
        focus = case.get("research_control_focus")
        if not isinstance(focus, str) or not focus.strip():
            raise ValueError(f"{case_id} requires research_control_focus")
        checks = case.get("evaluator_checks")
        if not isinstance(checks, list) or len(checks) < 4 or not all(
            isinstance(item, str) and item.strip() for item in checks
        ):
            raise ValueError(f"{case_id} requires at least four evaluator checks")
        tags = case.get("capabilities")
        if not isinstance(tags, list) or len(tags) < 3 or not all(
            isinstance(item, str) and item for item in tags
        ):
            raise ValueError(f"{case_id} has invalid capability tags")
        capabilities.update(tags)
        applicability = case.get("metric_applicability")
        required = STRUCTURAL | BEHAVIORAL_APPLICABILITY
        if not isinstance(applicability, dict) or set(applicability) != required:
            raise ValueError(f"{case_id} metric_applicability must freeze exactly {sorted(required)}")
        if not all(isinstance(value, bool) for value in applicability.values()):
            raise ValueError(f"{case_id} metric applicability values must be booleans")
        for metric in STRUCTURAL:
            if applicability[metric]:
                structural_applicable[metric] += 1
    if orders[("protocol2", "protocol3")] != 3 or orders[("protocol3", "protocol2")] != 3:
        raise ValueError("paired order must be balanced 3/3")
    if len(capabilities) < 15:
        raise ValueError("corpus capability coverage is too narrow")
    if any(structural_applicable[metric] < 3 for metric in STRUCTURAL):
        raise ValueError("each structural primary metric must be applicable to at least three cases")
    return {
        "case_count": 6,
        "order_counts": {"protocol2_first": 3, "protocol3_first": 3},
        "unique_capabilities": len(capabilities),
        "structural_applicability": dict(sorted(structural_applicable.items())),
        "corpus_sha256": sha256_file(CORPUS),
    }


def main() -> int:
    try:
        summary = validate(json.loads(CORPUS.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, indent=2))
        return 1
    print(json.dumps({"ok": True, "summary": summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
