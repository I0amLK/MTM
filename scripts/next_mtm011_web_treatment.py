#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "conformance" / "mtm011-math-corpus.json"
EVALUATION = ROOT / "mtm011-protocol3-cutover-evaluation.json"


def main() -> int:
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    evaluation = json.loads(EVALUATION.read_text(encoding="utf-8"))
    pairs = {item["case_id"]: item for item in evaluation["pairs"]}
    for case in corpus["cases"]:
        pair = pairs[case["case_id"]]
        for treatment in case["pair_order"]:
            if pair.get(treatment) is None:
                protocol = 2 if treatment == "protocol2" else 3
                print(json.dumps({
                    "ok": True,
                    "status": "treatment_pending",
                    "case_id": case["case_id"],
                    "protocol": protocol,
                    "problem_tex": case["problem_tex"],
                    "solver_visible_fields": ["case_id", "protocol", "problem_tex"],
                    "withheld_fields": ["difficulty", "capabilities", "research_control_focus", "metric_applicability", "evaluator_checks"],
                    "final_artifact": "proof_verified.tex"
                }, indent=2))
                return 0
    print(json.dumps({
        "ok": True,
        "status": "all_treatments_recorded",
        "blind_pairs_pending": sum(item.get("blind_evaluation") is None for item in evaluation["pairs"])
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
