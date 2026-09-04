#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVALUATION = ROOT / "records/evidence/MTM-009/research-state-math-evaluation.json"


def score(value: str) -> int:
    parsed = int(value)
    if not 1 <= parsed <= 5:
        raise argparse.ArgumentTypeError("score must be an integer from 1 to 5")
    return parsed


def atomic_write(path: Path, payload: dict[str, object]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Record one frozen treatment-blind MTM-009 A/B score.")
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--evaluation", type=Path, default=EVALUATION)
    parser.add_argument("--evaluator-id-hash", required=True)
    parser.add_argument("--a-logic", type=score, required=True)
    parser.add_argument("--a-readability", type=score, required=True)
    parser.add_argument("--a-efficiency", type=score, required=True)
    parser.add_argument("--b-logic", type=score, required=True)
    parser.add_argument("--b-readability", type=score, required=True)
    parser.add_argument("--b-efficiency", type=score, required=True)
    parser.add_argument("--winner", choices=("A", "B", "tie"), required=True)
    parser.add_argument("--rationale", required=True)
    arguments = parser.parse_args()
    if not 12 <= len(arguments.evaluator_id_hash) <= 128:
        raise SystemExit("evaluator-id-hash must be 12..128 characters")
    if not arguments.rationale.strip() or len(arguments.rationale) > 2000:
        raise SystemExit("rationale must be non-empty and <=2000 characters")
    evaluation = json.loads(arguments.evaluation.read_text(encoding="utf-8"))
    if evaluation.get("status") == "complete":
        raise SystemExit("evaluation is already complete and immutable")
    pair = next(
        (item for item in evaluation["pairs"] if item["case_id"] == arguments.case_id), None
    )
    if pair is None:
        raise SystemExit("unknown evaluation case")
    if pair.get("protocol2") is None or pair.get("protocol3") is None:
        raise SystemExit("both treatment runs must be recorded before blind scoring")
    if pair.get("blind_evaluation") is not None:
        raise SystemExit("blind score already recorded; refusing overwrite")
    pair["blind_evaluation"] = {
        "status": "scored",
        "treatment_hidden_until_scores_frozen": True,
        "evaluator_id_hash": arguments.evaluator_id_hash,
        "artifacts": {
            "A": {
                "logic_completeness": arguments.a_logic,
                "readability": arguments.a_readability,
                "research_efficiency": arguments.a_efficiency,
            },
            "B": {
                "logic_completeness": arguments.b_logic,
                "readability": arguments.b_readability,
                "research_efficiency": arguments.b_efficiency,
            },
        },
        "winner": arguments.winner,
        "rationale": arguments.rationale.strip(),
    }
    evaluation["status"] = "in_progress"
    atomic_write(arguments.evaluation, evaluation)
    print(json.dumps({"ok": True, "case_id": arguments.case_id, "blind_score": "recorded"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
