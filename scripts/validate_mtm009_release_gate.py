#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.validate_mtm009_math_evaluation import EVALUATION, validate as validate_math
from scripts.validate_mtm009_math_corpus import CORPUS, validate as validate_corpus
from scripts.validate_mtm009_math_simulation import SIMULATION
from scripts.validate_mtm009_research_resource import REPORT, validate as validate_resource


def main() -> int:
    blockers: list[str] = []
    try:
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        corpus_summary = validate_corpus(corpus)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        corpus_summary = None
        blockers.append(f"corpus_invalid:{error}")
    try:
        resource = json.loads(REPORT.read_text(encoding="utf-8"))
        resource_summary = validate_resource(resource)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        resource_summary = None
        blockers.append(f"resource_invalid:{error}")
    try:
        evaluation = json.loads(EVALUATION.read_text(encoding="utf-8"))
        evaluation_summary = validate_math(evaluation)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        evaluation_summary = None
        blockers.append(f"evaluation_invalid:{error}")

    simulation_summary = None
    try:
        simulation = json.loads(SIMULATION.read_text(encoding="utf-8"))
        simulation_summary = {
            "status": simulation.get("status"),
            "official_a4_eligible": simulation.get("official_a4_eligible"),
            "case_count": len(simulation.get("pairs") or []),
        }
        if simulation_summary["official_a4_eligible"] is not False:
            blockers.append("simulation_must_not_be_a4_eligible")
    except (OSError, json.JSONDecodeError) as error:
        blockers.append(f"simulation_invalid:{error}")

    if evaluation_summary is not None:
        if evaluation_summary.get("status") != "complete":
            blockers.append(
                f"real_web_pairs_incomplete:{evaluation_summary.get('complete_pairs', 0)}/"
                f"{evaluation_summary.get('total_pairs', 8)}"
            )
        elif evaluation_summary.get("release_gate_passed") is not True:
            blockers.append("mathematical_release_gate_failed")

    payload = {
        "ok": not blockers,
        "milestone": "MTM-009",
        "delivery7_cutover_allowed": not blockers,
        "corpus": corpus_summary,
        "resource": resource_summary,
        "evaluation": evaluation_summary,
        "simulation": simulation_summary,
        "blockers": blockers,
    }
    print(json.dumps(payload, indent=2))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
