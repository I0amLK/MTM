#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SIMULATION = ROOT / "conformance" / "mtm009-math-simulation.json"
CORPUS = ROOT / "conformance" / "mtm009-math-corpus.json"

METRICS = (
    "verified_tex_completion",
    "first_verification_pass",
    "repeated_failed_route_without_new_evidence",
    "counterexample_probe_on_blocker",
    "focused_retrieval_when_missing_reference",
    "max_no_novelty_retrieval_streak",
    "preserved_usable_partial_results",
    "repair_count",
    "verifier_finding_count",
    "harmful_advice_events",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    simulation = json.loads(SIMULATION.read_text(encoding="utf-8"))
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    if simulation.get("official_a4_eligible") is not False:
        raise SystemExit("simulation must never be A4-eligible")
    if simulation.get("status") != "complete":
        raise SystemExit("simulation status must be complete")
    if not simulation.get("contamination_notice"):
        raise SystemExit("simulation contamination must be recorded")
    expected = [case["case_id"] for case in corpus["cases"]]
    pairs = simulation.get("pairs")
    if not isinstance(pairs, list) or [pair.get("case_id") for pair in pairs] != expected:
        raise SystemExit("simulation cases do not match the frozen corpus in order")

    totals = {"protocol2": {metric: 0 for metric in METRICS}, "protocol3": {metric: 0 for metric in METRICS}}
    readable = {"protocol2": 0, "protocol3": 0, "tie": 0}
    for pair in pairs:
        for protocol in ("protocol2", "protocol3"):
            treatment = pair.get(protocol)
            if not isinstance(treatment, dict):
                raise SystemExit(f"{pair['case_id']} missing {protocol}")
            tex = treatment.get("final_tex")
            trace = treatment.get("normalized_trace")
            metrics = treatment.get("metrics")
            if not isinstance(tex, str) or "\\begin{proof}" not in tex or "\\end{proof}" not in tex:
                raise SystemExit(f"{pair['case_id']} {protocol} final_tex is invalid")
            if not isinstance(trace, list) or not trace or not all(isinstance(item, str) and item for item in trace):
                raise SystemExit(f"{pair['case_id']} {protocol} normalized_trace is invalid")
            if set(metrics or {}) != set(METRICS):
                raise SystemExit(f"{pair['case_id']} {protocol} metrics are incomplete")
            for metric in METRICS:
                value = metrics[metric]
                if not isinstance(value, int) or value < 0:
                    raise SystemExit(f"{pair['case_id']} {protocol} metric {metric} is invalid")
                totals[protocol][metric] += value
        if pair["protocol3"]["metrics"]["harmful_advice_events"] != 0:
            raise SystemExit(f"{pair['case_id']} simulated harmful advice is nonzero")
        judgment = pair.get("simulated_blind_judgment") or {}
        if judgment.get("correctness") not in {"tie", "protocol2", "protocol3"}:
            raise SystemExit(f"{pair['case_id']} invalid simulated correctness judgment")
        choice = judgment.get("readability")
        if choice not in readable:
            raise SystemExit(f"{pair['case_id']} invalid readability judgment")
        readable[choice] += 1

    if totals["protocol3"]["verified_tex_completion"] < totals["protocol2"]["verified_tex_completion"]:
        raise SystemExit("simulated protocol3 completion regressed")
    improvements = {
        "first_verification_pass": totals["protocol3"]["first_verification_pass"] - totals["protocol2"]["first_verification_pass"],
        "repeated_failed_route_without_new_evidence": totals["protocol2"]["repeated_failed_route_without_new_evidence"] - totals["protocol3"]["repeated_failed_route_without_new_evidence"],
        "max_no_novelty_retrieval_streak": totals["protocol2"]["max_no_novelty_retrieval_streak"] - totals["protocol3"]["max_no_novelty_retrieval_streak"],
        "preserved_usable_partial_results": totals["protocol3"]["preserved_usable_partial_results"] - totals["protocol2"]["preserved_usable_partial_results"],
        "repair_count": totals["protocol2"]["repair_count"] - totals["protocol3"]["repair_count"],
        "verifier_finding_count": totals["protocol2"]["verifier_finding_count"] - totals["protocol3"]["verifier_finding_count"],
    }
    result = {
        "ok": True,
        "official_a4_eligible": False,
        "case_count": len(pairs),
        "simulation_sha256": sha256(SIMULATION),
        "corpus_sha256": sha256(CORPUS),
        "totals": totals,
        "predeclared_directional_improvements": improvements,
        "simulated_readability_preferences": readable,
        "warning": "Structural rehearsal only; evaluator-contaminated and not admissible as A4 evidence."
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
