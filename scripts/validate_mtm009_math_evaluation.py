#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
EVALUATION = ROOT / "records/evidence/MTM-009/research-state-math-evaluation.json"
CORPUS = ROOT / "conformance" / "mtm009-math-corpus.json"
RESOURCE = ROOT / "records/evidence/MTM-009/research-resource.json"

EXPECTED_METRICS = {
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
}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def non_negative_int(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


def validate_run(run: Any, *, protocol: int, case_id: str) -> dict[str, Any] | None:
    if run is None:
        return None
    if not isinstance(run, dict):
        raise ValueError(f"{case_id} protocol{protocol} run must be an object or null")
    if run.get("status") != "complete" or run.get("protocol") != protocol:
        raise ValueError(f"{case_id} protocol{protocol} run identity/status is invalid")
    for field in ("run_fingerprint", "model_surface", "connector_profile"):
        value = run.get(field)
        if not isinstance(value, str) or not value.strip() or len(value) > 256:
            raise ValueError(f"{case_id} protocol{protocol} {field} is invalid")
    if run.get("research_tools_policy") != "normal_web_plus_mtm_workspace":
        raise ValueError(f"{case_id} protocol{protocol} research tool policy drifted")
    outcome = run.get("final_outcome")
    if outcome not in {"verified_tex", "unresolved"}:
        raise ValueError(f"{case_id} protocol{protocol} final_outcome is invalid")
    final_hash = run.get("final_tex_sha256")
    if outcome == "verified_tex":
        if not isinstance(final_hash, str) or len(final_hash) != 64:
            raise ValueError(f"{case_id} verified run requires final_tex_sha256")
    elif final_hash is not None:
        raise ValueError(f"{case_id} unresolved run cannot claim final_tex_sha256")
    if not isinstance(run.get("first_verification_pass"), bool):
        raise ValueError(f"{case_id} protocol{protocol} first_verification_pass must be boolean")
    for field in (
        "repair_count",
        "verifier_finding_count",
        "repeated_failed_route_without_new_evidence",
        "max_no_novelty_retrieval_streak",
        "preserved_usable_partial_results",
        "harmful_advice_events",
    ):
        non_negative_int(run.get(field), f"{case_id} protocol{protocol} {field}")
    for field in ("counterexample_probe_on_blocker", "focused_retrieval_when_missing_reference"):
        if run.get(field) not in {True, False, None}:
            raise ValueError(f"{case_id} protocol{protocol} {field} must be boolean or null")
    if protocol == 2 and run.get("advisory_rule_counts") not in ({}, None):
        raise ValueError(f"{case_id} protocol2 cannot report protocol3 advisory rules")
    if protocol == 3:
        counts = run.get("advisory_rule_counts")
        if not isinstance(counts, dict) or any(
            not isinstance(key, str) or non_negative_int(value, f"{case_id} advisory count") < 0
            for key, value in counts.items()
        ):
            raise ValueError(f"{case_id} protocol3 advisory_rule_counts is invalid")
    if run.get("raw_web_transcript_recorded") is not False or run.get("private_reasoning_recorded") is not False:
        raise ValueError(f"{case_id} run record must not contain raw transcript/private reasoning")
    return run


def validate_blind(value: Any, *, case_id: str) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or value.get("status") != "scored":
        raise ValueError(f"{case_id} blind evaluation must be scored object or null")
    if value.get("treatment_hidden_until_scores_frozen") is not True:
        raise ValueError(f"{case_id} blind scoring was not treatment-hidden")
    evaluator = value.get("evaluator_id_hash")
    if not isinstance(evaluator, str) or len(evaluator) < 12 or len(evaluator) > 128:
        raise ValueError(f"{case_id} evaluator_id_hash is invalid")
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != {"A", "B"}:
        raise ValueError(f"{case_id} blind artifacts must be A/B")
    for label in ("A", "B"):
        item = artifacts[label]
        if not isinstance(item, dict):
            raise ValueError(f"{case_id} blind artifact {label} must be object")
        for score in ("logic_completeness", "readability", "research_efficiency"):
            raw = item.get(score)
            if not isinstance(raw, int) or isinstance(raw, bool) or not (1 <= raw <= 5):
                raise ValueError(f"{case_id} {label} {score} must be integer 1..5")
    if value.get("winner") not in {"A", "B", "tie"}:
        raise ValueError(f"{case_id} blind winner is invalid")
    rationale = value.get("rationale")
    if not isinstance(rationale, str) or not rationale.strip() or len(rationale) > 2000:
        raise ValueError(f"{case_id} blind rationale is invalid")
    return value


def aggregate_complete(pairs: list[dict[str, Any]]) -> tuple[dict[str, Any], bool]:
    p2 = [pair["protocol2"] for pair in pairs]
    p3 = [pair["protocol3"] for pair in pairs]
    completion2 = sum(run["final_outcome"] == "verified_tex" for run in p2)
    completion3 = sum(run["final_outcome"] == "verified_tex" for run in p3)
    first2 = sum(run["first_verification_pass"] for run in p2)
    first3 = sum(run["first_verification_pass"] for run in p3)
    repeated2 = sum(run["repeated_failed_route_without_new_evidence"] for run in p2)
    repeated3 = sum(run["repeated_failed_route_without_new_evidence"] for run in p3)
    no_novelty2 = sum(run["max_no_novelty_retrieval_streak"] for run in p2)
    no_novelty3 = sum(run["max_no_novelty_retrieval_streak"] for run in p3)
    counter_pairs = [
        (a["counterexample_probe_on_blocker"], b["counterexample_probe_on_blocker"])
        for a, b in zip(p2, p3)
        if a["counterexample_probe_on_blocker"] is not None
        and b["counterexample_probe_on_blocker"] is not None
    ]
    retrieval_pairs = [
        (a["focused_retrieval_when_missing_reference"], b["focused_retrieval_when_missing_reference"])
        for a, b in zip(p2, p3)
        if a["focused_retrieval_when_missing_reference"] is not None
        and b["focused_retrieval_when_missing_reference"] is not None
    ]
    primary_improvements = {
        "repeated_failed_route_without_new_evidence": repeated3 < repeated2,
        "max_no_novelty_retrieval_streak": no_novelty3 < no_novelty2,
        "counterexample_probe_on_blocker": bool(counter_pairs)
        and sum(b for _, b in counter_pairs) > sum(a for a, _ in counter_pairs),
        "focused_retrieval_when_missing_reference": bool(retrieval_pairs)
        and sum(b for _, b in retrieval_pairs) > sum(a for a, _ in retrieval_pairs),
    }
    harmful3 = sum(run["harmful_advice_events"] for run in p3)
    gate = completion3 >= completion2 and any(primary_improvements.values()) and harmful3 == 0
    aggregate = {
        "verified_tex_completion": {"protocol2": completion2, "protocol3": completion3},
        "first_verification_pass": {"protocol2": first2, "protocol3": first3},
        "repeated_failed_route_without_new_evidence": {"protocol2": repeated2, "protocol3": repeated3},
        "max_no_novelty_retrieval_streak_sum": {"protocol2": no_novelty2, "protocol3": no_novelty3},
        "protocol3_harmful_advice_events": harmful3,
        "primary_research_control_improvements": primary_improvements,
        "release_gate_passed": gate,
    }
    return aggregate, gate


def validate(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("schema_version") != "1.0.0" or payload.get("evaluation_id") != "mtm009-web-mathematics-v1":
        raise ValueError("unexpected MTM-009 math evaluation identity")
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    if payload.get("corpus", {}).get("sha256") != sha256_file(CORPUS):
        raise ValueError("math evaluation is stale for the frozen corpus")
    if payload.get("resource_evidence", {}).get("sha256") != sha256_file(RESOURCE):
        raise ValueError("math evaluation is stale for the A5 resource evidence")
    metric_names = {item.get("metric") for item in payload.get("predeclared_metrics", []) if isinstance(item, dict)}
    if metric_names != EXPECTED_METRICS:
        raise ValueError("predeclared metric set changed")
    treatment = payload.get("treatment_contract")
    if not isinstance(treatment, dict) or treatment.get("final_artifact") != "proof_verified.tex":
        raise ValueError("treatment contract final artifact drifted")
    if treatment.get("raw_web_transcript_recorded") is not False or treatment.get("private_reasoning_recorded") is not False:
        raise ValueError("evaluation must not record transcript/private reasoning")
    pairs = payload.get("pairs")
    corpus_cases = corpus.get("cases")
    if not isinstance(pairs, list) or not isinstance(corpus_cases, list) or len(pairs) != len(corpus_cases):
        raise ValueError("evaluation pair count does not match corpus")
    complete_pairs = 0
    normalized_pairs: list[dict[str, Any]] = []
    for pair, case in zip(pairs, corpus_cases):
        if not isinstance(pair, dict) or pair.get("case_id") != case.get("case_id"):
            raise ValueError("evaluation case order/identity drifted")
        if pair.get("pair_order") != case.get("pair_order"):
            raise ValueError(f"{pair.get('case_id')} pair order drifted")
        case_id = str(pair["case_id"])
        p2 = validate_run(pair.get("protocol2"), protocol=2, case_id=case_id)
        p3 = validate_run(pair.get("protocol3"), protocol=3, case_id=case_id)
        blind = validate_blind(pair.get("blind_evaluation"), case_id=case_id)
        finished = p2 is not None and p3 is not None and blind is not None
        if any(value is not None for value in (p2, p3, blind)) and not finished:
            if payload.get("status") == "complete":
                raise ValueError(f"{case_id} is incomplete in complete evaluation")
        if finished:
            if p2["model_surface"] != p3["model_surface"] or p2["connector_profile"] != p3["connector_profile"]:
                raise ValueError(f"{case_id} pair did not use the same web surface/connector profile")
            complete_pairs += 1
            normalized_pairs.append({"protocol2": p2, "protocol3": p3})
    status = payload.get("status")
    if status not in {"pending_web_runs", "in_progress", "complete"}:
        raise ValueError("evaluation status is invalid")
    if status == "pending_web_runs" and complete_pairs != 0:
        raise ValueError("pending_web_runs cannot contain completed pairs")
    if status == "complete" and complete_pairs != len(pairs):
        raise ValueError("complete evaluation requires all eight pairs and blind scores")
    result: dict[str, Any] = {
        "evaluation_sha256": sha256_file(EVALUATION),
        "complete_pairs": complete_pairs,
        "total_pairs": len(pairs),
        "status": status,
        "release_gate_passed": False,
    }
    if status == "complete":
        aggregate, gate = aggregate_complete(normalized_pairs)
        if payload.get("aggregate") != aggregate:
            raise ValueError("stored aggregate does not match deterministic recomputation")
        if payload.get("decision") != ("accepted" if gate else "rejected"):
            raise ValueError("evaluation decision does not match release gate")
        result["release_gate_passed"] = gate
    else:
        if payload.get("aggregate") is not None or payload.get("decision") != "pending_real_web_evidence":
            raise ValueError("incomplete evaluation must not claim aggregate/decision")
    return result


def main() -> int:
    try:
        payload = json.loads(EVALUATION.read_text(encoding="utf-8"))
        summary = validate(payload)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, indent=2))
        return 1
    print(json.dumps({"ok": True, "summary": summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
