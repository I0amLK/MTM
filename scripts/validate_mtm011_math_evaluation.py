#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "conformance" / "mtm011-math-corpus.json"
EVALUATION = ROOT / "mtm011-protocol3-cutover-evaluation.json"
SHA256_RE = re.compile(r"[0-9a-f]{64}$")
ALLOWED_ADVICE = {
    "R01_REPLAN_REFUTED", "R02_REPLAN_CYCLE", "R03_TEST_COUNTEREXAMPLE",
    "R04_RETRIEVE_FOCUSED", "R05_STOP_RETRIEVAL", "R06_SCREEN_FRONTIER",
    "R07_CONSOLIDATE", "R08_ASSEMBLE", "R09_REVIEW_STATE",
}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def non_negative_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def validate_optional_bool(value: Any, applicable: bool, label: str) -> bool | None:
    if applicable:
        if not isinstance(value, bool):
            raise ValueError(f"{label} must be boolean when applicable")
        return value
    if value is not None:
        raise ValueError(f"{label} must be null when not applicable")
    return None


def validate_run(run: dict[str, Any], protocol: int, case: dict[str, Any], candidate_sha: str) -> None:
    if run.get("status") != "complete" or run.get("protocol") != protocol:
        raise ValueError(f"{case['case_id']} protocol{protocol} identity is invalid")
    if run.get("binary_sha256") != candidate_sha:
        raise ValueError(f"{case['case_id']} protocol{protocol} binary binding drifted")
    for field in ("run_fingerprint", "model_surface", "connector_profile"):
        if not isinstance(run.get(field), str) or not run[field].strip():
            raise ValueError(f"{case['case_id']} protocol{protocol} missing {field}")
    if run.get("research_tools_policy") != "normal_web_plus_mtm_workspace":
        raise ValueError("research tools policy drifted")
    if run.get("final_outcome") not in {"verified_tex", "unresolved"}:
        raise ValueError("invalid final_outcome")
    final_hash = run.get("final_tex_sha256")
    if run["final_outcome"] == "verified_tex":
        if not isinstance(final_hash, str) or SHA256_RE.fullmatch(final_hash) is None:
            raise ValueError("verified_tex requires final_tex_sha256")
    elif final_hash is not None:
        raise ValueError("unresolved treatment may not claim a final artifact hash")
    if not isinstance(run.get("first_verification_pass"), bool):
        raise ValueError("first_verification_pass must be boolean")
    for field in (
        "repair_count", "verifier_finding_count", "repeated_failed_route_without_new_evidence",
        "max_no_novelty_retrieval_streak", "harmful_advice_events",
        "canonical_partial_results_preserved",
    ):
        non_negative_int(run.get(field), field)
    applicability = case["metric_applicability"]
    validate_optional_bool(run.get("counterexample_probe_on_blocker"), applicability["counterexample_probe_on_blocker"], "counterexample_probe_on_blocker")
    validate_optional_bool(run.get("focused_retrieval_when_missing_reference"), applicability["focused_retrieval_when_missing_reference"], "focused_retrieval_when_missing_reference")
    validate_optional_bool(run.get("refuted_target_state_preserved"), applicability["refuted_target_state_preserved"], "refuted_target_state_preserved")
    validate_optional_bool(run.get("typed_obstruction_class_preserved"), applicability["typed_obstruction_class_preserved"], "typed_obstruction_class_preserved")
    if not applicability["canonical_partial_results_preserved"] and run["canonical_partial_results_preserved"] != 0:
        raise ValueError("canonical partial results must be zero when not applicable")
    advice = run.get("advisory_rule_counts")
    if not isinstance(advice, dict):
        raise ValueError("advisory_rule_counts must be an object")
    for key, value in advice.items():
        if key not in ALLOWED_ADVICE:
            raise ValueError(f"invalid advisory rule: {key}")
        non_negative_int(value, f"advisory_rule_counts.{key}")
    if protocol == 2 and (advice or run["harmful_advice_events"] != 0):
        raise ValueError("protocol 2 cannot report protocol-3 advisory behavior")
    for field in ("transition_log_sha256", "verification_report_sha256"):
        value = run.get(field)
        if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
            raise ValueError(f"invalid {field}")
    if run.get("raw_web_transcript_recorded") is not False or run.get("private_reasoning_recorded") is not False:
        raise ValueError("raw transcript/private reasoning retention is forbidden")


def validate_blind(value: Any, case_id: str) -> None:
    if not isinstance(value, dict) or value.get("status") != "scored":
        raise ValueError(f"{case_id} requires a frozen blind score")
    if value.get("treatment_hidden_until_scores_frozen") is not True:
        raise ValueError(f"{case_id} blind treatment labels were not frozen")
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != {"A", "B"}:
        raise ValueError(f"{case_id} blind artifacts must be A/B")
    for label in ("A", "B"):
        item = artifacts[label]
        if not isinstance(item, dict):
            raise ValueError(f"{case_id} blind artifact must be object")
        for metric in ("logic_completeness", "readability", "research_efficiency"):
            score = item.get(metric)
            if not isinstance(score, int) or isinstance(score, bool) or not 1 <= score <= 5:
                raise ValueError(f"{case_id} invalid blind {metric}")
    if value.get("winner") not in {"A", "B", "tie"}:
        raise ValueError(f"{case_id} blind winner is invalid")
    if not isinstance(value.get("rationale"), str) or not value["rationale"].strip():
        raise ValueError(f"{case_id} blind rationale is invalid")


def applicable_bool_pairs(pairs: list[dict[str, Any]], cases: dict[str, dict[str, Any]], field: str) -> list[tuple[bool, bool]]:
    result = []
    for pair in pairs:
        case = cases[pair["case_id"]]
        if case["metric_applicability"][field]:
            result.append((pair["protocol2"][field], pair["protocol3"][field]))
    return result


def aggregate_complete(pairs: list[dict[str, Any]], cases: dict[str, dict[str, Any]]) -> tuple[dict[str, Any], bool]:
    p2 = [pair["protocol2"] for pair in pairs]
    p3 = [pair["protocol3"] for pair in pairs]
    completion2 = sum(run["final_outcome"] == "verified_tex" for run in p2)
    completion3 = sum(run["final_outcome"] == "verified_tex" for run in p3)
    first2 = sum(run["first_verification_pass"] for run in p2)
    first3 = sum(run["first_verification_pass"] for run in p3)
    repair2 = sum(run["repair_count"] for run in p2)
    repair3 = sum(run["repair_count"] for run in p3)
    findings2 = sum(run["verifier_finding_count"] for run in p2)
    findings3 = sum(run["verifier_finding_count"] for run in p3)
    repeated2 = sum(run["repeated_failed_route_without_new_evidence"] for run in p2)
    repeated3 = sum(run["repeated_failed_route_without_new_evidence"] for run in p3)
    no_novelty2 = sum(run["max_no_novelty_retrieval_streak"] for run in p2)
    no_novelty3 = sum(run["max_no_novelty_retrieval_streak"] for run in p3)
    harmful3 = sum(run["harmful_advice_events"] for run in p3)
    counter_pairs = applicable_bool_pairs(pairs, cases, "counterexample_probe_on_blocker")
    retrieval_pairs = applicable_bool_pairs(pairs, cases, "focused_retrieval_when_missing_reference")
    refuted_pairs = applicable_bool_pairs(pairs, cases, "refuted_target_state_preserved")
    obstruction_pairs = applicable_bool_pairs(pairs, cases, "typed_obstruction_class_preserved")
    partial2 = sum(pair["protocol2"]["canonical_partial_results_preserved"] for pair in pairs if cases[pair["case_id"]]["metric_applicability"]["canonical_partial_results_preserved"])
    partial3 = sum(pair["protocol3"]["canonical_partial_results_preserved"] for pair in pairs if cases[pair["case_id"]]["metric_applicability"]["canonical_partial_results_preserved"])
    structural = {
        "refuted_target_state_preserved": sum(b for _, b in refuted_pairs) > sum(a for a, _ in refuted_pairs),
        "typed_obstruction_class_preserved": sum(b for _, b in obstruction_pairs) > sum(a for a, _ in obstruction_pairs),
        "canonical_partial_results_preserved": partial3 > partial2,
    }
    behavioral = {
        "verified_tex_completion": completion3 >= completion2,
        "first_verification_pass": first3 >= first2,
        "repair_count": repair3 <= repair2,
        "verifier_finding_count": findings3 <= findings2,
        "repeated_failed_route_without_new_evidence": repeated3 <= repeated2,
        "max_no_novelty_retrieval_streak": no_novelty3 <= no_novelty2,
        "counterexample_probe_on_blocker": sum(b for _, b in counter_pairs) >= sum(a for a, _ in counter_pairs),
        "focused_retrieval_when_missing_reference": sum(b for _, b in retrieval_pairs) >= sum(a for a, _ in retrieval_pairs),
    }
    strict_count = sum(structural.values())
    gate = all(behavioral.values()) and harmful3 == 0 and strict_count >= 2
    aggregate = {
        "verified_tex_completion": {"protocol2": completion2, "protocol3": completion3},
        "first_verification_pass": {"protocol2": first2, "protocol3": first3},
        "repair_count": {"protocol2": repair2, "protocol3": repair3},
        "verifier_finding_count": {"protocol2": findings2, "protocol3": findings3},
        "repeated_failed_route_without_new_evidence": {"protocol2": repeated2, "protocol3": repeated3},
        "max_no_novelty_retrieval_streak_sum": {"protocol2": no_novelty2, "protocol3": no_novelty3},
        "protocol3_harmful_advice_events": harmful3,
        "structural_primary_improvements": structural,
        "strict_structural_improvement_count": strict_count,
        "behavioral_non_regression": behavioral,
        "release_gate_passed": gate,
    }
    return aggregate, gate


def validate(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("schema_version") != "1.0.0" or payload.get("evaluation_id") != "mtm011-protocol3-cutover-v1":
        raise ValueError("unexpected MTM-011 evaluation identity")
    corpus_payload = json.loads(CORPUS.read_text(encoding="utf-8"))
    if payload.get("corpus", {}).get("sha256") != sha256_file(CORPUS):
        raise ValueError("evaluation is stale for the frozen MTM-011 corpus")
    cases = {case["case_id"]: case for case in corpus_payload["cases"]}
    pairs = payload.get("pairs")
    if not isinstance(pairs, list) or len(pairs) != len(cases):
        raise ValueError("evaluation pair count does not match corpus")
    candidate_sha = payload.get("candidate", {}).get("binary_sha256")
    recorded_runs = sum(pair.get("protocol2") is not None for pair in pairs) + sum(pair.get("protocol3") is not None for pair in pairs)
    if recorded_runs:
        if not isinstance(candidate_sha, str) or SHA256_RE.fullmatch(candidate_sha) is None:
            raise ValueError("recorded treatments require one candidate binary SHA-256")
    elif candidate_sha is not None:
        raise ValueError("candidate binary may not be bound before the first treatment")
    complete_pairs = 0
    for pair in pairs:
        case_id = pair.get("case_id")
        if case_id not in cases or pair.get("pair_order") != cases[case_id]["pair_order"]:
            raise ValueError("evaluation pair identity/order drifted")
        for protocol in (2, 3):
            run = pair.get(f"protocol{protocol}")
            if run is not None:
                if not isinstance(run, dict) or candidate_sha is None:
                    raise ValueError("invalid treatment record")
                validate_run(run, protocol, cases[case_id], candidate_sha)
        if isinstance(pair.get("protocol2"), dict) and isinstance(pair.get("protocol3"), dict):
            if pair["protocol2"]["model_surface"] != pair["protocol3"]["model_surface"] or pair["protocol2"]["connector_profile"] != pair["protocol3"]["connector_profile"]:
                raise ValueError(f"{case_id} treatment surface/profile mismatch")
            if pair.get("blind_evaluation") is not None:
                validate_blind(pair["blind_evaluation"], case_id)
                complete_pairs += 1
        elif pair.get("blind_evaluation") is not None:
            raise ValueError("blind score cannot precede both treatment records")
    resource = payload.get("resource_evidence")
    if not isinstance(resource, dict):
        raise ValueError("resource_evidence must be an object")
    resource_sha = resource.get("sha256")
    if resource_sha is not None:
        if not isinstance(resource_sha, str) or SHA256_RE.fullmatch(resource_sha) is None:
            raise ValueError("resource evidence SHA is invalid")
        resource_path = ROOT / str(resource.get("path"))
        if not resource_path.is_file() or sha256_file(resource_path) != resource_sha:
            raise ValueError("resource evidence binding is stale")
    status = payload.get("status")
    if status not in {"pending_web_runs", "in_progress", "complete"}:
        raise ValueError("invalid evaluation status")
    if status == "complete":
        if complete_pairs != len(pairs) or resource_sha is None:
            raise ValueError("complete evaluation requires all treatments, blind scores and A5 evidence")
        aggregate, gate = aggregate_complete(pairs, cases)
        if payload.get("aggregate") != aggregate:
            raise ValueError("stored MTM-011 aggregate does not match deterministic recomputation")
        if payload.get("decision") != ("accepted" if gate else "rejected"):
            raise ValueError("stored decision does not match deterministic gate")
    else:
        gate = False
        if payload.get("aggregate") is not None or payload.get("decision") != "pending":
            raise ValueError("non-complete evaluation may not publish aggregate/decision")
    return {
        "evaluation_sha256": sha256_file(EVALUATION),
        "complete_pairs": complete_pairs,
        "total_pairs": len(pairs),
        "status": status,
        "release_gate_passed": gate,
    }


def main() -> int:
    try:
        summary = validate(json.loads(EVALUATION.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, indent=2))
        return 1
    print(json.dumps({"ok": True, "summary": summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
