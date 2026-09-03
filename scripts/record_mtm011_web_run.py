#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
EVALUATION = ROOT / "mtm011-protocol3-cutover-evaluation.json"
CORPUS = ROOT / "conformance" / "mtm011-math-corpus.json"
HEX_RE = re.compile(r"[0-9a-f]{12,64}$")
SHA256_RE = re.compile(r"[0-9a-f]{64}$")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def boolean(value: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise argparse.ArgumentTypeError("expected true or false")


def optional_boolean(value: str) -> bool | None:
    if value == "na":
        return None
    return boolean(value)


def non_negative(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("expected a non-negative integer")
    return parsed


def advisory_counts(raw: str, protocol: int) -> dict[str, int]:
    if protocol == 2:
        if raw not in {"{}", ""}:
            raise ValueError("protocol 2 cannot report advisory_rule_counts")
        return {}
    payload = json.loads(raw or "{}")
    if not isinstance(payload, dict):
        raise ValueError("advisory_rule_counts must be a JSON object")
    allowed = {
        "R01_REPLAN_REFUTED",
        "R02_REPLAN_CYCLE",
        "R03_TEST_COUNTEREXAMPLE",
        "R04_RETRIEVE_FOCUSED",
        "R05_STOP_RETRIEVAL",
        "R06_SCREEN_FRONTIER",
        "R07_CONSOLIDATE",
        "R08_ASSEMBLE",
        "R09_REVIEW_STATE",
    }
    normalized: dict[str, int] = {}
    for key, value in payload.items():
        if key not in allowed or not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"invalid advisory rule count: {key}")
        normalized[key] = value
    return dict(sorted(normalized.items()))


def atomic_write(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def require_applicability(name: str, value: bool | None, applicable: bool) -> None:
    if applicable and value is None:
        raise ValueError(f"{name} is applicable for this case and may not be na")
    if not applicable and value is not None:
        raise ValueError(f"{name} is not applicable for this case and must be na")


def main() -> int:
    parser = argparse.ArgumentParser(description="Record one sanitized MTM-011 paired web treatment.")
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--protocol", type=int, choices=(2, 3), required=True)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--run-fingerprint", required=True)
    parser.add_argument("--model-surface", required=True)
    parser.add_argument("--connector-profile", required=True)
    parser.add_argument("--final-outcome", choices=("verified_tex", "unresolved"), required=True)
    parser.add_argument("--final-tex", type=Path)
    parser.add_argument("--first-verification-pass", type=boolean, required=True)
    parser.add_argument("--repair-count", type=non_negative, required=True)
    parser.add_argument("--verifier-finding-count", type=non_negative, required=True)
    parser.add_argument("--repeated-failed-route-without-new-evidence", type=non_negative, required=True)
    parser.add_argument("--counterexample-probe-on-blocker", type=optional_boolean, required=True)
    parser.add_argument("--focused-retrieval-when-missing-reference", type=optional_boolean, required=True)
    parser.add_argument("--max-no-novelty-retrieval-streak", type=non_negative, required=True)
    parser.add_argument("--harmful-advice-events", type=non_negative, required=True)
    parser.add_argument("--refuted-target-state-preserved", type=optional_boolean, required=True)
    parser.add_argument("--typed-obstruction-class-preserved", type=optional_boolean, required=True)
    parser.add_argument("--canonical-partial-results-preserved", type=non_negative, required=True)
    parser.add_argument("--advisory-rule-counts", default="{}")
    parser.add_argument("--transition-log-sha256", required=True)
    parser.add_argument("--verification-report-sha256", required=True)
    arguments = parser.parse_args()

    fingerprint = arguments.run_fingerprint.strip().lower()
    if HEX_RE.fullmatch(fingerprint) is None:
        raise SystemExit("run-fingerprint must be 12..64 lowercase hex characters")
    binary_sha = arguments.binary_sha256.strip().lower()
    if SHA256_RE.fullmatch(binary_sha) is None:
        raise SystemExit("binary-sha256 must be a full lowercase SHA-256")
    for name, value in (
        ("transition-log-sha256", arguments.transition_log_sha256),
        ("verification-report-sha256", arguments.verification_report_sha256),
    ):
        if SHA256_RE.fullmatch(value) is None:
            raise SystemExit(f"{name} must be a full lowercase SHA-256")

    final_hash: str | None = None
    if arguments.final_outcome == "verified_tex":
        if arguments.final_tex is None or not arguments.final_tex.is_file():
            raise SystemExit("verified_tex outcome requires --final-tex")
        arguments.final_tex.read_text(encoding="utf-8")
        final_hash = sha256_file(arguments.final_tex)
    elif arguments.final_tex is not None:
        raise SystemExit("unresolved outcome must not provide --final-tex")

    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    case = next((item for item in corpus["cases"] if item["case_id"] == arguments.case_id), None)
    if case is None:
        raise SystemExit("case-id is not in the frozen MTM-011 corpus")
    applicability = case["metric_applicability"]
    require_applicability(
        "counterexample-probe-on-blocker",
        arguments.counterexample_probe_on_blocker,
        applicability["counterexample_probe_on_blocker"],
    )
    require_applicability(
        "focused-retrieval-when-missing-reference",
        arguments.focused_retrieval_when_missing_reference,
        applicability["focused_retrieval_when_missing_reference"],
    )
    require_applicability(
        "refuted-target-state-preserved",
        arguments.refuted_target_state_preserved,
        applicability["refuted_target_state_preserved"],
    )
    require_applicability(
        "typed-obstruction-class-preserved",
        arguments.typed_obstruction_class_preserved,
        applicability["typed_obstruction_class_preserved"],
    )
    if not applicability["canonical_partial_results_preserved"] and arguments.canonical_partial_results_preserved != 0:
        raise SystemExit("canonical-partial-results-preserved must be 0 when not applicable")
    if arguments.protocol == 2 and arguments.harmful_advice_events != 0:
        raise SystemExit("protocol 2 cannot report harmful advisory events")

    evaluation = json.loads(EVALUATION.read_text(encoding="utf-8"))
    if evaluation.get("status") == "complete":
        raise SystemExit("evaluation is already complete and immutable")
    candidate = evaluation["candidate"]
    if candidate.get("binary_sha256") is None:
        candidate["binary_sha256"] = binary_sha
    elif candidate.get("binary_sha256") != binary_sha:
        raise SystemExit("all MTM-011 treatments must use the same exact binary SHA-256")
    pair = next((item for item in evaluation["pairs"] if item["case_id"] == arguments.case_id), None)
    if pair is None:
        raise SystemExit("evaluation pair is missing")
    slot = f"protocol{arguments.protocol}"
    if pair.get(slot) is not None:
        raise SystemExit(f"{arguments.case_id} {slot} is already recorded; refusing overwrite")
    other = pair.get("protocol3" if arguments.protocol == 2 else "protocol2")
    if isinstance(other, dict) and (
        other.get("model_surface") != arguments.model_surface
        or other.get("connector_profile") != arguments.connector_profile
        or other.get("binary_sha256") != binary_sha
    ):
        raise SystemExit("paired treatment must use the same model surface, connector profile and binary")

    pair[slot] = {
        "status": "complete",
        "protocol": arguments.protocol,
        "binary_sha256": binary_sha,
        "run_fingerprint": fingerprint,
        "model_surface": arguments.model_surface,
        "connector_profile": arguments.connector_profile,
        "research_tools_policy": "normal_web_plus_mtm_workspace",
        "final_outcome": arguments.final_outcome,
        "final_tex_sha256": final_hash,
        "first_verification_pass": arguments.first_verification_pass,
        "repair_count": arguments.repair_count,
        "verifier_finding_count": arguments.verifier_finding_count,
        "repeated_failed_route_without_new_evidence": arguments.repeated_failed_route_without_new_evidence,
        "counterexample_probe_on_blocker": arguments.counterexample_probe_on_blocker,
        "focused_retrieval_when_missing_reference": arguments.focused_retrieval_when_missing_reference,
        "max_no_novelty_retrieval_streak": arguments.max_no_novelty_retrieval_streak,
        "harmful_advice_events": arguments.harmful_advice_events,
        "refuted_target_state_preserved": arguments.refuted_target_state_preserved,
        "typed_obstruction_class_preserved": arguments.typed_obstruction_class_preserved,
        "canonical_partial_results_preserved": arguments.canonical_partial_results_preserved,
        "advisory_rule_counts": advisory_counts(arguments.advisory_rule_counts, arguments.protocol),
        "transition_log_sha256": arguments.transition_log_sha256,
        "verification_report_sha256": arguments.verification_report_sha256,
        "raw_web_transcript_recorded": False,
        "private_reasoning_recorded": False,
    }
    evaluation["status"] = "in_progress"
    atomic_write(EVALUATION, evaluation)
    print(json.dumps({"ok": True, "case_id": arguments.case_id, "slot": slot}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
