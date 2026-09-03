#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.validate_mtm011_math_corpus import CORPUS, validate as validate_corpus
from scripts.validate_mtm011_math_evaluation import EVALUATION, validate as validate_evaluation
from scripts.validate_mtm011_research_resource import REPORT, validate as validate_resource


MTM009_EVALUATION = ROOT / "mtm009-research-state-math-evaluation.json"
AUTHORITY = ROOT / "authority-inventory.json"
GRAPH = ROOT / "migration-graph.json"
MTM009_IMMUTABLE_SHA = "e7596fbaed70655228bd1530376ba457153e575ea0b845c4c8e64e2848e7e564"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate() -> dict[str, object]:
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    corpus_summary = validate_corpus(corpus)
    evaluation = json.loads(EVALUATION.read_text(encoding="utf-8"))
    evaluation_summary = validate_evaluation(evaluation)
    resource = json.loads(REPORT.read_text(encoding="utf-8"))
    resource_summary = validate_resource(resource)
    authority = json.loads(AUTHORITY.read_text(encoding="utf-8"))
    protocols = authority.get("preview_policy", {})
    if protocols.get("production_default_workflow_protocol") != 2:
        raise ValueError("production default changed before MTM-011 qualification completed")
    if protocols.get("protocol3_default_cutover_allowed") is not False:
        raise ValueError("authority inventory claims cutover before qualification")
    if sha256_file(MTM009_EVALUATION) != MTM009_IMMUTABLE_SHA:
        raise ValueError("immutable MTM-009 v1 evaluation was modified")
    mtm009 = json.loads(MTM009_EVALUATION.read_text(encoding="utf-8"))
    if mtm009.get("decision") != "rejected" or mtm009.get("aggregate", {}).get("release_gate_passed") is not False:
        raise ValueError("MTM-009 v1 historical rejected decision drifted")
    if evaluation.get("status") != "complete" or evaluation.get("decision") != "accepted":
        raise ValueError("MTM-011 mathematical evaluation is not accepted")
    if evaluation_summary["release_gate_passed"] is not True:
        raise ValueError("MTM-011 deterministic mathematical gate did not pass")
    candidate_sha = evaluation.get("candidate", {}).get("binary_sha256")
    if candidate_sha != resource_summary["implementation_sha256"]:
        raise ValueError("A4/A5 candidate binary binding mismatch")
    graph = json.loads(GRAPH.read_text(encoding="utf-8"))
    milestone = next((item for item in graph.get("milestones", []) if item.get("id") == "MTM-011"), None)
    if not isinstance(milestone, dict) or milestone.get("status") not in {"in_progress", "authoritative"}:
        raise ValueError("MTM-011 milestone is not in a cutover-eligible state")
    return {
        "milestone": "MTM-011",
        "delivery_cutover_allowed": True,
        "candidate_binary_sha256": candidate_sha,
        "corpus": corpus_summary,
        "resource": resource_summary,
        "evaluation": evaluation_summary,
        "production_default_before_cutover": 2,
        "target_default_after_cutover": 3,
        "rollback_default": 2,
        "mtm009_v1_immutable_sha256": MTM009_IMMUTABLE_SHA,
    }


def main() -> int:
    try:
        summary = validate()
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(json.dumps({"ok": False, "error": str(error), "cutover_allowed": False}, indent=2))
        return 1
    print(json.dumps({"ok": True, "summary": summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
