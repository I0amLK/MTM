#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.validate_mtm011_math_evaluation import CORPUS, EVALUATION, aggregate_complete, validate


def atomic_write(path: Path, payload: dict[str, object]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Finalize one complete MTM-011 evaluation ledger.")
    parser.add_argument("--evaluation", type=Path, default=EVALUATION)
    arguments = parser.parse_args()
    evaluation = json.loads(arguments.evaluation.read_text(encoding="utf-8"))
    if evaluation.get("status") == "complete":
        raise SystemExit("evaluation is already complete and immutable")
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    cases = {case["case_id"]: case for case in corpus["cases"]}
    pairs = evaluation["pairs"]
    for pair in pairs:
        if pair.get("protocol2") is None or pair.get("protocol3") is None or pair.get("blind_evaluation") is None:
            raise SystemExit(f"{pair['case_id']} is incomplete")
    if evaluation.get("resource_evidence", {}).get("sha256") is None:
        raise SystemExit("current-candidate A5 resource evidence is not bound")
    aggregate, gate = aggregate_complete(pairs, cases)
    evaluation["aggregate"] = aggregate
    evaluation["decision"] = "accepted" if gate else "rejected"
    evaluation["status"] = "complete"
    atomic_write(arguments.evaluation, evaluation)
    summary = validate(
        json.loads(arguments.evaluation.read_text(encoding="utf-8")),
        evaluation_path=arguments.evaluation,
    )
    print(json.dumps({"ok": True, "summary": summary, "decision": evaluation["decision"]}, indent=2))
    return 0 if gate else 1


if __name__ == "__main__":
    raise SystemExit(main())
