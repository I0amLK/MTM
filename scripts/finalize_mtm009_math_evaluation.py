#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.validate_mtm009_math_evaluation import (
    EVALUATION,
    aggregate_complete,
    validate,
    validate_blind,
    validate_run,
)


def atomic_write(path: Path, payload: dict[str, object]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Freeze aggregate metrics and accepted/rejected decision after all MTM-009 web pairs are complete."
    )
    parser.add_argument("--evaluation", type=Path, default=EVALUATION)
    arguments = parser.parse_args()
    payload = json.loads(arguments.evaluation.read_text(encoding="utf-8"))
    if payload.get("status") == "complete":
        raise SystemExit("evaluation is already complete and immutable")
    normalized: list[dict[str, object]] = []
    for pair in payload.get("pairs", []):
        if not isinstance(pair, dict):
            raise SystemExit("evaluation contains an invalid pair")
        case_id = str(pair.get("case_id") or "")
        p2 = validate_run(pair.get("protocol2"), protocol=2, case_id=case_id)
        p3 = validate_run(pair.get("protocol3"), protocol=3, case_id=case_id)
        blind = validate_blind(pair.get("blind_evaluation"), case_id=case_id)
        if p2 is None or p3 is None or blind is None:
            raise SystemExit(f"{case_id} is incomplete; refusing to aggregate partial evidence")
        if p2["model_surface"] != p3["model_surface"] or p2["connector_profile"] != p3["connector_profile"]:
            raise SystemExit(f"{case_id} pair surface/connector mismatch")
        normalized.append({"protocol2": p2, "protocol3": p3})
    if len(normalized) != 8:
        raise SystemExit("all eight frozen pairs are required")
    aggregate, gate = aggregate_complete(normalized)
    payload["status"] = "complete"
    payload["aggregate"] = aggregate
    payload["decision"] = "accepted" if gate else "rejected"
    # Validate the complete form before committing it to disk. validate() reads hashes
    # from the frozen corpus/resource evidence but otherwise uses this payload only.
    original = arguments.evaluation.read_bytes()
    atomic_write(arguments.evaluation, payload)
    try:
        summary = validate(payload)
    except Exception:
        arguments.evaluation.write_bytes(original)
        raise
    print(json.dumps({"ok": True, "summary": summary, "decision": payload["decision"]}, indent=2))
    return 0 if gate else 1


if __name__ == "__main__":
    raise SystemExit(main())
