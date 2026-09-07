#!/usr/bin/env python3
"""Attribute MTM-015 unpaired submitted capability fingerprints across web sessions.

The report is intentionally aggregate-only: it never prints a capability, token
fingerprint, OAuth credential, operator password, public URL, or raw log line.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


DIAGNOSTIC_RE = re.compile(
    r"\[capability:(issued|submitted)\] trace=[A-Za-z0-9_.:-]* "
    r"token_sha256=([0-9a-f]{64}) bytes=\d+ signer=[0-9a-f]{64} "
    r"instance=[0-9a-f]{32} stage=([A-Za-z0-9_.:-]+)"
)
INVALID_STAGES = {
    "token_shape",
    "signature_encoding",
    "signature_mismatch",
    "payload_encoding",
    "payload_json",
    "payload_version",
    "claims_invalid",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("session_descriptor", type=Path)
    return parser.parse_args()


def load_descriptor(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("milestone") != "MTM-015":
        raise ValueError("descriptor is not an MTM-015 web-client session")
    return value


def diagnostics(log_path: Path) -> tuple[set[str], set[str], dict[str, int]]:
    text = log_path.read_text(encoding="utf-8", errors="replace")
    issued: set[str] = set()
    submitted: set[str] = set()
    invalid_stages: dict[str, int] = {}
    for kind, fingerprint, stage in DIAGNOSTIC_RE.findall(text):
        if kind == "issued":
            issued.add(fingerprint)
        else:
            submitted.add(fingerprint)
        if stage in INVALID_STAGES:
            invalid_stages[stage] = invalid_stages.get(stage, 0) + 1
    return issued, submitted, invalid_stages


def main() -> int:
    args = parse_args()
    current_path = args.session_descriptor.resolve()
    current = load_descriptor(current_path)
    current_log = Path(str(current["operator_log"]))
    issued, submitted, invalid_stages = diagnostics(current_log)
    unpaired = submitted - issued

    sessions_root = current_path.parent.parent
    matches: list[dict[str, Any]] = []
    for descriptor_path in sorted(sessions_root.glob("*/session.json")):
        if descriptor_path.resolve() == current_path:
            continue
        try:
            descriptor = load_descriptor(descriptor_path)
            prior_issued, _, _ = diagnostics(Path(str(descriptor["operator_log"])))
        except (OSError, KeyError, ValueError, json.JSONDecodeError):
            continue
        overlap = unpaired & prior_issued
        if overlap:
            matches.append(
                {
                    "session_id": descriptor.get("session_id"),
                    "candidate_binary_sha256": descriptor.get("candidate_binary_sha256"),
                    "matched_unpaired_count": len(overlap),
                }
            )

    matched_count = sum(int(item["matched_unpaired_count"]) for item in matches)
    result = {
        "ok": True,
        "current_session_id": current.get("session_id"),
        "current_candidate_binary_sha256": current.get("candidate_binary_sha256"),
        "issued_count": len(issued),
        "submitted_count": len(submitted),
        "paired_count": len(issued & submitted),
        "unpaired_submitted_count": len(unpaired),
        "invalid_stages": invalid_stages,
        "matched_previous_session_count": matched_count,
        "unmatched_unpaired_count": max(0, len(unpaired) - matched_count),
        "matches": matches,
        "raw_fingerprints_recorded": False,
        "raw_capabilities_recorded": False,
        "raw_oauth_tokens_recorded": False,
        "raw_logs_recorded": False,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
