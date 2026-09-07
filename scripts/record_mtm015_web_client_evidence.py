#!/usr/bin/env python3
"""Record bounded MTM-015 web-client evidence after explicit user confirmation."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from validate_mtm015_candidate_stage import validate as validate_stage


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "records/evidence/MTM-015/web-client.json"
DIAGNOSTIC_RE = re.compile(
    r"\[capability:(issued|submitted)\] trace=[A-Za-z0-9_.:-]* "
    r"token_sha256=([0-9a-f]{64}) bytes=\d+ signer=[0-9a-f]{64} "
    r"instance=[0-9a-f]{32} stage=([A-Za-z0-9_.:-]+)"
)
RAW_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{80,}\.[A-Za-z0-9_-]{40,}")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("session_descriptor", type=Path)
    parser.add_argument("--confirmed-web-client", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.confirmed_web_client:
        print(json.dumps({"ok": False, "error": "explicit web-client confirmation is required"}))
        return 2
    stage = validate_stage()
    descriptor = json.loads(args.session_descriptor.read_text(encoding="utf-8"))
    if descriptor.get("milestone") != "MTM-015":
        raise ValueError("session descriptor belongs to another milestone")
    if descriptor.get("candidate_binary_sha256") != stage["candidate_binary_sha256"]:
        raise ValueError("session candidate does not match the accepted staged candidate")
    if descriptor.get("metadata_issuer_validated") is not True:
        raise ValueError("session did not validate public OAuth metadata")
    log_path = Path(descriptor["operator_log"])
    password_file = Path(descriptor["operator_password_file"])
    log_text = log_path.read_text(encoding="utf-8", errors="replace")
    password = password_file.read_text(encoding="utf-8").strip()
    if password and password in log_text:
        raise ValueError("operator password appeared in the diagnostic log")
    if "Bearer " in log_text or RAW_TOKEN_RE.search(log_text):
        raise ValueError("raw credential-shaped material appeared in the diagnostic log")
    issued: set[str] = set()
    submitted: set[str] = set()
    invalid = 0
    for kind, fingerprint, stage_name in DIAGNOSTIC_RE.findall(log_text):
        if kind == "issued":
            issued.add(fingerprint)
        else:
            submitted.add(fingerprint)
        if stage_name in {
            "token_shape", "signature_encoding", "signature_mismatch", "payload_encoding",
            "payload_json", "payload_version", "claims_invalid",
        }:
            invalid += 1
    paired = issued & submitted
    unpaired_submitted = submitted - issued
    invalid_stages = Counter(
        stage_name
        for kind, _fingerprint, stage_name in DIAGNOSTIC_RE.findall(log_text)
        if kind == "submitted"
        and stage_name in {
            "token_shape", "signature_encoding", "signature_mismatch", "payload_encoding",
            "payload_json", "payload_version", "claims_invalid",
        }
    )
    rejected_lines = sum(
        1 for line in log_text.splitlines()
        if "submission rejected:" in line or "CAPABILITY_INVALID" in line
    )
    if len(paired) < 5:
        raise ValueError(
            "fewer than five issued/submitted capability fingerprints were paired "
            f"(paired={len(paired)}, unpaired_submitted={len(unpaired_submitted)})"
        )
    if invalid != 0 or rejected_lines != 0:
        raise ValueError(
            "normal web-client session contained capability rejection evidence "
            f"(paired={len(paired)}, unpaired_submitted={len(unpaired_submitted)}, "
            f"invalid_diagnostic_count={invalid}, invalid_stages={dict(sorted(invalid_stages.items()))}, "
            f"submission_rejection_count={rejected_lines})"
        )
    payload = {
        "schema_version": "1.0.0",
        "milestone": "MTM-015",
        "phase": "web_client",
        "ok": True,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "candidate_binary_sha256": stage["candidate_binary_sha256"],
        "candidate_stage_sha256": stage["report_sha256"],
        "session_id": descriptor["session_id"],
        "session_descriptor_sha256": digest(args.session_descriptor),
        "public_tunnel_observed": True,
        "public_metadata_issuer_validated": True,
        "explicit_user_confirmation": True,
        "confirmation_source": "conversation_user_confirmation",
        "issued_fingerprint_count": len(issued),
        "submitted_fingerprint_count": len(submitted),
        "paired_fingerprint_count": len(paired),
        "invalid_diagnostic_count": invalid,
        "submission_rejection_count": rejected_lines,
        "operator_log_sha256": digest(log_path),
        "transport": "quick_tunnel_oauth_mcp",
        "harness_sha256": {
            path: digest(ROOT / path)
            for path in (
                "scripts/launch_mtm015_web_candidate.py",
                "scripts/record_mtm015_web_client_evidence.py",
                "scripts/validate_mtm015_web_client.py",
            )
        },
        "web_client_tested": True,
        "selector_changed": False,
        "production_state_rewritten": False,
        "evidence_hygiene": {
            "fingerprint_values_recorded": False,
            "raw_capability_recorded": False,
            "raw_oauth_token_recorded": False,
            "raw_secret_recorded": False,
            "raw_logs_recorded": False,
            "operator_password_path_recorded": False,
            "public_url_recorded": False,
        },
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    temporary = REPORT.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    temporary.replace(REPORT)
    print(json.dumps({
        "ok": True,
        "report": str(REPORT),
        "paired_fingerprint_count": len(paired),
        "invalid_diagnostic_count": invalid,
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
