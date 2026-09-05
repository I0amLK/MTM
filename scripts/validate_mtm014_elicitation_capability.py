#!/usr/bin/env python3
"""Validate the redacted MTM-014 D5A human MRTR acceptance receipt."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "records/evidence/MTM-014/elicitation-capability.json"


def _exact(value: Any, expected: Any, message: str) -> None:
    if type(value) is not type(expected) or value != expected:
        raise ValueError(message)


def validate(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("elicitation evidence must be an object")
    required = {
        "schema_version", "milestone", "phase", "accepted_scope", "recorded_at",
        "source_commit", "candidate_binary_sha256", "candidate_version", "client",
        "independent_human_action_observed", "client_owned_form_observed",
        "model_supplied_input_responses", "form", "observations",
        "supporting_automated_evidence", "trust_limitations", "evidence_hygiene",
        "production_exec_or_patch_authority_cutover", "d5a_accepted",
        "d5_authority_cutover_allowed",
    }
    if set(payload) != required:
        raise ValueError("elicitation evidence has missing or unexpected fields")
    for key, expected in {
        "schema_version": "1.0.0",
        "milestone": "MTM-014",
        "phase": "verified_human_mrtr_consent",
        "accepted_scope": "D5A_only",
        "candidate_version": "0.4.0",
        "independent_human_action_observed": True,
        "client_owned_form_observed": True,
        "model_supplied_input_responses": False,
        "production_exec_or_patch_authority_cutover": False,
        "d5a_accepted": True,
        "d5_authority_cutover_allowed": False,
    }.items():
        _exact(payload[key], expected, f"elicitation evidence scope is invalid: {key}")
    if not isinstance(payload["recorded_at"], str) or not payload["recorded_at"]:
        raise ValueError("elicitation evidence timestamp is missing")
    if re.fullmatch(r"[0-9a-f]{40}", str(payload["source_commit"])) is None:
        raise ValueError("elicitation evidence source commit is invalid")
    if re.fullmatch(r"[0-9a-f]{64}", str(payload["candidate_binary_sha256"])) is None:
        raise ValueError("elicitation evidence binary digest is invalid")

    client = payload["client"]
    if not isinstance(client, dict) or set(client) != {
        "name", "version", "protocol_era", "protocol_version", "transport"
    }:
        raise ValueError("elicitation evidence client identity is incomplete")
    for key, expected in {
        "name": "MCP Inspector",
        "version": "2.5.0",
        "protocol_era": "modern",
        "protocol_version": "2026-07-28",
        "transport": "streamable_http_over_cloudflare_quick_tunnel",
    }.items():
        _exact(client[key], expected, f"elicitation evidence client field is invalid: {key}")

    form = payload["form"]
    if not isinstance(form, dict) or set(form) != {
        "method", "mode", "fields", "displayed_context", "argument_fingerprint",
        "raw_arguments_displayed", "edit_as_json_used",
    }:
        raise ValueError("elicitation evidence form description is incomplete")
    _exact(form["method"], "elicitation/create", "elicitation method drifted")
    _exact(form["mode"], "form", "elicitation mode drifted")
    _exact(form["fields"], ["approved"], "elicitation form fields drifted")
    expected_context = {
        "permission", "tool_name", "workspace_label", "scope", "ttl_seconds",
        "reason", "argument_fingerprint",
    }
    if not isinstance(form["displayed_context"], list) or set(form["displayed_context"]) != expected_context:
        raise ValueError("elicitation context is incomplete")
    if re.fullmatch(r"[0-9a-f]{12}", str(form["argument_fingerprint"])) is None:
        raise ValueError("elicitation argument fingerprint is invalid")
    _exact(form["raw_arguments_displayed"], False, "raw arguments were displayed")
    _exact(form["edit_as_json_used"], False, "manual JSON response bypass was used")

    observations = payload["observations"]
    if not isinstance(observations, dict) or set(observations) != {"accept", "decline", "cancel"}:
        raise ValueError("elicitation human observations are incomplete")
    accept = observations["accept"]
    decline = observations["decline"]
    cancel = observations["cancel"]
    if not isinstance(accept, dict) or set(accept) != {
        "human_action", "status", "source", "scope", "workflow_authority_inherited"
    }:
        raise ValueError("accept observation is malformed")
    for key, expected in {
        "human_action": "checked_approved_and_submitted",
        "status": "granted",
        "source": "verified_mcp_mrtr_form_elicitation",
        "scope": "once",
        "workflow_authority_inherited": False,
    }.items():
        _exact(accept[key], expected, f"accept observation is invalid: {key}")
    for name, observation, action in (
        ("decline", decline, "decline"), ("cancel", cancel, "cancel")
    ):
        if not isinstance(observation, dict) or set(observation) != {
            "human_action", "status", "error_code", "grant_minted"
        }:
            raise ValueError(f"{name} observation is malformed")
        for key, expected in {
            "human_action": action,
            "status": "denied",
            "error_code": "ELICITATION_DENIED",
            "grant_minted": False,
        }.items():
            _exact(observation[key], expected, f"{name} observation is invalid: {key}")

    automated = payload["supporting_automated_evidence"]
    if not isinstance(automated, dict) or set(automated) != {
        "mrtr_bridge_check_count", "capacity_check_count", "replay_denied",
        "argument_mutation_denied", "cross_owner_denied",
    }:
        raise ValueError("supporting automated evidence is incomplete")
    _exact(automated["mrtr_bridge_check_count"], 22, "MRTR check count drifted")
    _exact(automated["capacity_check_count"], 13, "capacity check count drifted")
    for key in ("replay_denied", "argument_mutation_denied", "cross_owner_denied"):
        _exact(automated[key], True, f"supporting check failed: {key}")

    limitations = payload["trust_limitations"]
    if not isinstance(limitations, dict) or not limitations or any(value is not True for value in limitations.values()):
        raise ValueError("elicitation trust limitations must remain explicit")
    hygiene = payload["evidence_hygiene"]
    if not isinstance(hygiene, dict) or not hygiene or any(value is not False for value in hygiene.values()):
        raise ValueError("elicitation evidence contains or claims raw authority material")
    return {
        "scope": "D5A_only",
        "human_ui_observed": True,
        "production_cutover_allowed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=REPORT)
    args = parser.parse_args()
    try:
        summary = validate(json.loads(args.report.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        print(json.dumps({"ok": False, "error": "elicitation evidence missing or invalid"}))
        return 1
    print(json.dumps({"ok": True, "summary": summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
