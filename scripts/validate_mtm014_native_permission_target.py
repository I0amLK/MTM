#!/usr/bin/env python3
"""Validate the hash-bound MTM-014 pre-cutover Native permission A4 report."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "records/evidence/MTM-014/native-permission-target.json"
HUMAN = ROOT / "records/evidence/MTM-014/elicitation-capability.json"
RUNNER = ROOT / "scripts/run_mtm014_native_permission_target.py"
CHECKS = {
    "human_receipt_validated",
    "candidate_binary_exact",
    "candidate_version",
    "production_source_compatible",
    "stable_cargo_command_unchanged",
    "stable_selector_unchanged",
    "required_tools_available",
    "safe_attestation",
    "trusted_attestation",
    "dangerous_attestation",
    "candidate_authority_tests",
    "real_dns_https",
    "prepared_patch_adversarial",
    "grant_ledger_adversarial",
    "command_lifecycle",
    "safe_network_plan_dimension",
    "bubblewrap_profile_invariants",
    "mrtr_candidate_22_checks",
    "capacity_candidate_13_checks",
    "magma_host_probe_classified",
    "workflow_authority_not_inherited",
    "public_cutover_not_performed",
}
ATTESTATION_FIELDS = {
    "hard_isolation",
    "workspace_mounted",
    "forbidden_paths_hidden",
    "private_vault_mounted",
    "capabilities_dropped",
    "no_privilege_escalation",
    "parent_environment_cleared",
    "nested_user_namespaces_disabled",
    "toolchain_roots_validated",
    "network_isolated",
}
TOOLS = {"bwrap", "curl", "git", "pdflatex", "latexmk", "sage", "magma"}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require_bool(value: Any, expected: bool, message: str) -> None:
    if value is not expected:
        raise ValueError(message)


def validate(
    payload: Any,
    *,
    human_payload: dict[str, Any] | None = None,
    human_sha256: str | None = None,
    runner_sha256: str | None = None,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("target evidence must be an object")
    required = {
        "schema_version",
        "milestone",
        "phase",
        "ok",
        "qualification_commit",
        "candidate_source_commit",
        "candidate_binary_sha256",
        "human_evidence_sha256",
        "runner_sha256",
        "check_count",
        "checks",
        "source_compatibility",
        "required_tools",
        "attestations",
        "mrtr_check_count",
        "capacity_check_count",
        "magma",
        "human_client",
        "pre_cutover_target_corpus_passed",
        "production_exec_or_patch_authority_cutover",
        "production_cutover_allowed_by_this_report",
        "stable_selector_changed",
        "workflow_authority_inherited",
        "evidence_hygiene",
    }
    if set(payload) != required:
        raise ValueError("target evidence has missing or unexpected fields")
    if payload["schema_version"] != "1.0.0" or payload["milestone"] != "MTM-014":
        raise ValueError("target evidence identity is invalid")
    if payload["phase"] != "pre_cutover_native_permission_target":
        raise ValueError("target evidence phase is invalid")
    require_bool(payload["ok"], True, "target evidence did not pass")
    require_bool(
        payload["pre_cutover_target_corpus_passed"], True, "target corpus is not accepted"
    )
    require_bool(
        payload["production_exec_or_patch_authority_cutover"],
        False,
        "target evidence cannot perform production cutover",
    )
    require_bool(
        payload["production_cutover_allowed_by_this_report"],
        False,
        "target report must not authorize its own cutover",
    )
    require_bool(payload["stable_selector_changed"], False, "stable selector changed")
    require_bool(payload["workflow_authority_inherited"], False, "workflow authority leaked")

    for key in ("qualification_commit", "candidate_source_commit"):
        if re.fullmatch(r"[0-9a-f]{40}", str(payload[key])) is None:
            raise ValueError(f"target evidence commit digest is invalid: {key}")
    for key in ("candidate_binary_sha256", "human_evidence_sha256", "runner_sha256"):
        if re.fullmatch(r"[0-9a-f]{64}", str(payload[key])) is None:
            raise ValueError(f"target evidence SHA-256 is invalid: {key}")

    human = (
        json.loads(HUMAN.read_text(encoding="utf-8"))
        if human_payload is None
        else human_payload
    )
    expected_human_sha256 = sha256_file(HUMAN) if human_sha256 is None else human_sha256
    expected_runner_sha256 = sha256_file(RUNNER) if runner_sha256 is None else runner_sha256
    if not isinstance(human, dict):
        raise ValueError("target human evidence payload is invalid")
    for digest, label in (
        (expected_human_sha256, "human evidence"),
        (expected_runner_sha256, "runner"),
    ):
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError(f"target injected {label} digest is invalid")
    if payload["candidate_source_commit"] != human.get("source_commit"):
        raise ValueError("target candidate source does not match D5A human evidence")
    if payload["candidate_binary_sha256"] != human.get("candidate_binary_sha256"):
        raise ValueError("target candidate binary does not match D5A human evidence")
    if payload["human_evidence_sha256"] != expected_human_sha256:
        raise ValueError("target human evidence binding is stale")
    if payload["runner_sha256"] != expected_runner_sha256:
        raise ValueError("target runner binding is stale")

    checks = payload["checks"]
    if not isinstance(checks, dict) or set(checks) != CHECKS:
        raise ValueError("target check set is incomplete")
    if any(value is not True for value in checks.values()):
        raise ValueError("target check set contains a failure")
    if type(payload["check_count"]) is not int or payload["check_count"] != len(CHECKS):
        raise ValueError("target check count is invalid")
    if payload["mrtr_check_count"] != 22 or payload["capacity_check_count"] != 13:
        raise ValueError("target integration check counts drifted")

    source = payload["source_compatibility"]
    if not isinstance(source, dict) or set(source) != {
        "candidate_is_ancestor",
        "changed_crate_files",
        "native_authority_production_prefix_equal",
        "packaging_inputs_equal",
    }:
        raise ValueError("target source compatibility evidence is incomplete")
    require_bool(source["candidate_is_ancestor"], True, "candidate source is not an ancestor")
    if source["changed_crate_files"] != ["crates/mtm-runtime/src/native_authority.rs"]:
        raise ValueError("unexpected production crate drift")
    require_bool(
        source["native_authority_production_prefix_equal"],
        True,
        "candidate production prefix drifted",
    )
    require_bool(source["packaging_inputs_equal"], True, "candidate packaging inputs drifted")

    tools = payload["required_tools"]
    if not isinstance(tools, dict) or set(tools) != TOOLS or any(value is not True for value in tools.values()):
        raise ValueError("target required-tool evidence is incomplete")

    attestations = payload["attestations"]
    if not isinstance(attestations, dict) or set(attestations) != {"safe", "trusted", "dangerous"}:
        raise ValueError("target attestation modes are incomplete")
    for mode, attestation in attestations.items():
        if not isinstance(attestation, dict) or set(attestation) != ATTESTATION_FIELDS:
            raise ValueError(f"target attestation fields are incomplete: {mode}")
        for key in ATTESTATION_FIELDS - {"private_vault_mounted", "network_isolated"}:
            require_bool(attestation[key], True, f"target attestation failed: {mode}.{key}")
        require_bool(attestation["private_vault_mounted"], False, "private vault became visible")
        require_bool(
            attestation["network_isolated"], mode == "safe", f"network profile drifted: {mode}"
        )

    magma = payload["magma"]
    if not isinstance(magma, dict) or set(magma) != {
        "executable_available",
        "candidate_reached",
        "host_status",
        "failure_attributed_to_mtm",
    }:
        raise ValueError("target Magma evidence is incomplete")
    require_bool(magma["executable_available"], True, "Magma executable is unavailable")
    require_bool(magma["candidate_reached"], True, "candidate did not reach Magma")
    if magma["host_status"] not in {"passed", "blocked_host_license"}:
        raise ValueError("Magma host status is not classified")
    require_bool(magma["failure_attributed_to_mtm"], False, "Magma failure was attributed to MTM")

    client = payload["human_client"]
    if not isinstance(client, dict) or client != {
        "name": "MCP Inspector",
        "version": "2.5.0",
        "protocol_version": "2026-07-28",
        "transport": "streamable_http_over_cloudflare_quick_tunnel",
    }:
        raise ValueError("target human-client binding drifted")
    hygiene = payload["evidence_hygiene"]
    if not isinstance(hygiene, dict) or not hygiene or any(value is not False for value in hygiene.values()):
        raise ValueError("target evidence contains raw authority material")
    return {
        "scope": "A4_pre_cutover",
        "target_corpus_passed": True,
        "production_cutover_allowed": False,
        "magma_host_status": magma["host_status"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=REPORT)
    args = parser.parse_args()
    try:
        payload = json.loads(args.report.read_text(encoding="utf-8"))
        summary = validate(payload)
    except (OSError, ValueError, json.JSONDecodeError):
        print(json.dumps({"ok": False, "error": "target evidence missing or invalid"}))
        return 1
    print(json.dumps({"ok": True, "summary": summary}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
