#!/usr/bin/env python3
"""Validate immutable MTM-014 preview evidence and, separately, deployed entries."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from datetime import datetime
from typing import Any

import mtm014_release_support as s


def exact(value: Any, expected: Any) -> None:
    s.require(type(value) is type(expected) and value == expected, "receipt_scope")
    if isinstance(expected, dict):
        for key in expected:
            exact(value[key], expected[key])
    elif isinstance(expected, list):
        for actual, wanted in zip(value, expected, strict=True):
            exact(actual, wanted)


def number(value: Any) -> None:
    s.require(type(value) in (int, float) and 0 <= value <= 2**63
              and math.isfinite(value), "receipt_number")


def timestamp(value: Any) -> None:
    s.require(isinstance(value, str) and len(value) <= 40, "receipt_timestamp")
    s.require(datetime.fromisoformat(value).tzinfo is not None, "receipt_timestamp_timezone")


def frame(value: Any) -> None:
    s.require(isinstance(value, dict) and set(value) == {"rss_kib", "threads", "fds", "children"},
              "resource_frame")
    for item in value.values():
        number(item)


def validate_soak(value: Any) -> None:
    s.require(isinstance(value, dict) and set(value) == {
        "duration_seconds", "iterations", "before", "peak", "after", "shutdown_ms"}, "soak_fields")
    for key in ("duration_seconds", "iterations", "shutdown_ms"):
        number(value[key])
    for key in ("before", "peak", "after"):
        frame(value[key])
    s.require(s.soak_ok(value), "soak_bounds")


def validate_resources(value: Any) -> None:
    s.require(isinstance(value, dict) and set(value) == {"stable", "preview"}, "resource_fields")
    keys = {"startup_samples", "request_samples", "startup_p50_ms", "startup_p95_ms",
            "request_p95_ms", "max_rss_kib", "max_threads", "max_fds", "max_shutdown_ms"}
    for data in value.values():
        s.require(isinstance(data, dict) and set(data) == keys, "resource_metrics")
        for item in data.values():
            number(item)
    s.require(s.resource_ok(value["stable"], value["preview"]), "resource_bounds")


def validate_qualification(payload: Any, *, binding_verified: bool | None = None) -> dict[str, Any]:
    required = {"schema_version", "milestone", "phase", "version", "ok", "recorded_at",
                "source_commit", "binary_sha256", "stable_sha256", "implementation_commit",
                "harness_sha256", "prerequisite_sha256", "checks", "check_count", "public_suites", "runtime_repair_sha256",
                "proof_facts", "tui_checks", "required_tools", "magma_host_status", "resource", "soak",
                "new_human_consent_claimed", "performance_claim", "production_state_rewritten",
                "selector_changed", "evidence_hygiene"}
    s.require(isinstance(payload, dict) and set(payload) == required, "qualification_fields")
    for key, value in {
        "schema_version": "1.0.0", "milestone": "MTM-014", "phase": "preview_qualification",
        "version": s.VERSION, "ok": True, "stable_sha256": s.STABLE_SHA,
        "implementation_commit": s.IMPLEMENTATION, "new_human_consent_claimed": False,
        "runtime_repair_sha256": {s.RUNTIME_REPAIR_FILE: s.RUNTIME_REPAIR_SHA},
        "performance_claim": False, "production_state_rewritten": False, "selector_changed": False,
        "evidence_hygiene": s.HYGIENE,
    }.items():
        exact(payload[key], value)
    for key, length in (("source_commit", 40), ("binary_sha256", 64)):
        s.require(isinstance(payload[key], str) and re.fullmatch(f"[0-9a-f]{{{length}}}", payload[key]) is not None,
                  "identity_digest")
    timestamp(payload["recorded_at"])
    exact(payload["checks"], dict.fromkeys(s.QUALIFICATION_CHECKS, True))
    s.require(all(value is True for value in payload["checks"].values()), "check_boolean")
    exact(payload["check_count"], len(s.QUALIFICATION_CHECKS))
    s.require(set(payload["harness_sha256"]) == set(s.HARNESS_FILES), "harness_set")
    s.require(set(payload["prerequisite_sha256"]) == set(s.PREREQUISITES), "prerequisite_set")
    exact(payload["required_tools"], dict.fromkeys(("bwrap", "curl", "git", "latexmk", "pdflatex", "sage", "magma"), True))
    s.require(all(v is True for v in payload["required_tools"].values()), "tool_boolean")
    s.require(payload["magma_host_status"] in {"passed", "blocked_host_license"}, "magma_status")
    suites = payload["public_suites"]
    s.require(isinstance(suites, dict) and set(suites) == {"safe", "trusted", "dangerous"}, "public_suites")
    for key, names in s.PUBLIC_SUITE_CHECKS.items():
        exact(suites[key], dict.fromkeys(names, True))
    exact(payload["tui_checks"], dict.fromkeys(s.TUI_CHECKS, True))
    proof_facts = payload["proof_facts"]
    s.require(isinstance(proof_facts, dict) and set(proof_facts) == {"qc", "compact"}, "proof_cases")
    for case in proof_facts.values():
        s.require(isinstance(case, dict) and set(case) == {
            "state", "verdict", "latex_passed", "sealed", "artifact_sha256", "artifact_bytes"}, "proof_fields")
        exact(case["state"], "done")
        exact(case["verdict"], "correct")
        exact(case["latex_passed"], True)
        exact(case["sealed"], True)
        s.require(isinstance(case["artifact_sha256"], str)
                  and re.fullmatch("[0-9a-f]{64}", case["artifact_sha256"]) is not None, "artifact_digest")
        s.require(type(case["artifact_bytes"]) is int and case["artifact_bytes"] > 0, "artifact_size")
    validate_resources(payload["resource"])
    validate_soak(payload["soak"])
    if binding_verified is None:
        commit = payload["source_commit"]
        s.git("merge-base", "--is-ancestor", commit, "HEAD")
        s.require(s.source_scope_verified(commit), "source_binding")
        for path, value in payload["harness_sha256"].items():
            exact(hashlib.sha256(s.git("show", f"{commit}:{path}")).hexdigest(), value)
        for path, value in payload["prerequisite_sha256"].items():
            exact(s.digest(s.ROOT / path), value)
    else:
        exact(binding_verified, True)
    return {"version": s.VERSION, "checks": len(s.QUALIFICATION_CHECKS),
            "binary_sha256": payload["binary_sha256"], "selector_changed": False}


def validate_release(payload: Any, qualification: dict[str, Any], *, deployed: bool = False,
                     binding_verified: bool | None = None) -> dict[str, Any]:
    validate_qualification(qualification, binding_verified=binding_verified)
    required = {"schema_version", "milestone", "phase", "version", "ok", "recorded_at",
                "source_commit", "binary_sha256", "stable_sha256", "qualification_sha256",
                "checks", "check_count", "post_recutover_soak", "existing_sessions_restarted",
                "production_state_rewritten", "performance_claim", "evidence_hygiene"}
    s.require(isinstance(payload, dict) and set(payload) == required, "release_fields")
    for key, expected in {
        "schema_version": "1.0.0", "milestone": "MTM-014", "phase": "preview_release",
        "version": s.VERSION, "ok": True, "source_commit": qualification["source_commit"],
        "binary_sha256": qualification["binary_sha256"], "stable_sha256": s.STABLE_SHA,
        "existing_sessions_restarted": False, "production_state_rewritten": False,
        "performance_claim": False, "evidence_hygiene": s.HYGIENE,
    }.items():
        exact(payload[key], expected)
    exact(payload["checks"], dict.fromkeys(s.RELEASE_CHECKS, True))
    s.require(all(v is True for v in payload["checks"].values()), "release_check_boolean")
    exact(payload["check_count"], len(s.RELEASE_CHECKS))
    timestamp(payload["recorded_at"])
    s.require(isinstance(payload["qualification_sha256"], str)
              and re.fullmatch("[0-9a-f]{64}", payload["qualification_sha256"]) is not None,
              "qualification_digest")
    validate_soak(payload["post_recutover_soak"])
    if binding_verified is None:
        exact(payload["qualification_sha256"], s.digest(s.QUALIFICATION))
    if deployed:
        exact(s.digest(s.INSTALLED), payload["binary_sha256"])
        exact(s.digest(s.STABLE), s.STABLE_SHA)
        s.require(s.SELECTOR.is_symlink() and s.SELECTOR.resolve() in (s.INSTALLED, s.STABLE), "preview_selector")
        active_preview = s.SELECTOR.resolve() == s.INSTALLED
        exact(s.digest(s.CARGO_ENTRY), payload["binary_sha256"] if active_preview else s.STABLE_SHA)
        deployment = json.loads((s.STATE_ROOT / "deployment/deployment-v1.json").read_text())
        exact(deployment["release"]["sha256"], payload["binary_sha256"])
        exact(deployment["state"], "rust_active" if active_preview else "previous_active")
        actions = {item["action"] for item in deployment["history"]}
        s.require({"mtm014_preview_cutover", "mtm014_stable_rollback", "mtm014_preview_recutover"} <= actions,
                  "rollout_history")
    return {"version": s.VERSION, "binary_sha256": payload["binary_sha256"],
            "qualified_public_authority": True, "rollback_recutover_passed": True,
            "deployment_checked": deployed}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployed", action="store_true")
    args = parser.parse_args()
    try:
        qualification = json.loads(s.QUALIFICATION.read_text())
        summary = (validate_release(json.loads(s.RELEASE.read_text()), qualification, deployed=True)
                   if args.deployed else validate_qualification(qualification))
        print(json.dumps({"ok": True, "summary": summary}, indent=2))
        return 0
    except Exception:
        print(json.dumps({"ok": False, "error": "preview evidence or deployment invalid"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
