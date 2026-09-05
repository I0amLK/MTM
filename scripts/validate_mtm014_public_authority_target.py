#!/usr/bin/env python3
"""Validate MTM-014 post-cutover public OAuth/MCP Native authority A4 evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "records/evidence/MTM-014/public-authority-target.json"
RUNNER = ROOT / "scripts/run_mtm014_public_authority_target.py"
D5A = ROOT / "records/evidence/MTM-014/elicitation-capability.json"
PRE_TARGET = ROOT / "records/evidence/MTM-014/native-permission-target.json"
IMPLEMENTATION_COMMIT = "2f11750c07317d879f1bedfd2198c36786b8ca74"
CHECKS = {
    "exact_committed_source",
    "candidate_build",
    "stable_selectors_unchanged",
    "required_tools_available",
    "public_tool_contract",
    "safe_all_seven_exec_permissions",
    "safe_once_replay",
    "safe_argument_mutation",
    "safe_cross_owner",
    "safe_multi_risk_atomicity",
    "safe_concurrent_one_winner",
    "safe_real_dns_https",
    "safe_tty_stdin_kill",
    "safe_descendant_cleanup",
    "safe_patch_authority",
    "safe_patch_symlink_escape",
    "safe_session_restart",
    "trusted_implicit_profile",
    "trusted_explicit_boundaries",
    "trusted_generated_patch_gated",
    "dangerous_complete_profile",
    "dangerous_real_network",
    "dangerous_privileged",
    "dangerous_generated_patch",
    "dangerous_git_latex_sage",
    "dangerous_workflow_non_inheritance",
    "safe_attestation",
    "trusted_attestation",
    "dangerous_attestation",
    "magma_host_status_classified",
}
TOOLS = {"bwrap", "curl", "git", "pdflatex", "latexmk", "sage", "magma"}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_qualification_binding(payload: dict[str, Any]) -> bool:
    qualification = str(payload["qualification_commit"])
    commands = (
        ["git", "cat-file", "-e", f"{qualification}^{{commit}}"],
        ["git", "merge-base", "--is-ancestor", IMPLEMENTATION_COMMIT, qualification],
        ["git", "merge-base", "--is-ancestor", qualification, "HEAD"],
        ["git", "diff", "--quiet", f"{IMPLEMENTATION_COMMIT}..{qualification}", "--", "crates"],
        [
            "git",
            "diff",
            "--quiet",
            f"{IMPLEMENTATION_COMMIT}..{qualification}",
            "--",
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            "crates/mtm-cli/assets",
        ],
    )
    for command in commands:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )
        if completed.returncode != 0:
            return False
    completed = subprocess.run(
        ["git", "show", f"{qualification}:scripts/run_mtm014_public_authority_target.py"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )
    return (
        completed.returncode == 0
        and hashlib.sha256(completed.stdout).hexdigest() == payload["runner_sha256"]
    )


def validate(
    payload: Any,
    *,
    d5a_sha256: str | None = None,
    pre_target_sha256: str | None = None,
    qualification_binding_verified: bool | None = None,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("public target evidence must be an object")
    required = {
        "schema_version",
        "milestone",
        "phase",
        "ok",
        "qualification_commit",
        "implementation_commit",
        "candidate_binary_sha256",
        "candidate_version",
        "runner_sha256",
        "d5a_evidence_sha256",
        "pre_cutover_target_evidence_sha256",
        "check_count",
        "checks",
        "required_tools",
        "magma_host_status",
        "human_consent_reused_from_d5a",
        "scripted_response_is_not_human_evidence",
        "public_exec_apply_patch_authority",
        "public_missing_grant_error",
        "client_supplied_grant_id",
        "stable_selector_changed",
        "workflow_authority_inherited",
        "release_or_selector_cutover_performed",
        "evidence_hygiene",
    }
    if set(payload) != required:
        raise ValueError("public target evidence has missing or unexpected fields")
    expected = {
        "schema_version": "1.0.0",
        "milestone": "MTM-014",
        "phase": "post_cutover_public_native_permission_target",
        "ok": True,
        "implementation_commit": IMPLEMENTATION_COMMIT,
        "candidate_version": "mtm 0.4.0",
        "human_consent_reused_from_d5a": True,
        "scripted_response_is_not_human_evidence": True,
        "public_exec_apply_patch_authority": "typed_rust_native_permission_authority",
        "public_missing_grant_error": "PERMISSION_REQUIRED",
        "client_supplied_grant_id": False,
        "stable_selector_changed": False,
        "workflow_authority_inherited": False,
        "release_or_selector_cutover_performed": False,
    }
    for key, value in expected.items():
        if type(payload[key]) is not type(value) or payload[key] != value:
            raise ValueError(f"public target evidence scope is invalid: {key}")
    for key in ("qualification_commit", "implementation_commit"):
        if re.fullmatch(r"[0-9a-f]{40}", str(payload[key])) is None:
            raise ValueError(f"public target commit digest is invalid: {key}")
    for key in (
        "candidate_binary_sha256",
        "runner_sha256",
        "d5a_evidence_sha256",
        "pre_cutover_target_evidence_sha256",
    ):
        if re.fullmatch(r"[0-9a-f]{64}", str(payload[key])) is None:
            raise ValueError(f"public target SHA-256 is invalid: {key}")

    expected_d5a = sha256_file(D5A) if d5a_sha256 is None else d5a_sha256
    expected_pre_target = sha256_file(PRE_TARGET) if pre_target_sha256 is None else pre_target_sha256
    for digest in (expected_d5a, expected_pre_target):
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError("injected evidence digest is invalid")
    if payload["d5a_evidence_sha256"] != expected_d5a:
        raise ValueError("D5A binding is stale")
    if payload["pre_cutover_target_evidence_sha256"] != expected_pre_target:
        raise ValueError("pre-cutover target binding is stale")

    checks = payload["checks"]
    if not isinstance(checks, dict) or set(checks) != CHECKS:
        raise ValueError("public target check set is incomplete")
    if any(value is not True for value in checks.values()):
        raise ValueError("public target check set contains a failure")
    if type(payload["check_count"]) is not int or payload["check_count"] != len(CHECKS):
        raise ValueError("public target check count is invalid")
    tools = payload["required_tools"]
    if not isinstance(tools, dict) or set(tools) != TOOLS or any(value is not True for value in tools.values()):
        raise ValueError("public target required tools are incomplete")
    if payload["magma_host_status"] not in {"passed", "blocked_host_license"}:
        raise ValueError("public target Magma status is not classified")
    hygiene = payload["evidence_hygiene"]
    if not isinstance(hygiene, dict) or not hygiene or any(value is not False for value in hygiene.values()):
        raise ValueError("public target evidence contains raw authority material")
    binding = (
        verify_qualification_binding(payload)
        if qualification_binding_verified is None
        else qualification_binding_verified
    )
    if binding is not True:
        raise ValueError("public target qualification commit binding is invalid")
    return {
        "scope": "A4_post_cutover_public",
        "check_count": len(CHECKS),
        "public_authority_qualified": True,
        "release_cutover_allowed": False,
        "magma_host_status": payload["magma_host_status"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=REPORT)
    args = parser.parse_args()
    try:
        summary = validate(json.loads(args.report.read_text(encoding="utf-8")))
    except (OSError, ValueError, json.JSONDecodeError):
        print(json.dumps({"ok": False, "error": "public target evidence missing or invalid"}))
        return 1
    print(json.dumps({"ok": True, "summary": summary}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
